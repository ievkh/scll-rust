//! # scll-backend-rustcrypto
//!
//! Pure-Rust crypto backend (shipped default, PDD §3.1/§3.6). Implements
//! `KeyBackend` + `Scp03Backend` (+ `ExportableKeyBackend`); `Scp02Backend`
//! lands in S5. Correctness is covered by known-answer tests in this crate
//! (§10.2): primitives against FIPS-197 / RFC 4493 / SP 800-108r1 and the
//! SCP03 flow against an independent reference (Amendment D v1.1.2).
//!
//! ## `no_std`
//! `#![no_std]` and alloc-free, matching `scll-core`. The `RustCrypto` primitive
//! crates are pulled with `default-features = false`. `std` is enabled only
//! under `cfg(test)` for the KAT suite (a host `critical-section` impl).
//!
//! ## Storage model (Fork A)
//! `KeyHandle` / `Scp0xSession` are indices into fixed-size tables this backend
//! owns ([`MAX_KEY_SLOTS`] / [`MAX_SESSION_SLOTS`]); no heap. The backend
//! constructs the opaque handles via their backend-facing `new(index)`
//! constructors.
//!
//! ## RNG (Fork B)
//! Generic over an injected `R: RngCore + CryptoRng`. Because the `&self` trait
//! methods mutate the key/session tables and draw randomness, the RNG and both
//! tables live behind one `critical_section::Mutex<RefCell<_>>`, giving
//! interior mutability while staying `Send + Sync`. The final binary must
//! register a `critical-section` implementation (host: the `std` feature).
//!
//! ## Security level (Fork F1)
//! `scp03_derive_session` opens the session *pre-authentication* (C-MAC only,
//! no encryption — correct for EXTERNAL AUTHENTICATE, which is never
//! encrypted). `scp03_wrap_command` latches the fixed security level from the EA
//! command's `P1` (the byte the card itself uses to set the level, Amendment D Table 7-3) and marks the session
//! authenticated; all later wraps/unwraps apply C-ENC / R-MAC / R-ENC according
//! to that latched level. The trait carries no per-call level, per §4.1.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod crypto;
mod key;
mod scp02;
mod scp03;

use core::cell::RefCell;

use critical_section::Mutex;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use scll_core::backend::{KeyKind, ScpMode};
use scll_core::limits::{CAPDU_MAX, KEY_BYTES_MAX, MAC_CHAIN_LEN, RAPDU_MAX};

/// Key slots the backend can hold at once (base + new + derived static keys
/// during provisioning). Tune per target. Handle index range is `0..MAX_KEY_SLOTS`.
pub const MAX_KEY_SLOTS: usize = 16;

/// Concurrent SCP sessions the backend tracks. One open channel is the common
/// case (§2.2); a larger table allows long single-run flows that open and close
/// many channels in sequence (e.g. the end-to-end example: ISD → SSD-perso →
/// ISD → applet → SSD → applet → ISD = 8 opens). Session index range is
/// `0..MAX_SESSION_SLOTS`.
///
/// NOTE: a slot is currently only reclaimed on crypto-failure tear-down, not on
/// a normal [`crate`]-level channel close, so each `open_scp` consumes a slot
/// for the lifetime of the backend. Until close-frees-the-slot lands, keep this
/// comfortably above the number of opens any single run performs.
pub const MAX_SESSION_SLOTS: usize = 16;

/// One stored key: algorithm class + raw bytes (zeroized on drop). Uses a fixed
/// array (not `heapless::Vec`) because heapless 0.8 has no `zeroize` feature, so
/// `heapless::Vec` is not `Zeroize`; `[u8; N]` is. `len` is the meaningful
/// prefix (16/24/32).
pub(crate) struct KeySlot {
    pub(crate) kind: KeyKind,
    pub(crate) bytes: Zeroizing<[u8; KEY_BYTES_MAX]>,
    pub(crate) len: u8,
}

impl KeySlot {
    /// The meaningful key bytes.
    pub(crate) fn key(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Derived SCP03 session state for one open channel (Fork A: a session-table
/// slot). The three session keys are secret and zeroized on drop (the slot is
/// dropped when the session is invalidated, §4.1 close / decrypt-failure
/// tear-down).
pub(crate) struct Scp03SessionSlot {
    pub(crate) s_enc: Zeroizing<[u8; KEY_BYTES_MAX]>,
    pub(crate) s_mac: Zeroizing<[u8; KEY_BYTES_MAX]>,
    pub(crate) s_rmac: Zeroizing<[u8; KEY_BYTES_MAX]>,
    pub(crate) key_len: u8,
    /// Size mode (S8/S16), recorded at derive; fixes the cryptogram length and
    /// the appended-MAC width for the session (Amendment D §5.1 / §6.2.4).
    pub(crate) mode: ScpMode,
    /// MAC chaining value (16×`00` at open; the full C-MAC of the last command
    /// thereafter — persists across C-MAC and R-MAC, Amendment D §6.2.3).
    pub(crate) chain: [u8; MAC_CHAIN_LEN],
    /// Command/encryption counter (Amendment D §6.2.6); `0` until the first
    /// post-authentication command.
    pub(crate) counter: u32,
    /// Fixed security level, latched from EXTERNAL AUTHENTICATE `P1` (Fork F1).
    pub(crate) level: u8,
    /// `false` until EXTERNAL AUTHENTICATE has been wrapped.
    pub(crate) authed: bool,
}

impl Scp03SessionSlot {
    pub(crate) fn s_enc(&self) -> &[u8] {
        &self.s_enc[..usize::from(self.key_len)]
    }
    pub(crate) fn s_mac(&self) -> &[u8] {
        &self.s_mac[..usize::from(self.key_len)]
    }
    pub(crate) fn s_rmac(&self) -> &[u8] {
        &self.s_rmac[..usize::from(self.key_len)]
    }
}

/// Upper bound for the SCP02 R-MAC accumulation buffer: one wrapped command
/// (≤ [`CAPDU_MAX`]) plus the response data + SW it is finalised against
/// (≤ [`RAPDU_MAX`]). Only used while an R-MAC level (`0x11`/`0x13`) is active.
pub(crate) const SCP02_RMAC_BUF_MAX: usize = CAPDU_MAX + RAPDU_MAX;

/// Derived SCP02 session state for one open channel (GPCS v2.3.1 §E). SCP02
/// session keys are always 16-byte two-key 3DES; all four are secret and
/// zeroized on drop (slot dropped on close / C-MAC failure tear-down, §4.2).
pub(crate) struct Scp02SessionSlot {
    pub(crate) s_enc: Zeroizing<[u8; 16]>,
    pub(crate) s_mac: Zeroizing<[u8; 16]>,
    pub(crate) s_rmac: Zeroizing<[u8; 16]>,
    /// Derived session DEK. Consumed by
    /// `scp02_encrypt_put_key_payload_for_session` (PUT KEY over a
    /// `DirectOnTargetSession` channel, GPCS v2.3.1 §E.4.1).
    pub(crate) s_dek: Zeroizing<[u8; 16]>,
    /// C-MAC chaining value: the full 8-byte C-MAC of the last wrapped command.
    /// `icv_valid` is `false` before the first command, when the ICV is zero
    /// (the EXTERNAL AUTHENTICATE rule, GPCS §E.4.4 / `SCP02Wrapper`).
    pub(crate) icv: [u8; 8],
    pub(crate) icv_valid: bool,
    /// R-MAC chaining value (`00…` at open); advanced per command/response pair.
    pub(crate) ricv: [u8; 8],
    /// Accumulates the current command for R-MAC; reset at each wrap, consumed
    /// at the matching unwrap. Empty unless an R-MAC level is active.
    pub(crate) rmac_buf: heapless::Vec<u8, SCP02_RMAC_BUF_MAX>,
    /// Fixed security level, latched from EXTERNAL AUTHENTICATE `P1` (Fork F1).
    pub(crate) level: u8,
    /// `false` until EXTERNAL AUTHENTICATE has been wrapped.
    pub(crate) authed: bool,
}

/// All mutable backend state, guarded by a single critical-section mutex so the
/// `&self` trait methods (key-slot writes, session chaining updates, RNG draws)
/// have interior mutability while the backend stays `Send + Sync` on `no_std`.
pub(crate) struct BackendState<R> {
    pub(crate) keys: [Option<KeySlot>; MAX_KEY_SLOTS],
    pub(crate) sessions: [Option<Scp03SessionSlot>; MAX_SESSION_SLOTS],
    pub(crate) scp02_sessions: [Option<Scp02SessionSlot>; MAX_SESSION_SLOTS],
    pub(crate) rng: R,
}

/// Pure-Rust software backend over the `RustCrypto` primitive crates.
///
/// Generic over an injected CSPRNG `R` (Fork B). Construct with [`Self::new`].
pub struct RustCryptoBackend<R: RngCore + CryptoRng + Send + 'static> {
    pub(crate) state: Mutex<RefCell<BackendState<R>>>,
}

impl<R: RngCore + CryptoRng + Send + 'static> RustCryptoBackend<R> {
    /// Construct the backend with a caller-supplied CSPRNG. An RNG must be
    /// injected (Fork B); there is no zero-arg `new()`/`Default`.
    #[must_use]
    pub fn new(rng: R) -> Self {
        Self {
            state: Mutex::new(RefCell::new(BackendState {
                keys: core::array::from_fn(|_| None),
                sessions: core::array::from_fn(|_| None),
                scp02_sessions: core::array::from_fn(|_| None),
                rng,
            })),
        }
    }

    /// Run `f` with exclusive access to the backend state under the
    /// critical-section mutex. Centralises the lock so the trait impls stay
    /// thin and there is exactly one borrow site.
    pub(crate) fn with_state<T>(&self, f: impl FnOnce(&mut BackendState<R>) -> T) -> T {
        critical_section::with(|cs| f(&mut self.state.borrow(cs).borrow_mut()))
    }
}
