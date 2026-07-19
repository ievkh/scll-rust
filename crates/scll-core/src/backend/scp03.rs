//! `Scp03Backend` — SCP03, Amendment D v1.1.2. PDD §3.3 / §4.1.
//!
//! `no_std`: `wrap`/`unwrap`/`encrypt_put_key_payload` return bounded
//! `heapless::Vec` (a wrapped C-APDU is still ≤ `CAPDU_MAX`; a stripped R-APDU
//! ≤ `RAPDU_MAX`; an encrypted key block ≤ `ENC_KEY_BLOCK_MAX`).

use heapless::Vec;

use crate::backend::key::{KeyBackend, KeyHandle};
use crate::error::BackendError;
use crate::limits::{CAPDU_MAX, ENC_KEY_BLOCK_MAX, RAPDU_MAX, SCP03_S16_MAX};

/// SCP03 secure-channel size mode (Amendment D §5.1 Table 5-1, bit b4 `0x08`):
/// `S8` uses 8-byte challenges/cryptograms and 8-byte (truncated) MACs (legacy);
/// `S16` (Amendment D v1.2) uses 16-byte challenges/cryptograms and full 16-byte
/// MACs. The MAC *chaining* value is 16 bytes in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpMode {
    /// 8-byte fields, 8-byte truncated MACs.
    S8,
    /// 16-byte fields, full 16-byte MACs (Amendment D v1.2).
    S16,
}

impl ScpMode {
    /// Derive the mode from the SCP03 `i` parameter (bit b4 `0x08` ⇒ S16).
    #[must_use]
    pub const fn from_i(i_param: u8) -> Self {
        if i_param & 0x08 != 0 {
            Self::S16
        } else {
            Self::S8
        }
    }
    /// Challenge / cryptogram length in bytes (8 or 16).
    #[must_use]
    pub const fn field_len(self) -> usize {
        match self {
            Self::S8 => 8,
            Self::S16 => 16,
        }
    }
    /// Length of the MAC appended to commands/responses: 8 bytes (truncated) in
    /// S8, the full 16 bytes in S16 (Amendment D §6.2.4/§6.2.5).
    #[must_use]
    pub const fn mac_len(self) -> usize {
        self.field_len()
    }
    /// KDF "L" (derived-data length in bits) for challenges and cryptograms:
    /// `0x0040` (64) in S8, `0x0080` (128) in S16 (Amendment D §6.2.2).
    #[must_use]
    pub const fn l_bits(self) -> u16 {
        match self {
            Self::S8 => 0x0040,
            Self::S16 => 0x0080,
        }
    }
}

/// Backend-defined opaque SCP03 session: an **index into the backend's session
/// table**, which holds the derived S-ENC/S-MAC/S-RMAC, MAC chaining value and
/// fixed security level. Opaque to callers; never exposes key material. The
/// `new`/`index` accessors are backend-facing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scp03Session(u16);

impl Scp03Session {
    /// Construct from a backend session-slot index.
    #[must_use]
    pub const fn new(index: u16) -> Self {
        Self(index)
    }
    /// The backend session-slot index.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.0
    }
}

/// SCP03 crypto flow. Required by the default card manager (§3.6).
pub trait Scp03Backend: KeyBackend {
    /// Derive the SCP03 session keys (S-ENC/S-MAC/S-RMAC) from the static keys
    /// and the host/card challenges, returning an opaque [`Scp03Session`]. The
    /// `mode` (S8/S16) is recorded in the session and fixes the MAC width and
    /// cryptogram length for its lifetime. `host_challenge`/`card_challenge` are
    /// `mode.field_len()` bytes (8 or 16).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if key derivation fails or a challenge
    /// length does not match `mode`, or [`BackendError::KeyGen`] if no session
    /// slot is free.
    fn scp03_derive_session(
        &self,
        static_enc: &KeyHandle,
        static_mac: &KeyHandle,
        mode: ScpMode,
        host_challenge: &[u8],
        card_challenge: &[u8],
    ) -> Result<Scp03Session, BackendError>;

    /// Compute the expected card cryptogram for verification (8 or 16 bytes per
    /// the session's mode).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or the MAC
    /// computation fails.
    fn scp03_card_cryptogram(
        &self,
        s: &Scp03Session,
        host_ch: &[u8],
        card_ch: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;

    /// Compute the host cryptogram for EXTERNAL AUTHENTICATE (8 or 16 bytes per
    /// the session's mode).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or the MAC
    /// computation fails.
    fn scp03_host_cryptogram(
        &self,
        s: &Scp03Session,
        host_ch: &[u8],
        card_ch: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;

    /// Recompute the expected **pseudo-random** card challenge for verification
    /// (Amendment D §6.2.2.1): KDF keyed by the static `Key-ENC`, derivation
    /// constant `0x02`, `L = mode.l_bits()`, context = `seq_counter ‖
    /// invoker_aid`. Returns 8 or 16 bytes per `mode`. The caller compares it
    /// (constant-time) to the card challenge from the IU response when a
    /// sequence counter is present.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the handle is invalid or derivation
    /// fails.
    fn scp03_pseudo_card_challenge(
        &self,
        static_enc: &KeyHandle,
        mode: ScpMode,
        seq_counter: &[u8; 3],
        invoker_aid: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;

    // No `level` arg: the session fixes its security level at open (§4.1).
    /// Apply the session security level (C-MAC, optional C-ENC) to `capdu`.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or wrapping
    /// fails.
    fn scp03_wrap_command(
        &self,
        s: &mut Scp03Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError>;

    /// Verify and strip the R-MAC/R-ENC from `rapdu`.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if R-MAC verification fails or the
    /// session is invalid.
    fn scp03_unwrap_response(
        &self,
        s: &mut Scp03Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError>;

    // New key is a HANDLE, not bytes (HSM-wrappable, no host plaintext).
    // SCP03 uses the static DEK (Amendment D §6.2.6).
    /// Encrypt `new_key` under the static DEK for a PUT KEY payload
    /// (Amendment D §6.2.6).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if encryption fails, or
    /// [`BackendError::Unsupported`] if a handle is not encryptable.
    fn scp03_encrypt_put_key_payload(
        &self,
        dek: &KeyHandle,
        new_key: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError>;

    /// Release the backend session slot held by `s`, zeroizing its session
    /// keys and MAC chaining value. Called by the card manager on channel
    /// close so a long-lived backend does not leak slots across many
    /// open/close cycles (PDD §3.6 / §4.1). The default is a no-op, so
    /// stateless or stub backends that keep no slot table need not override it.
    fn scp03_close_session(&self, _s: Scp03Session) {}
}
