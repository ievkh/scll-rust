//! `Scp02Backend` — SCP02, GPCS v2.3.1 §E. PDD §3.3 / §4.2.
//!
//! Separate trait so SCP03-only backends omit it (and the 3DES/Retail-MAC path).
//!
//! `no_std`: same bounded-`heapless::Vec` returns as the SCP03 trait.

use heapless::Vec;

use crate::backend::key::{KeyBackend, KeyHandle};
use crate::error::BackendError;
use crate::limits::{CAPDU_MAX, ENC_KEY_BLOCK_MAX, RAPDU_MAX};

/// Backend-defined opaque SCP02 session: an **index into the backend's session
/// table** (session ENC/MAC/DEK, ICV, fixed level). The `new`/`index` accessors
/// are backend-facing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scp02Session(u16);

impl Scp02Session {
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

/// SCP02 crypto flow. The INITIALIZE UPDATE response carries a 2-byte sequence
/// counter and a 6-byte card challenge; the card/host cryptograms (GPCS v2.3.1
/// Appendix E.4.4) are computed over the **8-byte card challenge** =
/// `sequence_counter(2) ‖ card_challenge(6)`, which is what the two cryptogram
/// methods below receive in `card_ch`.
pub trait Scp02Backend: KeyBackend {
    /// Derive the SCP02 session from the base keys and `seq_counter`,
    /// returning an opaque [`Scp02Session`].
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if key derivation fails, or
    /// [`BackendError::KeyGen`] if no session slot is free.
    fn scp02_derive_session(
        &self,
        base_enc: &KeyHandle,
        base_mac: &KeyHandle,
        base_dek: &KeyHandle,
        seq_counter: [u8; 2],
    ) -> Result<Scp02Session, BackendError>;

    /// Compute the expected card cryptogram for verification. `card_ch` is the
    /// 8-byte `sequence_counter(2) ‖ card_challenge(6)` (GPCS v2.3.1 §E.4.4).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or the MAC
    /// computation fails.
    fn scp02_card_cryptogram(
        &self,
        s: &Scp02Session,
        host_ch: &[u8; 8],
        card_ch: &[u8; 8],
    ) -> Result<[u8; 8], BackendError>;

    /// Compute the host cryptogram for EXTERNAL AUTHENTICATE. `card_ch` is the
    /// 8-byte `sequence_counter(2) ‖ card_challenge(6)` (GPCS v2.3.1 §E.4.4).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or the MAC
    /// computation fails.
    fn scp02_host_cryptogram(
        &self,
        s: &Scp02Session,
        host_ch: &[u8; 8],
        card_ch: &[u8; 8],
    ) -> Result<[u8; 8], BackendError>;

    /// Apply the session security level (C-MAC, optional C-ENC) to `capdu`.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if the session is invalid or wrapping
    /// fails.
    fn scp02_wrap_command(
        &self,
        s: &mut Scp02Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError>;

    // R-MAC verify/strip (level 0x13). Closes the v0.5 unwrap gap (§4.2).
    /// Verify and strip the R-MAC (level `0x13`) from `rapdu`.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if R-MAC verification fails or the
    /// session is invalid.
    fn scp02_unwrap_response(
        &self,
        s: &mut Scp02Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError>;

    /// Encrypt `new_key` for a PUT KEY payload under **session `s`'s own
    /// derived DEK** (`S-DEK`, GPCS v2.3.1 §E.4.1) rather than a
    /// caller-supplied static key.
    ///
    /// SCP02 PUT KEY over a direct channel against the target SD must encrypt
    /// the new key material under the session DEK derived at channel open
    /// (from the base DEK + the sequence counter read from INITIALIZE UPDATE),
    /// not the static base DEK — confirmed both by GPCS §E.4.1 and empirically
    /// against a live NXP JCOP 4 P71 SSD, where `GlobalPlatformPro`'s own
    /// debug trace shows it encrypting under this derived value (distinct
    /// from the static key it authenticated with) before a PUT KEY that the
    /// card accepts (static-DEK encryption is rejected with `6982`). The
    /// workflow layer (`workflow::keys::put_sd_keys`) always calls this for
    /// SCP02, so callers of `put_sd_keys` never need to
    /// supply the (inaccessible) session DEK themselves.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if encryption fails, or
    /// [`BackendError::Unsupported`] if `new_key` is not encryptable, or if
    /// `s` is not a live session (its DEK cannot be read).
    fn scp02_encrypt_put_key_payload_for_session(
        &self,
        s: &Scp02Session,
        new_key: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError>;

    /// Release the backend session slot held by `s`, zeroizing its session
    /// keys, DEK and ICV. Called by the card manager on channel close so a
    /// long-lived backend does not leak slots across many open/close cycles
    /// (PDD §3.6 / §4.2). The default is a no-op, so stateless or stub
    /// backends that keep no slot table need not override it.
    fn scp02_close_session(&self, _s: Scp02Session) {}
}
