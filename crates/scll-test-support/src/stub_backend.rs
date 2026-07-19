//! `StubBackend` — a deterministic, crypto-free backend for workflow replay
//! tests (PDD §10.1 layer 3).
//!
//! The replay layer exercises *workflow orchestration* (command order, SW
//! handling, report population), not crypto correctness — that is the layer-2
//! KAT job (S4/S5). So this backend performs no real crypto: `wrap` echoes the
//! plaintext, `unwrap` echoes the response, cryptograms/KCVs/encrypted blocks
//! are fixed canned values. Because the SCP state machines are "pure given a
//! backend", driving them with this stub makes every C-APDU on the wire exactly
//! the plaintext the builders produced — so a [`crate::MockTransport`] script
//! can assert exact bytes and the whole chain stays hand-computable.
//!
//! The canned values are configurable so a test can line up the IU response's
//! card cryptogram with [`StubBackend::card_cryptogram`].

use heapless::Vec;
use scll_core::backend::{
    KeyBackend, KeyHandle, KeyKind, Scp02Backend, Scp02Session, Scp03Backend, Scp03Session, ScpMode,
};
use scll_core::error::BackendError;
use scll_core::limits::{CAPDU_MAX, ENC_KEY_BLOCK_MAX, RAPDU_MAX, SCP03_S16_MAX};

/// Deterministic, crypto-free backend (see module docs).
#[derive(Debug, Clone, Copy)]
pub struct StubBackend {
    card_crypto: [u8; 8],
    host_crypto: [u8; 8],
    kcv: [u8; 3],
    enc_block: [u8; 16],
    /// Canned pseudo-random card challenge returned by
    /// [`Scp03Backend::scp03_pseudo_card_challenge`]; defaults to `[9; 8]` to
    /// match the conventional scripted IU card challenge so the §6.2.2.1 check
    /// in `scp03::begin` passes for pseudo-random `i` (e.g. `0x70`).
    pseudo_challenge: [u8; 8],
}

impl Default for StubBackend {
    fn default() -> Self {
        Self {
            card_crypto: [0xAA; 8],
            host_crypto: [0xBB; 8],
            kcv: [0xC0, 0xC1, 0xC2],
            enc_block: [0xE0; 16],
            pseudo_challenge: [9; 8],
        }
    }
}

impl StubBackend {
    /// A stub with the default canned values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The canned card cryptogram (script the IU response to carry this so
    /// `scp0x::begin`'s constant-time check passes).
    #[must_use]
    pub fn card_cryptogram(&self) -> [u8; 8] {
        self.card_crypto
    }

    /// The canned host cryptogram (appears in the EXTERNAL AUTHENTICATE body).
    #[must_use]
    pub fn host_cryptogram(&self) -> [u8; 8] {
        self.host_crypto
    }

    /// The canned 3-byte KCV echoed for every key.
    #[must_use]
    pub fn kcv(&self) -> [u8; 3] {
        self.kcv
    }

    /// The canned encrypted-key block in a PUT KEY payload.
    #[must_use]
    pub fn encrypted_key_block(&self) -> [u8; 16] {
        self.enc_block
    }

    /// Override the cryptograms (e.g. to match a specific scripted IU response).
    #[must_use]
    pub fn with_cryptograms(mut self, card: [u8; 8], host: [u8; 8]) -> Self {
        self.card_crypto = card;
        self.host_crypto = host;
        self
    }

    /// Override the canned pseudo-random card challenge (match the scripted IU
    /// card challenge so the §6.2.2.1 verification in `begin` succeeds).
    #[must_use]
    pub fn with_pseudo_challenge(mut self, challenge: [u8; 8]) -> Self {
        self.pseudo_challenge = challenge;
        self
    }
}

fn echo_capdu(bytes: &[u8]) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
    let mut v = Vec::new();
    v.extend_from_slice(bytes)
        .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
    Ok(v)
}

fn echo_rapdu(bytes: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
    let mut v = Vec::new();
    v.extend_from_slice(bytes)
        .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
    Ok(v)
}

/// Build a `Vec<u8, SCP03_S16_MAX>` from a canned cryptogram/challenge (8 bytes
/// for the S8 stub flows).
fn vec_of(bytes: &[u8]) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
    let mut v = Vec::new();
    v.extend_from_slice(bytes)
        .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
    Ok(v)
}

impl KeyBackend for StubBackend {
    fn import_key(&self, _kind: KeyKind, _bytes: &[u8]) -> Result<KeyHandle, BackendError> {
        Ok(KeyHandle::new(0))
    }
    fn generate_key(&self, _kind: KeyKind) -> Result<KeyHandle, BackendError> {
        Ok(KeyHandle::new(0))
    }
    fn compute_kcv(&self, _h: &KeyHandle) -> Result<[u8; 3], BackendError> {
        Ok(self.kcv)
    }
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), BackendError> {
        out.fill(0);
        Ok(())
    }
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        a == b
    }
}

impl Scp03Backend for StubBackend {
    fn scp03_derive_session(
        &self,
        _e: &KeyHandle,
        _m: &KeyHandle,
        _mode: ScpMode,
        _h: &[u8],
        _c: &[u8],
    ) -> Result<Scp03Session, BackendError> {
        Ok(Scp03Session::new(0))
    }
    fn scp03_card_cryptogram(
        &self,
        _s: &Scp03Session,
        _h: &[u8],
        _c: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        vec_of(&self.card_crypto)
    }
    fn scp03_host_cryptogram(
        &self,
        _s: &Scp03Session,
        _h: &[u8],
        _c: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        vec_of(&self.host_crypto)
    }
    fn scp03_pseudo_card_challenge(
        &self,
        _e: &KeyHandle,
        _mode: ScpMode,
        _seq: &[u8; 3],
        _aid: &[u8],
    ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
        vec_of(&self.pseudo_challenge)
    }
    fn scp03_wrap_command(
        &self,
        _s: &mut Scp03Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
        echo_capdu(capdu)
    }
    fn scp03_unwrap_response(
        &self,
        _s: &mut Scp03Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
        echo_rapdu(rapdu)
    }
    fn scp03_encrypt_put_key_payload(
        &self,
        _d: &KeyHandle,
        _n: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.enc_block)
            .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
        Ok(v)
    }
}

impl Scp02Backend for StubBackend {
    fn scp02_derive_session(
        &self,
        _e: &KeyHandle,
        _m: &KeyHandle,
        _d: &KeyHandle,
        _seq: [u8; 2],
    ) -> Result<Scp02Session, BackendError> {
        Ok(Scp02Session::new(0))
    }
    fn scp02_card_cryptogram(
        &self,
        _s: &Scp02Session,
        _h: &[u8; 8],
        _c: &[u8; 8],
    ) -> Result<[u8; 8], BackendError> {
        Ok(self.card_crypto)
    }
    fn scp02_host_cryptogram(
        &self,
        _s: &Scp02Session,
        _h: &[u8; 8],
        _c: &[u8; 8],
    ) -> Result<[u8; 8], BackendError> {
        Ok(self.host_crypto)
    }
    fn scp02_wrap_command(
        &self,
        _s: &mut Scp02Session,
        capdu: &[u8],
    ) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
        echo_capdu(capdu)
    }
    fn scp02_unwrap_response(
        &self,
        _s: &mut Scp02Session,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
        echo_rapdu(rapdu)
    }
    fn scp02_encrypt_put_key_payload_for_session(
        &self,
        _s: &Scp02Session,
        _n: &KeyHandle,
    ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.enc_block)
            .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
        Ok(v)
    }
}
