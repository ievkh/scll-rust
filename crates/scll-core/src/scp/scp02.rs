//! SCP02 state machine — PDD §5.9 (SCP02 path; GPCS v2.3.1 Appendix E). Crypto
//! is delegated to a [`Scp02Backend`]; this module owns only the *framing* and
//! the pure decisions, so it is unit-testable with a stub backend (no real
//! crypto).
//!
//! INITIALIZE UPDATE (INS `50`, P2 = key id) → 28-byte IU response:
//! KDD(10) KVN(1) SCP=02(1) `seq_counter(2)` `card_challenge(6)`
//! `card_cryptogram(8)`. Unlike SCP03 the response carries no `i` byte — the
//! `i` parameter comes from the CRD / version selection (§4.3) and is passed in.
//! The sequence counter is read from the card and fed to the KDF (§E.4.1).
//! EXTERNAL AUTHENTICATE (INS `82`) carries the host cryptogram; its `P1` is the
//! effective security level, capped to the card's `i` capability (§5.9 step 8;
//! default `0x03`). R-MAC (levels `0x11`/`0x13`) uses BEGIN/END R-MAC SESSION
//! (INS `7A`/`78`), issued by the workflow (S6).

use heapless::Vec;

use crate::backend::{KeyHandle, Scp02Backend, Scp02Session};
use crate::command::{BuildError, Capdu};
use crate::error::ScllError;
use crate::limits::RAPDU_MAX;

const INS_INITIALIZE_UPDATE: u8 = 0x50;
const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
const SCP_ID_SCP02: u8 = 0x02;

/// Length of the SCP02 INITIALIZE UPDATE response with the SW stripped
/// (PDD §5.9 SCP02 step 5).
const IU_RESPONSE_LEN: usize = 28;

/// Parsed SCP02 INITIALIZE UPDATE response fields (PDD §5.9 SCP02 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IuResponse {
    /// Key Version Number the card actually used.
    pub kvn: u8,
    /// 2-byte sequence counter (feeds the §E.4.1 session-key derivation).
    pub seq_counter: [u8; 2],
    /// 6-byte card challenge.
    pub card_challenge: [u8; 6],
    /// 8-byte card cryptogram (verified against the backend's value).
    pub card_cryptogram: [u8; 8],
}

/// Host-side SCP02 channel state. Holds the backend [`Scp02Session`] handle (an
/// index into the backend's session table — all secret state lives there) plus
/// the negotiated `i` parameter and the effective security level.
pub struct Scp02State {
    session: Scp02Session,
    i_param: u8,
    security_level: u8,
    kvn: u8,
}

impl Scp02State {
    /// The backend session handle.
    #[must_use]
    pub fn session(&self) -> Scp02Session {
        self.session
    }
    /// The key version number the card authenticated with (from INITIALIZE
    /// UPDATE). Used to tell whether a later PUT KEY replaces the active keyset.
    #[must_use]
    pub fn kvn(&self) -> u8 {
        self.kvn
    }
    /// The card's negotiated `i` parameter (from the CRD / §4.3 selection).
    #[must_use]
    pub fn i_param(&self) -> u8 {
        self.i_param
    }
    /// The effective (capped) security level fixed at channel open.
    #[must_use]
    pub fn security_level(&self) -> u8 {
        self.security_level
    }

    /// Wrap a command C-APDU plaintext for transmission (C-MAC, and
    /// C-DECRYPTION when the level enables it).
    ///
    /// # Errors
    /// Propagates [`ScllError::Backend`] if the backend rejects the session or
    /// wrapping fails.
    pub fn wrap_command<B: Scp02Backend>(
        &mut self,
        backend: &B,
        capdu: &[u8],
    ) -> Result<Capdu, ScllError> {
        Ok(backend.scp02_wrap_command(&mut self.session, capdu)?)
    }

    /// Verify and strip a response R-APDU. At levels without R-MAC SCP02
    /// responses are unprotected, so this returns `data ‖ SW` unchanged; at
    /// level `0x13` the backend verifies and strips the R-MAC.
    ///
    /// # Errors
    /// Propagates [`ScllError::Backend`]; on an R-MAC failure the backend tears
    /// the session down (Fork F3).
    pub fn unwrap_response<B: Scp02Backend>(
        &mut self,
        backend: &B,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, ScllError> {
        Ok(backend.scp02_unwrap_response(&mut self.session, rapdu)?)
    }
}

/// Build the INITIALIZE UPDATE C-APDU: `80 50 <kvn> <key_id> 08
/// <host_challenge> 00` (P2 is the key identifier for SCP02; Case 4S with
/// `Le = 00`). PDD §5.9 SCP02 step 4.
///
/// # Errors
/// [`ScllError::Build`] only on the structurally impossible buffer overflow
/// (the inputs are fixed-size); kept fallible for a uniform builder contract.
pub fn iu_command(kvn: u8, key_id: u8, host_challenge: &[u8; 8]) -> Result<Capdu, ScllError> {
    let mut apdu = Capdu::new();
    extend(&mut apdu, &[0x80, INS_INITIALIZE_UPDATE, kvn, key_id, 0x08])?;
    extend(&mut apdu, host_challenge)?;
    extend(&mut apdu, &[0x00])?;
    Ok(apdu)
}

/// Build the EXTERNAL AUTHENTICATE *plaintext* C-APDU (pre-MAC):
/// `84 82 <security_level> 00 08 <host_cryptogram>`. The backend's
/// `scp02_wrap_command` appends the C-MAC (growing `Lc` to `0x10`) and latches
/// the level from `P1` (Fork F1). PDD §5.9 SCP02 step 10.
fn ea_plaintext(security_level: u8, host_cryptogram: [u8; 8]) -> Result<Capdu, ScllError> {
    let mut apdu = Capdu::new();
    extend(
        &mut apdu,
        &[0x84, INS_EXTERNAL_AUTHENTICATE, security_level, 0x00, 0x08],
    )?;
    extend(&mut apdu, &host_cryptogram)?;
    Ok(apdu)
}

/// Parse and validate the SCP02 INITIALIZE UPDATE response (SW already
/// stripped).
///
/// # Errors
/// [`ScllError::ScpProtocolUnsupported`] if the length is wrong or the SCP id
/// is not `0x02` (PDD §5.9 SCP02 step 5).
pub fn parse_iu_response(bytes: &[u8]) -> Result<IuResponse, ScllError> {
    if bytes.len() != IU_RESPONSE_LEN {
        return Err(ScllError::ScpProtocolUnsupported);
    }
    if bytes[11] != SCP_ID_SCP02 {
        return Err(ScllError::ScpProtocolUnsupported);
    }
    let mut seq_counter = [0u8; 2];
    let mut card_challenge = [0u8; 6];
    let mut card_cryptogram = [0u8; 8];
    seq_counter.copy_from_slice(&bytes[12..14]);
    card_challenge.copy_from_slice(&bytes[14..20]);
    card_cryptogram.copy_from_slice(&bytes[20..28]);
    Ok(IuResponse {
        kvn: bytes[10],
        seq_counter,
        card_challenge,
        card_cryptogram,
    })
}

/// Cap the requested security level to the card's `i` capability (PDD §5.9
/// SCP02 step 8): C-MAC + C-DECRYPTION (`0x03`) are always allowed; for the
/// R-MAC-capable `i ∈ {0x15, 0x55}` the R-MAC bit (`0x10`) is added. SCP02 has
/// no R-ENC, so `0x20` is never allowed.
///
/// # Errors
/// [`ScllError::NoCommonSecurityLevel`] if nothing remains after masking.
pub fn cap_security_level(i_param: u8, requested: u8) -> Result<u8, ScllError> {
    let mut allowed = 0x03u8;
    if matches!(i_param, 0x15 | 0x55) {
        allowed |= 0x10;
    }
    let effective = requested & allowed;
    if effective == 0 {
        return Err(ScllError::NoCommonSecurityLevel);
    }
    Ok(effective)
}

/// Drive the host side of the SCP02 open from a received IU response to a
/// ready-to-send EXTERNAL AUTHENTICATE (PDD §5.9 SCP02 steps 5–10). Pure given a
/// `backend`: parses+validates the IU, derives the session from the sequence
/// counter, verifies the card cryptogram (constant-time), caps the level, and
/// returns the wrapped EA alongside the [`Scp02State`]. Transport I/O (SELECT,
/// sending IU/EA, checking the EA status word, BEGIN R-MAC SESSION) is the
/// workflow's job (S6). `i_param` is the negotiated value from the CRD / §4.3
/// selection (the SCP02 IU response carries no `i` byte).
///
/// # Errors
/// [`ScllError::KvnMismatch`] if a non-zero `kvn_expected` differs from the
/// card's; [`ScllError::CardCryptogramFail`] on cryptogram mismatch;
/// [`ScllError::NoCommonSecurityLevel`] / [`ScllError::ScpProtocolUnsupported`]
/// from parsing/capping; [`ScllError::Backend`] from the backend.
// SCP02 open genuinely needs ENC/MAC/DEK + i + kvn + level + challenge + IU.
#[allow(clippy::too_many_arguments)]
pub fn begin<B: Scp02Backend>(
    backend: &B,
    base_enc: &KeyHandle,
    base_mac: &KeyHandle,
    base_dek: &KeyHandle,
    i_param: u8,
    kvn_expected: u8,
    requested_level: u8,
    host_challenge: &[u8; 8],
    iu_response: &[u8],
) -> Result<(Scp02State, Capdu), ScllError> {
    let iu = parse_iu_response(iu_response)?;

    // KVN default 0x00 means "card picks"; only enforce a caller-pinned KVN.
    if kvn_expected != 0x00 && iu.kvn != kvn_expected {
        return Err(ScllError::KvnMismatch);
    }

    let mut session = backend.scp02_derive_session(base_enc, base_mac, base_dek, iu.seq_counter)?;

    // GPCS v2.3.1 §E.4.4: the card/host cryptograms run over the 8-byte card
    // challenge = sequence_counter(2) ‖ card_challenge(6), NOT the 6-byte
    // challenge alone. Omitting the sequence counter yields a 14-byte MAC input
    // and a spurious CardCryptogramFail against real cards.
    let mut card_ch8 = [0u8; 8];
    card_ch8[..2].copy_from_slice(&iu.seq_counter);
    card_ch8[2..].copy_from_slice(&iu.card_challenge);

    let expected_card = backend.scp02_card_cryptogram(&session, host_challenge, &card_ch8)?;
    if !backend.ct_eq(&expected_card, &iu.card_cryptogram) {
        return Err(ScllError::CardCryptogramFail);
    }

    let security_level = cap_security_level(i_param, requested_level)?;

    let host_cryptogram = backend.scp02_host_cryptogram(&session, host_challenge, &card_ch8)?;

    let ea_plain = ea_plaintext(security_level, host_cryptogram)?;
    let ea_wrapped = backend.scp02_wrap_command(&mut session, &ea_plain)?;

    Ok((
        Scp02State {
            session,
            i_param,
            security_level,
            kvn: iu.kvn,
        },
        ea_wrapped,
    ))
}

/// `extend_from_slice` mapping the `heapless` capacity error to a builder
/// overflow (no panic, §10.5).
fn extend(apdu: &mut Capdu, src: &[u8]) -> Result<(), ScllError> {
    apdu.extend_from_slice(src)
        .map_err(|()| ScllError::Build(BuildError::Overflow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{KeyBackend, KeyKind};
    use crate::error::BackendError;
    use crate::limits::{CAPDU_MAX, ENC_KEY_BLOCK_MAX};
    use scll_test_util::HexSlice;

    /// Pure stub backend: canned cryptograms, real `ct_eq`, echoing wrap. Lets
    /// the framing/decision logic in `begin` be tested without crypto.
    struct StubBackend {
        card_crypto: [u8; 8],
        host_crypto: [u8; 8],
    }

    impl KeyBackend for StubBackend {
        fn import_key(&self, _k: KeyKind, _b: &[u8]) -> Result<KeyHandle, BackendError> {
            Ok(KeyHandle::new(0))
        }
        fn generate_key(&self, _k: KeyKind) -> Result<KeyHandle, BackendError> {
            Ok(KeyHandle::new(0))
        }
        fn compute_kcv(&self, _h: &KeyHandle) -> Result<[u8; 3], BackendError> {
            Ok([0; 3])
        }
        fn random_bytes(&self, out: &mut [u8]) -> Result<(), BackendError> {
            out.fill(0);
            Ok(())
        }
        fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
            a == b
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
            let mut v = Vec::new();
            v.extend_from_slice(capdu)
                .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
            Ok(v)
        }
        fn scp02_unwrap_response(
            &self,
            _s: &mut Scp02Session,
            rapdu: &[u8],
        ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
            let mut v = Vec::new();
            v.extend_from_slice(rapdu)
                .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
            Ok(v)
        }
        fn scp02_encrypt_put_key_payload_for_session(
            &self,
            _s: &Scp02Session,
            _n: &KeyHandle,
        ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
            Ok(Vec::new())
        }
    }

    /// Build a synthetic 28-byte SCP02 IU response.
    fn iu_bytes(kvn: u8, scp: u8, seq: [u8; 2], challenge: [u8; 6], crypto: [u8; 8]) -> [u8; 28] {
        let mut b = [0u8; 28];
        b[10] = kvn;
        b[11] = scp;
        b[12..14].copy_from_slice(&seq);
        b[14..20].copy_from_slice(&challenge);
        b[20..28].copy_from_slice(&crypto);
        b
    }

    #[test]
    fn iu_command_bytes() {
        let host = [0, 1, 2, 3, 4, 5, 6, 7];
        let apdu = iu_command(0x00, 0x00, &host).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0x50, 0x00, 0x00, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0x00])
        );
    }

    #[test]
    fn iu_command_carries_key_id_in_p2() {
        let apdu = iu_command(0x20, 0x01, &[0u8; 8]).unwrap();
        assert_eq!(apdu[2], 0x20); // P1 = kvn
        assert_eq!(apdu[3], 0x01); // P2 = key id
    }

    #[test]
    fn parse_valid_iu() {
        let b = iu_bytes(0x01, 0x02, [0x00, 0x05], [9; 6], [0xAA; 8]);
        let iu = parse_iu_response(&b).unwrap();
        assert_eq!(iu.kvn, 0x01);
        assert_eq!(iu.seq_counter, [0x00, 0x05]);
        assert_eq!(iu.card_challenge, [9; 6]);
        assert_eq!(iu.card_cryptogram, [0xAA; 8]);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(matches!(
            parse_iu_response(&[0u8; 29]),
            Err(ScllError::ScpProtocolUnsupported)
        ));
    }

    #[test]
    fn parse_rejects_non_scp02() {
        let b = iu_bytes(0x00, 0x03, [0; 2], [0; 6], [0; 8]); // SCP03 id
        assert!(matches!(
            parse_iu_response(&b),
            Err(ScllError::ScpProtocolUnsupported)
        ));
    }

    #[test]
    fn level_cap_table() {
        // i=0x55 (R-MAC capable): C-MAC+C-DEC survive, R-MAC survives.
        assert_eq!(cap_security_level(0x55, 0x13).unwrap(), 0x13);
        assert_eq!(cap_security_level(0x55, 0x03).unwrap(), 0x03);
        assert_eq!(cap_security_level(0x15, 0x13).unwrap(), 0x13);
        // i without R-MAC capability: R-MAC bit masked off.
        assert_eq!(cap_security_level(0x05, 0x13).unwrap(), 0x03);
        // SCP02 never grants R-ENC (0x20).
        assert_eq!(cap_security_level(0x55, 0x33).unwrap(), 0x13);
        // Requesting only bits the card disallows → error.
        assert!(matches!(
            cap_security_level(0x05, 0x20),
            Err(ScllError::NoCommonSecurityLevel)
        ));
    }

    #[test]
    fn begin_happy_path_builds_external_authenticate() {
        let backend = StubBackend {
            card_crypto: [0xAA; 8],
            host_crypto: [0xBB; 8],
        };
        let enc = KeyHandle::new(0);
        let mac = KeyHandle::new(1);
        let dek = KeyHandle::new(2);
        let host = [0u8; 8];
        let iu = iu_bytes(0x00, 0x02, [0x00, 0x01], [9; 6], [0xAA; 8]); // matches card_crypto
        let (state, ea) = begin(&backend, &enc, &mac, &dek, 0x55, 0x00, 0x03, &host, &iu).unwrap();
        assert_eq!(state.i_param(), 0x55);
        assert_eq!(state.security_level(), 0x03);
        // EA plaintext: 84 82 <level> 00 08 <host_cryptogram> (stub echoes it).
        assert_eq!(
            HexSlice(&ea),
            HexSlice([
                0x84, 0x82, 0x03, 0x00, 0x08, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
            ])
        );
    }

    #[test]
    fn begin_rejects_bad_card_cryptogram() {
        let backend = StubBackend {
            card_crypto: [0xAA; 8],
            host_crypto: [0xBB; 8],
        };
        let iu = iu_bytes(0x00, 0x02, [0; 2], [9; 6], [0xCC; 8]); // != card_crypto
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            &KeyHandle::new(2),
            0x55,
            0x00,
            0x03,
            &[0; 8],
            &iu,
        );
        assert!(matches!(r, Err(ScllError::CardCryptogramFail)));
    }

    #[test]
    fn begin_rejects_kvn_mismatch() {
        let backend = StubBackend {
            card_crypto: [0xAA; 8],
            host_crypto: [0xBB; 8],
        };
        let iu = iu_bytes(0x05, 0x02, [0; 2], [9; 6], [0xAA; 8]);
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            &KeyHandle::new(2),
            0x55,
            0x01,
            0x03,
            &[0; 8],
            &iu,
        );
        assert!(matches!(r, Err(ScllError::KvnMismatch)));
    }

    #[test]
    fn begin_caps_rmac_for_plain_i55() {
        let backend = StubBackend {
            card_crypto: [0xAA; 8],
            host_crypto: [0xBB; 8],
        };
        let iu = iu_bytes(0x00, 0x02, [0; 2], [9; 6], [0xAA; 8]);
        let (state, ea) = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            &KeyHandle::new(2),
            0x55,
            0x00,
            0x13,
            &[0; 8],
            &iu,
        )
        .unwrap();
        assert_eq!(state.security_level(), 0x13);
        assert_eq!(ea[2], 0x13); // EA P1 carries the capped level
    }
}
