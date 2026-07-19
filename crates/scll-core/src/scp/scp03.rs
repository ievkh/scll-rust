//! SCP03 state machine — PDD §5.9 (SCP03 path). Crypto is delegated to a
//! [`Scp03Backend`]; this module owns only the *framing* and the pure
//! decisions, so it is unit-testable with a stub backend (no real crypto).
//!
//! INITIALIZE UPDATE (INS `50`, P2 `00`) → IU response (SW stripped):
//! `KDD(10) KVN(1) SCP=03(1) i(1) card_challenge(n) card_cryptogram(n)` plus a
//! conditional trailing `sequence_counter(3)`, where `n = 8` in S8 mode and
//! `n = 16` in S16 mode (Amendment D v1.2; mode = `i & 0x08`). The sequence
//! counter is present **iff the card uses pseudo-random challenges** —
//! `i & 0x10` set (§5.1 Table 5-1, §6.2.2.1, §7.1.1.6). So the four valid
//! response lengths are 29 (S8 random), 32 (S8 pseudo-random), 45 (S16 random)
//! and 48 (S16 pseudo-random). `i & 0x20`/`0x40` add R-MAC/R-ENC (R-ENC implies
//! R-MAC).
//!
//! Session keys and cryptograms use `host_challenge ‖ card_challenge` as the KDF
//! context (§6.2.1, §6.2.2.2/.3); the sequence counter does not feed them. When
//! a sequence counter is present (pseudo-random card), [`begin`] additionally
//! recomputes the expected card challenge per §6.2.2.1 — KDF keyed by Key-ENC,
//! constant `0x02`, context = `sequence_counter ‖ invoker_aid` — and rejects a
//! mismatch with [`ScllError::CardChallengeFail`] (defence in depth).
//!
//! EXTERNAL AUTHENTICATE (INS `82`) carries the host cryptogram; its `P1` is the
//! effective security level, capped to the card's `i` capability (§5.9 step 8;
//! default `0x33`).

use heapless::Vec;

use crate::backend::{KeyHandle, Scp03Backend, Scp03Session, ScpMode};
use crate::command::{BuildError, Capdu};
use crate::error::ScllError;
use crate::limits::{RAPDU_MAX, SCP03_S16_MAX};

const INS_INITIALIZE_UPDATE: u8 = 0x50;
const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
const SCP_ID_SCP03: u8 = 0x03;

/// IU response prefix length: `KDD(10) KVN(1) SCP(1) i(1)` (Amendment D
/// §7.1.1.6). The card challenge and cryptogram (each `mode.field_len()` bytes)
/// and the optional 3-byte sequence counter follow.
const IU_PREFIX_LEN: usize = 13;
/// Byte offset of the `i` parameter within the IU response.
const IU_I_OFFSET: usize = 12;
/// Length of the SCP03 sequence counter (Amendment D §6.2.2.1).
const SEQ_COUNTER_LEN: usize = 3;

/// `i`-parameter bit (Amendment D §5.1 Table 5-1): set ⇒ S16 mode (16-byte
/// challenges/cryptograms, full 16-byte MACs); clear ⇒ S8 mode.
const I_S16: u8 = 0x08;
/// `i`-parameter bit: set ⇒ the card uses pseudo-random challenges and the IU
/// response carries a sequence counter; clear ⇒ random challenges.
const I_PSEUDO_RANDOM: u8 = 0x10;
/// `i`-parameter bit: R-MAC support.
const I_RMAC: u8 = 0x20;
/// `i`-parameter bit: R-ENCRYPTION support (only valid combined with R-MAC).
const I_RENC: u8 = 0x40;

/// Parsed INITIALIZE UPDATE response fields (PDD §5.9 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IuResponse {
    /// Key Version Number the card actually used.
    pub kvn: u8,
    /// SCP `i` parameter (e.g. `0x00,0x10,…,0x70`, optionally `| 0x08` for S16).
    pub i_param: u8,
    /// Size mode derived from `i_param` (`i & 0x08`).
    pub mode: ScpMode,
    /// Card challenge (`mode.field_len()` bytes: 8 in S8, 16 in S16).
    pub card_challenge: Vec<u8, SCP03_S16_MAX>,
    /// Card cryptogram (`mode.field_len()` bytes), verified against the backend.
    pub card_cryptogram: Vec<u8, SCP03_S16_MAX>,
    /// 3-byte sequence counter, present **iff** the card uses pseudo-random
    /// challenges (`i & 0x10`; Amendment D §6.2.2.1 / §7.1.1.6). Drives the
    /// optional §6.2.2.1 challenge verification in [`begin`]; not used in
    /// session-key or cryptogram derivation.
    pub sequence_counter: Option<[u8; SEQ_COUNTER_LEN]>,
}

/// Host-side SCP03 channel state. Holds the backend [`Scp03Session`] handle (an
/// index into the backend's session table — all secret state lives there) plus
/// the negotiated `i` parameter and the effective security level.
pub struct Scp03State {
    session: Scp03Session,
    i_param: u8,
    security_level: u8,
    kvn: u8,
}

impl Scp03State {
    /// The backend session handle.
    #[must_use]
    pub fn session(&self) -> Scp03Session {
        self.session
    }
    /// The key version number the card authenticated with (from INITIALIZE
    /// UPDATE). Used to tell whether a later PUT KEY replaces the active keyset.
    #[must_use]
    pub fn kvn(&self) -> u8 {
        self.kvn
    }
    /// The card's advertised `i` parameter.
    #[must_use]
    pub fn i_param(&self) -> u8 {
        self.i_param
    }
    /// The effective (capped) security level fixed at channel open.
    #[must_use]
    pub fn security_level(&self) -> u8 {
        self.security_level
    }

    /// Wrap a command C-APDU plaintext for transmission (C-MAC, and C-ENC when
    /// the level enables it).
    ///
    /// # Errors
    /// Propagates [`ScllError::Backend`] if the backend rejects the session or
    /// wrapping fails.
    pub fn wrap_command<B: Scp03Backend>(
        &mut self,
        backend: &B,
        capdu: &[u8],
    ) -> Result<Capdu, ScllError> {
        Ok(backend.scp03_wrap_command(&mut self.session, capdu)?)
    }

    /// Verify and strip a response R-APDU (R-MAC / R-ENC per the level).
    ///
    /// # Errors
    /// Propagates [`ScllError::Backend`]; on a MAC/decrypt failure the backend
    /// tears the session down (Fork F3).
    pub fn unwrap_response<B: Scp03Backend>(
        &mut self,
        backend: &B,
        rapdu: &[u8],
    ) -> Result<Vec<u8, RAPDU_MAX>, ScllError> {
        Ok(backend.scp03_unwrap_response(&mut self.session, rapdu)?)
    }
}

/// Build the INITIALIZE UPDATE C-APDU: `80 50 <kvn> 00 <Lc> <host_challenge> 00`
/// where `Lc` is the host-challenge length (`0x08` in S8, `0x10` in S16; P2
/// always `00` for SCP03; Case 4S with `Le = 00`). PDD §5.9 step 4.
///
/// # Errors
/// [`ScllError::Build`] on buffer overflow or if `host_challenge` is longer than
/// a short `Lc` (255).
pub fn iu_command(kvn: u8, host_challenge: &[u8]) -> Result<Capdu, ScllError> {
    let lc =
        u8::try_from(host_challenge.len()).map_err(|_| ScllError::Build(BuildError::Overflow))?;
    let mut apdu = Capdu::new();
    extend(&mut apdu, &[0x80, INS_INITIALIZE_UPDATE, kvn, 0x00, lc])?;
    extend(&mut apdu, host_challenge)?;
    extend(&mut apdu, &[0x00])?;
    Ok(apdu)
}

/// Build the EXTERNAL AUTHENTICATE *plaintext* C-APDU (pre-MAC):
/// `84 82 <security_level> 00 <Lc> <host_cryptogram>` where `Lc` is the
/// cryptogram length (`0x08` in S8, `0x10` in S16). The backend's
/// `scp03_wrap_command` appends the C-MAC (growing `Lc` by the MAC length) and
/// latches the level from `P1` (Fork F1). PDD §5.9 step 10.
fn ea_plaintext(security_level: u8, host_cryptogram: &[u8]) -> Result<Capdu, ScllError> {
    let lc =
        u8::try_from(host_cryptogram.len()).map_err(|_| ScllError::Build(BuildError::Overflow))?;
    let mut apdu = Capdu::new();
    extend(
        &mut apdu,
        &[0x84, INS_EXTERNAL_AUTHENTICATE, security_level, 0x00, lc],
    )?;
    extend(&mut apdu, host_cryptogram)?;
    Ok(apdu)
}

/// True if `i` is an SCP03 configuration this build implements. Only the S16
/// (`0x08`), pseudo-random (`0x10`), R-MAC (`0x20`) and R-ENC (`0x40`) bits may
/// be set, and R-ENC implies R-MAC (Amendment D §5.1 Table 5-1). Random and
/// pseudo-random challenges, and both S8 and S16 size modes, are in scope; any
/// RFU bit (incl. `0x01`/`0x02`/`0x04`) is out of scope.
#[must_use]
pub fn i_supported(i_param: u8) -> bool {
    if i_param & !(I_S16 | I_PSEUDO_RANDOM | I_RMAC | I_RENC) != 0 {
        return false;
    }
    // R-ENCRYPTION without R-MAC is not a valid combination (Table 5-1).
    !(i_param & I_RENC != 0 && i_param & I_RMAC == 0)
}

/// Parse and validate the INITIALIZE UPDATE response (SW already stripped).
///
/// The size mode (S8/S16) is read from the echoed `i` parameter (`i & 0x08`),
/// fixing the challenge/cryptogram length (8 or 16). Pseudo-random cards
/// (`i & 0x10`) append a 3-byte sequence counter. So exactly four total lengths
/// are valid — 29 (S8 random), 32 (S8 pseudo), 45 (S16 random), 48 (S16 pseudo)
/// — and the sequence-counter presence must agree with the pseudo-random bit
/// (Amendment D §6.2.2.1 / §7.1.1.6).
///
/// # Errors
/// [`ScllError::ScpProtocolUnsupported`] if the SCP id is not `0x03`, or if the
/// length does not match the `(mode, pseudo)` implied by `i`;
/// [`ScllError::NoCommonSecurityLevel`] if `i` is not an in-scope configuration
/// (see [`i_supported`]).
pub fn parse_iu_response(bytes: &[u8]) -> Result<IuResponse, ScllError> {
    // Need at least the fixed prefix to read the SCP id and the `i` parameter.
    if bytes.len() < IU_PREFIX_LEN || bytes[11] != SCP_ID_SCP03 {
        return Err(ScllError::ScpProtocolUnsupported);
    }
    let i_param = bytes[IU_I_OFFSET];
    if !i_supported(i_param) {
        return Err(ScllError::NoCommonSecurityLevel);
    }
    let mode = ScpMode::from_i(i_param);
    let field = mode.field_len();
    let pseudo = i_param & I_PSEUDO_RANDOM != 0;
    // Exact expected length for this (mode, pseudo): prefix + 2×field [+ 3].
    let expected = IU_PREFIX_LEN + 2 * field + if pseudo { SEQ_COUNTER_LEN } else { 0 };
    if bytes.len() != expected {
        return Err(ScllError::ScpProtocolUnsupported);
    }

    let chal_start = IU_PREFIX_LEN; // 13
    let crypto_start = chal_start + field;
    let seq_start = crypto_start + field;

    let mut card_challenge: Vec<u8, SCP03_S16_MAX> = Vec::new();
    let mut card_cryptogram: Vec<u8, SCP03_S16_MAX> = Vec::new();
    // Cannot fail: field ∈ {8,16} ≤ SCP03_S16_MAX (16).
    card_challenge
        .extend_from_slice(&bytes[chal_start..crypto_start])
        .map_err(|()| ScllError::ScpProtocolUnsupported)?;
    card_cryptogram
        .extend_from_slice(&bytes[crypto_start..seq_start])
        .map_err(|()| ScllError::ScpProtocolUnsupported)?;
    let sequence_counter = if pseudo {
        let mut sc = [0u8; SEQ_COUNTER_LEN];
        sc.copy_from_slice(&bytes[seq_start..seq_start + SEQ_COUNTER_LEN]);
        Some(sc)
    } else {
        None
    };
    Ok(IuResponse {
        kvn: bytes[10],
        i_param,
        mode,
        card_challenge,
        card_cryptogram,
        sequence_counter,
    })
}

/// Cap the requested security level to the card's `i` capability (PDD §5.9
/// step 8): C-MAC + C-DEC (`0x03`) are always allowed; `i & 0x20` adds R-MAC
/// (`0x10`), `i & 0x40` adds R-ENC (`0x20`).
///
/// # Errors
/// [`ScllError::NoCommonSecurityLevel`] if nothing remains after masking.
pub fn cap_security_level(i_param: u8, requested: u8) -> Result<u8, ScllError> {
    let mut allowed = 0x03u8;
    if i_param & I_RMAC != 0 {
        allowed |= 0x10;
    }
    if i_param & I_RENC != 0 {
        allowed |= 0x20;
    }
    let effective = requested & allowed;
    if effective == 0 {
        return Err(ScllError::NoCommonSecurityLevel);
    }
    Ok(effective)
}

/// Drive the host side of the SCP03 open from a received IU response to a
/// ready-to-send EXTERNAL AUTHENTICATE (PDD §5.9 steps 5–10). Pure given a
/// `backend`: parses+validates the IU (S8/S16), derives the session, verifies
/// the card cryptogram (constant-time), verifies the pseudo-random card
/// challenge against §6.2.2.1 when a sequence counter is present (using
/// `invoker_aid`), caps the level, and returns the wrapped EA alongside the
/// [`Scp03State`]. Transport I/O is the workflow's job (S6). `host_challenge` is
/// `mode.field_len()` bytes; `invoker_aid` is the AID of the application
/// invoking the `SecureChannel` (the SD AID for direct targeting).
///
/// # Errors
/// [`ScllError::KvnMismatch`] if a non-zero `kvn_expected` differs from the
/// card's; [`ScllError::CardCryptogramFail`] on cryptogram mismatch;
/// [`ScllError::CardChallengeFail`] on pseudo-random challenge mismatch;
/// [`ScllError::NoCommonSecurityLevel`] / [`ScllError::ScpProtocolUnsupported`]
/// from parsing/capping; [`ScllError::Backend`] from the backend.
pub fn begin<B: Scp03Backend>(
    backend: &B,
    static_enc: &KeyHandle,
    static_mac: &KeyHandle,
    kvn_expected: u8,
    requested_level: u8,
    host_challenge: &[u8],
    invoker_aid: &[u8],
    iu_response: &[u8],
) -> Result<(Scp03State, Capdu), ScllError> {
    let iu = parse_iu_response(iu_response)?;

    // KVN default 0x00 means "card picks"; only enforce a caller-pinned KVN.
    if kvn_expected != 0x00 && iu.kvn != kvn_expected {
        return Err(ScllError::KvnMismatch);
    }

    let mut session = backend.scp03_derive_session(
        static_enc,
        static_mac,
        iu.mode,
        host_challenge,
        &iu.card_challenge,
    )?;

    let expected_card =
        backend.scp03_card_cryptogram(&session, host_challenge, &iu.card_challenge)?;
    if !backend.ct_eq(&expected_card, &iu.card_cryptogram) {
        return Err(ScllError::CardCryptogramFail);
    }

    // Pseudo-random card (sequence counter present): verify the card challenge
    // against the §6.2.2.1 derivation as defence in depth (Fork: decision #3).
    if let Some(seq) = iu.sequence_counter {
        let expected_challenge =
            backend.scp03_pseudo_card_challenge(static_enc, iu.mode, &seq, invoker_aid)?;
        if !backend.ct_eq(&expected_challenge, &iu.card_challenge) {
            return Err(ScllError::CardChallengeFail);
        }
    }

    let security_level = cap_security_level(iu.i_param, requested_level)?;

    let host_cryptogram =
        backend.scp03_host_cryptogram(&session, host_challenge, &iu.card_challenge)?;

    let ea_plain = ea_plaintext(security_level, &host_cryptogram)?;
    let ea_wrapped = backend.scp03_wrap_command(&mut session, &ea_plain)?;

    Ok((
        Scp03State {
            session,
            i_param: iu.i_param,
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

    fn v(bytes: &[u8]) -> Vec<u8, SCP03_S16_MAX> {
        let mut out: Vec<u8, SCP03_S16_MAX> = Vec::new();
        out.extend_from_slice(bytes).unwrap();
        out
    }

    /// Pure stub backend: canned cryptograms / pseudo-challenge, real `ct_eq`,
    /// echoing wrap. Lets the framing/decision logic in `begin` be tested
    /// without crypto. Fields are length-flexible (8 or 16) for S8/S16.
    struct StubBackend {
        card_crypto: Vec<u8, SCP03_S16_MAX>,
        host_crypto: Vec<u8, SCP03_S16_MAX>,
        pseudo_challenge: Vec<u8, SCP03_S16_MAX>,
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
            Ok(self.card_crypto.clone())
        }
        fn scp03_host_cryptogram(
            &self,
            _s: &Scp03Session,
            _h: &[u8],
            _c: &[u8],
        ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
            Ok(self.host_crypto.clone())
        }
        fn scp03_pseudo_card_challenge(
            &self,
            _e: &KeyHandle,
            _mode: ScpMode,
            _seq: &[u8; 3],
            _aid: &[u8],
        ) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError> {
            Ok(self.pseudo_challenge.clone())
        }
        fn scp03_wrap_command(
            &self,
            _s: &mut Scp03Session,
            capdu: &[u8],
        ) -> Result<Vec<u8, CAPDU_MAX>, BackendError> {
            let mut out = Vec::new();
            out.extend_from_slice(capdu)
                .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
            Ok(out)
        }
        fn scp03_unwrap_response(
            &self,
            _s: &mut Scp03Session,
            rapdu: &[u8],
        ) -> Result<Vec<u8, RAPDU_MAX>, BackendError> {
            let mut out = Vec::new();
            out.extend_from_slice(rapdu)
                .map_err(|()| BackendError::Crypto(heapless::String::new()))?;
            Ok(out)
        }
        fn scp03_encrypt_put_key_payload(
            &self,
            _d: &KeyHandle,
            _n: &KeyHandle,
        ) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError> {
            Ok(Vec::new())
        }
    }

    /// Build a synthetic IU response. `challenge`/`crypto` are 8 bytes (S8) or
    /// 16 bytes (S16) matching `i & 0x08`; a 3-byte sequence counter is appended
    /// when `i & 0x10` is set. Capacity 48 = S16 pseudo-random max.
    fn iu_bytes(kvn: u8, scp: u8, i: u8, challenge: &[u8], crypto: &[u8]) -> Vec<u8, 48> {
        let mut b: Vec<u8, 48> = Vec::new();
        let _ = b.extend_from_slice(&[0u8; 10]); // key diversification data
        let _ = b.push(kvn);
        let _ = b.push(scp);
        let _ = b.push(i);
        let _ = b.extend_from_slice(challenge);
        let _ = b.extend_from_slice(crypto);
        if i & I_PSEUDO_RANDOM != 0 {
            let _ = b.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // sequence counter
        }
        b
    }

    #[test]
    fn iu_command_bytes_s8() {
        let host = [0, 1, 2, 3, 4, 5, 6, 7];
        let apdu = iu_command(0x00, &host).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0x50, 0x00, 0x00, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0x00])
        );
    }

    #[test]
    fn iu_command_bytes_s16() {
        // 16-byte host challenge ⇒ Lc = 0x10.
        let host = [0u8; 16];
        let apdu = iu_command(0x00, &host).unwrap();
        assert_eq!(apdu[4], 0x10);
        assert_eq!(apdu.len(), 5 + 16 + 1);
    }

    #[test]
    fn parse_valid_iu_random_s8() {
        // i=0x60: S8 random + R-MAC + R-ENC ⇒ 29 bytes, no seq counter.
        let b = iu_bytes(0x01, 0x03, 0x60, &[9; 8], &[0xAA; 8]);
        assert_eq!(b.len(), 29);
        let iu = parse_iu_response(&b).unwrap();
        assert_eq!(iu.kvn, 0x01);
        assert_eq!(iu.i_param, 0x60);
        assert_eq!(iu.mode, ScpMode::S8);
        assert_eq!(&iu.card_challenge[..], &[9u8; 8]);
        assert_eq!(&iu.card_cryptogram[..], &[0xAAu8; 8]);
        assert_eq!(iu.sequence_counter, None);
    }

    #[test]
    fn parse_valid_iu_pseudo_random_s8() {
        // i=0x70: S8 pseudo-random + R-MAC + R-ENC ⇒ 32 bytes, seq present.
        let b = iu_bytes(0x01, 0x03, 0x70, &[9; 8], &[0xAA; 8]);
        assert_eq!(b.len(), 32);
        let iu = parse_iu_response(&b).unwrap();
        assert_eq!(iu.mode, ScpMode::S8);
        assert_eq!(iu.sequence_counter, Some([0xAB, 0xCD, 0xEF]));
    }

    #[test]
    fn parse_valid_iu_random_s16() {
        // i=0x68: S16 (0x08) random + R-MAC + R-ENC ⇒ 45 bytes, no seq counter.
        let b = iu_bytes(0x01, 0x03, 0x68, &[9; 16], &[0xAA; 16]);
        assert_eq!(b.len(), 45);
        let iu = parse_iu_response(&b).unwrap();
        assert_eq!(iu.i_param, 0x68);
        assert_eq!(iu.mode, ScpMode::S16);
        assert_eq!(&iu.card_challenge[..], &[9u8; 16]);
        assert_eq!(&iu.card_cryptogram[..], &[0xAAu8; 16]);
        assert_eq!(iu.sequence_counter, None);
    }

    #[test]
    fn parse_valid_iu_pseudo_random_s16() {
        // i=0x78: S16 pseudo-random + R-MAC + R-ENC ⇒ 48 bytes, seq present.
        let b = iu_bytes(0x01, 0x03, 0x78, &[9; 16], &[0xAA; 16]);
        assert_eq!(b.len(), 48);
        let iu = parse_iu_response(&b).unwrap();
        assert_eq!(iu.mode, ScpMode::S16);
        assert_eq!(&iu.card_challenge[..], &[9u8; 16]);
        assert_eq!(iu.sequence_counter, Some([0xAB, 0xCD, 0xEF]));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        // Shorter than the fixed prefix.
        assert!(matches!(
            parse_iu_response(&[0u8; 12]),
            Err(ScllError::ScpProtocolUnsupported)
        ));
        // Valid S8 prefix (scp=03, i=0x60 ⇒ expect 29) but one byte too long.
        let mut wrong = iu_bytes(0x00, 0x03, 0x60, &[0; 8], &[0; 8]);
        let _ = wrong.push(0x00);
        assert!(matches!(
            parse_iu_response(&wrong),
            Err(ScllError::ScpProtocolUnsupported)
        ));
    }

    #[test]
    fn parse_rejects_seq_counter_mismatch() {
        // Pseudo-random i (expects 32) but only 29 bytes ⇒ length mismatch.
        let mut short = iu_bytes(0x00, 0x03, 0x70, &[9; 8], &[0xAA; 8]);
        short.truncate(29);
        assert!(matches!(
            parse_iu_response(&short),
            Err(ScllError::ScpProtocolUnsupported)
        ));
        // Random i (expects 29) but 32 bytes ⇒ length mismatch.
        let mut long = iu_bytes(0x00, 0x03, 0x60, &[9; 8], &[0xAA; 8]);
        let _ = long.extend_from_slice(&[0, 0, 0]);
        assert!(matches!(
            parse_iu_response(&long),
            Err(ScllError::ScpProtocolUnsupported)
        ));
    }

    #[test]
    fn parse_rejects_non_scp03() {
        let b = iu_bytes(0x00, 0x02, 0x70, &[0; 8], &[0; 8]); // SCP02 id
        assert!(matches!(
            parse_iu_response(&b),
            Err(ScllError::ScpProtocolUnsupported)
        ));
    }

    #[test]
    fn parse_rejects_out_of_scope_i() {
        // 0x04 = RFU bit (out of scope). Build an S8-shaped 29-byte body.
        let b = iu_bytes(0x00, 0x03, 0x04, &[0; 8], &[0; 8]);
        assert!(matches!(
            parse_iu_response(&b),
            Err(ScllError::NoCommonSecurityLevel)
        ));
    }

    #[test]
    fn i_supported_table() {
        // In scope: S8/S16 × random/pseudo-random × R-MAC/R-ENC combos.
        for i in [
            0x00, 0x10, 0x20, 0x30, 0x60, 0x70, // S8
            0x08, 0x18, 0x28, 0x38, 0x68, 0x78, // S16
        ] {
            assert!(i_supported(i), "{i:#04x} should be supported");
        }
        // Out of scope: R-ENC without R-MAC (0x40/0x48), RFU bits (0x01/0x02/0x04).
        for i in [0x40, 0x48, 0x50, 0x04, 0x02, 0x01] {
            assert!(!i_supported(i), "{i:#04x} should be unsupported");
        }
    }

    #[test]
    fn level_cap_table() {
        // i=0x70 (R-MAC+R-ENC capable): full 0x33 survives.
        assert_eq!(cap_security_level(0x70, 0x33).unwrap(), 0x33);
        // i=0x30 (R-MAC only): R-ENC bit masked off.
        assert_eq!(cap_security_level(0x30, 0x33).unwrap(), 0x13);
        // i=0x10 (no R-MAC/R-ENC): only C-MAC+C-DEC.
        assert_eq!(cap_security_level(0x10, 0x33).unwrap(), 0x03);
        // S16 capability bits are read identically (0x08 is mode, not a level).
        assert_eq!(cap_security_level(0x78, 0x33).unwrap(), 0x33);
        // Requesting nothing the card allows → error.
        assert!(matches!(
            cap_security_level(0x10, 0x20),
            Err(ScllError::NoCommonSecurityLevel)
        ));
    }

    #[test]
    fn begin_happy_path_s8_pseudo_random() {
        // i=0x70 (S8 pseudo-random): card cryptogram AND pseudo-random challenge
        // are both verified. pseudo_challenge must match the IU card challenge.
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[9; 8]),
        };
        let enc = KeyHandle::new(0);
        let mac = KeyHandle::new(1);
        let host = [0u8; 8];
        let aid = [0xA0u8; 8];
        let iu = iu_bytes(0x00, 0x03, 0x70, &[9; 8], &[0xAA; 8]);
        let (state, ea) = begin(&backend, &enc, &mac, 0x00, 0x33, &host, &aid, &iu).unwrap();
        assert_eq!(state.i_param(), 0x70);
        assert_eq!(state.security_level(), 0x33);
        // EA plaintext: 84 82 33 00 08 <host_cryptogram> (stub echoes it).
        assert_eq!(
            HexSlice(&ea),
            HexSlice([
                0x84, 0x82, 0x33, 0x00, 0x08, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB
            ])
        );
    }

    #[test]
    fn begin_happy_path_s16() {
        // i=0x78 (S16 pseudo-random + R-MAC + R-ENC): 16-byte fields.
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 16]),
            host_crypto: v(&[0xBB; 16]),
            pseudo_challenge: v(&[9; 16]),
        };
        let host = [0u8; 16];
        let aid = [0xA0u8; 8];
        let iu = iu_bytes(0x00, 0x03, 0x78, &[9; 16], &[0xAA; 16]);
        let (state, ea) = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x00,
            0x33,
            &host,
            &aid,
            &iu,
        )
        .unwrap();
        assert_eq!(state.i_param(), 0x78);
        assert_eq!(state.security_level(), 0x33);
        // EA: 84 82 33 00 10 <16-byte host cryptogram>.
        assert_eq!(ea[4], 0x10);
        assert_eq!(&ea[5..], &[0xBBu8; 16]);
    }

    #[test]
    fn begin_random_skips_challenge_check() {
        // i=0x60 (S8 random, no seq counter): the pseudo-challenge is NOT
        // consulted even when it would mismatch — proves the gate is the
        // sequence counter, not the i bit alone.
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[0xFF; 8]), // deliberately wrong
        };
        let iu = iu_bytes(0x00, 0x03, 0x60, &[9; 8], &[0xAA; 8]);
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x00,
            0x33,
            &[0u8; 8],
            &[0xA0u8; 8],
            &iu,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn begin_rejects_bad_pseudo_challenge() {
        // Pseudo-random card, card cryptogram OK, but challenge mismatches.
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[0xFF; 8]), // != iu card challenge [9;8]
        };
        let iu = iu_bytes(0x00, 0x03, 0x70, &[9; 8], &[0xAA; 8]);
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x00,
            0x33,
            &[0u8; 8],
            &[0xA0u8; 8],
            &iu,
        );
        assert!(matches!(r, Err(ScllError::CardChallengeFail)));
    }

    #[test]
    fn begin_rejects_bad_card_cryptogram() {
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[9; 8]),
        };
        let iu = iu_bytes(0x00, 0x03, 0x70, &[9; 8], &[0xCC; 8]); // != card_crypto
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x00,
            0x33,
            &[0u8; 8],
            &[0xA0u8; 8],
            &iu,
        );
        assert!(matches!(r, Err(ScllError::CardCryptogramFail)));
    }

    #[test]
    fn begin_rejects_kvn_mismatch() {
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[9; 8]),
        };
        let iu = iu_bytes(0x05, 0x03, 0x70, &[9; 8], &[0xAA; 8]);
        let r = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x01,
            0x33,
            &[0u8; 8],
            &[0xA0u8; 8],
            &iu,
        );
        assert!(matches!(r, Err(ScllError::KvnMismatch)));
    }

    #[test]
    fn begin_caps_level_for_i30() {
        let backend = StubBackend {
            card_crypto: v(&[0xAA; 8]),
            host_crypto: v(&[0xBB; 8]),
            pseudo_challenge: v(&[9; 8]),
        };
        let iu = iu_bytes(0x00, 0x03, 0x30, &[9; 8], &[0xAA; 8]);
        let (state, ea) = begin(
            &backend,
            &KeyHandle::new(0),
            &KeyHandle::new(1),
            0x00,
            0x33,
            &[0u8; 8],
            &[0xA0u8; 8],
            &iu,
        )
        .unwrap();
        assert_eq!(state.security_level(), 0x13);
        assert_eq!(ea[2], 0x13); // EA P1 carries the capped level
    }
}
