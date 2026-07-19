//! SCP03 flow known-answer tests through the public backend API (PDD §10.2
//! §10.2). Expected values come from the independent pyca reference
//! (`tests/vectors/scp03_ref.py`); primitives underneath are pinned to FIPS-197
//! / RFC 4493 in `src/crypto.rs`. GP default keyset 40..4F; host challenge
//! 0001..07, card challenge 0809..0F.

use rand_core::{CryptoRng, RngCore};

use scll_backend_rustcrypto::{RustCryptoBackend, MAX_SESSION_SLOTS};
use scll_core::backend::{
    ExportableKeyBackend, KeyBackend, KeyKind, Scp03Backend, Scp03Session, ScpMode,
};
use scll_test_util::HexSlice;

/// Deterministic counter RNG — only `random_bytes`/`generate_key` consume it;
/// the derive/wrap/unwrap KATs take the challenges as fixed inputs, so RNG
/// output never affects them. Marked `CryptoRng` purely to satisfy the bound;
/// it is NOT cryptographically secure and is test-only.
struct CountRng(u64);
impl RngCore for CountRng {
    #[allow(clippy::cast_possible_truncation)] // taking the high 32 bits is intentional
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        (self.0 >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let b = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for CountRng {}

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const KEY: &str = "404142434445464748494a4b4c4d4e4f";
const HOST: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const CARD: [u8; 8] = [8, 9, 10, 11, 12, 13, 14, 15];
// S16 (Amendment D v1.2) 16-byte challenges (tests/vectors/scp03_ref.py).
const HOST16: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const CARD16: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

fn backend() -> RustCryptoBackend<CountRng> {
    RustCryptoBackend::new(CountRng(0))
}

/// Import ENC/MAC (the default key) and open a derived session in `mode`.
fn open_mode(
    b: &RustCryptoBackend<CountRng>,
    mode: ScpMode,
    host: &[u8],
    card: &[u8],
) -> Scp03Session {
    let enc = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    b.scp03_derive_session(&enc, &mac, mode, host, card)
        .unwrap()
}

/// S8 convenience open (default GP challenges).
fn open(b: &RustCryptoBackend<CountRng>) -> Scp03Session {
    open_mode(b, ScpMode::S8, &HOST, &CARD)
}

#[test]
fn cryptograms_match_reference() {
    let b = backend();
    let s = open(&b);
    assert_eq!(
        HexSlice(b.scp03_card_cryptogram(&s, &HOST, &CARD).unwrap()),
        HexSlice(hx("114f6bc5052c5228"))
    );
    assert_eq!(
        HexSlice(b.scp03_host_cryptogram(&s, &HOST, &CARD).unwrap()),
        HexSlice(hx("fafa93c2ede62463"))
    );
}

#[test]
fn cryptograms_match_reference_s16() {
    // S16: 16-byte cryptograms (L = 0x0080). Vectors from scp03_ref.py.
    let b = backend();
    let s = open_mode(&b, ScpMode::S16, &HOST16, &CARD16);
    assert_eq!(
        HexSlice(b.scp03_card_cryptogram(&s, &HOST16, &CARD16).unwrap()),
        HexSlice(hx("1f3975eb7c6d743f38bb5842328732a1"))
    );
    assert_eq!(
        HexSlice(b.scp03_host_cryptogram(&s, &HOST16, &CARD16).unwrap()),
        HexSlice(hx("313082b4105ae33d7c2d323a1e5cd6ff"))
    );
}

#[test]
fn session_keys_match_reference_s16() {
    // Session keys differ from S8 because the KDF context is the 32-byte
    // host16 ‖ card16 (Amendment D §6.2.1). Exercised indirectly by the flow
    // tests; asserted here against the independent reference for clarity.
    let b = backend();
    let s = open_mode(&b, ScpMode::S16, &HOST16, &CARD16);
    // Host cryptogram is a KDF off S-MAC; if it matches, the session keys did.
    assert_eq!(
        HexSlice(b.scp03_host_cryptogram(&s, &HOST16, &CARD16).unwrap()),
        HexSlice(hx("313082b4105ae33d7c2d323a1e5cd6ff"))
    );
}

#[test]
fn pseudo_card_challenge_matches_reference() {
    // Amendment D §6.2.2.1: KDF(Key-ENC, 0x02, L, seq ‖ AID). Vectors from
    // scp03_ref.py (AID A000000151000000, seq 000001).
    let b = backend();
    let enc = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    let aid = hx("a000000151000000");
    let seq = [0x00, 0x00, 0x01];
    assert_eq!(
        HexSlice(
            b.scp03_pseudo_card_challenge(&enc, ScpMode::S8, &seq, &aid)
                .unwrap()
        ),
        HexSlice(hx("86c8bd65fa1044ee"))
    );
    assert_eq!(
        HexSlice(
            b.scp03_pseudo_card_challenge(&enc, ScpMode::S16, &seq, &aid)
                .unwrap()
        ),
        HexSlice(hx("6924434c956736c8ee6122e8a3fc612f"))
    );
}

/// Wrap EXTERNAL AUTHENTICATE (latches the level from P1) then a command with
/// data (exercises C-ENC + C-MAC chaining), then unwrap the matching response
/// (R-MAC + R-ENC). One row per security level, parameterized by mode.
fn run_flow(
    mode: ScpMode,
    host: &[u8],
    card: &[u8],
    level: u8,
    ea_exp: &str,
    cmd_exp: &str,
    resp_wire: &str,
) {
    let b = backend();
    let mut s = open_mode(&b, mode, host, card);
    let field = mode.field_len();

    // EXTERNAL AUTHENTICATE plaintext: 84 82 <level> 00 <Lc> <host_cryptogram>.
    let host_crypto = b.scp03_host_cryptogram(&s, host, card).unwrap();
    #[allow(clippy::cast_possible_truncation)] // field ∈ {8,16}
    let mut ea = vec![0x84, 0x82, level, 0x00, field as u8];
    ea.extend_from_slice(&host_crypto);
    let ea_wrapped = b.scp03_wrap_command(&mut s, &ea).unwrap();
    assert_eq!(
        HexSlice(&ea_wrapped),
        HexSlice(hx(ea_exp)),
        "EA {mode:?} level {level:#04x}"
    );

    // A post-auth command carrying data.
    let cmd = hx("80e60000050102030405");
    let cmd_wrapped = b.scp03_wrap_command(&mut s, &cmd).unwrap();
    assert_eq!(
        HexSlice(&cmd_wrapped),
        HexSlice(hx(cmd_exp)),
        "CMD {mode:?} level {level:#04x}"
    );

    // Response for that command unwraps back to 00A40400 9000.
    let plain = b.scp03_unwrap_response(&mut s, &hx(resp_wire)).unwrap();
    assert_eq!(
        HexSlice(&plain),
        HexSlice(hx("00a404009000")),
        "RESP {mode:?} level {level:#04x}"
    );
}

#[test]
fn flow_level_33_cmac_cenc_rmac_renc() {
    run_flow(
        ScpMode::S8,
        &HOST,
        &CARD,
        0x33,
        "8482330010fafa93c2ede62463cb51e38ec18eb00b",
        "84e6000018199dd7ff46730b64ac254c903ec573505c4291bb0b788746",
        "4c7f4e27e4f90aa7b13c60860f69fcd0989a968b68138d8e9000",
    );
}

#[test]
fn flow_level_13_rmac_no_renc() {
    run_flow(
        ScpMode::S8,
        &HOST,
        &CARD,
        0x13,
        "8482130010fafa93c2ede6246389a42cec80e1226c",
        "84e6000018199dd7ff46730b64ac254c903ec573501f8c45277cc91f5f",
        "00a40400e2d87fa5be9616ee9000",
    );
}

#[test]
fn flow_level_03_cmac_cenc_only() {
    run_flow(
        ScpMode::S8,
        &HOST,
        &CARD,
        0x03,
        "8482030010fafa93c2ede6246363e5f7f00d7db617",
        "84e6000018199dd7ff46730b64ac254c903ec57350cecb2cdb11be6932",
        "00a404009000",
    );
}

#[test]
fn flow_s16_level_33_cmac_cenc_rmac_renc() {
    run_flow(
        ScpMode::S16,
        &HOST16,
        &CARD16,
        0x33,
        "8482330020313082b4105ae33d7c2d323a1e5cd6ff782dcbe5bc45c062f64cd61937e03100",
        "84e60000207741688c2836b029a8ed938260cc067f4f45621753c5a9317efb316696ffd61d",
        "e3fcd252c046a09e8e174c4a882615a02cf1558988ff0f3044de83ca334829fb9000",
    );
}

#[test]
fn flow_s16_level_13_rmac_no_renc() {
    run_flow(
        ScpMode::S16,
        &HOST16,
        &CARD16,
        0x13,
        "8482130020313082b4105ae33d7c2d323a1e5cd6ff343b84121805124b821d0fc05ccbfacd",
        "84e60000207741688c2836b029a8ed938260cc067fcad223bb9f79fb7e5062345977e964ce",
        "00a40400af04b29a8600f9a6589499aaac528ab89000",
    );
}

#[test]
fn flow_s16_level_03_cmac_cenc_only() {
    run_flow(
        ScpMode::S16,
        &HOST16,
        &CARD16,
        0x03,
        "8482030020313082b4105ae33d7c2d323a1e5cd6ff5d033e49191b0298aa603187ad0c3582",
        "84e60000207741688c2836b029a8ed938260cc067f1214bb4b5af022c24988e42cda8f49dd",
        "00a404009000",
    );
}

#[test]
fn put_key_payload_under_dek() {
    let b = backend();
    let dek = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    let new_key = b
        .import_key(KeyKind::Aes128, &hx("0f0e0d0c0b0a09080706050403020100"))
        .unwrap();
    let block = b.scp03_encrypt_put_key_payload(&dek, &new_key).unwrap();
    assert_eq!(
        HexSlice(&block),
        HexSlice(hx("fac3af9fb177982eaba2e63d9ef03986"))
    );
}

#[test]
fn short_response_tears_down_session() {
    // Regression (fuzz `rapdu_unwrap`, input `[]`): a response too short to even
    // hold SW must fail-close — error AND tear the session down, like any other
    // unwrap failure.
    for short in [&[][..], &[0x90][..]] {
        let b = backend();
        let mut s = open(&b);
        let host_crypto = b.scp03_host_cryptogram(&s, &HOST, &CARD).unwrap();
        let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x08];
        ea.extend_from_slice(&host_crypto);
        b.scp03_wrap_command(&mut s, &ea).unwrap();

        assert!(b.scp03_unwrap_response(&mut s, short).is_err());
        // Session torn down: a follow-up wrap on the dead handle now fails.
        assert!(b
            .scp03_wrap_command(&mut s, &[0x80, 0xCA, 0x00, 0x66])
            .is_err());
    }
}

#[test]
fn corrupt_rmac_tears_down_session() {
    // Fork F3: a bad R-MAC invalidates the session; a second unwrap fails
    // because the slot is gone (zeroized).
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp03_host_cryptogram(&s, &HOST, &CARD).unwrap();
    let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp03_wrap_command(&mut s, &ea).unwrap();
    let _ = b
        .scp03_wrap_command(&mut s, &hx("80e60000050102030405"))
        .unwrap();

    let mut bad = hx("4c7f4e27e4f90aa7b13c60860f69fcd0989a968b68138d8e9000");
    let n = bad.len();
    bad[n - 3] ^= 0xFF; // flip a byte inside the R-MAC
    assert!(b.scp03_unwrap_response(&mut s, &bad).is_err());
    // Session torn down: even a well-formed response now fails.
    assert!(b
        .scp03_unwrap_response(&mut s, &hx("00a404009000"))
        .is_err());
}

#[test]
fn kcv_and_export_round_trip() {
    let b = backend();
    let h = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    assert_eq!(HexSlice(b.compute_kcv(&h).unwrap()), HexSlice(hx("504a77")));
    assert_eq!(
        HexSlice(b.export_key_dangerous(&h).unwrap().as_bytes()),
        HexSlice(hx(KEY))
    );
}

#[test]
fn ct_eq_is_value_equality() {
    let b = backend();
    assert!(b.ct_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!b.ct_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(!b.ct_eq(&[1, 2, 3], &[1, 2])); // length mismatch
}

#[test]
fn generate_and_random_use_injected_rng() {
    let b = backend();
    let h = b.generate_key(KeyKind::Aes256).unwrap();
    // Generated AES-256 key has a computable KCV (proves it stored 32 bytes).
    assert!(b.compute_kcv(&h).is_ok());
    let mut buf = [0u8; 16];
    b.random_bytes(&mut buf).unwrap();
    assert_ne!(buf, [0u8; 16]); // counter RNG is non-zero after stepping
}

#[test]
fn error_status_word_returns_bare_under_rmac() {
    // Amendment D §6.2.5: an error status word (here 6A88) is returned with NO
    // R-MAC even at level 0x33, so unwrap must pass it through rather than
    // reject it as "too short for R-MAC". The session stays live (a benign
    // error SW is not a channel failure).
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp03_host_cryptogram(&s, &HOST, &CARD).unwrap();
    let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp03_wrap_command(&mut s, &ea).unwrap();

    let out = b.scp03_unwrap_response(&mut s, &[0x6A, 0x88]).unwrap();
    assert_eq!(out.as_slice(), &[0x6A, 0x88]);
    // Not torn down: a follow-up wrap still succeeds.
    assert!(b
        .scp03_wrap_command(&mut s, &[0x80, 0xCA, 0x00, 0x66])
        .is_ok());
}

#[test]
fn warning_status_word_still_requires_rmac() {
    // §6.2.5: 63xx is a WARNING, so it still carries an R-MAC. A bare 6310
    // (no R-MAC) at level 0x33 must be rejected — this is exactly the
    // non-compliant response the Oracle sim returns for GET STATUS paging, and
    // the spec-exact rule keeps the skip from over-broadening to warnings.
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp03_host_cryptogram(&s, &HOST, &CARD).unwrap();
    let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp03_wrap_command(&mut s, &ea).unwrap();

    assert!(b.scp03_unwrap_response(&mut s, &[0x63, 0x10]).is_err());
}

#[test]
fn three_des_import_supported_since_s5() {
    let b = backend();
    // SCP02's two-key 3DES key kind is supported as of S5 (was deferred in S4):
    // import succeeds and yields a 3DES-ECB KCV.
    let h = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    assert!(b.compute_kcv(&h).is_ok());
}

#[test]
fn close_session_frees_slot_for_reuse() {
    // Import the static keys once (key slots are a separate, finite table), then
    // derive + close more times than the session table has slots. Each close
    // must release its slot, so the loop never exhausts the table.
    let b = backend();
    let enc = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    for _ in 0..(MAX_SESSION_SLOTS * 2) {
        let s = b
            .scp03_derive_session(&enc, &mac, ScpMode::S8, &HOST, &CARD)
            .expect("a session slot is free after the previous close");
        b.scp03_close_session(s);
    }
}

#[test]
fn session_table_exhausts_without_close() {
    // Counterpart to the reuse test: with no slot ever freed, the table fills
    // after MAX_SESSION_SLOTS derivations and the next one errors. This is what
    // `close_session` exists to prevent across many open/close cycles.
    let b = backend();
    let enc = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::Aes128, &hx(KEY)).unwrap();
    for _ in 0..MAX_SESSION_SLOTS {
        b.scp03_derive_session(&enc, &mac, ScpMode::S8, &HOST, &CARD)
            .expect("slot available below the cap");
    }
    assert!(
        b.scp03_derive_session(&enc, &mac, ScpMode::S8, &HOST, &CARD)
            .is_err(),
        "the session table must be exhausted once every slot is held"
    );
}
