//! SCP02 flow known-answer tests through the public backend API (PDD §10.2
//! §S5 / §10.2). Expected values come from the independent reference
//! (`tests/vectors/scp02_ref.py`), which mirrors `GlobalPlatformPro`
//! `SCP02Wrapper`/`GPCrypto` (i=0x55); the primitives underneath are anchored
//! to FIPS-81 (single DES) and GPCS §E in `src/crypto.rs`. GP default keyset
//! 40..4F (used as ENC/MAC/DEK); host challenge 0001..07; 6-byte card challenge
//! 0809..0D; sequence counter 0001. Per GPCS v2.3.1 §E.4.4 the cryptograms run
//! over the 8-byte card challenge = `seq(2) ‖ card_challenge(6)` (`CARD8`).
//! `hardware_vector_jcop_p71` additionally pins a live JCOP 4 P71 capture.

use rand_core::{CryptoRng, RngCore};

use scll_backend_rustcrypto::{RustCryptoBackend, MAX_SESSION_SLOTS};
use scll_core::backend::{KeyBackend, KeyKind, Scp02Backend, Scp02Session};
use scll_test_util::HexSlice;

/// Deterministic counter RNG — only `random_bytes`/`generate_key` consume it;
/// the derive/wrap/unwrap KATs take the challenges + sequence counter as fixed
/// inputs, so RNG output never affects them. `CryptoRng` is asserted only to
/// satisfy the bound; it is NOT cryptographically secure and is test-only.
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
const CARD: [u8; 6] = [8, 9, 10, 11, 12, 13];
const SEQ: [u8; 2] = [0x00, 0x01];
/// 8-byte card challenge fed to the cryptograms: `SEQ ‖ CARD` (GPCS §E.4.4).
const CARD8: [u8; 8] = [
    SEQ[0], SEQ[1], CARD[0], CARD[1], CARD[2], CARD[3], CARD[4], CARD[5],
];

fn backend() -> RustCryptoBackend<CountRng> {
    RustCryptoBackend::new(CountRng(0))
}

/// Import ENC/MAC/DEK (all the default key, as 3DES double-length) and open a
/// derived session for the given sequence counter.
fn open(b: &RustCryptoBackend<CountRng>) -> Scp02Session {
    let enc = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let dek = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    b.scp02_derive_session(&enc, &mac, &dek, SEQ).unwrap()
}

#[test]
fn kcv_3des_matches_reference() {
    let b = backend();
    let k = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    assert_eq!(HexSlice(b.compute_kcv(&k).unwrap()), HexSlice(hx("8baf47")));
}

#[test]
fn cryptograms_match_reference() {
    let b = backend();
    let s = open(&b);
    assert_eq!(
        HexSlice(b.scp02_card_cryptogram(&s, &HOST, &CARD8).unwrap()),
        HexSlice(hx("9d8da672f05c4e45"))
    );
    assert_eq!(
        HexSlice(b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap()),
        HexSlice(hx("e87e4c9e45c47f79"))
    );
}

/// Wrap EXTERNAL AUTHENTICATE (latches the level from P1), then post-auth
/// commands. `level` 0x03 exercises C-MAC + C-DECRYPTION + ICV-encryption
/// chaining; 0x01 is C-MAC only.
fn run_flow(level: u8, ea_exp: &str, cmds: &[(&str, &str)]) {
    let b = backend();
    let mut s = open(&b);

    let host_crypto = b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap();
    let mut ea = vec![0x84, 0x82, level, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    let ea_wrapped = b.scp02_wrap_command(&mut s, &ea).unwrap();
    assert_eq!(
        HexSlice(&ea_wrapped),
        HexSlice(hx(ea_exp)),
        "EA {level:#04x}"
    );

    for (plain, exp) in cmds {
        let wrapped = b.scp02_wrap_command(&mut s, &hx(plain)).unwrap();
        assert_eq!(HexSlice(&wrapped), HexSlice(hx(exp)), "CMD {plain}");
    }
}

#[test]
fn flow_level_03_cmac_cdec() {
    run_flow(
        0x03,
        "8482030010e87e4c9e45c47f7937ba873e0e37b968",
        &[
            (
                "80e60000050102030405",
                "84e60000106614336af48ec608a398d78a712fc7a1",
            ),
            (
                "80e80000020102",
                "84e800001046c90c13f2f9216f53de2adce0e27621",
            ),
        ],
    );
}

#[test]
fn flow_level_01_cmac_only() {
    run_flow(
        0x01,
        "8482010010e87e4c9e45c47f79ad804734ce044ffc",
        &[(
            "80e60000050102030405",
            "84e600000d0102030405c846bea70ddcd2d8",
        )],
    );
}

/// `scp02_encrypt_put_key_payload_for_session` (patch #15): `open()` derives
/// a session whose session DEK works out to `0e51fdf196141f227a57bd154012fd39`
/// from the KEY/CARD/HOST/SEQ constants (3DES-CBC derivation, GPCS v2.3.1
/// §E.4.1); 3DES-EDE2-ECB of the new key `0f0e..0100` under that DEK is the
/// expected ciphertext below (cross-checked against the `scp02_ref.py`
/// pycryptodome oracle). This is the regression test for the SSD PUT KEY
/// `6982` root cause: PUT KEY over a direct SCP02 channel must encrypt under
/// the session's own derived DEK, not a caller-supplied static key (confirmed
/// empirically against a live JCOP 4 P71 SSD — see CHANGELOG patch #15).
#[test]
fn put_key_payload_for_session_matches_known_session_dek() {
    let b = backend();
    let s = open(&b);
    let new_key = b
        .import_key(
            KeyKind::TripleDesDouble,
            &hx("0f0e0d0c0b0a09080706050403020100"),
        )
        .unwrap();
    assert_eq!(
        HexSlice(
            &b.scp02_encrypt_put_key_payload_for_session(&s, &new_key)
                .unwrap()
        ),
        HexSlice(hx("fac6d80e61620cf9e342b787b95afea4"))
    );
}

#[test]
fn unwrap_passthrough_without_rmac() {
    // At level 0x03 (no R-MAC) SCP02 responses are unprotected: data ‖ SW back
    // unchanged.
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap();
    let mut ea = vec![0x84, 0x82, 0x03, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp02_wrap_command(&mut s, &ea).unwrap();
    let resp = hx("01020304059000");
    assert_eq!(
        HexSlice(&b.scp02_unwrap_response(&mut s, &resp).unwrap()),
        HexSlice(&resp)
    );
}

#[test]
fn unwrap_rmac_level_13_verifies_and_strips() {
    // Level 0x13 (C-MAC + C-DEC + R-MAC). EA, one post-auth command (which is
    // accumulated for the R-MAC), then a response carrying the R-MAC.
    //
    // GPCS v2.3.1 §E.3.2: the R-MAC chaining value (ricv) is seeded from the
    // EA's own C-MAC, not zero (see CHANGELOG patch #11) — the expected R-MAC
    // below was regenerated from tests/vectors/scp02_ref.py accordingly.
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap();
    let mut ea = vec![0x84, 0x82, 0x13, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp02_wrap_command(&mut s, &ea).unwrap();
    b.scp02_wrap_command(&mut s, &hx("80ca006e00")).unwrap();

    let plain = b
        .scp02_unwrap_response(&mut s, &hx("9f7f2a4100b1377a5f0d699000"))
        .unwrap();
    assert_eq!(HexSlice(&plain), HexSlice(hx("9f7f2a9000")));
}

#[test]
fn unwrap_rmac_case1_command_carries_lc_zero() {
    // GPCS v2.3.1 §E.4.5: a case-1 (4-byte, no Lc/Le) command still carries
    // `Lc = 00` in the R-MAC data block. The accumulated command is therefore
    // `80ca006600` (not `80ca0066`), and the card's R-MAC over it verifies and
    // strips. Vector regenerated from tests/vectors/scp02_ref.py
    // (RMAC13_CASE1_RESP_WIRE), including the §E.3.2 EA-C-MAC ricv seed
    // (CHANGELOG patch #11).
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap();
    let mut ea = vec![0x84, 0x82, 0x13, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp02_wrap_command(&mut s, &ea).unwrap();
    b.scp02_wrap_command(&mut s, &hx("80ca0066")).unwrap(); // 4-byte case-1

    let plain = b
        .scp02_unwrap_response(&mut s, &hx("9f7f2a9f4939a75d4081049000"))
        .unwrap();
    assert_eq!(HexSlice(&plain), HexSlice(hx("9f7f2a9000")));
}

#[test]
fn unwrap_rmac_failure_tears_down_session() {
    // A corrupted R-MAC must fail and invalidate the session (Fork F3): the
    // next wrap then fails because the slot is gone.
    let b = backend();
    let mut s = open(&b);
    let host_crypto = b.scp02_host_cryptogram(&s, &HOST, &CARD8).unwrap();
    let mut ea = vec![0x84, 0x82, 0x13, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    b.scp02_wrap_command(&mut s, &ea).unwrap();
    b.scp02_wrap_command(&mut s, &hx("80ca006e00")).unwrap();

    // Flip the last R-MAC byte.
    assert!(b
        .scp02_unwrap_response(&mut s, &hx("9f7f2a4a76c806d3946e0f9000"))
        .is_err());
    assert!(b.scp02_wrap_command(&mut s, &hx("80ca006e00")).is_err());
}

#[test]
fn first_wrap_must_be_external_authenticate() {
    let b = backend();
    let mut s = open(&b);
    // A non-EA command before EXTERNAL AUTHENTICATE is rejected.
    assert!(b
        .scp02_wrap_command(&mut s, &hx("80e60000050102030405"))
        .is_err());
}

/// Hardware-anchored vector: NXP JCOP 4 P71 J3R150, SCP02 i=55, captured live
/// with `GlobalPlatformPro` v25.10.20 (`gp -l -d`). The card returned
/// `CARD_CRYPTO` in its INITIALIZE UPDATE response, and accepted the EXTERNAL
/// AUTHENTICATE carrying `HOST_CRYPTO`+C-MAC with 9000. Reproducing all three
/// proves the §E.4.4 sequence-counter inclusion against real silicon — this is
/// the regression that the synthetic vectors (and the old reference model)
/// missed because both dropped the counter.
#[test]
fn hardware_vector_jcop_p71_scp02() {
    let b = backend();
    let enc = b
        .import_key(
            KeyKind::TripleDesDouble,
            &hx("90379a3e7116d455e55f9398736a01ca"),
        )
        .unwrap();
    let mac = b
        .import_key(
            KeyKind::TripleDesDouble,
            &hx("473f36161a7f7f60cc3a766ea4be5247"),
        )
        .unwrap();
    let dek = b
        .import_key(
            KeyKind::TripleDesDouble,
            &hx("d3749ed4ff42fd58b39eeb562b017cd9"),
        )
        .unwrap();

    let host: [u8; 8] = [0x25, 0x72, 0xae, 0x5c, 0x04, 0xa7, 0xc3, 0x29];
    // card challenge from IU response = seq(001c) ‖ card(3a58bf1253d5)
    let card8: [u8; 8] = [0x00, 0x1c, 0x3a, 0x58, 0xbf, 0x12, 0x53, 0xd5];
    let seq: [u8; 2] = [0x00, 0x1c];

    let mut s = b.scp02_derive_session(&enc, &mac, &dek, seq).unwrap();

    // Card-observed cryptograms.
    assert_eq!(
        HexSlice(b.scp02_card_cryptogram(&s, &host, &card8).unwrap()),
        HexSlice(hx("bc5d5979580a581f")),
        "card cryptogram must match the value the JCOP card sent"
    );
    let host_crypto = b.scp02_host_cryptogram(&s, &host, &card8).unwrap();
    assert_eq!(
        HexSlice(host_crypto),
        HexSlice(hx("079f403962f6ca28")),
        "host cryptogram must match the value gp put in EXTERNAL AUTHENTICATE"
    );

    // The full EA the card accepted (host_crypto ‖ C-MAC) — exact wire bytes.
    let mut ea = vec![0x84, 0x82, 0x01, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    assert_eq!(
        HexSlice(&b.scp02_wrap_command(&mut s, &ea).unwrap()),
        HexSlice(hx("8482010010079f403962f6ca28d06bd84078d9e3c2")),
        "wrapped EXTERNAL AUTHENTICATE must equal the APDU the card accepted (9000)"
    );
}

#[test]
fn close_session_frees_slot_for_reuse() {
    // Import the static keys once (key slots are a separate, finite table), then
    // derive + close more times than the session table has slots. Each close
    // must release its SCP02 slot, so the loop never exhausts the table.
    let b = backend();
    let enc = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let dek = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    for _ in 0..(MAX_SESSION_SLOTS * 2) {
        let s = b
            .scp02_derive_session(&enc, &mac, &dek, SEQ)
            .expect("a session slot is free after the previous close");
        b.scp02_close_session(s);
    }
}

#[test]
fn session_table_exhausts_without_close() {
    // Counterpart: with no slot ever freed, the SCP02 table fills after
    // MAX_SESSION_SLOTS derivations and the next one errors — what
    // `scp02_close_session` exists to prevent across many open/close cycles.
    let b = backend();
    let enc = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let mac = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    let dek = b.import_key(KeyKind::TripleDesDouble, &hx(KEY)).unwrap();
    for _ in 0..MAX_SESSION_SLOTS {
        b.scp02_derive_session(&enc, &mac, &dek, SEQ)
            .expect("slot available below the cap");
    }
    assert!(
        b.scp02_derive_session(&enc, &mac, &dek, SEQ).is_err(),
        "the SCP02 session table must be exhausted once every slot is held"
    );
}
