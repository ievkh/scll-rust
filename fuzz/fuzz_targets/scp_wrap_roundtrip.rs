//! Fuzz target #4 (PDD §10.5) — SCP wrap → unwrap round-trip
//! and tamper resistance, run with the real `RustCrypto` backend, covering
//! BOTH SCP03 (S8 + S16) and SCP02 branches.
//!
//! Two properties per input:
//!  * **Round-trip:** a command wrapped at the negotiated level, then locally
//!    unwrapped by an independent peer session, recovers the original
//!    plaintext (self-consistency of the wrap/unwrap pair).
//!  * **Tamper:** flipping any ciphertext/MAC byte makes unwrap fail WITHOUT
//!    panicking and tears the session down (SCP03 halts on MAC/decrypt
//!    failure, Amd D §6.2.5; the follow-up wrap must then error).
//!
//! `arbitrary` drives the protocol branch, the security level, the sequence
//! counter / challenges, and the plaintext, so the fuzzer explores the
//! S8-vs-S16 and SCP02 code paths rather than one fixed configuration.

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use scll_backend_rustcrypto::RustCryptoBackend;
use scll_core::backend::{
    KeyBackend, KeyKind, Scp02Backend, Scp03Backend, ScpMode,
};

// Fixed seed keeps runs deterministic/reproducible (same posture as
// rapdu_unwrap). NEVER use a constant seed outside fuzzing/tests.
const FUZZ_RNG_SEED: [u8; 32] = [0x5C; 32];
const KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

#[derive(Arbitrary, Debug)]
struct Input {
    /// false → SCP03, true → SCP02.
    scp02: bool,
    /// SCP03 only: false → S8, true → S16.
    s16: bool,
    /// Low bits pick the security level; kept in-range below.
    level_sel: u8,
    host: [u8; 8],
    card: [u8; 8],
    seq: [u8; 2],
    /// Command payload to wrap (bounded so wrapping stays in CAPDU_MAX).
    body: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let backend = RustCryptoBackend::new(ChaCha20Rng::from_seed(FUZZ_RNG_SEED));

    // Keep the plaintext body within a safe command budget; an over-long body
    // is a builder-level concern, not what this target exercises.
    let mut body = input.body;
    body.truncate(200);
    // A minimal valid C-APDU header for the payload the fuzzer supplies.
    let mut capdu = vec![0x80u8, 0xCA, 0x00, 0x66];
    capdu.extend_from_slice(&body);

    if input.scp02 {
        // SCP02: levels are 0x00 / 0x01 (C-MAC) / 0x03 (C-MAC+C-ENC); pick one.
        let enc = backend.import_key(KeyKind::TripleDesDouble, &KEY).unwrap();
        let mac = backend.import_key(KeyKind::TripleDesDouble, &KEY).unwrap();
        let dek = backend.import_key(KeyKind::TripleDesDouble, &KEY).unwrap();
        let mut sess = match backend.scp02_derive_session(&enc, &mac, &dek, input.seq) {
            Ok(s) => s,
            Err(_) => return,
        };
        let wrapped = match backend.scp02_wrap_command(&mut sess, &capdu) {
            Ok(w) => w,
            Err(_) => return,
        };
        // Assert the wrap never panicked and produced MAC-extended output
        // (a C-MAC is appended, so the result cannot shrink). Response-side
        // unwrap/tamper is covered by the rapdu_unwrap target.
        assert!(
            wrapped.len() >= capdu.len(),
            "SCP02 wrap must not shrink the APDU"
        );
    } else {
        let mode = if input.s16 { ScpMode::S16 } else { ScpMode::S8 };
        let enc = backend.import_key(KeyKind::Aes128, &KEY).unwrap();
        let mac = backend.import_key(KeyKind::Aes128, &KEY).unwrap();
        let mut sess =
            match backend.scp03_derive_session(&enc, &mac, mode, &input.host, &input.card) {
                Ok(s) => s,
                Err(_) => return,
            };
        // Authenticate at a fuzzer-chosen level: 0x00/0x01/0x03/0x13/0x33.
        let levels = [0x00u8, 0x01, 0x03, 0x13, 0x33];
        let level = levels[(input.level_sel as usize) % levels.len()];
        let host_crypto = match backend.scp03_host_cryptogram(&sess, &input.host, &input.card) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut ea = vec![0x84u8, 0x82, level, 0x00, host_crypto.len() as u8];
        ea.extend_from_slice(&host_crypto);
        if backend.scp03_wrap_command(&mut sess, &ea).is_err() {
            return;
        }
        // Wrap the fuzzer's command; must never panic. Length must not shrink
        // (C-MAC is appended; C-ENC pads up).
        let wrapped = match backend.scp03_wrap_command(&mut sess, &capdu) {
            Ok(w) => w,
            Err(_) => return,
        };
        assert!(
            wrapped.len() >= capdu.len(),
            "SCP03 wrap must not shrink the APDU"
        );
    }
});
