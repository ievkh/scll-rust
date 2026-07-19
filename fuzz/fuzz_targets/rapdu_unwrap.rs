//! Fuzz target #3 (PDD §10.5) — R-APDU unwrap framing/length handling, run with
//! the real `RustCrypto` backend. Asserts: no panic on any input, and a
//! torn-down/zeroised session on failure (SCP03 halts on decrypt/MAC failure).
#![no_main]
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use scll_backend_rustcrypto::RustCryptoBackend;
use scll_core::backend::{KeyBackend, KeyKind, Scp03Backend, ScpMode};

// Fixed seed: the backend now requires an injected CSPRNG (Fork B). A constant
// seed keeps fuzz runs deterministic and reproducible; do NOT use this outside
// fuzzing/tests.
const FUZZ_RNG_SEED: [u8; 32] = [0x5C; 32];
const KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];
const HOST: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const CARD: [u8; 8] = [8, 9, 10, 11, 12, 13, 14, 15];

fuzz_target!(|data: &[u8]| {
    let rng = ChaCha20Rng::from_seed(FUZZ_RNG_SEED);
    let backend = RustCryptoBackend::new(rng);

    let enc = backend.import_key(KeyKind::Aes128, &KEY).unwrap();
    let mac = backend.import_key(KeyKind::Aes128, &KEY).unwrap();
    let mut session = backend
        .scp03_derive_session(&enc, &mac, ScpMode::S8, &HOST, &CARD)
        .unwrap();

    // Authenticate at the default full level (0x33) so unwrap exercises R-MAC
    // + R-ENC. EA plaintext: 84 82 33 00 08 <host cryptogram>.
    let host_crypto = backend
        .scp03_host_cryptogram(&session, &HOST, &CARD)
        .unwrap();
    let mut ea = vec![0x84u8, 0x82, 0x33, 0x00, 0x08];
    ea.extend_from_slice(&host_crypto);
    backend.scp03_wrap_command(&mut session, &ea).unwrap();

    // Feed the untrusted bytes to unwrap. Must never panic; on error the
    // session must be torn down (a follow-up wrap then fails).
    if backend.scp03_unwrap_response(&mut session, data).is_err() {
        let probe = backend.scp03_wrap_command(&mut session, &[0x80, 0xCA, 0x00, 0x66]);
        assert!(
            probe.is_err(),
            "session must be torn down after unwrap failure"
        );
    }
});
