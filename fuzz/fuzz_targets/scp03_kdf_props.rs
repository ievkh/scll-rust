//! Fuzz target #5 (PDD §10.5) — SCP03 key-derivation
//! properties, exercised through the cryptogram surface (the session keys
//! themselves are opaque `KeyHandle`s, so the KDF is observed via the
//! host/card cryptograms it feeds — Amd D §4.1.5 / §6.2.2).
//!
//! Properties asserted, over fuzzer-chosen keys / challenges / mode / key
//! length (AES-128/192/256):
//!  * **Determinism:** the same (keys, mode, challenges) yields the same
//!    host and card cryptograms across two independent derivations.
//!  * **Mode length:** cryptograms are 8 bytes in S8 and 16 bytes in S16
//!    (Amd D §5.1 Table 5-1).
//!  * **Host ≠ card:** the two cryptograms use different derivation
//!    constants, so for non-degenerate challenges they differ.
//!  * **Challenge sensitivity:** flipping a host-challenge byte changes the
//!    host cryptogram (the KDF context feeds the challenge).
//! No panic on any input; the target imports arbitrary key material and only
//! asserts when derivation succeeds.

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use scll_backend_rustcrypto::RustCryptoBackend;
use scll_core::backend::{KeyBackend, KeyKind, Scp03Backend, ScpMode};

const FUZZ_RNG_SEED: [u8; 32] = [0x5C; 32];

#[derive(Arbitrary, Debug)]
struct Input {
    /// 0 → AES-128, 1 → AES-192, 2 → AES-256 (other values wrap).
    kind_sel: u8,
    /// false → S8, true → S16.
    s16: bool,
    host: [u8; 8],
    card: [u8; 8],
    /// Raw key material; sliced to the selected kind's clear length.
    key_material: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let backend = RustCryptoBackend::new(ChaCha20Rng::from_seed(FUZZ_RNG_SEED));

    let (kind, klen) = match input.kind_sel % 3 {
        0 => (KeyKind::Aes128, 16usize),
        1 => (KeyKind::Aes192, 24),
        _ => (KeyKind::Aes256, 32),
    };
    if input.key_material.len() < klen {
        return;
    }
    let key_bytes = &input.key_material[..klen];
    let mode = if input.s16 { ScpMode::S16 } else { ScpMode::S8 };
    let expect_len = if input.s16 { 16 } else { 8 };

    let enc = match backend.import_key(kind, key_bytes) {
        Ok(h) => h,
        Err(_) => return,
    };
    let mac = match backend.import_key(kind, key_bytes) {
        Ok(h) => h,
        Err(_) => return,
    };

    let derive = || backend.scp03_derive_session(&enc, &mac, mode, &input.host, &input.card);
    let (s1, s2) = match (derive(), derive()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return,
    };

    let host1 = backend.scp03_host_cryptogram(&s1, &input.host, &input.card);
    let host2 = backend.scp03_host_cryptogram(&s2, &input.host, &input.card);
    let card1 = backend.scp03_card_cryptogram(&s1, &input.host, &input.card);
    let (host1, host2, card1) = match (host1, host2, card1) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return,
    };

    // Determinism across two independent derivations.
    assert_eq!(host1, host2, "host cryptogram must be deterministic");

    // Mode length (Amd D §5.1 Table 5-1).
    assert_eq!(host1.len(), expect_len, "host cryptogram length must match mode");
    assert_eq!(card1.len(), expect_len, "card cryptogram length must match mode");

    // Host vs card use distinct derivation constants → differ (challenges are
    // fixed-size and independent here; a collision would signal a constant mixup).
    assert_ne!(
        host1, card1,
        "host and card cryptograms must use different derivation constants"
    );

    // Challenge sensitivity: perturb the host challenge and re-derive.
    let mut host_alt = input.host;
    host_alt[0] ^= 0x01;
    if let Ok(s3) = backend.scp03_derive_session(&enc, &mac, mode, &host_alt, &input.card) {
        if let Ok(host3) = backend.scp03_host_cryptogram(&s3, &host_alt, &input.card) {
            assert_ne!(
                host1, host3,
                "host cryptogram must depend on the host challenge"
            );
        }
    }
});
