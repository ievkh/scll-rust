//! `key-tools` — HOST-ONLY demo of the key-backend traits (PDD §3.3): no
//! card, no transport, no environment required. Everything runs inside the
//! shipped `RustCrypto` backend:
//!
//! 1. `KeyKind::clear_len` per kind (Amendment D §7.2 clear vs encrypted length)
//! 2. `import_key` + `compute_kcv` against the crate's known-answer vectors
//! 3. `generate_key` → `export_key_dangerous` → re-`import_key` round-trips
//!    for AES-128/192/256 and two-key 3DES, KCVs compared in constant time
//! 4. `ExportedKey` semantics: `from_slice`, `as_bytes`/`Deref`, zeroize-on-drop
//! 5. `random_bytes` (host-challenge material)
//!
//! The KCV reference values are the SAME in-repo known answers the backend's
//! test suite asserts (`scll-backend-rustcrypto/tests/scp02_kat.rs`
//! `kcv_3des_matches_reference`; `tests/scp03_kat.rs`
//! `kcv_and_export_round_trip`), for the GlobalPlatform default test key
//! `40 41 .. 4F`: 3DES `8BAF47` (KCV = 3DES-ECB(key, 8×'00')[0..3], GPCS
//! v2.3.1 §B.4 conventions / §E usage) and AES-128 `504A77`
//! (KCV = AES-ECB(key, 16×'01')[0..3], Amendment D §4.1.4). A mismatch fails
//! the run with `KeyCheckValueMismatch`.
//!
//! `export_key_dangerous` (the optional `ExportableKeyBackend` trait) exists
//! on SOFTWARE backends only — an HSM/PKCS#11 backend simply does not
//! implement it, so "keys never leave the token" is enforced by the type
//! system (PDD §3.3). The returned `ExportedKey` zeroizes its buffer on drop;
//! treat the bytes as radioactive and never copy them anywhere unprotected.

use std::process::ExitCode;

use rand_core::OsRng;
use scll::backend::{ExportableKeyBackend, ExportedKey, KeyBackend, KeyKind};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::error::ScllError;

use scll_examples::{banner, to_hex, Be};

/// GlobalPlatform default test key (the `40 41 .. 4F` pattern).
const GP_DEFAULT_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
    0x4F,
];
/// 3DES KCV of [`GP_DEFAULT_KEY`] — in-repo known answer (`scp02_kat.rs`).
const KCV_3DES_REF: [u8; 3] = [0x8B, 0xAF, 0x47];
/// AES-128 KCV of [`GP_DEFAULT_KEY`] — in-repo known answer (`scp03_kat.rs`).
const KCV_AES128_REF: [u8; 3] = [0x50, 0x4A, 0x77];

fn main() -> ExitCode {
    println!("========================================");
    println!(" scll example: key-tools (host-only key-backend demo — no card needed)");
    println!("========================================");
    scll_examples::finish(run().map_err(|e| format!("{e}")))
}

fn run() -> Result<(), ScllError> {
    let b: Be = RustCryptoBackend::new(OsRng);
    const KINDS: [KeyKind; 4] = [
        KeyKind::Aes128,
        KeyKind::Aes192,
        KeyKind::Aes256,
        KeyKind::TripleDesDouble,
    ];

    // 1 — clear-key lengths. The PUT KEY "clear key length" byte carries
    // these values (Amendment D §7.2); the ENCRYPTED length differs for
    // AES-192 (24 clear bytes pad to 32 ciphertext bytes), so the two only
    // coincide for AES-128 and AES-256.
    banner(1, "KeyKind::clear_len (Amendment D §7.2)");
    for kind in KINDS {
        println!("  {kind:?}: {} clear bytes", kind.clear_len());
    }
    println!("  (AES-192 encrypts to 32 bytes — clear and encrypted length differ)");

    // 2 — import + KCV against the in-repo known answers.
    banner(2, "import_key + compute_kcv vs known answers");
    let h3 = b.import_key(KeyKind::TripleDesDouble, &GP_DEFAULT_KEY)?;
    let kcv3 = b.compute_kcv(&h3)?;
    println!(
        "  3DES   KCV of GP default key: {} (expect {})",
        to_hex(&kcv3),
        to_hex(&KCV_3DES_REF)
    );
    if !b.ct_eq(&kcv3, &KCV_3DES_REF) {
        return Err(ScllError::KeyCheckValueMismatch);
    }
    let ha = b.import_key(KeyKind::Aes128, &GP_DEFAULT_KEY)?;
    let kcva = b.compute_kcv(&ha)?;
    println!(
        "  AES-128 KCV of GP default key: {} (expect {})",
        to_hex(&kcva),
        to_hex(&KCV_AES128_REF)
    );
    if !b.ct_eq(&kcva, &KCV_AES128_REF) {
        return Err(ScllError::KeyCheckValueMismatch);
    }

    // 3 — generate → export → re-import round-trip for every kind. The two
    // KCVs are compared with the backend's constant-time `ct_eq`; the
    // exported plaintext drops (and zeroizes) at the end of each iteration.
    banner(3, "generate_key -> export_key_dangerous -> import_key round-trips");
    for kind in KINDS {
        let g = b.generate_key(kind)?;
        let exported = b.export_key_dangerous(&g)?;
        if exported.as_bytes().len() != kind.clear_len() {
            println!(
                "  {kind:?}: exported {} bytes, expected {}",
                exported.as_bytes().len(),
                kind.clear_len()
            );
            return Err(ScllError::KeyCheckValueMismatch);
        }
        let kcv_generated = b.compute_kcv(&g)?;
        let reimported = b.import_key(kind, exported.as_bytes())?;
        let kcv_reimported = b.compute_kcv(&reimported)?;
        if !b.ct_eq(&kcv_generated, &kcv_reimported) {
            return Err(ScllError::KeyCheckValueMismatch);
        }
        println!(
            "  {kind:?}: {} bytes exported, KCV {} — round-trip OK",
            kind.clear_len(),
            to_hex(&kcv_generated)
        );
        // `exported` drops here: `ExportedKey`'s Drop impl zeroizes the buffer.
    }

    // 4 — ExportedKey construction + views. The zeroize-on-drop property is
    // a compile-time contract of the type (Drop impl); it cannot be observed
    // from safe code after the drop — which is exactly the point.
    banner(4, "ExportedKey: from_slice / as_bytes / Deref / zeroize-on-drop");
    if let Some(ek) = ExportedKey::from_slice(&GP_DEFAULT_KEY) {
        println!("  from_slice: {} bytes: {}", ek.len(), to_hex(&ek));
        drop(ek); // buffer zeroized here (Drop -> Zeroize)
        println!("  dropped — buffer zeroized by the Drop impl");
    } else {
        println!("  from_slice refused the slice (over KEY_BYTES_MAX) — unexpected here");
        return Err(ScllError::KeyCheckValueMismatch);
    }

    // 5 — CSPRNG access (the same source SCP host challenges come from).
    banner(5, "random_bytes");
    let mut challenge = [0u8; 8];
    b.random_bytes(&mut challenge)?;
    println!("  8 random bytes: {}", to_hex(&challenge));

    Ok(())
}
