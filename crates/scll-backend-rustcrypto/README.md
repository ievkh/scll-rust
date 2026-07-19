# scll-backend-rustcrypto

Shipped default crypto backend for the **Simple Card Lifecycle Library**
([`scll`](https://crates.io/crates/scll)). Implements the `scll-core` backend
traits (`KeyBackend`, `Scp02Backend`, `Scp03Backend`, `ExportableKeyBackend`)
with pure-Rust [RustCrypto](https://github.com/RustCrypto) crates
(`aes`, `cmac`, `des`, `cbc`, `sha2`, …).

- `no_std`; RNG is injected by the caller (`R: RngCore + CryptoRng`, no
  `getrandom` dependency) — pass an OS RNG on hosts or a board TRNG on
  embedded targets.
- Internal key/session tables behind a `critical-section` mutex; enable the
  `std` feature on hosts to register the host `critical-section` impl.
- Key material is zeroized on drop (`zeroize`); plaintext export only through
  the explicit `ExportableKeyBackend` API.
- Validated by SCP02/SCP03 known-answer tests cross-checked against
  independent Python reference implementations.

Most users get this crate via the `backend-rustcrypto` feature (default) of
the [`scll`](https://crates.io/crates/scll) facade.

License: MIT OR Apache-2.0.
