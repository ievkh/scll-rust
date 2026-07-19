# scll-core

Core crate of the **Simple Card Lifecycle Library** (`scll`): transport and
backend traits, GlobalPlatform command builders/parsers, SCP02/SCP03 secure
channel state machines (state only — crypto is delegated to a backend), and a
CAP file parser.

- `no_std` + alloc-free (fixed-capacity `heapless` buffers); MSRV 1.81.
- No concrete transport and no concrete cryptography: implement `Transport`
  and the split backend traits (`KeyBackend`, `Scp02Backend`, `Scp03Backend`,
  optional `ExportableKeyBackend`), or use the shipped implementations via the
  [`scll`](https://crates.io/crates/scll) facade crate.
- Opaque `KeyHandle`s throughout the public API — key material never crosses
  the API as bytes (HSM/PKCS#11-friendly).
- Baseline specs: GlobalPlatform Card Specification v2.3.1, Amendment D v1.1.2
  (SCP03), Amendment E v1.0.1 (SCP02).

Design document and examples: see the
[repository](https://github.com/ievkh/scll-rust).

License: MIT OR Apache-2.0.
