# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-07-22

### Added
- New guide [`docs/jcsim-testing.md`](docs/jcsim-testing.md) — zero-to-first-test
  setup for running the library, the example binaries, and third-party
  applications against the Oracle Java Card simulator through
  [`javacard-simulator-apdu-bridge`](https://github.com/ievkh/javacard-simulator-apdu-bridge):
  simulator socket port, bridge build/configure/run, `cargo test-jcsim`
  invocation, the two applet-deployment routes (library `load_package` vs the
  bridge's AMService startup deployment), the setup's limits (single client, no
  card reset, PDD §10.7 simulator deviations), and a minimal downstream crate
  using `scll` with `features = ["jcsim", "std"]`. Linked from `README.md`.

## [1.0.2] - 2026-07-22

### Added
- README **Quick start (host-only)**: a representative example that runs
  `workflow::discover_card` with **no reader and no simulator**. A small stub
  `Transport` replays real card-shaped TLVs — a SELECT FCI with the ISD AID
  (tag `'84'`), Card Recognition Data (tag `'66'`) advertising SCP03 (i=0x70),
  and a Key Information Template (tag `'00E0'`) reporting one keyset at KVN 0x30 —
  so discovery resolves AID, SCP variant, and keysets from the card's own bytes;
  remaining optional objects answer `6A88` and surface as warnings (PDD §5.2).
  The facade pulls the README in via `#![doc = include_str!("../../../README.md")]`,
  so the block also runs as a doctest under `cargo test` (single source).

## [1.0.1] - 2026-07-19

### Fixed
- crates.io pages showed no README for any of the five published crates: the
  packages contained no README file and the normalized manifests carried
  `readme = false` (workspace-root `README.md` is not auto-detected by member
  crates). Added a short per-crate `README.md` to each publishable crate and
  an explicit `readme = "README.md"` in each `[package]` section.
  Ref: Cargo Book, "The readme field"
  (https://doc.rust-lang.org/cargo/reference/manifest.html#the-readme-field).

## [1.0.0] - 2026-07-19 

Initial consolidated state of the library (design and iteration history up to
this point lives in the git log; the canonical design is
[`docs/pdd.md`](docs/pdd.md), v1.0).

### Library

- **Five-crate workspace** (`scll-core`, `scll-backend-rustcrypto`,
  `scll-transport-pcsc`, `scll-transport-jcsim`, `scll` facade) plus dev-only
  test crates (`scll-test-util`, `scll-test-support`) and a `cargo-fuzz`
  sub-workspace. `scll-core` and the RustCrypto backend are `no_std` +
  alloc-free (fixed `heapless` capacities); MSRV 1.81.
- **Secure channels:** SCP03 (Amendment D v1.1.2, S8 and S16 modes,
  `i ∈ {0x00,0x10,0x20,0x30,0x60,0x70}` + S16 bit) and SCP02 (GPCS v2.3.1
  Annex E, `i = 0x55`, incl. R-MAC at level `0x13` with the §E.3.2 EA-C-MAC
  ICV seed), with SCP03-first automatic selection (PDD §4.3).
- **Split backend traits** (`KeyBackend`, `Scp03Backend`, `Scp02Backend`,
  optional `ExportableKeyBackend`) with opaque `KeyHandle`s; caller-injected
  CSPRNG; shipped RustCrypto backend.
- **Workflows** (PDD §5): probe, discover, `put_sd_keys` / `delete_sd_keyset`
  (single Add-only PUT KEY + KVN-only DELETE KEY engine), `create_ssd`,
  `load_package` (in-library CAP parsing, STORED + DEFLATE, streamed 'C4'
  LFDB), `install_applet`, `delete_applet`, `delete_ssd`, `open_scp`,
  applet APDU exchange, `set_card_status` / `get_card_status`,
  `get_card_inventory` (byte-level `63 10` page chaining).
- **Typed error surface:** `ScllError` / `WarningKind`; per-function
  `Result<XReport, ScllError>`; table-driven SW mapping.
- **Verified targets:** NXP JCOP 4 P71 (J3R150) over PC/SC and the Oracle
  JCDK simulator over the apdu bridge; target quirks and their handling are
  catalogued in PDD §10.7.

### Testing & CI

- Pure-layer unit tests (coverage-gated), crypto KATs cross-checked against
  out-of-process `pycryptodome`/`pyca` oracles and reference implementations,
  replay tests over `MockTransport`, property tests (`proptest`), and five
  fuzz targets (CAP parser, card-response parsers, R-APDU unwrap, SCP
  wrap round-trip, SCP03 KDF properties).
- CI: `fmt`, `clippy` (pedantic, `-D warnings`), tests, `cargo-llvm-cov`
  line-coverage gate (ratchet-up), `cargo-deny` license policy, MSRV 1.81
  job, `no_std` build job (`thumbv7em-none-eabi`), fuzz smoke + scheduled
  long-budget fuzz run.

### Examples

- Six example binaries (`card-info`, `card-status`, `key-tools`,
  `workflow-free`, `ssd-lifecycle`, `isd-lifecycle`) in the detached
  `examples/` workspace, idempotent against both targets; see
  [`examples/README.md`](examples/README.md) for the API coverage map.

### Documentation

- Documentation consolidated: PDD v1.0 (`docs/pdd.md`, versionless filename)
  is the single canonical design document; per-patch manifests and the
  completed implementation plan were removed (history in git); example
  documentation and the API coverage map moved to `examples/README.md`;
  crate versions set to 1.0.0.
