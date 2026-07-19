# scll — Simple Card Lifecycle Library

A Rust library for **off-card** management of GlobalPlatform-compatible Java Cards
(post-fuse, any administratively open life-cycle state). Covers the full SSD/applet
lifecycle: discovery, SCP key provisioning, CAP loading, install, delete, secure-channel
exchange, and card life-cycle management.

> **Status:** implemented and hardened (unit + KAT + replay + property tests,
> fuzzing, coverage gate, MSRV/no_std CI). Verified end-to-end against NXP JCOP 4
> P71 (PC/SC) and the Oracle JCDK simulator. The canonical design is
> [`docs/pdd.md`](docs/pdd.md) (v1.0).

## Scope (PDD §2)

- **SCP03** (Amendment D v1.1.2) preferred; **SCP02** (GPCS §E) automatic fallback.
- SCP03 `i` ∈ `{0x10, 0x30, 0x70}`; SCP02 default `i = 0x55`.
- Authorized Management only; PUT KEY (Add-only) / DELETE KEY (KVN-only) for key provisioning.
- Cooperative applets (`org.globalplatform.SecureChannel`); library-internal CAP parsing.
- Card (ISD) life-cycle: forward provisioning + reversible lock/unlock; `TERMINATED` refused.
- Short APDUs only. Single SCP session at a time.

**Out of scope:** SCP01/10/11, Delegated Management, DAP Verification, STORE DATA Sensitive,
extradition, parent-mediated personalization, extended APDUs, async I/O. (PDD §2.2)

## Crate layout (PDD §3.1)

| Crate | Role |
|---|---|
| `scll-core` | Transport + backend traits, GP commands, SCP02/03 state machines, CAP parser. No concrete transport/crypto. |
| `scll-backend-rustcrypto` | Pure-Rust crypto backend (shipped default). |
| `scll-transport-pcsc` | PC/SC adapter (Linux production). |
| `scll-transport-jcsim` | TCP adapter for the Oracle Java Card simulator. |
| `scll` | Facade crate; Cargo features select transports and backend. |

Facade features: `pcsc`, `jcsim`, `backend-rustcrypto` (default).
Constrained targets depend on `scll-core` directly and supply their own transport/backend.

## Architecture highlights

- **Opaque `KeyHandle`s** across the whole public API — key material never crosses as bytes
  (HSM/PKCS#11-safe). Plaintext export only via the optional `ExportableKeyBackend`. (§3.3/§3.4)
- **Split backend traits:** `KeyBackend` + `Scp03Backend` + `Scp02Backend` (+ optional
  `ExportableKeyBackend`). (§3.3)
- **Typed errors:** `ScllError` / `WarningKind`; per-function `Result<XReport, ScllError>`. (§7/§8)
- **Testable without a card:** every byte-level transform is a pure function in `scll-core`. (§3.5/§10)
- **`no_std` + alloc-free** core and backend (fixed `heapless` capacities); MSRV 1.81.

## Examples

Six end-to-end example binaries (read-only info, card life-cycle, host-only key
tools, no_std-style free workflow, SSD and ISD lifecycles) live in the detached
[`examples/`](examples/) workspace — see [`examples/README.md`](examples/README.md)
for usage and the API coverage map.

## Building

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo deny check          # license/advisory policy (§10.6)
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## References

Primary specs and reference implementations are listed in [PDD §11](docs/pdd.md#11-references).
Notable: GlobalPlatform Card Specification v2.3.1, Amendment D (SCP03), Amendment E,
ISO/IEC 9797-1:2011, NIST SP 800-108r1.
