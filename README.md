# scll — Simple Card Lifecycle Library

A Rust library for **off-card** management of GlobalPlatform-compatible Java Cards
(post-fuse, any administratively open life-cycle state). Covers the full SSD/applet
lifecycle: discovery, SCP key provisioning, CAP loading, install, delete, secure-channel
exchange, and card life-cycle management.

> **Status:** implemented and hardened (unit + KAT + replay + property tests,
> fuzzing, coverage gate, MSRV/no_std CI). Verified end-to-end against NXP JCOP 4
> P71 (PC/SC) and the Oracle JCDK simulator. The canonical design is
> [`docs/pdd.md`](docs/pdd.md) (v1.0).

## Quick start (host-only)

`discover_card` is step 1 of every workflow: it resets, SELECTs the ISD, and
reads the card's pre-auth data — no secure channel yet. It runs here with **no
reader and no simulator**: a small stub `Transport` replays the *same TLV shapes
a real card sends* — a SELECT FCI carrying the ISD AID (tag `'84'`), Card
Recognition Data (tag `'66'`) advertising **SCP03 i=0x70**, and a Key Information
Template (tag `'00E0'`) reporting one keyset at **KVN 0x30** — so discovery
resolves all three straight from the card's own bytes. Remaining optional
objects answer `6A88` ("absent") and become warnings, never errors (PDD §5.2).
The block also runs as a doctest under `cargo test`.

```rust
use scll::workflow::discover_card;
use scll::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};
use scll::model::ScpVariant;
use scll::limits::RAPDU_MAX;
use heapless::Vec;

// Standard GlobalPlatform Card Manager AID (GPCS §H).
const ISD_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// Off-card stub reader returning real card-shaped TLVs.
struct StubReader;
impl Transport for StubReader {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> {
        // capdu[1] = INS (A4 SELECT, CA GET DATA); capdu[2..4] = GET DATA tag.
        let rapdu: &[u8] = match (capdu.get(1), capdu.get(2), capdu.get(3)) {
            // SELECT -> FCI '6F' { DF name '84' = ISD AID }.
            (Some(&0xA4), _, _) => &[
                0x6F, 0x0A, 0x84, 0x08,
                0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00,
                0x90, 0x00,
            ],
            // GET DATA '0066' -> CRD '66'>'73'>'64'> OID ...04 03 70 (SCP, id 03, i 70).
            (Some(&0xCA), Some(&0x00), Some(&0x66)) => &[
                0x66, 0x0F, 0x73, 0x0D, 0x64, 0x0B,
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x70,
                0x90, 0x00,
            ],
            // GET DATA '00E0' -> KIT 'E0' { 'C0' KID 01, KVN 30, AES(88) len 16 }.
            (Some(&0xCA), Some(&0x00), Some(&0xE0)) => &[
                0xE0, 0x06, 0xC0, 0x04, 0x01, 0x30, 0x88, 0x10,
                0x90, 0x00,
            ],
            // Everything else: reference data not found.
            _ => &[0x6A, 0x88],
        };
        let mut r = Vec::new();
        let _ = r.extend_from_slice(rapdu);
        Ok(r)
    }
    fn reset(&mut self) -> Result<AtrAts, TransportError> {
        Ok(AtrAts { bytes: Vec::new(), protocol: TransportProtocol::T1 })
    }
    fn capabilities(&self) -> TransportCaps {
        TransportCaps { handles_t0_get_response: false, protocol: TransportProtocol::T1, contactless: false }
    }
    fn protocol(&self) -> TransportProtocol { TransportProtocol::T1 }
    fn is_connected(&self) -> bool { true }
}

let mut card = StubReader;
let info = discover_card(&mut card, None).unwrap();
assert_eq!(info.isd_aid.as_bytes(), &ISD_AID);                            // from FCI '84'
assert!(matches!(info.scp_default, ScpVariant::Scp03 { i_param: 0x70 })); // from CRD '66'
assert_eq!(info.isd_keysets.len(), 1);                                    // from KIT '00E0'
assert_eq!(info.isd_keysets[0].kvn, 0x30);
```

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
Notable: `GlobalPlatform` Card Specification v2.3.1, Amendment D (SCP03), Amendment E,
ISO/IEC 9797-1:2011, NIST SP 800-108r1.
