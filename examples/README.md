# scll examples

End-to-end demonstrations of the `scll` GlobalPlatform SDK against a real
JavaCard (**NXP JCOP 4 P71**, PC/SC) or the **Oracle JCDK simulator**
(`jcsim`), using the default **RustCrypto** backend and printing the full
result of each call.

This crate is an **independent** workspace (note the empty `[workspace]` table
in `Cargo.toml`); it is *not* a member of the `scll` library workspace and
builds / runs on its own from this directory. It is split into a shared
library (`src/lib.rs` — configuration/env parsing, transport selection + APDU
tracing, channel and printing helpers, the predefined demo keysets) and six
binaries under `src/bin/`.

## Target applet

[`ievkh/javacard-scp03-cooperative-applet`](https://github.com/ievkh/javacard-scp03-cooperative-applet)
— a cooperative SCP03 applet that delegates secure messaging to its associated
Security Domain. The custom `HELLO` command (`80F000000548656C6C6F`) is taken
from that repo's `scripts/20-send-hello.sh`.

## Binaries

| Binary | Demonstrates | Channels |
|---|---|---|
| `card-info` | probe, discover (plus a second, expected-AID discovery pass), `get_card_status`, `get_card_inventory`, explicit warning surfacing, manager accessors, and a final re-open with **automatic** SCP selection (`force_scp: None`, PDD §4.3) — read-only throughout | two sequential ISD channels |
| `card-status` | `set_card_status` (PDD §5.11): same-state no-op (`LifecycleNoOp`, no APDU — the card would reject a same-state write, GPCS §11.10.2.2), host-side refusals of an illegal transition without/with `force` and of a `TERMINATED` target (`IllegalLifecycleTransition` / `TerminateOutOfScope`, all pre-wire), and the only real SET STATUS — `OP_READY → INITIALIZED` — doubly gated behind `SCLL_LIFECYCLE_ADVANCE=1` **and** the jcsim transport (irreversible on real hardware, GPCS §5.1.1.2; a bridge restart resets the simulator). Idempotent: an already-INITIALIZED sim reports the no-op instead of advancing (never targets SECURED) | one ISD channel |
| `key-tools` | HOST-ONLY (no card/transport): `KeyKind::clear_len` (Amd D §7.2), `import_key`+`compute_kcv` against the crate's KAT known answers (3DES `8BAF47` / AES-128 `504A77` for the GP default key), `generate_key` → `export_key_dangerous` → re-import round-trips for all four kinds with constant-time (`ct_eq`) KCV comparison, `ExportedKey` `from_slice`/`Deref`/zeroize-on-drop, `random_bytes` | none |
| `workflow-free` | the no_std-style pattern: `CardManager` assembly + accessors (`transport()`, `transport_mut()`, `into_parts()`), then the workflow FREE functions (`discover_card`, `open_scp`, `get_card_status`, `get_card_inventory`) with the `ScpSession` threaded explicitly and closed manually via the backend; surfaces `OpenScpReport.warnings` (which the manager drops). Resilient KVN candidate loop mirrors `open_isd_original`. Read-only | one ISD channel |
| `ssd-lifecycle` | `create_ssd`, direct-SSD `put_sd_keys` (personalization + Add-rotation KVN `0x30`→`0x31`), `load_package`/`install_applet` into the SSD, applet APDUs under both keysets, teardown via ISD object DELETEs (PDD §10.7: no explicit SSD key deletion — `6985` on this card; the SSD object DELETE removes its key material, GPCS §11.2 Table 11-22) | ISD mgmt, direct SSD (PUT-KEY level), applet ×2 |
| `isd-lifecycle` | the same applet lifecycle run **on the ISD**: `load_package`/`install_applet` with SD = ISD (GPCS §11.5.2.3.2), `put_sd_keys` Add KVN `0x32`, applet channel under it, Add KVN `0x33` over a keyset-1 session, applet channel under keyset 2, then `delete_applet` + **`delete_sd_keyset`** for both demo KVNs over a channel authenticated with the card's original ISD keyset. Opt-ins (default-off): `SCLL_ISD_AES256=1` (AES-256 demo keysets, SCP03 only, abort-on-SCP02 guard) and `SCLL_APPLET_LEVEL=<hex>` (requested level for the applet channels; library caps to the card's `i`) | ISD mgmt, ISD key-ops (level `0x03`) ×3, applet ×2 |

## Build & run

```sh
# PC/SC (real reader)
export SCLL_PCSC="uTrust"
export SCLL_PCSC_KEY_ENC=404142434445464748494A4B4C4D4E4F
export SCLL_PCSC_KEY_MAC=404142434445464748494A4B4C4D4E4F
export SCLL_PCSC_KEY_DEK=404142434445464748494A4B4C4D4E4F
export SCLL_CAP=/path/to/scpapplet.cap
./run.sh

# jcsim (Oracle Java Card simulator via the apdu bridge)
export SCLL_JCSIM_ADDR=127.0.0.1:10000
export SCLL_JCSIM_KEY_ENC=404142434445464748494A4B4C4D4E4F
export SCLL_JCSIM_KEY_MAC=404142434445464748494A4B4C4D4E4F
export SCLL_JCSIM_KEY_DEK=404142434445464748494A4B4C4D4E4F
export SCLL_CAP=/path/to/scpapplet.cap
SCLL_TRANSPORT=jcsim ./run.sh
```

`run.sh <binary>` runs one binary (`cargo run --release --bin <binary>`);
`run.sh` / `run.sh all` runs them all. `SCLL_CAP` is required only by the two
lifecycle binaries. Requires a Rust toolchain ≥ 1.81 (the SDK's MSRV).

## Environment

The transport is chosen by `SCLL_TRANSPORT=pcsc|jcsim`, or inferred when
exactly one of `SCLL_PCSC` / `SCLL_JCSIM_ADDR` is set.

| Variable | Meaning |
|---|---|
| `SCLL_TRANSPORT` | optional `pcsc` / `jcsim` override |
| `SCLL_PCSC` | PC/SC reader-name substring, optional `@<index>` |
| `SCLL_PCSC_KEY_ENC/_MAC/_DEK` | ISD keys for PC/SC (hex, 16/24/32 bytes, equal length) |
| `SCLL_JCSIM_ADDR` | jcsim bridge `host:port` |
| `SCLL_JCSIM_KEY_ENC/_MAC/_DEK` | ISD keys for jcsim (sim GP default `4041…4F`) |
| `SCLL_CAP` | path to the applet CAP file (lifecycle binaries only) |
| `SCLL_SSD_AID` | SSD instance AID override (hex) |
| `SCLL_APPLET_AID` | applet instance AID override (hex; default = CAP module AID) |
| `SCLL_ISD_KVN` | ISD keyset version for the management channel (default `0x00`) |
| `SCLL_KEEP` | `1` ⇒ skip teardown |
| `SCLL_APDU_TRACE` | `1` ⇒ hex-dump every C-APDU/R-APDU to stderr (both transports) |
| `SCLL_ISD_AES256` | `1` ⇒ AES-256 demo keysets in `isd-lifecycle` (SCP03 targets only) |
| `SCLL_APPLET_LEVEL` | requested applet-channel security level (hex) in `isd-lifecycle` |
| `SCLL_LIFECYCLE_ADVANCE` | `1` ⇒ `card-status` performs the real `OP_READY → INITIALIZED` write (jcsim only) |

The `*_KEY_*` values are the **ISD** keys (they open the management channel).
The demo keysets the binaries provision are predefined constants in the
example library (SSD: KVN `0x30`/`0x31`; ISD: KVN `0x32`/`0x33`).

## Key rotation & safety properties

Rotation in both lifecycle binaries uses the **Add-then-delete** pattern (PUT
KEY P1 = `0x00`, GPCS v2.3.1 §11.8 Table 11-66; then KVN-only DELETE, tag
`'D2'`, §11.2.2.3.2) — never in-place Replace, which is unverified on the
available targets. Safety properties of `isd-lifecycle`:

- **Demo key versions are `0x32`/`0x33`, not `0x30`/`0x31`:** unlike a
  freshly created SSD, the ISD already carries the card's own keyset(s), and
  the jcsim ISD's default keyset version **is `0x30`** (KIT
  `'C0'{01 30 88 10}…`, confirmed by INITIALIZE UPDATE).
- **P1 addressability clamp:** confirmed original versions above 0x7F
  (initial keys at 0xFF on real JCOP) are never fed back into INITIALIZE
  UPDATE P1 — the lifecycles use selector 0x00 for them, and the candidate
  list filters them out (GPCS v2.3.1 §11.8.2.3 Table 11-67; the P71 answers
  `6A86` to P1=0xFF). The ISD restore path likewise cannot recreate a 0xFF
  version and restores the original key VALUES at 0x30.
- **Resilient ISD opens:** every binary opens original-keys ISD channels via
  the shared `open_isd_original` (candidates: known KVN → `SCLL_ISD_KVN` →
  non-demo KIT-reported versions → `0x30`), so the jcsim default-pointer
  artifact left by key-registry mutations cannot strand any example;
  `ssd-lifecycle` confirms the version once and reuses it explicitly for all
  later ISD channels.
- **Idempotency:** the binaries can be re-run indefinitely and no run —
  successful, failed, or interrupted — leaves data on the card (`SCLL_KEEP=1`
  opts out). `card-info` and `workflow-free` are read-only. `ssd-lifecycle`
  has a pre-clean, a teardown, and a best-effort failure cleanup (applet +
  ELF, then the SSD object, which takes its key material with it).
  `isd-lifecycle` runs one shared `cleanup` routine as pre-run recovery, as
  the teardown, and after any failure: applet + ELF deleted, demo keysets
  removed, **original ISD keyset in place** — when the original keys no
  longer authenticate (the sim's Add-replaces quirk), it authenticates with a
  demo keyset and **restores the original keyset by value** via PUT KEY Add
  (the environment holds the key values), then verifies by re-opening with
  the original keys. The restore version is the effective KVN observed when
  the original keys last authenticated, else `SCLL_ISD_KVN` if non-zero,
  else `0x30` (the jcsim ISD default).
- **Guards:** (1) refuse when `SCLL_ISD_KVN ∈ {0x32, 0x33}`; (2) refuse when
  a channel opened with the *original* ISD keys reports an effective KVN of
  `0x32`/`0x33` (`OpenScpParams::kvn_effective` — with `SCLL_ISD_KVN=0x00`
  the card picks its default at INITIALIZE UPDATE); (3) versions
  `0x32`/`0x33` are owned by the demo **by contract** — cleanup deletes them
  whenever present (with a loud printed line); do not run the demo against a
  card whose `0x32`/`0x33` keysets belong to someone else.
- **jcsim key-registry model:** only the **first** PUT KEY replaces the
  factory keyset (initial-key replacement); later Adds coexist. The sim's IU
  **P1=00 default-KVN pointer dangles** once the keyset it references is
  deleted (`6A88` despite existing keysets). Consequently the demo confirms
  the original key version once, in the pre-run recovery (`open_original`
  tries the known KVN, `SCLL_ISD_KVN`, every non-demo version the discovery
  KIT reported — the factory KVN varies per target: `0x30` plain jcsim,
  `0x03` JCOP-mocking bridge, typically `0xFF` on real cards — then explicit
  `0x30` last), and uses it **explicitly** for every original-keys channel —
  IU P1=00 is never relied upon after the registry has been mutated. The
  restore-by-value path covers the replaced factory keyset.
- ISD key-operation channels run at level `0x03` (C-MAC + C-DEC, no R-MAC)
  on both transports — a conservative mirror of the SSD PUT-KEY R-MAC
  restriction (PDD §10.7); PUT KEY at `0x33` on this card's ISD is untested.

## API coverage map

Which public API items the examples exercise end-to-end. Statuses: **C**
covered, **P** partial, **N** not covered.

| Public item | Status | Where |
|---|---|---|
| `probe` (Pcsc + Jcsim) | C | all binaries |
| `discover(None)` / `discover(Some(aid))` | C | `card-info` (expected-AID pass) |
| `open_scp` — forced SCP, explicit KVN + `0x00` fallback | C | `open` / `open_isd_original` (example lib) |
| `open_scp` — `force_scp: None` (PDD §4.3 auto-selection) | C | `card-info` |
| `transmit` | C | both lifecycles |
| `put_sd_keys` (ISD + SSD; SCP03 on jcsim, SCP02 on P71) | C | both lifecycles |
| `put_sd_keys` with `Aes256` | C | opt-in `SCLL_ISD_AES256=1` (`isd-lifecycle`, SCP03 only) — VERIFIED on jcsim: PUT KEY with 32-byte encrypted blocks / clear-length 32, `key_length: 32`, full lifecycle incl. AES-256 session channels and teardown restore; SCP02 abort guard verified on the P71. `Aes192` has no example path (handle side host-covered by `key-tools`) |
| `delete_sd_keyset` (ISD) | C | `isd-lifecycle` |
| `delete_sd_keyset` (SSD target) | N | intentionally: `6985` on the P71's own SSD channel (PDD §10.7) |
| `create_ssd` / `load_package` / `install_applet` / `delete_applet` / `delete_ssd` | C | both lifecycles |
| `DeleteCascade` — `Never`, `Always` (cascade_elf) | C | both lifecycles |
| `DeleteCascade` — `OnlyIfEmpty`, `IfLastInstance` | C | `ssd-lifecycle` teardown — wire-identical to `Always`/`Never` on the happy path, with the blocking SWs mapped (`6985` → `ElfHasOtherInstances` / `SsdHasApplets`); `Cascade` stays excluded (`6A86`, PDD §10.7 C2) |
| `get_card_status` / `get_card_inventory` | C | `card-info`, `ssd-lifecycle` |
| `set_card_status` (+ `CardLifeCycle`, `force`, `LifecycleNoOp`, `TerminateOutOfScope`) | C | `card-status`; real transition opt-in `SCLL_LIFECYCLE_ADVANCE=1`, jcsim-only |
| Warning surfaces (`discovery_warnings`, report `warnings`, `InventoryTruncated`) | P | surfaced explicitly in `card-info`; `InventoryTruncated` itself needs a populated card to trigger |
| Manager accessors — `is_channel_open`, `session()` | C | `card-info` |
| Manager accessors — `into_parts`, `transport()/transport_mut()` | C | `workflow-free` |
| Workflow free functions without `CardManager` (no_std-style) | C | `workflow-free`: explicit `ScpSession` threading + manual backend session close |
| `KeyBackend::import_key` | C | all binaries |
| `generate_key`, `compute_kcv` (host-side), `ExportableKeyBackend::export_key_dangerous` + `ExportedKey` zeroize | C | `key-tools` (host-only; KCVs asserted against the KAT vectors) |
| `KeyKind` — `Aes128`, `TripleDesDouble` | C | via `key_kind_for` per target |
| `ScpTargetKind` — both variants | C | ISD opens / applet channels |
| Transports — `connect_selector` (PC/SC), `connect` (jcsim) | C | `run_demo` |
| Transports — `connect_first`, `connect(reader)`, `connect_with_timeout` | N | not planned (thin constructors; doctest territory) |
| APDU trace (`SCLL_APDU_TRACE`) | C | both transports |
| Applet channel at level `0x33` on jcsim | C | opt-in `SCLL_APPLET_LEVEL=33` — VERIFIED on jcsim: EXTERNAL AUTHENTICATE accepted at P1=`0x33`, applet responses R-MAC'd + R-ENC'd and unwrapped correctly (`sec_level: 51`). The sim's R-MAC gap is confined to GET STATUS `63xx` pages (PDD §10.7) |

**Audit observation:** `CardManager::open_scp` returns only `OpenScpParams`
and drops the `OpenScpReport.warnings`; the free function keeps them. Callers
needing open-time warnings must use `workflow::open_scp` directly —
`workflow-free` demonstrates exactly this. Recorded here as a candidate API
refinement.
