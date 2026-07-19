# Simple Card Lifecycle Library — Project Description Document

**Version:** 1.0 (implemented design; `no_std` + alloc-free)
**Spec baseline:** GlobalPlatform Card Specification v2.3.1 (Public Release, May 2018); Amendment D v1.1.2 (SCP03 S8) and v1.2 (SCP03 S16 mode); Amendment E v1.0.1 (security upgrade for SHA-256); ISO/IEC 9797-1:2011 (Retail MAC for SCP02); ISO/IEC 7816-4:2020 / 7816-5 (AID structure).
**Implementation language:** Rust. **MSRV 1.81** (`core::error::Error` for `no_std` `thiserror`).
**License:** MIT or Apache-2.0 dual.

**Design stance:** the library ships **only paths verified end-to-end on the available targets** (direct SSD keying, Add-only PUT KEY, KVN-only DELETE, load/install-into-SSD). Spec-faithful but unexercised capabilities — extradition, parent-mediated personalization, per-KID DELETE KEY, in-place key replacement — are excluded rather than carried on spec authority alone; each can be added once run logs and APDU evidence exist for it.

---

## Table of contents

1. [Purpose](#1-purpose)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
   - 3.1 [Crate layout](#31-crate-layout)
   - 3.2 [Transport trait](#32-transport-trait)
   - 3.3 [Backend traits (split)](#33-backend-traits-split)
   - 3.4 [Key design contracts](#34-key-design-contracts)
   - 3.5 [Testability contract](#35-testability-contract)
   - 3.6 [SCP02 as a type-level capability](#36-scp02-as-a-type-level-capability-locked-decision)
4. [SCP details — locked decisions](#4-scp-details--locked-decisions)
5. [Workflow specifications](#5-workflow-specifications) — steps 1–12a (probe, discover, keys, SSD, load, install, delete, open_scp, exchange, life-cycle, inventory)
6. [CardInfo struct — public API](#6-cardinfo-struct--public-api)
7. [Per-function reports — public API](#7-per-function-reports--public-api)
8. [ScllError enum — public API](#8-scllerror-enum--public-api)
9. [Default values](#9-default-values)
10. [Test, coverage & fuzzing strategy](#10-test-coverage--fuzzing-strategy)
    - 10.7 [Known card / simulator limitations & verification status](#107-known-card--simulator-limitations--verification-status)
11. [References](#11-references)

Example applications and their API coverage map are documented in [`examples/README.md`](../examples/README.md).

---

## 1. Purpose

A Rust library for off-card management of GlobalPlatform-compatible Java Cards that are post-fuse and in any administratively open life-cycle state. Provides an API for the following workflow:

1. Probe APDU transport availability.
2. Discover card capabilities (no authentication).
3. Replace, add, or delete SCP keys on the Issuer Security Domain.
4. Create a Supplementary Security Domain under the ISD.
   - 4a. Load a CAP file into the SSD.
5. Delete an SSD (optionally cascading contents).
6. Provision or delete SCP keys on an SSD (initial provisioning, rotation, or removal of a superseded keyset).
7. Install an applet from a loaded ELF into an SSD.
8. Delete an applet instance (optionally cascading its ELF).
9. Open an SCP03 or SCP02 secure channel with an applet (cooperative model).
10. Exchange APDUs with the applet over the open channel.
11. Manage the card (ISD) life-cycle state — forward provisioning and reversible lock/unlock; `TERMINATED` refused.
12. Read the card (ISD) life-cycle state.

---

## 2. Scope

### 2.1 In scope

- SCP03 (Amendment D v1.1.2) preferred.
- SCP02 (GPCS §E) as automatic fallback when card does not advertise SCP03.
- Authorized Management privilege on SSDs.
- PUT KEY for all key provisioning.
- DELETE KEY (GPCS `DELETE` command, key scope) for removing superseded keysets on the ISD or an SSD.
- Cooperative applets using `org.globalplatform.SecureChannel` (Card API v1.6).
- Library-internal CAP file parsing (Java Card VM Spec v3.1 Ch. 6).
- Card life-cycle states `OP_READY`, `INITIALIZED`, `SECURED`, `CARD_LOCKED` (restricted).
- Card (ISD) life-cycle state management via `SET STATUS` / `GET STATUS`: forward provisioning (`OP_READY → INITIALIZED → SECURED`) and reversible lock/unlock (`SECURED ↔ CARD_LOCKED`).
- Transports: PC/SC (Linux production), Oracle JC Simulator TCP (development), plus user-pluggable.
- Crypto backends: `scll-backend-rustcrypto` shipped; user-pluggable via the public backend traits (`KeyBackend`/`Scp03Backend`/`Scp02Backend`, §3.3).
- Single SCP session at a time, no logical-channel parallelism.
- Short APDUs only.

### 2.2 Out of scope

- SCP01, SCP10, SCP11 (PKI-based).
- SCP03 `i` configurations outside the supported set: any RFU bit (`0x01`/`0x02`/`0x04`) and R-ENCRYPTION without R-MAC (`0x40` without `0x20`) (Amendment D §5.1 Table 5-1).
- Delegated Management.
- DAP Verification and Mandated DAP Verification.
- STORE DATA Sensitive (and therefore Confidential Card Content Management).
- TERMINATED life-cycle (refused).
- Application / Supplementary Security Domain life-cycle state management via `SET STATUS` (P1 = application or SD scope); deferred. Only the card / ISD scope (`SET STATUS` P1 = ISD) is in scope. Application states are still *read* during existing pre-flight checks (e.g. §5.8) and via `get_card_status` is ISD-only.
- Async I/O (deferred; sync core only).
- Concurrent / multi-session operation.
- Extended APDUs (short APDUs only; CAPs > ~60 KB are not loadable).
- Android OMAPI transport (out of scope; users may implement against the transport trait).
- Built-in OpenSSL, BoringSSL, mbedTLS, and PKCS#11 backends (users may implement against the backend traits, §3.3).

---

## 3. Architecture

### 3.1 Crate layout

```
scll-core               # transport trait, backend traits, GP commands,
                        # SCP02/SCP03 state machines (state only — crypto
                        # delegated to the backend), CAP parser. no_std +
                        # heapless (alloc-free). Depends on heapless,
                        # thiserror, zeroize, miniz_oxide (no-alloc inflate).
                        # No concrete transport, no concrete crypto.

scll-backend-rustcrypto # backend-traits implementation using pure-Rust crates
                        # (aes, cmac, des, cbc, ecb, sha2, retail-mac,
                        # zeroize, rand_core, heapless, critical-section).
                        # no_std; RNG injected by the caller (no getrandom).

scll-transport-pcsc     # PC/SC adapter (depends on `pcsc` crate, MIT). std host crate.
scll-transport-jcsim    # TCP adapter for Oracle JC Simulator. std host crate.

scll                    # facade crate. Feature flags select transports
                        # and the backend.
```

Cargo features on `scll`:
- `pcsc` → re-exports `scll-transport-pcsc`.
- `jcsim` → re-exports `scll-transport-jcsim`.
- `backend-rustcrypto` (default) → re-exports `scll-backend-rustcrypto`.
- `std` → registers a host `critical-section` implementation for the backend.

Users on embedded or unusual platforms depend on `scll-core` directly and supply their own transport and/or backend. Common user-supplied backends will target OpenSSL/BoringSSL or PKCS#11 tokens; the library does not ship either.

### 3.2 Transport trait

- Blocking; per-APDU timeout owned by the transport.
- Caller owns the transport; library borrows `&mut dyn Transport`.
- Reader enumeration is the transport's responsibility.

Trait surface (minimum). The trait is `no_std`; returns are bounded `heapless` buffers (caps from `scll-core::limits`):

| Member | Purpose |
|---|---|
| `transmit(capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, _>` | Send one short C-APDU, get one R-APDU. Per-call timeout enforced inside. |
| `capabilities() -> TransportCaps` | T=0 GET RESPONSE handled transparently?, T=0/T=1/T=CL, contactless yes/no. |
| `reset() -> Result<AtrAts>` | Cold/warm reset, return ATR (contact) or ATS (contactless); `AtrAts.bytes: Vec<u8, ATR_ATS_MAX>`. |
| `protocol() -> Protocol` | Currently negotiated protocol. |
| `is_connected() -> bool` | Liveness check without sending an APDU. |

`TransportError` distinguishes at minimum: `CardRemoved`, `ReaderGone`, `Timeout`, `ProtocolError`, `Other(String<OTHER_DETAIL_MAX>)`. The `std` `pcsc`/`jcsim` adapters fill these `heapless` buffers from the reader/socket; an over-length response maps to `ProtocolError` rather than truncating.

### 3.3 Backend traits (split)

High-level / SCP-aware: each backend implements the SCP02 and SCP03 crypto flows in full; `scll-core` orchestrates state but performs no crypto. (This is required — see the locked decision in §3.6 — so that HSM/PKCS#11 keys never leave the token.)

**Split rationale.** A single monolithic backend trait is split into capability traits. Benefits: an SCP03-only backend needs no SCP02 stubs; the SCP03 KAT/fuzz suite runs without SCP02 present; and a token that cannot do SCP02's 3DES Retail-MAC path simply does not implement that trait, instead of failing at runtime.

Two locked-decision consequences are baked in:
- **Key material never crosses the public API as bytes.** Callers obtain opaque `KeyHandle`s from `import_key` / `generate_key`; the backend (software or HSM) is the sole holder of plaintext. `*_encrypt_put_key_payload` therefore takes a **`KeyHandle`** for the new key, not `&[u8]` — on a token this is a wrap (e.g. PKCS#11 `C_WrapKey`) and no plaintext appears in host memory.
- **Security level is fixed at channel-open and stored in the session**, so `wrap`/`unwrap` take no per-call `level` argument (removes a class of caller error).
- **`export_key_dangerous` moved to the optional `ExportableKeyBackend`** — a token that never releases keys simply does not implement it, so the contradiction (an HSM that "can't leave the token" being asked to export) disappears at the type level.
- **`scp02_unwrap_response`** — the SCP02 response-side method required by R-MAC (`0x13`) being in scope (§4.2).

**`no_std` handle model.** Handles/sessions are backend-constructed `u16` slot indices (`KeyHandle(u16)`, `Scp03Session(u16)`, `Scp02Session(u16)`, with `new(index)`/`index()`); the backend owns fixed key/session tables (§3.4 Fork A). `random_bytes` fills a caller buffer; `wrap`/`unwrap`/`encrypt_put_key_payload` return bounded `heapless` buffers (caps from `scll-core::limits`). `export_key_dangerous` returns an `ExportedKey` — a fixed-capacity, drop-zeroizing secret-bytes type — rather than `Zeroizing<heapless::Vec<..>>`, because heapless 0.8 has no `zeroize` feature (so `heapless::Vec` is not `Zeroize`); this keeps the core on heapless 0.8 / MSRV 1.81.

```rust
/// Backend-defined opaque key reference: an index into a fixed key-slot table
/// the backend owns. Opaque to callers; no key material crosses this boundary
/// except via the optional ExportableKeyBackend.
pub struct KeyHandle(u16);                 // + new(index)/index()

/// Key handles, randomness, KCV, constant-time compare. Required by every backend.
pub trait KeyBackend: Send + Sync + 'static {
    fn import_key(&self, kind: KeyKind, bytes: &[u8]) -> Result<KeyHandle, BackendError>;
    fn generate_key(&self, kind: KeyKind) -> Result<KeyHandle, BackendError>;
    fn compute_kcv(&self, h: &KeyHandle) -> Result<[u8; 3], BackendError>;
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), BackendError>; // fills caller buffer
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool;
}

/// OPTIONAL. Plaintext export of a key the backend holds. A software backend
/// (RustCrypto) implements this; an HSM/PKCS#11 backend does NOT — so "keys
/// never leave the token" is enforced by the type system, not a runtime error.
/// Exported key plaintext: fixed-capacity (<= KEY_BYTES_MAX), zeroized on drop.
/// Replaces Zeroizing<heapless::Vec<..>> (heapless 0.8 has no zeroize feature).
pub struct ExportedKey { /* bytes: [u8; KEY_BYTES_MAX], len: usize */ }

pub trait ExportableKeyBackend: KeyBackend {
    fn export_key_dangerous(&self, h: &KeyHandle) -> Result<ExportedKey, BackendError>;
}

/// SCP03 (Amendment D v1.1.2 S8 + v1.2 S16). Required by the default card manager (§3.6).
pub trait Scp03Backend: KeyBackend {
    fn scp03_derive_session(
        &self, static_enc: &KeyHandle, static_mac: &KeyHandle,
        mode: ScpMode, host_challenge: &[u8], card_challenge: &[u8],   // 8 (S8) or 16 (S16) bytes
    ) -> Result<Scp03Session, BackendError>;     // Scp03Session(u16) = session-table index
    fn scp03_card_cryptogram(&self, s: &Scp03Session, host_ch: &[u8], card_ch: &[u8]) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;
    fn scp03_host_cryptogram(&self, s: &Scp03Session, host_ch: &[u8], card_ch: &[u8]) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;
    // Expected pseudo-random card challenge (§6.2.2.1): KDF(Key-ENC, 0x02, L, seq ‖ invoker_AID).
    fn scp03_pseudo_card_challenge(&self, static_enc: &KeyHandle, mode: ScpMode, seq_counter: &[u8; 3], invoker_aid: &[u8]) -> Result<Vec<u8, SCP03_S16_MAX>, BackendError>;
    // No `level` arg: the session fixes its security level at open (§4.1). MAC width (8/16) follows the session mode.
    fn scp03_wrap_command(&self, s: &mut Scp03Session, capdu: &[u8]) -> Result<Vec<u8, CAPDU_MAX>, BackendError>;
    fn scp03_unwrap_response(&self, s: &mut Scp03Session, rapdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, BackendError>;
    // New key is a HANDLE, not bytes (HSM-wrappable, no host plaintext).
    // SCP03 uses the static DEK (Amendment D §6.2.6).
    fn scp03_encrypt_put_key_payload(&self, dek: &KeyHandle, new_key: &KeyHandle) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError>;
}

/// SCP02 (GPCS v2.3.1 §E). Separate trait so SCP03-only backends omit it.
pub trait Scp02Backend: KeyBackend {
    fn scp02_derive_session(
        &self, base_enc: &KeyHandle, base_mac: &KeyHandle, base_dek: &KeyHandle,
        seq_counter: [u8; 2],
    ) -> Result<Scp02Session, BackendError>;     // Scp02Session(u16) = session-table index
    fn scp02_card_cryptogram(&self, s: &Scp02Session, host_ch: &[u8; 8], card_ch: &[u8; 6]) -> Result<[u8; 8], BackendError>;
    fn scp02_host_cryptogram(&self, s: &Scp02Session, host_ch: &[u8; 8], card_ch: &[u8; 6]) -> Result<[u8; 8], BackendError>;
    fn scp02_wrap_command(&self, s: &mut Scp02Session, capdu: &[u8]) -> Result<Vec<u8, CAPDU_MAX>, BackendError>;
    // Response-side R-MAC verify/strip (level 0x13). Closes the
    // gap where SCP02 would have a wrap but no unwrap despite R-MAC in scope (§4.2).
    fn scp02_unwrap_response(&self, s: &mut Scp02Session, rapdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, BackendError>;
    // PUT KEY payload encryption uses the session's own derived S-DEK
    // (GPCS §E.4.1); the static-DEK variant was removed with the
    // parent-mediated mechanism (its only consumer).
    fn scp02_encrypt_put_key_payload_for_session(&self, s: &Scp02Session, new_key: &KeyHandle) -> Result<Vec<u8, ENC_KEY_BLOCK_MAX>, BackendError>;
}
```

`KeyHandle`, `Scp03Session`, and `Scp02Session` are backend-defined opaque types. They are `u16` indices into fixed-size tables the backend owns: the RustCrypto backend stores key bytes in a key-slot table and session state (S-ENC, S-MAC, S-RMAC, S-DEK, MAC chaining, fixed level) in a session-slot table; an OpenSSL backend would map the index to `EVP_PKEY` references; a PKCS#11 backend to session+object handle pairs. Plaintext never crosses the trait boundary except through the **optional** `ExportableKeyBackend`; session and static keys stay inside the backend.

### 3.4 Key design contracts

- Every public function returns `Result<XReport, ScllError>` (§7/§8) — error handling is compiler-enforced; there is no success payload reachable on the error path.
- Default parameters chosen for maximum security level achievable on the negotiated SCP version.
- Effective parameter values returned inside the per-function report.
- Library refuses any operation outside the locked scope by contract.
- Zero blind retries on authentication failure.
- **Key material never crosses the public API as bytes.** Callers pass opaque `KeyHandle`s obtained from `import_key`/`generate_key`; plaintext export is possible only when the backend implements the optional `ExportableKeyBackend` (software backends). HSM/PKCS#11 backends never expose it.
- **Opaque handles are backend-owned slot indices.** `KeyHandle`/`Scp0xSession` index fixed-size tables the backend owns; constructing a handle is backend-only. Alloc-free, embedded-friendly, and still opaque to callers.
- **RNG is injected.** The software backend is `RustCryptoBackend<R: RngCore + CryptoRng>`; the caller supplies the CSPRNG (board TRNG on embedded, OS RNG on host). The RNG and the key/session tables sit behind one `critical_section::Mutex<RefCell<_>>`, giving the `&self` trait methods interior mutability while the backend stays `Send + Sync` on `no_std`. The final binary must register a `critical-section` implementation (host: the `std` feature).

### 3.5 Testability contract

The library is designed to be testable without a card. Every byte-level transform (TLV/CRD/CCI/`'E3'` parsing, APDU building, SCP wrap/unwrap framing, CAP parsing, AID validation, the life-cycle transition state machine) is a **pure function** in `scll-core` with no transport and no crypto dependency, and is therefore unit-testable and fuzzable directly. Crypto correctness lives in the backend and is covered by known-answer tests there. Full-workflow behaviour is covered by replaying recorded APDU traces through a mock transport. The full plan — layering, KATs, property tests, fuzz targets, and coverage goals — is §10.

### 3.6 SCP02 as a type-level capability (locked decision)

SCP02 is a **hard requirement** (real inventory cards are SCP02-only), so the default `CardManager` requires `KeyBackend + Scp03Backend + Scp02Backend`; the shipped `scll-backend-rustcrypto` satisfies all three (plus `ExportableKeyBackend`). The trait split (§3.3) is purely organisational: it lets an advanced user on a constrained target construct an `Scp03Only` manager that drops the `Scp02Backend` bound (and the 3DES/Retail-MAC code with it). The selection rule (§4.3) is unchanged for the default manager.

The shipped backend is generic over the injected RNG — `RustCryptoBackend<R: RngCore + CryptoRng + Send + 'static>`, constructed with `new(rng)` (no zero-arg `new`/`Default`); the trait-capability discussion above is otherwise unchanged.

---

## 4. SCP details — locked decisions

### 4.1 SCP03

- **Supported `i` set:** S8 `{0x00,0x10,0x20,0x30,0x60,0x70}` and S16 `{0x08,0x18,0x28,0x38,0x68,0x78}` (Amendment D §5.1 Table 5-1). Bit b4 `0x08` selects **S16** (16-byte challenges/cryptograms, full 16-byte MACs); bit b5 `0x10` selects **pseudo-random** card challenges (a 3-byte sequence counter is then returned, §6.2.2.1 / §7.1.1.6); `0x20`/`0x40` add R-MAC/R-ENC (R-ENC implies R-MAC). Out of scope: any RFU bit and R-ENC without R-MAC.
- **Default `i`** = `0x70` (S8, **pseudo-random** card challenge + R-MAC + R-ENC).
- **S16 (Amendment D v1.2):** 16-byte host/card challenges and cryptograms (KDF `L = 0x0080`); full 16-byte C-MAC/R-MAC (no truncation); 16-byte MAC chaining value unchanged; INITIALIZE UPDATE `Lc = 0x10`, EXTERNAL AUTHENTICATE `Lc = 0x20`; IU response 45 bytes (random) / 48 bytes (pseudo-random). Session-key KDF and the C-ENC/R-ENC ICV scheme are mode-independent. Mode is derived from `i & 0x08` and carried in the session.
- **Pseudo-random challenge verification (§6.2.2.1):** when the card returns a sequence counter, the host recomputes the expected card challenge — KDF keyed by the static Key-ENC, derivation constant `0x02`, context = `sequence_counter ‖ invoker_AID` — via `backend.scp03_pseudo_card_challenge(...)` and constant-time compares it to the received challenge; a mismatch is `ScllError::CardChallengeFail` (fail-closed defence in depth). The invoker AID is threaded into the SCP03 `begin`.
- **Default `i`** historic note: the earlier "compliance subset `{0x10,0x30,0x70}`" wording described the same three values but mislabelled them as random; they are pseudo-random per Table 5-1.
- **Hybrid AID addressing** for `open_scp`: explicit SD AID if given, else auto-resolved via `GET STATUS` against ISD.
- **Security level capped to "i" capability**, default `0x33` (C-MAC + C-DEC + R-MAC + R-ENC). Amendment D §6.2; bitmap per GPCS Table 10-1 (Current Security Level). The effective level is **fixed at channel-open and stored in the session**, so `wrap`/`unwrap` carry no per-call level.
- **KVN default `0x00`** (card picks highest); library verifies returned KVN matches caller-supplied keys.
- **Sequence counter is stateless on host side.**
- **Channel closure:** implicit on next SELECT or reset; explicit `close()` zeroises session keys and rejects further calls.
- **Hard fail on EXTERNAL AUTHENTICATE failure;** no retry.
- **PUT KEY uses static DEK** (Amendment D §6.2.6); SCP03 does not derive a session DEK.

### 4.2 SCP02

- **Default `i`** = `0x55` (explicit initiation, 3 keys, CBC mode, ICV MAC over AID, ICV encryption for C-MAC session, R-MAC supported). Aligns with UL GP Compliance Test Suite certification of SCP02 `i = '55'`.
- **Security level default** = `0x03` (C-MAC + C-DECRYPTION). SCP02 has no response encryption, so the SCP03-style `0x33` is invalid for SCP02; valid SCP02 levels are `0x01`, `0x03`, `0x11`, `0x13` (GPCS Table 10-1 constrained by Appendix E). R-MAC, when enabled, raises this to `0x13` and is carried out via the separate session below. `i = 0x55` is retained as the default per UL CTS, independently of R-MAC.
- **Session keys** derived per GPCS v2.3.1 §E.4.1 (3DES-CBC over fixed constant + 2-byte sequence counter; separate session ENC, MAC, DEK).
- **Retail MAC** per ISO/IEC 9797-1:2011 Algorithm 3 (single-DES CBC chain, final block re-encrypted under K2 then K1).
- **KCV** = 3DES-ECB encrypt eight `0x00` bytes under the key; take first 3 bytes (GPCS §E).
- **Hard fail on EXTERNAL AUTHENTICATE failure;** no retry.
- **R-MAC (GPCS v2.3.1 §E.4.5).** Response R-MAC at level `0x13` is implemented (`scp02_unwrap_response`; KATs `unwrap_rmac_level_13_verifies_and_strips`, `unwrap_rmac_case1_command_carries_lc_zero`). Per §E.4.5 (p. 269) the R-MAC data block is: the **stripped** command (C-MAC removed and the modified header undone, logical channel assumed zero) ‖ `Li` ‖ response data ‖ SW, padded per §B.1.3. scll accumulates the command header as `CLA & ~0x07` (= `0x80`) and always emits the `Lc` byte, which matches §E.4.5 — the earlier `0x80`-vs-`0x84` open point is **resolved in scll's favour** (the transmitted `0x84` / modified header is *not* used; the `skythen` reference's use of it is the outlier). Two consequences of §E.4.5:
    - When R-MAC is requested in EXTERNAL AUTHENTICATE P1 (level `0x13`), the card R-MACs **all** subsequent responses automatically and the EA pair is excluded — **no `BEGIN R-MAC SESSION` is required**, so scll's default path is correct as-is.
    - `BEGIN` / `END R-MAC SESSION` (INS `0x7A` / `0x78`, builders in `command::rmac_session`) are for starting R-MAC **mid-session or under implicit initiation**; the `BEGIN` pair *is* included in the R-MAC and the `END` command is excluded (§E.4.5).
  **Case-1/2 `Lc` (§E.4.5):** `Lc` is always present in the R-MAC data block, set to zero for a case-1/2 (no-data) command; covered by `unwrap_rmac_case1_command_carries_lc_zero`. **First R-MAC ICV (§E.3.2, p. 264):** after a successful EXTERNAL AUTHENTICATE "the C-MAC of the EXTERNAL AUTHENTICATE command becomes the ICV for the subsequent C-MAC verification **and/or R-MAC generation**", i.e. the first R-MAC's ICV is the EA C-MAC — **not** zeroes. Seeding `ricv` with zeroes is a conformance gap that changes every R-MAC value and is the confirmed root cause of "R-MAC verification failed" against a real JCOP 4 P71 at level `0x13` (jcsim and gppro don't exercise SCP02 R-MAC, so no external vector catches it). `ricv` is seeded from the EA's own C-MAC on the first wrap; both R-MAC KAT vectors (`unwrap_rmac_level_13_verifies_and_strips`, `unwrap_rmac_case1_command_carries_lc_zero`) are generated from `scp02_ref.py` with that seed. Command/data-block layout is confirmed against §E.4.5; `scll-transport-pcsc` ships a `SCLL_APDU_TRACE=1` wire dump for on-card verification. The `scp02_close_session` slot release is covered by `close_session_frees_slot_for_reuse` / `session_table_exhausts_without_close`.
- **Known weakness:** SCP02 is subject to a padding-oracle attack (Avoine & Ferreira, TCHES 2018). Library accepts this risk in exchange for inventory-card compatibility; SCP02 is never selected when SCP03 is available.

### 4.3 Selection rule

`open_scp` step:

1. Read `CardInfo.scp_supported` from step 2.
2. If any `Scp03 { i_param }` entry with `i_param ∈ {0x10, 0x30, 0x70}` exists → use SCP03 with the highest-`i` advertised variant.
3. Else if any `Scp02 { i_param }` entry exists → use SCP02 with that `i_param` (typically `0x15` or `0x55`).
4. Else → `ScllError::ScpProtocolUnsupported`.

Caller may override step 2/3 with an explicit `force_scp_version` parameter; not recommended.

If CRD (`GET DATA '66'`) is absent or empty, library assumes `Scp02 { i = 0x55 }` as fallback and logs `WarningKind::CardRecognitionDataMissing`.

---

## 5. Workflow specifications

Each step section gives: inputs, the returned `…Report` type (§7), pre-flight checks, wire-level APDU sequence, post-condition housekeeping. Error codes are the typed `ScllError` of §8.

### 5.1 Step 1 — transport probe

Trivial wrapper over `Transport::capabilities()`, `Transport::reset()`, `Transport::is_connected()`. No card-side state. Returns `ProbeReport` populated from the transport's self-report.

Failure mode: `ScllError::TransportUnavailable` if the transport reports it cannot be opened. (A missing transport is unrepresentable: `CardManager` owns its transport by construction, so no `NoTransport` guard exists.)

---

### 5.2 Step 2 — discover_card

Read everything the card willingly tells you **before** any SCP authentication. The output drives every later step's behaviour (SCP version selection, key-type capability checks).

**Inputs:**

| Input | Required? | Default if absent | Notes |
|---|---|---|---|
| `transport` | yes | — | Any open `&mut dyn Transport` |
| `expected_isd_aid` | optional | none | If known, skip the empty SELECT and select it directly |

**Returned:** `CardInfo` (see §6).

**Step-by-step:**

1. **Reset and read ATR/ATS** (transport concern; library records).
   ```
   transport.reset() → AtrAts { bytes, protocol }
   ```

2. **SELECT the ISD.** With `expected_isd_aid`:
   ```
   CLA=00 INS=A4 P1=04 P2=00 Lc=<n> Data=<expected_isd_aid> Le=00
   ```
   Without: empty-AID SELECT returns the default selected application (ISD on every GP-compliant card per GPCS v2.3.1 §5.2.2):
   ```
   CLA=00 INS=A4 P1=04 P2=00 Lc=00 Le=00
   ```
   ISD AID is inside FCI under tag `'84'`.

3. **Read Card Recognition Data:**
   ```
   CLA=80 INS=CA P1=00 P2=66 Le=00
   ```
   Tag `'66'` per GPCS v2.3.1 §H.2. Parse all `'64'` entries inside `'73'` → list of `(scp_id, i_param)` pairs.
   Selection rule applied in step 9 (see §4.3). Refuse SCP01.
   If `6A88`: card does not advertise CRD. Fall back assuming `SCP02 i=0x55`, log warning.

4. **Read Key Information Template:**
   ```
   CLA=80 INS=CA P1=00 P2=E0 Le=00
   ```
   Tag `'E0'` per GPCS v2.3.1 §11.3.3.1. Each `'C0'` Key Information Data entry:
   - Basic format: `KVN(1) | KID(1) | KeyType(1) | KeyLength(1)`.
   - Extended format (GPCS 2.3+): `KVN(1) | KID(1) | 'B9' Lb { ... }`.

   KeyType decode: `0x80`=DES, `0x88`=AES, `0xA1`/`A2`/`A3`=RSA, `0xB0`/`B1`/`B2`=ECC.
   Group by KVN; KIDs `0x01`/`0x02`/`0x03` = ENC/MAC/DEK (semantics shared by SCP02 and SCP03).

5. **Read Card Capability Information** (optional):
   ```
   CLA=80 INS=CA P1=00 P2=67 Le=00
   ```
   Tag `'67'` per GPCS v2.3.1 §H.4. Sub-tags parsed: `'A0'` channels, `'A1'` ciphers, `'A2'` SCP, `'A3'` privileges, `'A4'` memory. Sub-tag `'A5'` (extended APDU) is read into `cci_raw` for diagnostics but ignored at runtime.
   If `6A88`: assume channel 0 only.

6. **(Optional) Read IIN / CIN:**
   ```
   GET DATA '0042'   // IIN
   GET DATA '0045'   // Card Image Number
   ```
   Diagnostic only.

**Pre-flight checks rolled in:** none beyond transport reset. Life-cycle detection deferred to first SCP-required step.

**Failure modes:**

| Condition | Library reaction |
|---|---|
| Empty SELECT returns `6A82` | `ScllError::CardNotUsable` — card misconfigured or TERMINATED. |
| `GET DATA '66'` returns `6A88` | Fall back to assumed `SCP02 i=0x55`; `WarningKind::CardRecognitionDataMissing` warning. |
| `GET DATA '00E0'` returns `6A88` | `WarningKind::KeyInformationTemplateMissing` warning. |
| `GET DATA '67'` returns `6A88` | `WarningKind::CardCapabilityInfoMissing` warning, conservative defaults. |
| `GET DATA '66'` returns `9000` with empty data | Treat as no CRD. |

Idempotent and safe to call repeatedly. Modifies no card state.

---

### 5.3 Step 3 — put_sd_keys (shared PUT KEY / DELETE KEY engine)

> **Shared engine.** §5.3 and §5.6 share a single key-management engine. This section defines it once (§5.3.1 PUT KEY, §5.3.3 DELETE KEY); §5.6 documents only the SSD-specific usage notes. The engine **is** the public surface: one pair — `put_sd_keys` / `delete_sd_keyset` — parameterised by `target_sd_aid` (no per-SD wrapper aliases). The engine is **Add-only over a session against the target SD itself**: in-place `Replace`, backend-minting `Generate`, `InitialProvisioning`, and the `ParentMediatedPersonalization` mechanism are not provided — unverified or failing on every available target.

#### 5.3.1 Shared PUT KEY core

**Add** an SCP keyset on a Security Domain (PUT KEY P1 = `0x00`, the new KVN inside the data field — GPCS v2.3.1 §11.8.2.1, Table 11-66). The engine is parameterised only by **`target_sd_aid`** — the SD whose keyset is written (ISD AID for §5.3.2; SSD AID for §5.6) — and always operates over a session opened against that SD itself. Rotation is **Add-then-delete**: add the new KVN, re-open the channel on it, then remove the superseded version via the §5.3.3 KVN-only DELETE.

> **Removed (unverified on all available targets):** the in-place `Replace`/`Generate` write (PUT KEY P1 = KVN) — failed with `6A88`/untested on all available targets — and the `ParentMediatedPersonalization` mechanism (`INSTALL [for Personalization]` redirect) — crashed the jcsim inner card, never exercised end-to-end. Both `PutKeyMode` and `PutKeyMechanism` are gone from the API; on the validated targets a fresh SSD authenticates with its inherited parent keyset, so first keying and rotation use the same Add path.

The engine is **protocol-aware**: SCP03 path uses AES-CBC encryption + AES KCV; SCP02 path uses 3DES-CBC + 3DES KCV.

**Common inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `session` | yes | — | SCP session opened against `target_sd_aid` itself with its current keys |
| `target_sd_aid` | yes | — | Provided by the wrapper (ISD or SSD AID) |
| `new_keys` (3 `KeyHandle`s: ENC, MAC, DEK) | yes | — | Handles from `backend.import_key`/`generate_key` (never bytes). All three same algorithm/length; algorithm must match negotiated SCP version |
| `new_kvn` | yes | — | `0x01`–`0x7F` (P1-addressable range, GPCS v2.3.1 §11.8.2.3 Table 11-67); `0x30`–`0x3F` conventional for SCP03; `0x20`–`0x2F` conventional for SCP02 |
| `dek` | yes | — | DEK `KeyHandle` of the keyset the session authenticated with; used for SCP03 payload encryption (static DEK, Amendment D §6.2.6). **Ignored under SCP02** — the engine uses the session's derived DEK (GPCS §E.4.1) |

**Returned:** `PutKeysReport` (records the target AID, effective SCP protocol, `new_kvn`, key type/length, the three KCVs).

**Pre-flight:**

a) **Target life-cycle.** `GET STATUS` against `target_sd_aid` (P1=`0x80` for ISD, `0x40`/`0x80` for an SSD; P2=`0x02`); reject if the SD state forbids content management. `CARD_LOCKED` blocks PUT KEY.

b) **Key capability.** `GET DATA` tag `'00E0'` against the target SD. Check `new_keys` length and type match an advertised KeyType/KeyLength. Mismatch → `ScllError::KeyTypeUnsupported { offered, supported }`.

c) **KVN consistency (Add).** `new_kvn` must not be present in the target KIT (with fast discovery the KIT snapshot is skipped and the card's SW is authoritative — a compliant card answers a colliding Add per its own policy). Note the jcsim initial-key exception in §12: the **first** PUT KEY on a factory-fresh SD replaces the initial keyset instead of adding.

**Encrypt each new key** per negotiated SCP: SCP03 via `backend.scp03_encrypt_put_key_payload(dek_handle, new_key_handle)` (static DEK of the authenticated keyset, Amendment D §6.2.6); SCP02 via `backend.scp02_encrypt_put_key_payload_for_session(session, new_key_handle)` (the session's own derived S-DEK, GPCS v2.3.1 §E.4.1 — static-DEK encryption over a direct SCP02 channel is rejected with `6982` on the JCOP 4 P71; see §3.3). All operands are `KeyHandle`s / backend session handles, so on an HSM/PKCS#11 backend this is a token wrap and no key plaintext appears in host memory. (The SCP02 static-DEK trait method is not provided with the parent-mediated mechanism, its only consumer.)

**KCV computation** via `backend.compute_kcv(handle)`:
- SCP03/AES: `AES-ECB(new_key, sixteen 0x01 bytes)[0..3]` (Amendment D §4.1.4).
- SCP02/3DES: `3DES-ECB(new_key, eight 0x00 bytes)[0..3]` (GPCS §E).

**Build the PUT KEY data field** for the 3-key set:

```
data = new_kvn(1)
     | key_block_ENC | key_block_MAC | key_block_DEK

key_block_AES  = 0x88 | block_len(1) | clear_key_len(1) | encrypted_key(N) | KCV_len(1) | KCV(3)
key_block_3DES = 0x80 | len_of_enc_value(1) | encrypted_key(16) | KCV_len(1) | KCV(3)
where
  block_len       = 1 + N  (the clear_key_len byte plus the ciphertext)
  clear_key_len   = 16 / 24 / 32  -- PLAINTEXT AES key length (Amendment D §7.2)
  encrypted_key N = 16 (AES-128) or 32 (AES-192 padded to the block boundary, AES-256)
  len_of_enc_value= 16 (3DES double-length)
  KCV_len = 3
  -- NB: for AES-192 the clear length (24) differs from the 32-byte ciphertext;
  --     the clear_key_len byte is the plaintext length, never the encrypted one.
```

**APDU** (PUT KEY, GPCS v2.3.1 §11.8):

```
CLA=84 INS=D8 P1=p1 P2=p2 Lc=<n> Data=data Le=00
```

P1 = `0x00` — Add; the new KVN is carried inside the data field (GPCS v2.3.1 §11.8.2.1, Table 11-66). (The in-place P1 = KVN replace form is not provided.)
P2 = `0x81` (multi-key bit + first KID `0x01`).

Sent via `session.transmit(...)`, which wraps with `CLA | 0x04`, C-MAC, optional C-ENC. (SCP02 uses `CLA | 0x04` for C-MAC-only sessions; the session abstraction hides this.)

**Card response:** `9000` with data = `new_kvn | KCV_ENC | KCV_MAC | KCV_DEK`. Library verifies returned KCVs against locally computed. Mismatch → `ScllError::KeyCheckValueMismatch`.

**Post-write housekeeping:**
1. Session keys unchanged; the target SD now additionally carries `new_keys` at `new_kvn`.
2. Update cached KIT for `target_sd_aid`.

(An SCP03 pseudo-random sequence counter reset — the card zeroes it when a whole keyset is replaced via a single PUT KEY, Amendment D §6.2.2 — cannot be host-detected under the Add-only engine; no `counter_reset` report field exists. The only replacement case is the jcsim initial-key quirk, §10.7.)

**Atomicity:** PUT KEY is atomic on the card (GPCS §10.5). If transport loses the response after commit, the card has new keys but the host does not know. Library should re-open SCP with both old and new keys on next connect.

#### 5.3.2 ISD usage of `put_sd_keys`

Call the §5.3.1 engine with `target_sd_aid = ISD_AID` (Add-only).

**Wrapper-specific inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `current_keys` (ENC, MAC, DEK) | yes | — | 3 `KeyHandle`s (from `import_key`/`generate_key`) for the open SCP to ISD. AES-128/192/256 (SCP03) or 3DES double-length (SCP02). |
| `current_kvn` | optional | `0x00` | Card picks highest |

**Behaviour:** opens SCP to the ISD via `open_scp(target_aid = ISD_AID, target_kind = SecurityDomainAid, sd_keys = current_keys, kvn = current_kvn)`, then delegates to §5.3.1.

#### 5.3.3 `delete_sd_keyset` (DELETE KEY engine)

Remove a superseded key **version** (whole keyset) from a Security Domain. Complements PUT KEY for rotation hygiene: after `put_*_keys` adds `new_kvn`, the old KVN can be deleted once no longer needed. The engine is **KVN-only** — a single `'D2'` reference deleting every key of that version (GPCS v2.3.1 §11.2.2.3.2); no per-KID `delete_isd_key`/`delete_ssd_key` wrappers are provided (per-KID DELETE of a PUT-KEY set returns `6A88` on JCOP 4 P71 — see the card note below).

**DELETE KEY core inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `session` | yes | — | SCP session against `target_sd_aid` itself (there is no parent-mediated delete) |
| `target_sd_aid` | yes | — | ISD or SSD AID |
| `kvn` | yes | — | Key Version Number → tag `'D2'`; every key of this version is deleted |

The wire builder (`command::delete::delete_key`) still accepts the full Table 11-24 grammar (`'D0'` KID / `'D2'` KVN, both Conditional; at least one present); the workflow engine always emits the KVN-only form.

**Pre-flight:**
- a) **Target life-cycle.** `CARD_LOCKED` blocks DELETE KEY (same restriction as PUT KEY).
- b) **Keyset presence.** The requested `kvn` must exist; the card answers `6A88` → `ScllError::KeyNotFound` (with fast discovery there is no client-side KIT snapshot to pre-check against).
- c) **Active-keyset guard.** Refuse deleting the KVN that the **current session** authenticated with → `ScllError::CannotDeleteActiveKeyset` (would brick the channel). The caller must rotate to a new KVN, re-open, then delete the old one.
- d) **Last-keyset guard (ISD).** Deleting the last remaining ISD keyset would make the card unmanageable — the caller must not do it. No client-side guard is implemented (the registry snapshot fast discovery skips would be required); the card's own policy/SW is authoritative. (No `CannotDeleteLastIsdKeyset` variant exists — it would never be constructed.)

**APDU** (DELETE, GPCS v2.3.1 §11.2.2, Table 11-20):

```
CLA=84 INS=E4 P1=00 P2=00 Lc=<n> Data=<tlv> Le=00
```

P1 = `0x00` — single/last command (Table 11-21: b8 = `0` "Last (or only) command"; b7–b1 RFU). The library never segments DELETE.
P2 = `0x00` — delete object only (Table 11-22: b8 = `0` "Delete object"; `0x80` would mean "delete object and related object", which is not used for keys). b7–b1 RFU.

Data field (DELETE [key], GPCS v2.3.1 Table 11-24, §11.2.2.3.2):

```
'D0' 01 <kid>      // Key Identifier      — Conditional (omit → all KIDs matching the KVN)
'D2' 01 <kvn>      // Key Version Number  — Conditional (omit → all KVNs matching the KID)
```

Per Table 11-24: a single key is deleted when **both** `'D0'` and `'D2'` are present; multiple keys are deleted by **omitting one tag**. The workflow always omits `'D0'` (KVN-only, all keys of the version). Omission is encoded by leaving the tag off the wire — never `0xFF`/`0x00` sentinel bytes (that convention belongs to the kaoh/globalplatform C API's *function arguments*, not the GP data field). The exact omission options a given card accepts are Issuer-policy-dependent (§11.2.2.3.2).

Sent via `session.transmit(...)` (`CLA | 0x04`, C-MAC, optional C-ENC).

**Card response:** a single `'00'` byte is always returned for DELETE [key] (GPCS v2.3.1 §11.2.3.1, Table 11-25) with SW `9000`. Status-word mapping to `ScllError` (§8):

| SW | Meaning | Source | Library reaction |
|---|---|---|---|
| `9000` | Key(s) deleted (`'00'` data byte) | §11.2.3.1 | `Ok` |
| `6A88` | Referenced data (key) not found | Table 11-26 | `ScllError::KeyNotFound` |
| `6A80` | Incorrect values in command data (e.g. malformed `'D0'`/`'D2'`) | Table 11-26 | `ScllError::Card { sw: 0x6A80 }` (no dedicated variant for DELETE-data errors) |
| `6581` | Memory failure | Table 11-26 | `ScllError::Card { sw: 0x6581 }` |
| `6985` | Conditions of use not satisfied (e.g. `CARD_LOCKED`) | Table 11-10 (general) | `ScllError::ConditionsNotSatisfied` |
| `6982` | Security status not satisfied | Table 11-10 (general) | `ScllError::SecurityStatusNotSatisfied` |

(`6A82` "Application not found" — Table 11-26 — does not arise for the key scope.)

**Post-delete:** update cached KIT; emit `DeleteKeyReport`.

> **Card note (JCOP 4 P71 — empirical, not spec):** a key set written by
> PUT KEY is addressed **as a unit by its key version**. A per-KID DELETE
> (`'D0' kid` + `'D2' kvn`) returns **`6A88`** for such a set; the **KVN-only**
> form (`'D2' kvn`, `kid = None`) deletes the whole version and returns `9000`
> — matching gppro `--connect <SD> -s 80E4000003D2013x`. This is why the
> the engine is KVN-only (per-KID wrappers are not provided). Both
> `'D0'`/`'D2'` tags per GPCS v2.3.1 §11.2, Table 11‑24 (DELETE [key] data).
> Ref: APDU transcript + gppro `30-remove.sh`.

**`delete_sd_keyset` (single function, KVN-only engine):** a single DELETE carrying only the `'D2'` tag deletes every key of that version (GPCS v2.3.1 §11.2.2.3.2), over a session opened against `target_sd_aid` itself. The caller must not target the keyset the current session authenticated with, nor the card's only remaining ISD keyset — the card's SW decides (no client-side KIT guard), but either would strand the SD.

---

### 5.4 Step 4 — create_ssd

Create a Supplementary Security Domain under the ISD.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `parent_session` | yes | — | SCP session against parent (typically ISD) |
| `ssd_aid` | optional | RID from ISD + 11-byte CSPRNG PIX | Total 5–16 bytes per ISO/IEC 7816-5 |
| `privileges` | optional | `0x80 0x00 0x00` (SD only) | 3-byte privilege string per GPCS Table 6-1; bit values Table 11-7 |
| `install_parameters` | optional | empty `'C9'` TLV | App-specific; rarely needed |
| `ssd_executable_module_aid` | optional | well-known resident SD module | Auto-resolved via `GET STATUS` |
| `ssd_package_aid` | optional | well-known resident SD package | Auto-resolved via `GET STATUS` |

**Resident SD code:** An SSD is an instance of a Security Domain *application* already resident on the card. Library runs `GET STATUS P1=0x20 P2=0x02` to find a load file containing an SD module. If none found → `ScllError::ResidentSdNotFound`.

**Pre-flight:**

a) **Parent privileges.** Verify parent has Authorized Management privilege. Tag `'CF'` from `GET STATUS P1=0x80`. Absent → `ScllError::ParentLacksAm`.

b) **AID collision.** `GET STATUS P1=0x40` and `P1=0x80`; reject if `ssd_aid` present → `ScllError::AidAlreadyExists`.

c) **AID format.** 5–16 bytes per ISO/IEC 7816-5.

d) **Privileges sanity.** Refuse privilege strings including DAP Verification (byte 1 bit 1), Mandated DAP Verification (byte 1 bit 0), Delegated Management (byte 1 bit 7). → `ScllError::UnsupportedPrivilege`.

**INSTALL [for Install and Make Selectable]** (GPCS §11.5.2.3):

```
CLA=84 INS=E6 P1=0C P2=00 Lc=<n> Data=<install data> Le=00
```

P1 = `0x0C` = Install + Make Selectable.

Data field:

```
Lf(1) | ELF_AID         (1+L bytes)
Lm(1) | Module_AID      (1+L bytes)
La(1) | Instance_AID    (1+L bytes)         // = ssd_aid
Lp(1) | Privileges      (1+3 bytes)
Li(1) | Install_Params  (1+L bytes)         // TLV-wrapped: 'C9' typically empty
Lt(1) | Install_Token   (1+0 bytes)         // length 0 for AM
```

`'C9'` is mandatory in Install Params even if empty (some older cards return `6A80` if absent).

**Card response:** `9000`.

**Post-create:** SSD in `INSTALLED` then `SELECTABLE` (because P1=`0x0C`). No keys yet — step 6 provisions them. Refresh SD inventory cache.

---

### 5.4a Step 4a — load_package

Load a CAP file under a target SD. Library parses the CAP and derives all `INSTALL [for Load]` parameters. Short APDUs only.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `parent_session` | yes | — | SCP session against the SD hosting the package |
| `cap_file` | yes | — | Borrowed `&[u8]` of the `.cap` (a ZIP per JC VM Spec). **STORED and DEFLATE entries both accepted** — DEFLATE is inflated by `miniz_oxide` (no-alloc) into a caller-lent 32 KiB window; the Load File Data Block is streamed in 240-byte chunks via `LoadFileDataBlock::next_block`, never held whole in RAM |
| `target_sd_aid` | optional | AID `parent_session` is open against | Caller can target different SD if parent has AM over it |

**CAP parsing:** A `.cap` is a ZIP per JC VM Spec v3.1 Ch. 6. Library extracts:

| Component | File | Used for |
|---|---|---|
| Header | `Header.cap` | Package AID, version, JC platform version |
| Directory | `Directory.cap` | Component order/lengths |
| Import | `Import.cap` | Imported package AIDs + versions (dependencies) |
| Applet | `Applet.cap` | List of (class AID, install method offset) |
| All others | as listed | Bytes appended to Load File Data Block |

**Load File Data Block order** per GPCS §C.2:
```
Header | Directory | Import | Applet | Class | Method | StaticField |
Export | ConstantPool | RefLocation | Descriptor | [Debug, normally excluded]
```

**Compression.** ZIP entries are read per the local-header method: STORED entries are taken directly from the borrowed input; DEFLATE entries are inflated with `miniz_oxide` (`default-features = false`, alloc-free) using `TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF` over a caller-lent 32 KiB wrapping window (`INFLATE_WINDOW`) that doubles as the LZ77 dictionary. The assembled LFDB is produced one 240-byte chunk at a time (`LoadFileDataBlock::next_block`) regardless of method, so neither the whole CAP nor the whole LFDB is held in RAM. Inflate failure → `ScllError::Cap(CapError::Inflate)`. (The standard converter emits DEFLATE JARs, so no host-side repack is needed.)

**Pre-flight:**

a) **Dependency check / JC platform version** — *not implemented*. Cross-referencing `Import.cap` AIDs against resident packages and checking the `Header.cap` required platform were planned client-side pre-checks; the card rejects a bad LOAD authoritatively, and the never-constructed `MissingDependency` / `CapPlatformTooNew` warnings were removed.

c) **Existing package.** If same package AID on card → `ScllError::PackageAidExists`.

d) **Memory.** Optional via `GET DATA '0044'` if supported; warn if insufficient.

e) **Size check.** Compute total LOAD blocks required at 240 bytes plaintext per block. If > 256 blocks (~60 KB) → `ScllError::LoadTooLarge`. Extended APDU is not supported.

**INSTALL [for Load]** (GPCS §11.5.2.1):

```
CLA=84 INS=E6 P1=02 P2=00 Lc=<n> Data=<install-for-load data> Le=00
```

Data field:

```
Lp(1) | Package_AID                (1+L)
Ls(1) | Target_SD_AID              (1+L)
Lh(1) | Load_File_DataBlock_Hash   (1+H)   // SHA-256, H=32
Lr(1) | Load_Parameters            (1+0)   // empty
Lt(1) | Load_Token                 (1+0)   // empty under AM
```

**LOAD blocks** (GPCS §11.6.2):

```
CLA=84 INS=E8 P1=<more> P2=<block#> Lc=<n> Data=<chunk> Le=00
```

P1: `0x00` = more blocks, `0x80` = last block.
P2: block number, starting `0x00`, incrementing.

**First block** prefixed with TLV wrapper:
```
data_field_first_block = 'C4' | length_BER | load_file_data_block_bytes
```

Tag `'C4'` = Load File. Length in 1/2/3-byte BER form.

**Chunking:**
```
chunk_size = 240 bytes plaintext (short APDU; SCP wrap adds C-MAC overhead).
```

Block_no must not exceed `0xFF`. Library enforces the limit pre-flight (step e above).

**Mid-load failure:** Card discards partial bytes. No rollback needed.

**Post-load:** ELF in state `LOADED`. Applet not yet instantiated; step 7 does that.

---

### 5.5 Step 5 — delete_ssd

Remove an SSD. Cascade decision is explicit.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `parent_session` | yes | — | SCP session against parent (typically ISD) |
| `ssd_aid` | yes | — | SSD to delete |
| `cascade` ∈ {`OnlyIfEmpty`, `Cascade`} | optional | `OnlyIfEmpty` | Caller must opt in to wiping contents |

**Pre-flight:**

a) **SSD existence and parent association.** `GET STATUS P1=0x80`; check associated SD matches `parent_session` target.

b) **Parent has AM.**

c) **Contents inventory (only if `OnlyIfEmpty`).**
- `GET STATUS P1=0x40` count applets with associated SD = `ssd_aid`. > 0 → `ScllError::SsdHasApplets`.
- `GET STATUS P1=0x20` count ELFs with associated SD = `ssd_aid`. > 0 → non-cascading delete fails on the card.

d) **Sub-SDs / self-deletion.** A locked AM-only design does not produce sub-SDs, and deleting the SD the session targets is the caller's error; both are answered authoritatively by the card's SW. (No `SsdHasElfs` / `SsdHasSubSds` / `CannotDeleteSelf` variants exist — they would never be constructed.)

**DELETE command** (GPCS §11.2):

```
CLA=84 INS=E4 P1=00 P2=p2 Lc=<n> Data=<tlv> Le=00
```

P1 = `0x00` (mandatory).
P2:
- `0x00` for `OnlyIfEmpty` — fail if dependents exist.
- `0x80` for `Cascade` — atomic wipe: all applets + ELFs + keys + SSD.

Data:
```
'4F' Llen <ssd_aid>
```

**Cascade behaviour** (GPCS §11.2.2): `P2 = 0x80` on an SSD deletes:
1. All applet instances with associated SD = `ssd_aid`.
2. All ELFs with associated SD = `ssd_aid`.
3. SSD's keysets.
4. The SSD itself.

**Not deleted by cascade:** sub-SDs whose parent = `ssd_aid` (card returns `6985`).

> **Card note (JCOP 4 P71 / Oracle JCDK sim — empirical, not spec):** these
> targets **reject the cascade bit `P2 = 0x80` on a Security Domain with
> `6A86` (Incorrect P1/P2)**. The working sequence is to empty the SD first
> (delete its applets/ELFs and key set) and then delete it with `P2 = 0x00`,
> which is exactly what GlobalPlatformPro's remove script does
> (`84 E4 00 00 12 4F 08 <ssd_aid> <MAC>`). `P2 = 0x80` was only accepted when
> the object was absent (returning `6A88`). So `OnlyIfEmpty` / `P2 = 0x00` is
> the validated path on these cards; `Cascade` is unverified there. Command
> layout per GPCS v2.3.1 §11.2, Table 11‑22 (P2) / Table 11‑23 (data).
> Ref: public GPCS v2.3.1 PDF, and APDU transcript + gppro `30-remove.sh`.

**Post-delete:** Invalidate cached inventory entries; mark any open session whose target was the SSD or its applets as `Closed` with reason `TargetDeleted`.

---

### 5.6 Step 6 — SSD keys via put_sd_keys / delete_sd_keyset (§5.3 engine)

SSD key management uses the same `put_sd_keys` / `delete_sd_keyset` engine (§5.3) with `target_sd_aid = ssd_aid`, over a session opened against the SSD itself with the SSD's current keys. The PUT KEY / DELETE KEY mechanics, data-field layout, KCV verification, atomicity, and housekeeping are exactly as in §5.3.1 / §5.3.3. (the former dedicated SSD wrappers were collapsed into the engine.)

**Initial provisioning.** On every validated target a freshly created SSD authenticates with the keyset it inherits from its parent (ISD), so its first key set is written over a direct SSD session with the inherited keys — the same Add path as rotation. The former **Mechanism A** (`ParentMediatedPersonalization`: PUT KEY over the parent's session prefixed by `INSTALL [for Personalization]`, GPCS v2.3.1 §11.5.2.4, for SSDs with a genuinely empty Key Information Template) is **not provided**: it crashed the jcsim inner card (broken pipe), was never exercised end-to-end on any available card, and the "empty KIT" precondition never arises on the reference hardware. The `INSTALL [for Personalization]` builder, the `PutKeyMechanism`/`PutKeyMode` selectors, the KIT-based auto-detection, and the SCP02 static-DEK payload-encryption trait method that would exist only for that path are likewise not provided. A card whose SSDs are created key-empty is out of scope until such a target is available for verification.

**Inputs:** as §5.3.1 (`session` against the SSD, `ssd_aid` as `target_sd_aid`, `new_keys`, `new_kvn`, `dek` — SCP03-only, see §5.3.1).

> **Verification status (JCOP 4 P71 / Oracle JCDK sim — empirical):**
> - **Direct-session keying is the validated path.** On the reference card a
>   freshly created SSD authenticates with the keys it inherits from its
>   parent (ISD key version `0x30`), so its first key set is written directly.
> - **PUT KEY rotates a single-key-version SD.** On this SSD a PUT KEY carrying
>   a *new* key version over the authenticated set **replaces** (rotates) the
>   version rather than adding a second coexisting set: after writing `0x31`
>   over a `0x30` session, `INIT-UPDATE P1=0x30` returns `6A88` (version gone).
>   So an Add with a new KVN behaves as a rotation on single-key-set SDs, and
>   there is no "old" version left to delete afterwards. GP does not require an
>   SD to hold multiple key versions (GPCS v2.3.1 §11.8, PUT KEY).
> Ref: APDU transcript, gppro `10-install.sh` / `30-remove.sh`, public GPCS
> v2.3.1 PDF.

**Wire flow:** identical to §5.3.1 with `target_sd_aid = ssd_aid`; the caller has already opened SCP against the SSD with its current keys.

**Note on "default SSD keyset":** GP does not mandate one. Some vendors pre-provision (JCOP 4 P71 and both simulator bridges inherit the parent keyset), others leave empty. The library never assumes; the examples confirm the working key version empirically at open time (`open_isd_original` pattern, §12).

**SSD key deletion:** `delete_sd_keyset` (§5.3.3) with `target_sd_aid = ssd_aid` over a session opened against the SSD with the SSD's own keys. (There is no parent-mediated DELETE KEY; the SSD must already be keyed to authenticate the deletion.) Note the JCOP 4 P71 empirical limit (§12): `DELETE [key]` on an SSD's **own** channel returns `6985` under all tested conditions — the ISD-level object DELETE of the SSD removes its key material instead.

---

### 5.7 Step 7 — install_applet

Instantiate an applet from a loaded ELF into an SSD. Same APDU as step 4; different field meanings.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `parent_session` | yes | — | SCP session against SSD hosting the applet |
| `package_aid` | yes | — | ELF AID loaded in step 4a |
| `applet_class_aid` | optional | first applet class in CAP | Module AID inside ELF |
| `instance_aid` | yes | — | 5–16 bytes per ISO/IEC 7816-5 |
| `privileges` | optional | `0x00 0x00 0x00` | 3-byte privilege string |
| `applet_install_parameters` | optional | empty | Passed verbatim to `Applet.install()` on card |
| `system_install_parameters` | optional | empty | GP system parameters (memory hints) |

**Pre-flight:**

a) **SSD state and privileges.** AM required.

b) **ELF presence.** `GET STATUS P1=0x20`; confirm package_aid in state `LOADED`. Missing → `ScllError::PackageNotFound`.

c) **ELF ↔ SSD relationship.** The ELF's associated SD must match the parent-session target; a mismatch is answered by the card's SW (no `ElfAssociatedWithOtherSd` variant exists — it would never be constructed).

d) **Applet class membership.** Confirm `applet_class_aid` in CAP's `Applet.cap` (cached from step 4a). If not in cache, defer to card-side error.

e) **Instance AID collision.** `GET STATUS P1=0x40`. Present → `ScllError::AidAlreadyExists`.

f) **Privilege contract.** Refuse DAP, Mandated DAP, DM, and Security Domain privilege (last would convert applet into SSD — not the function's intent).

**INSTALL [for Install and Make Selectable]:**

```
CLA=84 INS=E6 P1=0C P2=00 Lc=<n> Data=<install data> Le=00
```

Same data structure as step 4:
```
Lf(1) | ELF_AID            (1+L)
Lm(1) | Module_AID          (1+L)
La(1) | Instance_AID        (1+L)
Lp(1) | Privileges          (1+3)
Li(1) | Install_Params      (1+L)
Lt(1) | Install_Token       (1+0)
```

**Install Params** (GPCS §11.5.2.3.7):

```
Install_Params = 'C9' Lc9 <applet_install_parameters>
                ['EF' Lef <system_install_parameters>]
```

`'C9'` mandatory (even if empty: `C9 00`). `'EF'` optional.

System parameter TLVs inside `'EF'`:
- `'C7'` Non-volatile code minimum (2 bytes)
- `'C8'` Volatile memory minimum (2 bytes)
- `'D7'` Non-volatile data minimum (2 bytes)
- `'D8'` Global service parameters (variable)

**Applet install parameters** is opaque to the library — passed verbatim to applet's `Applet.install(byte[], short, byte)`. Common convention: `<aid_len> <aid> <ctrl_info_len> <ctrl_info> <app_params_len> <app_params>`. Library does not parse but sanity-checks first byte plausibility.

**Card response:** `9000`. Applet now in `INSTALLED` then `SELECTABLE`.

**`6A80` vs `6F00`:** `6A80` = install parameters didn't parse (caller's fault); `6F00` = applet's own `install()` crashed (applet author's fault).

**Post-install:** Refresh application inventory cache.

---

### 5.8 Step 8 — delete_applet

Remove an applet instance. Optionally cascade to its ELF if it was the last instance.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `parent_session` | yes | — | SCP session against SSD owning the applet |
| `instance_aid` | yes | — | |
| `cascade_elf` ∈ {`Never`, `IfLastInstance`, `Always`} | optional | `Never` | |

**Pre-flight:**

a) **Applet existence and association.** `GET STATUS P1=0x40`; locate `instance_aid`. Associated SD must match parent_session target.

b) **Applet life cycle.** States allowing deletion (GPCS Table 11-3): `INSTALLED`, `SELECTABLE`, `LOCKED`, application-specific states ≥ `0x07`. Card `CARD_LOCKED` blocks DELETE on ISD-child applets.

c) **Parent has AM.**

d) **Cascade pre-check** (only if `cascade_elf != Never`). Count instances from the parent ELF.

**DELETE command:**

```
CLA=84 INS=E4 P1=00 P2=00 Lc=<n> Data=<'4F' Llen instance_aid> Le=00
```

P2 = `0x00` always for applet instances (cascade bit meaningless on instances).

**Cascade-ELF behaviour (library-side, not card-side):**

After successful instance delete:

- **`IfLastInstance`:** Re-run `GET STATUS P1=0x40`. If count = 0 from this ELF → DELETE the ELF (second APDU, P2=`0x00`). Else skip and report `instances_remaining`.
- **`Always`:** Attempt ELF DELETE directly. If other instances still exist, ELF DELETE returns `6985` → `ScllError::ElfHasOtherInstances`. Instance delete still succeeded.

**Distinction from step 5's cascade:**
- Step 5 cascade = **card-side atomic** (single APDU with `P2 = 0x80`).
- Step 8 cascade-ELF = **library-side sequenced** (two separate APDUs).

For `6985`: library follows up with `GET STATUS P1=0x40` to diagnose the actual block (state, AM, dependents).

**Post-delete:** Invalidate any session whose target was the deleted applet (`ScllError::TargetNoLongerExists`). Refresh inventory cache.

---

### 5.9 Step 9 — open_scp

Open an SCP secure channel. For cooperative applets, SELECT targets the applet AID; the applet routes IU/EA to its associated SD via `SecureChannel.processSecurity()`. For direct SD targeting (steps 3, 6, 7, 8), SELECT targets the SD.

Library negotiates SCP version per §4.3: SCP03 preferred, SCP02 only if SCP03 unavailable.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `target_aid` | yes | — | 5–16 bytes |
| `target_kind` ∈ {`ApplicationAid`, `SecurityDomainAid`} | yes | — | |
| `sd_keys` (ENC, MAC, DEK) | yes | — | 3 `KeyHandle`s (from `import_key`/`generate_key`); never raw bytes. AES-128/192/256 for SCP03; 3DES double-length for SCP02 |
| `sd_aid` | optional (only if `target_kind=ApplicationAid`) | auto-resolved via `GET STATUS P1=0x40` | |
| `kvn` | optional | `0x00` (card picks highest) | |
| `requested_security_level` | optional | `0x33` (SCP03) / `0x03` (SCP02) | capped to negotiated protocol; see §4.1 / §4.2 |
| `force_scp_version` | optional | none (use §4.3 selection rule) | Override; not recommended |

**Returned:** `ScpSession` handle (protocol-tagged enum: `Scp03(...)` or `Scp02(...)`) + `OpenScpReport`.

**Wire-level flow — SCP03 path:**

1. **SELECT target.**
   ```
   CLA=00 INS=A4 P1=04 P2=00 Lc=len(target_aid) Data=target_aid Le=00
   ```

2. **If `target_kind = ApplicationAid` and `sd_aid` absent → resolve via `GET STATUS`.** Re-SELECT ISD first if needed.
   ```
   GET STATUS  CLA=80 INS=F2 P1=40 P2=02 Lc=05 Data=4F00 Le=00
   ```
   Parse returned tag `'E3'` entries; find one whose AID matches `target_aid`; extract associated SD AID from tag `'CC'`. Re-SELECT applet.

3. **Generate host challenge.** `mode.field_len()` bytes (8 in S8, 16 in S16) via `backend.random_bytes(..)`, where `mode = ScpMode::from_i(i)` of the selected variant.

4. **INITIALIZE UPDATE.**
   ```
   CLA=80 INS=50 P1=kvn P2=00 Lc=<8|16> Data=host_challenge[8|16] Le=00
   ```
   `Lc` = host-challenge length (`08` S8 / `10` S16). P2 always `0x00` for SCP03.

5. **Parse IU response.** The size mode is read from the echoed `i` (`i & 0x08`); pseudo-random cards (`i & 0x10`) append a 3-byte sequence counter. Four valid lengths (SW stripped): 29 (S8 random), 32 (S8 pseudo-random), 45 (S16 random), 48 (S16 pseudo-random).
   ```
   offset  field                            length
     0     key diversification data         10
    10     KVN actually used                 1
    11     SCP identifier (must equal 0x03)  1
    12     i parameter                       1
    13     card challenge                    n   (n = 8 S8 / 16 S16)
   13+n    card cryptogram                   n
   13+2n   sequence counter (pseudo only)    3
   ```
   Assert SCP id == `0x03`. Assert `i` is in the supported set (else `ScllError::NoCommonSecurityLevel`) and the total length equals `13 + 2n [+3]` (else `ScllError::ScpProtocolUnsupported`). Assert returned KVN matches caller's keys → mismatch = `ScllError::KvnMismatch`.

6. **Derive session keys** via `backend.scp03_derive_session(static_enc, static_mac, mode, host_ch, card_ch)`. Per Amendment D §4.1.5 (NIST SP 800-108 CMAC-based KDF in counter mode); context = `host_ch ‖ card_ch` (16 B S8 / 32 B S16); the backend produces `S-ENC`, `S-MAC`, `S-RMAC` and records `mode` in the session.

7. **Verify card cryptogram** via `backend.scp03_card_cryptogram(session, host_ch, card_ch)` (8/16 bytes) + constant-time compare. Mismatch → `ScllError::CardCryptogramFail`.

7a. **Verify pseudo-random card challenge (§6.2.2.1)** — only when a sequence counter is present. Recompute the expected challenge via `backend.scp03_pseudo_card_challenge(static_enc, mode, sequence_counter, invoker_aid)` and constant-time compare to the received card challenge. Mismatch → `ScllError::CardChallengeFail`. `invoker_aid` is the AID `open_scp` SELECTed (the SD AID for direct targeting).

8. **Cap security level to `i` capability:**
   ```
   allowed = 0x03                       // C-MAC + C-DEC always allowed
   if i & 0x20: allowed |= 0x10         // R-MAC supported
   if i & 0x40: allowed |= 0x20         // R-ENC supported
   effective_sec_level = requested_security_level & allowed
   ```
   `effective_sec_level == 0` → `ScllError::NoCommonSecurityLevel`. (`i & 0x08` is the size mode, not a level bit.)

9. **Compute host cryptogram** via `backend.scp03_host_cryptogram(...)` (8/16 bytes).

10. **EXTERNAL AUTHENTICATE:**
    ```
    CLA=84 INS=82 P1=effective_sec_level P2=00 Lc=<10|20>
    Data = host_cryptogram[8|16] || C-MAC[8|16]
    ```
    `Lc` = `0x10` (S8) / `0x20` (S16). C-MAC computed by `backend.scp03_wrap_command` over the EA C-APDU per Amendment D §6.2.3/§6.2.4 (8-byte truncated MAC in S8, full 16-byte MAC in S16).
    Expect `9000`. Hard fail on any other SW → `ScllError::ExternalAuthFail { sw }`.

11. **Channel open.** Returns `ScpSession::Scp03(Scp03Session)`.

**Wire-level flow — SCP02 path:**

1–2. **SELECT target** and resolve `sd_aid` if needed (identical to SCP03).

3. **Generate host challenge.** 8 bytes via `backend.random_bytes(8)`.

4. **INITIALIZE UPDATE.**
   ```
   CLA=80 INS=50 P1=kvn P2=key_id Lc=08 Data=host_challenge[8] Le=00
   ```
   P2 = key identifier for SCP02 (typically `0x00` for default keyset).

5. **Parse IU response** (28 bytes + SW):
   ```
   offset  field                            length
     0     key diversification data         10
    10     KVN                               1
    11     SCP identifier (must equal 0x02)  1
    12     sequence counter                  2
    14     card challenge                    6
    20     card cryptogram                   8
   ```
   Assert SCP id == `0x02`. Assert returned KVN matches caller's keys.

6. **Derive session keys** via `backend.scp02_derive_session(base_enc, base_mac, base_dek, seq_counter)`. Per GPCS v2.3.1 §E.4.1.

7. **Verify card cryptogram** via `backend.scp02_card_cryptogram(...)` + constant-time compare.

8. **Cap security level to `i` capability** (R-MAC bit only relevant for SCP02 `i ∈ {0x15, 0x55}`).

9. **Compute host cryptogram** via `backend.scp02_host_cryptogram(...)`.

10. **EXTERNAL AUTHENTICATE:**
    ```
    CLA=84 INS=82 P1=effective_sec_level P2=00 Lc=10
    Data = host_cryptogram[8] || C-MAC[8]
    ```
    C-MAC computed by `backend.scp02_wrap_command` per GPCS §E.4.2 (Retail MAC over EA C-APDU under session MAC key).

11. **If sec_level includes R-MAC: `BEGIN R-MAC SESSION` (INS `0x7A`).** Library issues this implicitly.

12. **Channel open.** Returns `ScpSession::Scp02(Scp02Session)`.

**Implementation gotchas:**
- `CLA | 0x04` is the secure-messaging marker for both SCP02 and SCP03 in single-channel mode.
- SCP02 sequence counter increments inside the card per session; library reads it from IU and feeds to KDF.
- SCP03 MAC chaining value persists across both C-MAC and R-MAC within one session.
- SCP02 has separate session DEK; SCP03 uses static DEK for PUT KEY.
- C-MAC input excludes `Le` byte. R-APDU has no `Le`.

---

### 5.10 Step 10 — applet APDU exchange

Public wrapper over `ScpSession::transmit()` from step 9.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `session` | yes | — | Open `ScpSession` from step 9 (against applet AID) |
| `plaintext_capdu` | yes | — | The application-level APDU |

**Wire flow:** Identical to step 9 transmit/receive. Backend wraps the C-APDU per session's SCP version. Applet on card receives wrapped APDU in `process()`, calls `secureChannel.unwrap()`, handles plaintext, calls `secureChannel.wrap()` on response.

**Returned:** Plaintext R-APDU + SW + `AppletTransmitReport`.

**Session lifetime:** Implicit close on any SELECT-of-another or card reset (which the library does not initiate during step 10). Explicit `session.close()` zeroises session keys (backend-internal) and rejects further calls.

**Contract on the applet:** Applet must be coded against `org.globalplatform.SecureChannel`. Library publishes this in README. Non-cooperating applets will return `6D00` or `6E00` to IU at step 9.

---

### 5.11 Step 11 — set_card_status

Manage the **card (ISD)** life-cycle state. Write-only. Covers the irreversible forward-provisioning chain and the reversible lock/unlock pair. `TERMINATED` is refused by contract (§2.2). Application / SSD life-cycle changes are out of scope (§2.2).

Card life-cycle state machine (GPCS v2.3.1 §5.1.1–§5.1.2; the ISD life-cycle *is* the card life-cycle):

```
OP_READY ──▶ INITIALIZED ──▶ SECURED ◀──▶ CARD_LOCKED        (──▶ TERMINATED, refused)
└───────────── irreversible ───────────┘   └── reversible ──┘
```

**Verified transition matrix** (against the §5.1.1.1–§5.1.1.5 prose and Figure 5-1, rasterized from page 54 of the GPCS v2.3.1 PDF):

| Transition | Allowed by spec? | Reversible? | Spec basis | Library handling |
|---|---|---|---|---|
| `OP_READY → INITIALIZED` | yes | no (irreversible) | §5.1.1.2 | forward provisioning |
| `INITIALIZED → SECURED` | yes | no (irreversible) | §5.1.1.3 | forward provisioning |
| `OP_READY → SECURED` (skip `INITIALIZED`) | yes | no | §5.1.2 ("skipping states") | only with `force` |
| `SECURED → CARD_LOCKED` (lock) | yes | yes (reversible) | §5.1.1.4 | `Locked` |
| `CARD_LOCKED → SECURED` (unlock) | yes | — | §5.1.1.4 | `Unlocked` |
| any state `→ TERMINATED` | yes | no (irreversible) | §5.1.1.5 | **refused** (library policy, §2.2) |
| any backward among `OP_READY/INITIALIZED/SECURED` | **no** | — | irreversibility (§5.1.1.2/.3) | refused |
| `→` current state | rejected by card | — | §11.10.2.2 | no-op, no APDU sent |

Two spec facts confirmed from the figure and prose:
- **Skip-ahead is spec-legal.** §5.1.2 states the chain "can typically be viewed as a sequential process with certain possibilities for … skipping states," so `OP_READY → SECURED` directly is permitted; the library still gates it behind `force` as a safety default.
- **Lock and Terminate may be initiated by a privileged Security Domain *or* a privileged Application** (§5.1.1.4 / §5.1.1.5; Figure 5-1 legend: solid = privileged Security Domain, dashed = privileged Application). The library only ever drives these over the ISD/SD path (the solid path); the Application path is not used.

The forward path `OP_READY → INITIALIZED → SECURED` is irreversible; `SECURED ↔ CARD_LOCKED` (lock / unlock) is the only reversible transition; any transition to `TERMINATED` is irreversible and is refused here.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `isd_session` | yes | — | Open SCP session against the **ISD** (from step 9, `target = ISD AID`), holding the authority needed for the requested transition |
| `target_state` ∈ {`Initialized`, `Secured`, `Locked`, `Unlocked`} | yes | — | `Unlocked` = `CARD_LOCKED → SECURED`. `Terminated` is intentionally **not** a variant (refused by contract) |
| `current_state` | optional | auto-read via §5.12 (`get_card_status`) | Used for the transition-legality check |
| `force` | optional | `false` | Permits skip-ahead to `SECURED` from any pre-`SECURED` state (mirrors GlobalPlatformPro `-f -secure-card`). Never bypasses the `TERMINATED` refusal or the backward-transition refusal |
| `isd_aid` | optional | from `isd_session` / `CardInfo` | Sent raw (untagged) in the data field; **ignored** by the card when P1=`0x80` (§11.10.2.3) |

**Returned:** `SetCardStatusReport` (see §7).

**Pre-flight:**

a) **Session targets the ISD.** Refuse if `isd_session.target_aid != isd_aid` → `ScllError::SessionNotIsd`.

b) **Resolve current state.** If `current_state` absent, read it via §5.12 (`get_card_status`) on the same session.

c) **Transition-legality check** against the state machine above:
   - Backward request (`SECURED → INITIALIZED`, `INITIALIZED → OP_READY`, `CARD_LOCKED → INITIALIZED`, …) → `ScllError::IllegalLifecycleTransition`.
   - Skip-ahead (`OP_READY → SECURED`) only when `force = true`; otherwise → `ScllError::IllegalLifecycleTransition` with a hint to set `INITIALIZED` first or pass `force`.
   - `Unlocked` valid only when `current_state == CARD_LOCKED`; else → `ScllError::IllegalLifecycleTransition`.
   - Target == current → **no-op**: return `Ok` with `WarningKind::LifecycleNoOp` and send no APDU (the card would reject a same-state transition per §11.10.2.2).
   - Any path to `TERMINATED` → `ScllError::TerminateOutOfScope` (per §2.2).

d) **Authority.** Forward provisioning requires issuer authority over the ISD; lock/unlock requires the **Card Lock** privilege (OPEN, a Security Domain with Card Lock, or an Application with Card Lock — §5.1.1.4). When the privilege is discoverable from `CardInfo`, check it; otherwise defer to the card (`6982`).

**SET STATUS command** (GPCS v2.3.1 **§11.10**, Tables 11-85 / 11-86 / 11-87 — *note: SET STATUS is §11.10; §11.9 is SELECT*):

```
CLA=84 INS=F0 P1=p1 P2=p2 Lc=<n> Data=<isd_aid>
```

`CLA = 0x84` (secure messaging; C-APDU wrapped by `isd_session`, consistent with DELETE/PUT KEY in this spec).

`P1` = Status Type = **`0x80`** for ISD / card scope. **Verified:** Table 11-86 codes the Issuer Security Domain as b8 b7 b6 = `1 0 0` (`0x80`); b8b7b6 = `010` is Application/SSD and `011` is "SD and its associated Applications". §11.10.2.2 confirms a Security Domain with Card Lock / Card Terminate privilege acts on the card with **P1 = `0x80`**.

`P2` = target life-cycle state byte. **Verified:** §11.10.2.2 states that for the ISD (which inherits the card life-cycle state) P2 is coded per **Table 11-6** (Card Life Cycle Coding) and must obey the Figure 5-1 transition rules:

| `target_state` | State | P2 (Table 11-6) |
|---|---|---|
| `Initialized` | `INITIALIZED` | `0x07` |
| `Secured` | `SECURED` | `0x0F` |
| `Locked` | `CARD_LOCKED` | `0x7F` |
| `Unlocked` | `SECURED` (return from `CARD_LOCKED`) | `0x0F` |

`Data` = the ISD AID as **raw, untagged bytes** (the `SET STATUS` data field carries the target identifier directly; it is **not** `'4F'`-tagged, unlike GET STATUS/DELETE). **Verified:** §11.10.2.3 — "If reference control parameter P1 is '80' the content of the command data field **shall be ignored**." So for our ISD scope the card ignores the data; the library sends the raw ISD AID for maximum cross-card compatibility (an empty data field is also spec-legal). Under SCP the C-MAC is appended by the session wrap (Table 11-85: "AID … and C-MAC if present").

`Le` absent.

**Card response:** `9000` on success. Status-word mapping to `ScllError` (§8):

| SW | Meaning | Library reaction |
|---|---|---|
| `9000` | Transition applied | `Ok` |
| `6985` | Conditions of use not satisfied (illegal transition / wrong current state) | `ScllError::IllegalLifecycleTransition` |
| `6982` | Security status not satisfied (privilege / channel) | `ScllError::SecurityStatusNotSatisfied` |
| `6A80` | Incorrect parameters in data field | `ScllError::Card { sw: 0x6A80 }` (the dedicated `BadSetStatusData` variant was never constructed and was removed) |
| `6A88` | Referenced data (AID) not found | `ScllError::IsdAidNotFound` |

*SW sources:* `6A80` / `6A88` are SET STATUS-specific (Table 11-87); `6982` (security status) / `6985` (conditions of use) are general error conditions (Table 11-10). A request to transition to the current state is rejected by the card (§11.10.2.2); the library detects this no-op first (`was_no_op`) and sends no APDU.

**Post-conditions:**

- **Entering `CARD_LOCKED`:** the card now restricts content management — subsequent CREATE / INSTALL / DELETE / PUT KEY against ISD-children will be refused card-side (cross-ref §5.8, which notes `CARD_LOCKED` blocks `DELETE` on ISD-child applets). Library marks the cached state as locked; open sessions persist but content operations will fail until unlocked.
- **`Unlocked` (`CARD_LOCKED → SECURED`):** content management restored.
- **Forward provisioning (`INITIALIZED`, `SECURED`):** recorded as irreversible in `SetCardStatusParams.irreversible = true`; cannot be undone.
- Invalidate any cached `CardInfo` life-cycle snapshot; the authoritative value is re-readable via §5.12.

---

### 5.12 Step 12 — get_card_status

Read the **card (ISD)** life-cycle state. Read-only, idempotent, modifies no card state. Promotes the `GET STATUS` already issued internally (§5.5, §5.9) to a first-class public function for the ISD scope.

> Unlike step 2 (`discover_card`), which reads pre-authentication `GET DATA`, `GET STATUS` is a privileged GlobalPlatform command and requires an open secure channel (typically at least C-MAC) on most cards. For a no-authentication life-cycle *hint*, rely on `discover_card`; the authoritative state comes from `GET STATUS` over an open session.

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `isd_session` | yes | — | Open SCP session against the ISD |
| `isd_aid` | optional | from `isd_session` / `CardInfo` | Search key in the `GET STATUS` data field |

**Returned:** `CardLifeCycle` (see §7) + `GetCardStatusReport`.

**Pre-flight:**

a) **Session liveness** (`Transport::is_connected()`).

b) **Session targets the ISD** (recommended; the channel must be open for `GET STATUS` to be accepted).

**GET STATUS command** (GPCS v2.3.1 §11.4, Tables 11-32 / 11-33 / 11-34 / 11-35 / 11-36):

```
CLA=80 INS=F2 P1=0x80 P2=0x02 Lc=02 Data=4F00 Le=00
```

`CLA = 0x80` base; wrapped to `0x84` by `isd_session`.

`P1 = 0x80` = Issuer Security Domain scope. **Verified:** Table 11-33 codes ISD as b8=1 (`0x80`); §11.4.2.1 — "the search criteria is ignored and the Issuer Security Domain information is returned" for P1 = `'80'`.

`P2 = 0x02` = get first/all occurrence(s) + modern TLV response. **Verified:** Table 11-34 — b1=0 (first/all), **b2=1** (response per Table 11-36); b2=0 is deprecated/out of scope. So `0x02` is the correct minimal value.

`Data = '4F' 00` = the mandatory AID search qualifier, zero-length = match-all. **Verified:** Table 11-35 — tag `'4F'` (Application AID) is Mandatory; §11.4.2.3 — "search for all the occurrences … using a search criteria of '4F' '00'." (Unlike SET STATUS, GET STATUS *does* TLV-tag the AID.)

**Response parsing:** one GlobalPlatform Registry entry under tag `'E3'`. **Verified** (Table 11-36): inside `'E3'`, the Life Cycle State is tag **`'9F70'`** (length 1), the AID is tag `'4F'`, and privileges are tag `'C5'` (3 bytes); §11.4.3.1 mandates that, absent a `'5C'` tag list, the ISD/Application `'E3'` contains `'4F'`, `'9F70'`, and `'C5'`. Extract the single `'9F70'` byte for the ISD entry. `63 10` "more data" (Table 11-38) is not expected for the single small ISD entry, but `get_card_status` runs the same byte-level accumulate-then-parse chaining as `get_card_inventory` (§5.12a) rather than assuming it — nothing in the spec actually guarantees a single-page response, and the mid-TLV split confirmed live on a JCOP 4 P71 (§5.12a) shows the assumption can't be relied on.

**Decode** the raw byte to `CardLifeCycle`:

| Raw `'9F70'` byte (Table 11-6) | `CardLifeCycle` |
|---|---|
| `0x01` | `OpReady` |
| `0x07` | `Initialized` |
| `0x0F` | `Secured` |
| `0x7F` | `CardLocked` |
| `0xFF` | `Terminated` |
| other | `Unknown(raw)` |

`Terminated` is reported if read from the card, even though §5.11 refuses to *set* it (§2.2). Unrecognised bytes map to `Unknown(raw)` and raise a `WarningKind::UnknownLifecycleByte` warning rather than an error.

**Failure modes:**

| Condition | Library reaction |
|---|---|
| `GET STATUS` returns `6982` | `ScllError::SecurityStatusNotSatisfied` (channel not open / insufficient level) |
| `GET STATUS` returns `6A88` | Not a hard error: `read_status_scope` (shared with §5.12a) treats `6A88` as an empty scope, falling through to the row below (`WarningKind::GetStatusParseFailed`; `CardLifeCycle::Unknown`) rather than a raw `ScllError::Card { sw: 0x6A88 }`. |
| `'E3'` template absent / unparseable | `WarningKind::GetStatusParseFailed` warning; `CardLifeCycle::Unknown` |

**Post-conditions:** none — read-only and safe to call repeatedly. Used by §5.11 pre-flight step (b) to resolve `current_state`.

---

### 5.12a Step 12a — get_card_inventory

Enumerate the card's full object inventory — Security Domains, Application instances, and Executable Load Files with their modules — into a `CardInventory` (§6). This is the `gp --list` equivalent. Read-only, idempotent, modifies no card state. Requires an open ISD session (same privilege requirement as §5.12).

**Inputs:**

| Input | Required? | Default | Notes |
|---|---|---|---|
| `isd_session` | yes | — | Open SCP session against the ISD |
| `isd_aid` | yes | — | Used to record the ISD once and as the default associated SD |

**Returned:** `GetCardInventoryReport` (§7), carrying a `CardInventory`.

**GET STATUS scopes.** Three passes over `GET STATUS` (INS `F2`), one per registry subset (GPCS v2.3.1 §11.4, Table 11-33). `CLA = 0x80` base, wrapped to `0x84` by the session; `Data = '4F' 00` (match-all, Table 11-35):

| Pass | P1 | Subset (Table 11-33) | Mapped to |
|---|---|---|---|
| 1 | `0x80` | Issuer Security Domain | `security_domains[0]` (no parent) |
| 2 | `0x40` | Applications **and** Supplementary Security Domains | `security_domains` (SSD) / `applets` (app) |
| 3 | `0x10` | Executable Load Files **and** their Executable Modules | `elfs` (+ `modules`) |

**Verified:** Table 11-33 codes the subsets as b8 (`0x80`) ISD, b7 (`0x40`) Applications + SDs, b5 (`0x20`) ELFs only, b4+b5 (`0x10`) ELFs + Modules; `0x10` supersets `0x20`, so it is used to obtain module AIDs in one pass.

**Pagination.** Each pass sends `P2 = 0x02` (first/all + TLV, Table 11-34) and, on a `63 10` "more data" warning (Table 11-38), re-issues the *same* P1 with `P2 = 0x03` (next occurrence + TLV) until `9000`. Bounded by `MAX_STATUS_PAGES` per scope. A `6A88` (referenced data not found) ends a pass cleanly as an **empty** subset, not an error (a card may legitimately have no SSDs).

**Byte-level chaining.** `63 10` splits the response at the **byte** level, not on `'E3'` entry boundaries: a single nested value (e.g. a `'84'` module AID) can straddle the page boundary. Confirmed against a live NXP JCOP 4 P71 (SCP02 i=0x55) capture, where a module AID's value was cut mid-way at exactly the page boundary and resumed on the next page — the same behavior `GlobalPlatformPro`'s `GPRegistry` already accounts for by buffering across pages before parsing. `read_status_scope` therefore accumulates the **raw** bytes of every page in a scope into one `MAX_STATUS_SCOPE_BYTES` buffer (§9) and parses it exactly once, after `9000`, rather than parsing each page independently — per-page parsing is unsound and produces `ScllError::MalformedResponse` ("TLV value runs past end of buffer") on real captures.

**Per-entry decode** (`'E3'`, Table 11-36 / 11-37; `parse_status_registry`, run once per scope on the fully-accumulated buffer): `'4F'` AID, `'9F70'` life cycle, `'C5'` privileges (1 or 3 bytes; padded to 3), `'CC'` associated Security Domain AID, `'C4'` the application's Executable Load File AID, and repeated `'84'` Executable Module AIDs.

**Classification & de-duplication.**

- The ISD is recorded **once**, from pass 1, with `associated_sd_aid = None`. Any echo of the ISD AID in pass 2 is dropped (de-duplicated by AID).
- In pass 2, an entry is a **Supplementary Security Domain** iff the Security Domain privilege bit is set — privileges byte 1, bit b8 (`0x80`), GPCS v2.3.1 Table 11-7 — otherwise it is an **Application**. This is the same discriminator `gp --list` uses.
- A missing `'CC'` defaults the associated SD to the ISD (for applications and ELFs). Individual entries whose `'4F'` fails AID validation are skipped.

**Truncation policy.** Capacity is bounded by `MAX_SDS` / `MAX_APPLETS` / `MAX_ELFS` (and `MAX_MODULES_PER_ELF`), plus the new `MAX_STATUS_SCOPE_BYTES` accumulation buffer per scope (§9). Exceeding any bound, `MAX_STATUS_PAGES`, or a final buffer that doesn't fit `tlv::parse`'s top-level cap returns a valid **prefix** plus `WarningKind::InventoryTruncated` — never an error. (`MAX_APPLETS = 48`, `MAX_ELFS = 32`, sized for a populated JCOP-class card; the reference `gp --list` dump has ~30 ELFs.)

**Failure modes:**

| Condition | Library reaction |
|---|---|
| `GET STATUS` returns `6982` | `ScllError::SecurityStatusNotSatisfied` (channel not open / insufficient level) |
| `GET STATUS` returns `6A88` for a scope | Empty subset for that scope (not an error) |
| `63 10` past `MAX_STATUS_PAGES`, or scope exceeds `MAX_STATUS_SCOPE_BYTES` | Stop; parse the last known-good byte prefix; `WarningKind::InventoryTruncated` |
| `CardInventory` capacity reached | Retain prefix; `WarningKind::InventoryTruncated` |
| Fully-accumulated scope structurally unparseable | `ScllError::MalformedResponse` (wrapped `TlvError`) |

**Post-conditions:** none — read-only, safe to call repeatedly; the result is a snapshot, stale after the next management operation.

---

## 6. CardInfo struct — public API

Returned by step 2 (`discover_card`). Read-only after construction.

```rust
// every owning Vec/String is a fixed-capacity heapless collection;
// capacities (UPPER_CASE) are defined in `scll-core::limits`.
struct CardInfo {
    // Basic identity
    isd_aid:                     Aid,                          // 5..16 bytes
    atr_or_ats:                  Vec<u8, ATR_ATS_MAX>,         // raw bytes from transport.reset()
    transport_protocol:          TransportProtocol,            // T0 | T1 | TCL

    // SCP capability — drives session-open logic
    scp_supported:               Vec<ScpVariant, MAX_SCP_VARIANTS>, // every (scp_id, i) advertised
    scp_default:                 ScpVariant,                   // first listed in CRD '64'

    // ISD key inventory — drives PUT KEY pre-flight
    isd_keysets:                 Vec<Keyset, MAX_KEYSETS>,     // grouped by KVN
    isd_key_template_format:     KeyTemplateFormat,            // Basic | Extended (B9-tagged)

    // Card capability — drives channel choice, cipher selection
    capabilities:                CardCapabilities,
    card_recognition_data_raw:   Vec<u8, GETDATA_RAW_MAX>,     // raw '66' for diagnostics

    // Optional identifying data
    iin:                         Option<Vec<u8, IIN_MAX>>,     // GET DATA '0042'
    cin:                         Option<Vec<u8, CIN_MAX>>,     // GET DATA '0045'
    card_image_number:           Option<Vec<u8, CIN_MAX>>,     // alias of cin if present
    jc_platform_version:         Option<(u8, u8, u8)>,         // major, minor, patch if parseable

    // Diagnostic
    quirks_detected:             Vec<String<OTHER_DETAIL_MAX>, MAX_QUIRKS>, // human-readable notes
    discovery_warnings:          Vec<DiscoveryWarning, MAX_WARNINGS>,       // typed; see below
}

struct CardInventory {
    security_domains:            Vec<SecurityDomainEntry, MAX_SDS>,
    applets:                     Vec<ApplicationEntry, MAX_APPLETS>,
    elfs:                        Vec<ExecutableLoadFileEntry, MAX_ELFS>,
}

enum ScpVariant {
    Scp02 { i_param: u8 },         // i = 0x55 typical modern default
    Scp03 { i_param: u8 },         // i = 0x70 typical modern default
}

struct Keyset {
    kvn:                u8,
    keys:               Vec<KeyInfo, MAX_KEYS_PER_SET>, // typically 3 entries (KID 1,2,3)
}

struct KeyInfo {
    kid:                u8,
    key_type:           KeyType,
    key_length:         u8,                      // byte length
}

enum KeyType {
    Des,                                          // 0x80, SCP02
    Aes,                                          // 0x88, SCP03
    RsaPublic,                                    // 0xA1
    RsaPrivateCrt,                                // 0xA2
    RsaPrivateExponent,                           // 0xA3
    EccPublic,                                    // 0xB0
    EccPrivate,                                   // 0xB1
    EccParametersRef,                             // 0xB2
    Other(u8),                                    // unknown / vendor-specific
}

enum KeyTemplateFormat {
    Basic,                                        // GPCS 2.2 single-byte fields
    Extended,                                     // GPCS 2.3+ B9-tagged sub-template
}

struct CardCapabilities {
    max_logical_channels:       u8,               // typically 1, 4, 8, or 16; default 1 if absent
    ciphers_supported:          Vec<CipherAlg, MAX_CIPHERS>,    // from '67' A1
    privileges_supported:       Vec<u8, MAX_PRIVILEGE_BYTES>,   // bitmap from '67' A3
    memory_total_bytes:         Option<u32>,      // rarely advertised
    memory_free_bytes:          Option<u32>,      // rarely advertised
    cci_raw:                    Vec<u8, GETDATA_RAW_MAX>,       // raw '67' for diagnostics
}

enum CipherAlg {
    Aes128, Aes192, Aes256,
    TripleDes,
    Rsa1024, Rsa2048, Rsa3072, Rsa4096,
    EccP256, EccP384, EccP521,
    Sha1, Sha256, Sha384, Sha512,
    Other(String<OTHER_DETAIL_MAX>),
}

enum TransportProtocol { T0, T1, TCL }

struct SecurityDomainEntry {
    aid:                Aid,
    life_cycle_state:   u8,                       // raw GP life-cycle byte
    privileges:         [u8; 3],
    associated_sd_aid:  Option<Aid>,              // present for SSDs; None for ISD
}

struct ApplicationEntry {
    aid:                Aid,
    life_cycle_state:   u8,
    privileges:         [u8; 3],
    associated_sd_aid:  Aid,                      // applets always have a parent SD
    associated_elf_aid: Option<Aid>,              // the app's ELF; present if card exposes tag 'C4'
}

struct ExecutableLoadFileEntry {
    aid:                Aid,
    life_cycle_state:   u8,
    associated_sd_aid:  Aid,
    modules:            Vec<Aid, MAX_MODULES_PER_ELF>, // class AIDs inside this ELF
}

/// typed (was a `{ code: String, detail: String }`). Discovery never
/// errors on missing optional data — it records one of these and proceeds.
/// (Former `D_*` taxonomy kept in comments.)
enum DiscoveryWarning {
    CardRecognitionDataMissing,        // was D_CardRecognitionDataMissing
    KeyInformationTemplateMissing,     // was D_KeyInformationTemplateMissing
    CardCapabilityInfoMissing,         // was D_CardCapabilityInfoMissing
    UnknownLifecycleByte(u8),          // was D_UnknownLifecycleByte
    GetStatusParseFailed,              // was D_GetStatusParseFailed
    Other(String<OTHER_DETAIL_MAX>),
}

// Aid is a validating newtype over a bounded heapless buffer.
struct Aid(Vec<u8, AID_MAX>);                     // 5..16 bytes, validated on construction
```

**Notes:**
- `Option<...>` everywhere card data is allowed to be absent. Discovery never errors on missing optional data — logs `DiscoveryWarning` and proceeds.
- `Aid` is a newtype wrapper enforcing 5–16 byte length in its constructor.
- `cci_raw` and `card_recognition_data_raw` retain original bytes so library upgrades can parse fields the current version doesn't understand without re-querying the card.
- The object inventory (Security Domains / Applications / ELFs) is **not** part of `CardInfo`. `discover_card` is pre-authentication and `GET STATUS` requires an open secure channel, so discovery never collects it. The inventory is obtained on demand via `get_card_inventory` (§5.12a), which returns a `CardInventory` in its report. (`CardInventory` and its `*Entry` types live in §6 because they are shared model types.)
- `extended_apdu_supported` field is intentionally absent; even when sub-tag `'A5'` is present in CCI, the library uses short APDUs exclusively (extended APDUs are out of scope, §2.2).

---

## 7. Per-function reports — public API

**Per-function reports.** The universal `OperationResult<T>` / `EffectiveParams` / `OperationKind` / `CommonParams` / `StepSpecific` envelope is **removed**. Each workflow function returns `Result<XReport, ScllError>` (§8). The report carries the typed payload, the *effective* parameters (defaults the library filled in, values the card returned), and any non-fatal warnings. Reasons:

- `Result<_, ScllError>` makes error handling compiler-enforced — there is no `payload: T` reachable when the call failed (an `OperationResult { result_code, payload }` allowed it).
- `OperationKind` duplicated the `StepSpecific` discriminant; two enums hand-synced forever is a drift bug. The function plus its return type already say which operation ran, so both enums are deleted.
- `CommonParams` stamped `library_version` / `spec_version` / `timestamp_utc` on every result, making outputs non-deterministic and harder to snapshot-test. Audit metadata belongs in a `tracing` span or a caller-supplied logging hook, exposed via the library version constant — not in every return value.

```rust
// Every workflow function returns one of these. Shape is uniform but the type
// is specific, so callers match on a concrete report, not a giant union.
// `warnings` and `rapdu` are bounded heapless collections.
pub struct PutKeysReport      { pub effective: PutKeysParams,      pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct DeleteKeyReport    { pub effective: DeleteKeyParams,    pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct CreateSsdReport    { pub effective: CreateSsdParams,    pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct LoadPackageReport  { pub effective: LoadPackageParams,  pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct DeleteObjectReport { pub effective: DeleteObjectParams, pub warnings: Vec<Warning, MAX_WARNINGS> } // delete_ssd / delete_applet
pub struct InstallAppletReport{ pub effective: InstallAppletParams,pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct AppletTransmitReport { pub rapdu: Vec<u8, RAPDU_MAX>, pub sw: u16, pub effective: AppletTransmitParams, pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct SetCardStatusReport{ pub effective: SetCardStatusParams,pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct GetCardStatusReport{ pub state: CardLifeCycle, pub effective: GetCardStatusParams, pub warnings: Vec<Warning, MAX_WARNINGS> }
pub struct GetCardInventoryReport{ pub inventory: CardInventory, pub effective: GetCardInventoryParams, pub warnings: Vec<Warning, MAX_WARNINGS> } // §5.12a
pub struct ProbeReport        { pub effective: ProbeParams,        pub warnings: Vec<Warning, MAX_WARNINGS> }

// open_scp additionally yields the session as its payload:
pub struct OpenScpReport      { pub session: ScpSession, pub effective: OpenScpParams, pub warnings: Vec<Warning, MAX_WARNINGS> }

// discover_card returns CardInfo directly (its report IS the CardInfo of §6):
//   fn discover_card(..) -> Result<CardInfo, ScllError>;

// Optional APDU trace is opt-in and lives on the report when enabled
// (keys and key-derived material are redacted):
//   report.trace: Option<Vec<ApduRecord, ...>>   // omitted above for brevity

// `Warning` is typed (see §8): { kind: WarningKind, detail: String<WARNING_DETAIL_MAX> }.

// The per-step *Params structs below are the `effective` payloads.
```

```rust
struct DiscoverCardParams {
    isd_select_strategy:    IsdSelectStrategy,    // Empty | ByAid
    used_cached_isd_aid:    bool,
}

enum IsdSelectStrategy { Empty, ByAid }

// PUT KEY is Add-only over a direct session (P1 = 0x00); the mode /
// mechanism selectors, GeneratedKeyset, and the rotation-inference flags were
// removed with the unverified Replace / Generate / parent-mediated paths.
struct PutKeysParams {
    target_sd_aid:          Aid,
    scp_protocol:           ScpProtocol,           // Scp02 | Scp03
    new_kvn:                u8,
    key_type:               KeyType,
    key_length:             u8,
    kcvs:                   [u8; 9],               // 3 bytes × 3 keys (ENC, MAC, DEK)
}

enum ScpProtocol { Scp02, Scp03 }

// DELETE KEY is KVN-only (single 'D2' reference; per-KID removed).
struct DeleteKeyParams {
    target_sd_aid:          Aid,                   // ISD or SSD
    kvn:                    u8,                    // tag 'D2'; every key of this version is deleted
}

struct CreateSsdParams {
    ssd_aid_effective:      Aid,                  // resolved if randomly generated
    aid_was_generated:      bool,
    parent_sd_aid:          Aid,
    privileges_used:        [u8; 3],
    elf_aid_used:           Aid,
    module_aid_used:        Aid,
    install_params_used:    Vec<u8, INSTALL_PARAMS_MAX>,
}

struct LoadPackageParams {
    package_aid:            Aid,
    load_file_size:         u32,
    hash_value:             Vec<u8, HASH_MAX>,
    block_count:            u16,
    target_sd_aid:          Aid,
}


struct DeleteObjectParams {
    target_aid:             Aid,
    target_kind:            DeleteTargetKind,
    cascade_requested:      DeleteCascade,
    cascade_used:           bool,
    instances_removed:      Vec<Aid, MAX_REMOVED_OBJECTS>, // populated for SSD-cascade and applet-with-ELF-cascade
    elfs_removed:           Vec<Aid, MAX_REMOVED_OBJECTS>,
}

enum DeleteTargetKind { Ssd, AppletInstance, ExecutableLoadFile }
enum DeleteCascade { Never, OnlyIfEmpty, IfLastInstance, Cascade, Always }

struct InstallAppletParams {
    instance_aid:           Aid,
    package_aid_used:       Aid,
    module_aid_used:        Aid,
    privileges_used:        [u8; 3],
    system_install_params:  Vec<u8, INSTALL_PARAMS_MAX>,
    applet_install_params:  Vec<u8, INSTALL_PARAMS_MAX>,
    parent_sd_aid:          Aid,
}

struct OpenScpParams {
    target_aid:             Aid,
    target_kind:            ScpTargetKind,
    sd_aid_used_for_keys:   Aid,                    // = target_aid if target_kind=Sd, else resolved
    scp_protocol_effective: ScpProtocol,            // Scp02 or Scp03 — outcome of §4.3 selection
    kvn_requested:          u8,                     // typically 0x00
    kvn_effective:          u8,                     // what the card returned in IU
    i_param_effective:      u8,
    security_level_requested: u8,
    security_level_effective: u8,
    session_id:             u64,
    invoker_aid_used:       Aid,                    // = target_aid (applet AID when cooperative)
}

enum ScpTargetKind { SecurityDomainAid, ApplicationAid }

struct AppletTransmitParams {
    session_id:             u64,
    capdu_plaintext_len:    u16,
    rapdu_plaintext_len:    u16,
    sw:                     [u8; 2],
    sec_level:              u8,
    scp_protocol:           ScpProtocol,
}

struct SetCardStatusParams {
    state_before:           CardLifeCycle,    // resolved during pre-flight
    target_state:           CardLifeCycle,    // requested transition target
    p1_status_type:         u8,               // ISD scope (conventionally 0x80)
    p2_state_byte:          u8,               // e.g. 0x0F SECURED, 0x7F CARD_LOCKED
    was_no_op:              bool,             // already in target; no APDU sent
    force_used:             bool,             // skip-ahead to SECURED was permitted
    irreversible:           bool,             // true for forward provisioning transitions
}

struct GetCardStatusParams {
    raw_state_byte:         u8,               // byte as returned by GET STATUS
    decoded_state:          CardLifeCycle,
    isd_aid:                Aid,
}

struct GetCardInventoryParams {                // §5.12a
    isd_aid:                Aid,
    security_domain_count:  usize,             // retained counts (post-truncation)
    application_count:      usize,
    elf_count:              usize,
    truncated:              bool,              // mirrors WarningKind::InventoryTruncated
}

enum CardLifeCycle {
    OpReady,                                  // 0x01
    Initialized,                              // 0x07
    Secured,                                  // 0x0F
    CardLocked,                               // 0x7F
    Terminated,                               // 0xFF (read-only; never a set target — §2.2)
    Unknown(u8),                              // unrecognised byte; raises WarningKind::UnknownLifecycleByte
}

struct ProbeParams {
    transport_name:         TransportName,          // was String
    transport_capabilities: TransportCaps,
}

// the known transports are a static set, so an enum is alloc-free and
// exhaustively matchable; `Other` keeps caller-supplied transports open.
enum TransportName { Pcsc, Jcsim, User, Other(String<TRANSPORT_NAME_MAX>) }

struct TransportCaps {
    handles_t0_get_response: bool,
    protocol:                TransportProtocol,
    contactless:             bool,
}

struct ApduRecord {
    direction:              ApduDirection,
    cla_ins_p1_p2:          [u8; 4],
    lc:                     u16,
    plaintext_data:         Option<Vec<u8, CAPDU_MAX>>, // pre-wrap if session active
    wire_data:              Vec<u8, CAPDU_MAX>,        // post-wrap actually transmitted
    le:                     Option<u8>,
    sw:                     Option<[u8; 2]>,
    timestamp_us:           u64,
}

enum ApduDirection { CommandToCard, ResponseFromCard }
```

**Notes:**
- Every parameter the caller could omit (taking a default) is echoed in the report's `effective`, so the caller can verify what was actually used.
- `scp_protocol` fields surface the §4.3 selection outcome, so the caller can detect when the card forced SCP02.
- Sensitive material is held in backend-opaque `KeyHandle`s. The optional `ExportableKeyBackend::export_key_dangerous` is the only path to plaintext (software backends only); the method is named to be searchable in audits. (the report-level `GeneratedKeyset` wrapper was removed with the `Generate` mode; the backend trait remains.)
- The optional `trace: Option<Vec<ApduRecord>>` is `None` in production; populated only when the caller opts into trace mode. Keys and key-derived material are **redacted** from the trace.
- `session_id` is library-side; not visible on the card.
- There is no `OperationKind`/`StepSpecific` union: the function called and its return type identify the operation statically.

---

## 8. ScllError enum — public API

**Committed error surface.** For a TDD-first library that is the wrong default — tests must assert on a value (`Err(ScllError::IllegalLifecycleTransition)`), not substring-match a string, and a stringly surface cannot be exhaustively matched or kept in sync with the status-word table. So `ScllError` is a real enum from day one. It can grow new variants later without losing the "typed" property.

**Naming.** Variant names are idiomatic Rust. The category prefixes (`T_` transport, `S_` secure channel, `K_` keys, `C_` content, `D_` discovery/warning, `L_` life-cycle, `P_` privilege, `I_` session, `V_` backend/vault) survive **only as doc comments** for traceability.

```rust
#[derive(thiserror::Error, Debug)]
pub enum ScllError {
    // --- Transport (was T_*) ---
    #[error("transport unavailable")]              TransportUnavailable,
    #[error("card removed")]                       CardRemoved,
    #[error("reader gone")]                        ReaderGone,
    #[error("transport timeout")]                  Timeout,

    // --- Secure channel (was S_*) ---
    #[error("no SCP protocol the library supports")] ScpProtocolUnsupported,
    #[error("no common security level")]           NoCommonSecurityLevel,
    #[error("KVN mismatch (card vs supplied keys)")] KvnMismatch,
    #[error("card cryptogram verification failed")] CardCryptogramFail,
    #[error("EXTERNAL AUTHENTICATE failed (sw={sw:#06x})")] ExternalAuthFail { sw: u16 },
    #[error("security status not satisfied")]      SecurityStatusNotSatisfied,

    // --- Keys (was K_*) ---
    #[error("referenced key not found")]           KeyNotFound,
    #[error("key type unsupported")]               KeyTypeUnsupported { offered: u8, supported: Vec<u8, MAX_KEYTYPE_SUPPORTED> },
    #[error("key check value mismatch")]           KeyCheckValueMismatch,
    #[error("cannot delete the active keyset")]    CannotDeleteActiveKeyset,

    // --- Content / CAP (was C_*) ---
    #[error("AID already exists")]                 AidAlreadyExists,
    #[error("package AID already exists")]          PackageAidExists,
    #[error("package not found")]                  PackageNotFound,
    #[error("resident SD module not found")]       ResidentSdNotFound,
    #[error("load file too large for short APDUs")] LoadTooLarge,
    #[error("SSD still has applets")]              SsdHasApplets,
    #[error("ELF has other instances")]            ElfHasOtherInstances,

    // --- Life-cycle (was L_*) ---
    #[error("card not usable (misconfigured or TERMINATED)")] CardNotUsable,
    #[error("illegal life-cycle transition")]      IllegalLifecycleTransition,
    #[error("conditions of use not satisfied")]    ConditionsNotSatisfied,
    #[error("ISD AID not found")]                  IsdAidNotFound,
    #[error("session is not against the ISD")]     SessionNotIsd,
    #[error("target no longer exists")]            TargetNoLongerExists,
    #[error("TERMINATED is out of scope as a set target")] TerminateOutOfScope,

    // --- Privilege (was P_*) ---
    #[error("parent lacks Authorized Management")] ParentLacksAm,
    #[error("unsupported privilege")]              UnsupportedPrivilege,

    // --- Card said no, with an SW the library does not map to a specific case ---
    #[error("card returned status word {sw:#06x}")] Card { sw: u16 },

    // --- Internal parse / build (wrapped sub-errors; `?` from those layers) ---
    #[error("malformed card response: {0}")]       MalformedResponse(#[from] TlvError),
    #[error("APDU build error: {0}")]              Build(#[from] BuildError),
    #[error("CAP parse error: {0}")]               Cap(#[from] CapError),

    // --- Backend / crypto / key-handle (was V_*) ---
    #[error(transparent)]                          Backend(#[from] BackendError),
}
```

(`#[derive(thiserror::Error, Debug)]` with `thiserror` v2 `default-features = false` — derives `core::error::Error`, Rust ≥1.81. `TlvError`/`BuildError`/`CapError` also derive `thiserror::Error` so they can be `#[from]` sources; their variants are `TlvError { Truncated, BadLength, TooMany, Overflow }`, `BuildError { Overflow }`, `CapError { NotAZip, MissingComponent(&'static str), Malformed, Inflate }`.)

**Non-fatal warnings** are likewise typed (no `String` codes):

```rust
pub struct Warning { pub kind: WarningKind, pub detail: String<WARNING_DETAIL_MAX> }

pub enum WarningKind {
    CardRecognitionDataMissing,        // was D_*
    KeyInformationTemplateMissing,
    CardCapabilityInfoMissing,
    UnknownLifecycleByte(u8),
    GetStatusParseFailed,
    LifecycleNoOp,                     // was L_LifecycleNoOp (no-op transition)
    InventoryTruncated,                // §5.12a: CardInventory capacity / page cap hit
}
```

**Backend error surface** (returned by every backend trait method, §3.3). Coarse by design; carries an opaque `detail` so software and HSM/PKCS#11 backends can attach implementation context without leaking key material:

```rust
#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("key import failed: {0}")]   KeyImport(String<OTHER_DETAIL_MAX>),     // was V_KeyImport
    #[error("key generation failed: {0}")] KeyGen(String<OTHER_DETAIL_MAX>),       // was V_KeyGen
    #[error("crypto operation failed: {0}")] Crypto(String<OTHER_DETAIL_MAX>),     // was V_Crypto
    #[error("RNG failure: {0}")]         Rng(String<OTHER_DETAIL_MAX>),            // was V_Rng
    #[error("operation unsupported by this backend: {0}")] Unsupported(String<OTHER_DETAIL_MAX>),
}
```

**Status-word coverage (test obligation, not deferred design).** Every SW1-SW2 the workflow can encounter maps to exactly one `ScllError` case, with `Card { sw }` as the explicit catch-all. This mapping is enforced by a table-driven unit test (§10), so an unmapped SW fails CI rather than surfacing as a surprise at runtime. The fixture is built from the GPCS v2.3.1 status-word tables: general conditions (Table 11-10), plus the per-command tables (e.g. SET STATUS Table 11-87, GET STATUS warning Table 11-38, DELETE Table 11-26). 

---

## 9. Default values

| Parameter | Default | Source |
|---|---|---|
| SCP version selection | SCP03 preferred; SCP02 only if card lacks SCP03 | Library policy (§4.3) |
| SCP03 supported `i` set | S8 `{0x00,0x10,0x20,0x30,0x60,0x70}` + S16 `{0x08,0x18,0x28,0x38,0x68,0x78}` | Amendment D §5.1 Table 5-1 (v1.1.2 S8 + v1.2 S16); excludes RFU bits and R-ENC-without-R-MAC |
| SCP03 default `i` | `0x70` (S8 pseudo-random challenge + R-MAC + R-ENC) | Amendment D Table 5-1 |
| SCP03 security level | `0x33` = C-MAC + C-DEC + R-MAC + R-ENC | Amendment D §6.2; GPCS Table 10-1 |
| SCP02 default `i` | `0x55` (explicit init, 3 keys, CBC, ICV MAC over AID, R-MAC) | UL GP Compliance Test Suites (May 2020) |
| SCP02 security level | `0x03` = C-MAC + C-DECRYPTION (R-MAC = `0x13`; no R-ENC in SCP02) | GPCS Table 10-1 + Appendix E |
| KVN in INITIALIZE UPDATE | `0x00` (card picks highest) | GPCS Appendix E (SCP02) / Amendment D §7.1.1 (SCP03) |
| SSD privileges | `0x80 0x00 0x00` (Security Domain only) | GPCS Table 6-1 (Privileges); bit values Table 11-7 (Byte 1) |
| Applet privileges | `0x00 0x00 0x00` | GPCS Table 6-1 (Privileges); bit values Tables 11-7/8/9 |
| SSD AID generation | RID from ISD + 11-byte CSPRNG PIX | ISO/IEC 7816-5 (RID/PIX); AID structure also ISO/IEC 7816-4:2020 §8 |
| Random key length when generating | AES-128 (SCP03) or 3DES double-length (SCP02) | Library policy |
| LOAD hash algorithm | SHA-256 | Library policy: SHA-256, per Amendment E SHA-1 deprecation (GPCS allows SHA-1/256/384/512) |
| LOAD block chunking | 240 bytes plaintext (short APDU; extended APDU out of scope) | Library policy: derived from Lc ≤ 255 minus SCP wrap; LOAD = GPCS §11.6.2 |
| LOAD max blocks | 256 (≈ 60 KB ELF) — hard limit | Short-APDU block-number ceiling `0xFF` |
| Authentication retries on wrong key | 0 (hard fail) | Library policy |
| `'C9'` install parameters | Always present, even if empty (`C9 00`) | Defence-in-depth |
| Crypto backend | `scll-backend-rustcrypto` (only shipped) | Library policy |
| Key material at public API | opaque `KeyHandle` (never raw bytes) | §3.3 / §3.4 (HSM-safe) |
| Backend trait shape | split: `KeyBackend` + `Scp03Backend` + `Scp02Backend` (+ optional `ExportableKeyBackend`) | §3.3 |
| Session security level | fixed at channel-open, stored in session (no per-call `level`) | §4.1 |
| Error / warning surface | typed `ScllError` / `WarningKind` (no `String` codes) | §8 |
| Per-call return | `Result<XReport, ScllError>` (no universal envelope) | §7 |
| User-supplied backends | Permitted via the public backend traits | §3.3 |
| Transport (production) | `scll-transport-pcsc` | Library policy |
| Transport (development) | `scll-transport-jcsim` | Library policy |
| `SET STATUS` P1 (card / ISD scope) | `0x80` | GPCS v2.3.1 §11.10.2.1 Table 11-86 (ISD = b8b7b6 `100`) — **verified** |
| `SET STATUS` P2 (card / ISD scope) | target byte per Table 11-6 (`INITIALIZED 0x07` / `SECURED 0x0F` / `CARD_LOCKED 0x7F`; unlock → `0x0F`) | GPCS v2.3.1 §11.10.2.2 — **verified** |
| `SET STATUS` data field (ISD scope) | raw ISD AID (untagged); **ignored** when P1=`0x80` (empty also legal) | GPCS v2.3.1 §11.10.2.3 — **verified** |
| Card life-cycle state bytes | `OP_READY 0x01`, `INITIALIZED 0x07`, `SECURED 0x0F`, `CARD_LOCKED 0x7F`, `TERMINATED 0xFF` | GPCS v2.3.1 **Table 11-6** (Card Life Cycle Coding) — **verified** |
| `TERMINATED` as `set_card_status` target | Refused | Library policy (out of scope §2.2) |
| `set_card_status` `force` (skip-ahead to SECURED) | `false` | Library policy (mirrors GlobalPlatformPro `-f -secure-card`) |
| `GET STATUS` for card state | P1 `0x80`, P2 `0x02`, Data `4F00` | GPCS v2.3.1 §11.4 Tables 11-33 / 11-34 / 11-35 — **verified** |
| Card life-cycle tag in `GET STATUS` response | `'9F70'` (len 1) inside `'E3'`; privileges `'C5'`, AID `'4F'` | GPCS v2.3.1 Table 11-36 / §11.4.3.1 — **verified** |
| `DELETE KEY` INS / P1 / P2 | `E4` / `0x00` / `0x00` | GPCS v2.3.1 §11.2.2 Tables 11-20 / 11-21 (P1 b8=0 last-only) / 11-22 (P2 b8=0 delete object) |
| `DELETE KEY` identification tags | `'D0'` = KID (1 byte), `'D2'` = KVN (1 byte), both Conditional | GPCS v2.3.1 Table 11-24 (DELETE [key] data field) |
| `DELETE KEY` multiple-key selection | Omit `'D0'` (all KIDs in KVN) or omit `'D2'` (all KVNs of KID); both present = single key | GPCS v2.3.1 §11.2.2.3.2 (Issuer-policy dependent) |
| `DELETE KEY` response data | single `'00'` byte | GPCS v2.3.1 §11.2.3.1 |
| `DELETE KEY` of active keyset | Refused (`ScllError::CannotDeleteActiveKeyset`) | Library policy (would brick the open channel) |
| `DELETE KEY` of last ISD keyset | Not guarded client-side; card SW authoritative — caller must not strand the ISD | Library policy note, §5.3.3 d) |
| Allocation model | `no_std`, alloc-free; fixed `heapless` capacities | §3.1; caps in `scll-core::limits` |
| Toolchain | MSRV 1.81 | `core::error::Error` for `no_std` `thiserror` v2 |
| Backend RNG | Injected `R: RngCore + CryptoRng` (no `getrandom`) | §3.3 / §3.4 |
| CAP compression | STORED + DEFLATE; DEFLATE via `miniz_oxide` no-alloc, 32 KiB streaming window | §2.2 / §5.4a |
| LFDB handling | Streamed in 240-byte chunks; never owned whole | §5.4a |

---

## 10. Test, coverage & fuzzing strategy

The library is built test-first. The architecture (§3.5) keeps every byte-level transform a pure function in `scll-core` with no transport and no crypto dependency, so the bulk of the logic is testable and fuzzable without a card or a backend. The design keeps this tractable: typed `ScllError` lets tests assert exact variants; `Result<XReport, ScllError>` removes "payload-on-error" cases; the `Scp03Backend`/`Scp02Backend` split lets the SCP03 suites run without SCP02 stubs; dropping the per-call timestamp/version makes report outputs deterministic for snapshot tests.

### 10.1 Test layering (where coverage comes from)

1. **Pure unit layer (`scll-core`, no I/O).** TLV / CRD `'66'` / CCI `'67'` / `'E3'` parsers; APDU builders; SCP02 + SCP03 wrap/unwrap framing; CAP-file parser; `Aid` validation (5–16 bytes); the card life-cycle transition state machine; the SW→`ScllError` mapping. Target **≈100% line + branch coverage** here — it is deterministic and hardware-free.
2. **Crypto known-answer layer (`scll-backend-rustcrypto`).** KATs for the primitives and the SCP flows (§10.2). Lives in the backend crate because that is where crypto lives.
3. **Replay / integration layer.** Recorded APDU traces replayed through a `MockTransport` (§10.3) to exercise full workflows (discover → open_scp → put_keys → install → delete) end-to-end without hardware.
4. **On-target smoke tests (manual / CI-optional).** Against the Oracle JC Simulator (`scll-transport-jcsim`) and, where available, a real card via PC/SC. These validate the resolved wire values (§5.11/§5.12) on real silicon (§10.5).

### 10.2 Known-answer tests (crypto)

There is no tidy official Amendment-D vector annex in the public release, so KATs are built two ways and cross-checked:
- **Primitive KATs from published vectors:** AES and CMAC from NIST CAVP; the counter-mode KDF from NIST SP 800-108r1 (the scheme Amendment D §4.1.5 builds on); ISO/IEC 9797-1:2011 Algorithm 3 (Retail MAC) for SCP02.
- **SCP-flow KATs derived from the spec** (session-key derivation, card/host cryptograms, command/response wrap), **cross-checked by generate-and-compare** against open reference implementations (GlobalPlatformPro, kaoh/globalplatform, simshell — which likewise separate their SCP02/SCP03 code paths, validating the trait split). Those references are LGPL/AGPL/etc. and stay **off the dependency graph**; running them out-of-process to emit comparison vectors is fine.

### 10.3 Replay tests

Repurpose the opt-in `ApduRecord` trace: capture real sessions against the JC simulator (or a card), store the C-APDU/R-APDU pairs as fixtures, and replay them through a `MockTransport` that returns the recorded R-APDU for each expected C-APDU. This gives deterministic full-workflow coverage in CI and catches accidental wire-format regressions. (Reports carry no per-call timestamp/version stamping, keeping replay output deterministic.)

### 10.4 Property tests (`proptest`)

- TLV: `parse ∘ encode == identity`; encoder never emits a buffer the parser rejects.
- `Aid`: constructor accepts exactly 5–16 bytes, rejects all else.
- Life-cycle state machine: only legal transitions accepted; forward provisioning is one-way; **`TERMINATED` is never accepted as a set target regardless of `force`**; lock/unlock is reversible.
- DELETE KEY: every `(kvn, kid)` presence/omission combination maps to the intended single-key vs multi-key selection (and the library never emits `0xFF`/`0x00` sentinels).
- SW mapping: every SW1-SW2 maps to exactly one `ScllError`, with `Card { sw }` as the only catch-all (table-driven, see §8).
- No-panic is enforced structurally: command builders return `Result<Capdu, BuildError>`, `tlv::parse`/`encode` return `TlvError` (`TooMany`/`Overflow`) and the CAP parser returns `CapError` on oversized/malformed input — no `unwrap` on a bounded `heapless` push.

### 10.5 Fuzzing (`cargo-fuzz` / libFuzzer + `arbitrary`)

Ranked by untrusted-input exposure (all targets assert: no panic, no UB, malformed input → typed `ScllError`, and — for the session paths — a torn-down/zeroised session on failure, matching SCP03's halt-on-decrypt-failure behaviour):
1. **CAP-file parser** — top priority; parses an attacker-influenceable ZIP. Highest memory-safety risk.
2. **Card-response parsers** — CRD `'66'`, CCI `'67'`, key-info template `'00E0'`, `GET STATUS 'E3'` (both the single-ISD `parse_status_e3` and the full multi-scope `parse_status_registry` of §5.12a) — consume bytes a malicious or buggy card controls.
3. **R-APDU unwrap** — `scp03_unwrap_response` / `scp02_unwrap_response` framing and length handling, run with the real RustCrypto backend.

Differential fuzzing against the out-of-process reference implementations (as in §10.2) is encouraged for the wrap/unwrap and KDF paths.

### 10.6 Tooling & gates

- Coverage measured with `cargo-llvm-cov`; CI gate on the pure layer (§10.1 item 1).
- `cargo-fuzz` targets run in CI (short budget) and in longer scheduled jobs; a seed corpus is checked in (valid CAPs, real CRD/CCI dumps, captured R-APDUs).
- `proptest` regressions (`.proptest-regressions`) committed so any shrunk counterexample is replayed.
- `cargo-deny` enforces the license policy (no LGPL/AGPL references on the dependency graph; deps stay MIT/Apache-2.0 dual, §11 References).
- MSRV 1.81 pinned in CI. `scll-core`/`scll-backend-rustcrypto` build `#![no_std]`; KATs run under `cfg(test)` (std) with the backend's `std` feature enabled so a host `critical-section` implementation is registered.

---

## 10.7 Known card / simulator limitations & verification status

Behaviour observed while running the reference examples end-to-end against
**NXP JCOP 4 P71 (J3R150)** and the **Oracle JDK/JCDK simulator (`jcsim`)**.
These are **empirical** notes about specific targets, not GlobalPlatform
requirements; where a GPCS clause explains the command it is cited, but the
status words below are what the cards actually return. Cross-checked against
GlobalPlatformPro v24.10.15 `10-install.sh` / `30-remove.sh` and archived
APDU transcripts. GPCS references are to the public v2.3.1 release PDF (§11).

| Area | Observation (target) | Handling in scll | GPCS anchor |
|---|---|---|---|
| DELETE SD cascade (C2) | `P2 = 0x80` on an SD → `6A86` (JCOP/sim). Empty first, delete with `P2 = 0x00` | Use `OnlyIfEmpty` (exercised by `ssd-lifecycle` teardown); `Cascade` unverified — see §5.5 | §11.2, Tbl 11‑22 |
| DELETE KEY scope (B4) | Per-KID (`'D0'`+`'D2'`) → `6A88` on JCOP for a PUT-KEY set; KVN-only (`'D2'`) → `9000` | KVN-only is the engine's only form — see §5.3.3 | §11.2, Tbl 11‑24 |
| PUT KEY rotation (C3) | On jcsim, only the **first** PUT KEY replaces the factory keyset (initial-key replacement semantics); **subsequent Adds coexist** (confirmed by full APDU traces: registry {0x32, 0x33} with IU P1=00 still resolving 0x32 while both existed, DELETE of 0x32 → 9000). On real hardware Adds always coexist | `Add` on a factory-fresh SD rotates the initial keyset; afterwards it adds normally — the ISD example restores the original keyset by value when needed | §11.8 |
| KVN 0xFF not P1-addressable (C1, real P71) | INITIALIZE UPDATE with P1=0xFF → `6A86`; the initial keyset's version (0xFF, reported in the KIT and echoed by IU) can only be selected with P1=0x00 — explicit P1 addresses versions 0x01–0x7F only. The same range limit applies to PUT KEY's NEW key version, so a 0xFF keyset can never be recreated at its own version | `open_isd_original` drops candidates > 0x7F and always tries P1=0x00; the lifecycles clamp their explicit selector to 0x00 when the confirmed version is above 0x7F; the ISD restore path falls back to KVN 0x30 (values preserved, version changes — loud print) | §11.8.2.3, Tbl 11-67 |
| jcsim default-KVN pointer (C3) | The sim stores a default key version for INITIALIZE UPDATE P1=00; it moves to the keyset that replaced the initial one and **dangles once that keyset is deleted** — IU P1=00 then answers `6A88` even though keysets exist and authenticate fine when addressed explicitly. The JCOP-mocking bridge answers the same `6A88` for IU P1=00 against a freshly created SSD (the inherited ISD keyset must be addressed at its explicit version). Factory KVN varies per target: 0x30 plain jcsim, 0x03 JCOP-mocking bridge, typically 0xFF real cards | Treat IU P1=00 as unreliable on jcsim after ANY key-registry mutation — the pointer/replacement rules are unstable across bridge versions and sessions. ALL example binaries open original-keys ISD channels via the shared `open_isd_original` (candidates: known KVN → `SCLL_ISD_KVN` → every non-demo KIT-reported version → 0x30 last), so no scll example can be stranded; external tools relying on P1=00 may need the KIT-listed KVN passed explicitly | (sim-specific) |
| Initial SSD keying (B3) | SSD authenticates with inherited parent keys → direct-session first keying works | Direct path validated; the parent-mediated Mechanism A + `GET DATA '00E0'` auto-detect are not provided (unverified) — see §5.6 | §11.5.2.4 |
| Standalone extradition (B2) | `INSTALL [for extradition]` of an applet to an SSD → `6985` on the Oracle sim; never exercised successfully on any target | `extradite` and the `INSTALL [for Extradition]` builder are not provided. The examples load/install directly into the SSD, which is the verified path | §11.5.2.2 |
| SSD secure channel (sim) | Sim's SSD channel mishandles C-DECRYPTION and does not apply R-MAC/R-ENC despite advertising `i='70'`; the ISD channel is otherwise compliant — incl. the ISD-backed APPLET channel at full `0x33` (EA at P1=`0x33`, responses R-MAC'd + R-ENC'd; verified by run logs) | Examples drop SSD-backed channels to C-MAC-only on `jcsim`, full `0x33` on real hardware (`security_level(endpoint, ChannelRole)` matrix); opt-in `SCLL_APPLET_LEVEL=33` exercises the compliant ISD-backed path | Amd D §4.1 |
| ISD R-MAC on GET STATUS (sim) | Sim returns a bare `6310` (`63xx` "more data") with **no R-MAC**, although §6.2.5 mandates R-MAC on `9000`/`62xx`/`63xx`; only genuine error SWs are returned bare. The sim's R-MAC gap is confined to the GET STATUS `63xx` page case | scll's response unwrap implements §6.2.5 (error SWs pass through bare; `9000`/`62xx`/`63xx` require R-MAC), so the bare `6310` is correctly rejected. The examples therefore run the **ISD** at C-MAC+C-DEC (`0x03`) on `jcsim` and full `0x33` on real hardware | Amd D §6.2.5 (SW facts x-checked: gppro #124) |
| Privilege encoding (JCOP) | JCOP 4 P71 requires the 1-byte privilege form in INSTALL; the 3-byte form is rejected | CPLC-based quirk detection selects the 1-byte encoding | 1-byte = GP 2.1.1 legacy vs 3-byte = GPCS 2.2+ §6.6.1 |

---

## 11. References

**Specifications:**
- [GlobalPlatform Card Specification v2.3.1 (May 2018 Public Release)](https://globalplatform.org/wp-content/uploads/2018/05/GPC_CardSpecification_v2.3.1_PublicRelease_CC.pdf)
- [Amendment D — SCP03 v1.1.2](https://globalplatform.org/wp-content/uploads/2014/07/GPC_2.3_D_SCP03_v1.1.2_PublicRelease.pdf)
- [Amendment E — Security Upgrade v1.0.1](https://globalplatform.org/wp-content/uploads/2018/06/GPC_2.2_E_SecurityUpgrade_v1.0.1.pdf)
- [GlobalPlatform Card API v1.6 (`org.globalplatform`)](https://globalplatform.org/specs-library/globalplatform-card-api-org-globalplatform-v1-6/)
- [Java Card Virtual Machine Specification v3.1](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/)
- [ISO/IEC 7816-4 (APDU and secure messaging)](https://www.iso.org/standard/77180.html)
- [ISO/IEC 7816-5 (AID registration)](https://www.iso.org/standard/34259.html)
- [ISO/IEC 7816-3 (T=0/T=1)](https://www.iso.org/standard/38770.html)
- [ISO/IEC 9797-1:2011 (Retail MAC for SCP02)](https://www.iso.org/standard/50375.html)
- [NIST SP 800-108r1 (KDF in Counter Mode, used for SCP03)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf) — referenced by Amendment D §4.1.5 (Data Derivation Scheme)
- [NIST CAVP (AES/CMAC validation vectors)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [PC/SC Workgroup Part 3 IFD Specification v3.0](https://pcscworkgroup.com/specifications/files/pcsc3_v3.0.0.pdf)

**Compliance:**
- [UL GlobalPlatform Compliance Test Suites (fact sheet, May 2020)](https://www.ul.com/sites/g/files/qbfpbp251/files/2021-08/Fact-sheet-UL-GlobalPlatform-Compliance-Test-Suites-Card_202005.pdf) — establishes the SCP02 `i = 0x55` and SCP03 `i ∈ {0x10, 0x30, 0x70}` compliance-tested set.

**Security analysis:**
- Avoine & Ferreira, ["Attacking GlobalPlatform SCP02-compliant Smart Cards Using a Padding Oracle Attack"](https://tches.iacr.org/index.php/TCHES/article/view/878), TCHES 2018 — motivates the SCP03-first selection rule.

**Rust crates depended on:**
- [`pcsc`](https://docs.rs/pcsc/) (MIT) — PC/SC transport (std host crate)
- [`heapless`](https://docs.rs/heapless/) (MIT/Apache-2.0) — fixed-capacity collections for the `no_std` core (v0.8; the `zeroize` feature only exists from heapless 0.9, which floats its MSRV, so the dangerous key-export path uses the in-crate drop-zeroizing `ExportedKey` instead)
- [`critical-section`](https://docs.rs/critical-section/) (MIT/Apache-2.0) — interior-mutability guard for the backend's key/session tables + RNG on `no_std`
- [`miniz_oxide`](https://docs.rs/miniz_oxide/) (MIT/Apache-2.0/Zlib) ≥ 0.8.4, `default-features = false` — alloc-free DEFLATE inflate for compressed CAP entries (§5.4a)
- [`aes`](https://docs.rs/aes/), [`cmac`](https://docs.rs/cmac/), [`des`](https://docs.rs/des/), [`cbc`](https://docs.rs/cbc/), [`ecb`](https://docs.rs/ecb/), [`sha2`](https://docs.rs/sha2/), [`retail-mac`](https://lib.rs/crates/retail-mac), [`zeroize`](https://docs.rs/zeroize/), [`rand_core`](https://docs.rs/rand_core/) — all MIT/Apache-2.0 dual, all RustCrypto-maintained, all `default-features = false` (the CSPRNG is injected by the caller; no `getrandom`)
- [`thiserror`](https://docs.rs/thiserror/) v2 (`default-features = false`) — typed error derive on `no_std`

**Test tooling:**
- [`proptest`](https://docs.rs/proptest) · [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) + [`arbitrary`](https://docs.rs/arbitrary) · [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) · [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)

**Reference implementations (study only, do not depend on for licensing reasons):**
- [GlobalPlatformPro (Java, LGPL)](https://github.com/martinpaljak/GlobalPlatformPro)
- [`globalplatform` (C, MIT)](https://github.com/kaoh/globalplatform)
- [`nexum-apdu-globalplatform` (Rust, AGPL — do not depend)](https://github.com/nxm-rs/apdu)
