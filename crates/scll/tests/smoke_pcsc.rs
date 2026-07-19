//! End-to-end on-card smoke over PC/SC (PDD §10.1 layer 4) — the
//! real-card analogue of `smoke_jcsim.rs`. Same production path
//! (`CardManager` over the [`RustCryptoBackend`]), but the [`PcscTransport`]
//! drives a physical reader/card instead of the TCP simulator bridge.
//!
//! Two gated tests, mirroring the jcsim end-to-end flow but split by what they
//! require of a *real* card:
//!
//! * [`pcsc_select_isd`] — needs only a reader with a card present. Runs
//!   `probe → discover` and asserts the ISD answers SELECT and advertises an
//!   SCP variant. **No keys**, so it is safe against any `GlobalPlatform` card.
//! * [`pcsc_open_channel_and_read_status`] — additionally opens a secure
//!   channel (INITIALIZE UPDATE + EXTERNAL AUTHENTICATE) and runs one in-session
//!   `GET STATUS`. This fires EXTERNAL AUTHENTICATE, which on a wrong key
//!   **increments the security domain's retry counter** (GPCS v2.3.1 §11) and
//!   can lock the domain, so it runs **only** when an operator supplies the key.
//!
//! ## Gating (mirrors the jcsim `SCLL_JCSIM_ADDR` pattern, not `#[ignore]`)
//! * `SCLL_PCSC` selects the reader: a reader-name substring with an optional
//!   trailing `@<index>` to disambiguate multiple matches (PC/SC encodes the
//!   slot in the reader name — there is no separate slot argument). Both tests
//!   skip when it is unset; both also skip (rather than fail) when the selector
//!   resolves no reader/card, so the suite stays green on hosts without one.
//! * The three keys `SCLL_PCSC_KEY_ENC`, `SCLL_PCSC_KEY_MAC` and
//!   `SCLL_PCSC_KEY_DEK` (each 32/48/64 hex chars → a 16/24/32-byte key, all the
//!   same length) gate the second test only; all three must be set and
//!   non-empty, otherwise that test is **not run** and says so. There is no
//!   `SCLL_PCSC_KEY` base variable and no default key — a real card is always
//!   driven with operator-supplied per-role keys.
//!
//! ```text
//! SCLL_PCSC='Identiv' \
//!     SCLL_PCSC_KEY_ENC=404142434445464748494A4B4C4D4E4F \
//!     SCLL_PCSC_KEY_MAC=404142434445464748494A4B4C4D4E4F \
//!     SCLL_PCSC_KEY_DEK=404142434445464748494A4B4C4D4E4F \
//!     cargo test-pcsc -- --nocapture
//! ```
//!
//! (`cargo test-pcsc` is defined in `.cargo/config.toml`; it enables the
//! `pcsc`/`std` features this file needs.) The whole file compiles to nothing
//! unless both `pcsc` and `std` are on, so a plain `cargo test --workspace` is
//! unaffected.
#![cfg(all(feature = "pcsc", feature = "std"))]

use scll::backend::{KeyBackend, KeyKind};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::model::ScpVariant;
use scll::report::TransportName;
use scll::transport_pcsc::PcscTransport;
use scll::workflow::{OpenScpArgs, SdKeys};
use scll::{report::ScpTargetKind, CardManager};
use scll_test_util::{skip_unless_pcsc, skip_unless_pcsc_key};
use std::sync::{Mutex, PoisonError};

/// Serializes the hardware tests in this binary. They share one physical reader
/// and card, but `cargo test` runs tests in parallel by default — a second
/// concurrent `ShareMode::Shared` connection (and the `ResetCard` disconnect that
/// `pcsc::Card`'s drop performs when the other test's transport falls out of
/// scope) would reset the card mid-exchange, surfacing as `TransportUnavailable`.
/// Each hardware test holds this guard for its whole body, so one test's
/// connect → use → disconnect completes before the next test connects.
static CARD_LOCK: Mutex<()> = Mutex::new(());

/// Deterministic test RNG. The host challenge only needs to vary per session
/// for the card to accept it; this is reproducible and NOT secure — a real
/// caller injects an OS/board CSPRNG. (Identical to the jcsim smoke RNG.)
struct SmokeRng(u64);
impl rand_core::RngCore for SmokeRng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        u32::try_from(self.0 >> 32).unwrap_or(u32::MAX)
    }
    fn next_u64(&mut self) -> u64 {
        (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let b = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for SmokeRng {}

/// Wall-clock RNG seed so repeated runs use a fresh host challenge.
fn smoke_seed() -> u64 {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    seed | 1
}

/// Map the negotiated SCP and the supplied key length to a `KeyKind`. SCP03
/// (GP Amendment D v1.1.2) accepts AES-128/192/256, so the 16/24/32-byte key
/// length selects the AES size; SCP02 is double-length (two-key) 3DES, which is
/// 16 bytes only. A length the SCP can't use is an operator misconfiguration and
/// panics.
fn key_kind_for(scp: ScpVariant, key_len: usize) -> KeyKind {
    match scp {
        ScpVariant::Scp03 { .. } => match key_len {
            16 => KeyKind::Aes128,
            24 => KeyKind::Aes192,
            32 => KeyKind::Aes256,
            other => panic!("SCP03 key must be 16/24/32 bytes, got {other}"),
        },
        ScpVariant::Scp02 { .. } => {
            assert!(
                key_len == 16,
                "SCP02 requires a 16-byte (32-hex) double-length 3DES key, got {key_len}"
            );
            KeyKind::TripleDesDouble
        }
    }
}

#[test]
fn pcsc_select_isd() {
    // Integration: auto-runs when SCLL_PCSC names a reader with a card present,
    // otherwise skips (no `#[ignore]`). No keys are used — safe on any card.
    let spec = skip_unless_pcsc!();
    // Serialize against the other hardware test (shared physical card).
    let _card = CARD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let transport = match PcscTransport::connect_selector(&spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "SKIP {}: SCLL_PCSC has no reader/card ({e:?})",
                module_path!()
            );
            return;
        }
    };
    let backend = RustCryptoBackend::new(SmokeRng(smoke_seed()));
    let mut mgr = CardManager::new(transport, backend);

    // Step 1 — transport must be live. Under PC/SC the reader driver performs
    // the T=0 GET RESPONSE chaining (the jcsim bridge does not), so this is the
    // opposite of the jcsim assertion.
    let probe = mgr.probe(TransportName::Pcsc).expect("probe");
    assert!(
        probe
            .effective
            .transport_capabilities
            .handles_t0_get_response
    );

    // Step 2 — discover: the ISD must answer SELECT and advertise SCP.
    let info = mgr.discover(None).expect("discover");
    assert!(!info.isd_aid.as_bytes().is_empty(), "no ISD AID resolved");
    assert!(
        !info.scp_supported.is_empty(),
        "card advertised no SCP variant"
    );
    println!("pcsc ISD AID + advertised SCP discovered (no secure channel opened)");
}

#[test]
fn pcsc_open_channel_and_read_status() {
    // Reader gate first, then the key gate: unless all three
    // SCLL_PCSC_KEY_ENC/_MAC/_DEK are set this test is NOT run (a failed EXTERNAL
    // AUTHENTICATE would burn a retry on the real SD), so the keys never default
    // silently.
    let spec = skip_unless_pcsc!();
    let (keys, key_len) = skip_unless_pcsc_key!();
    // Serialize against the other hardware test (shared physical card).
    let _card = CARD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let transport = match PcscTransport::connect_selector(&spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "SKIP {}: SCLL_PCSC has no reader/card ({e:?})",
                module_path!()
            );
            return;
        }
    };
    let backend = RustCryptoBackend::new(SmokeRng(smoke_seed()));
    let mut mgr = CardManager::new(transport, backend);

    let info = mgr.discover(None).expect("discover");
    assert!(
        !info.scp_supported.is_empty(),
        "card advertised no SCP variant"
    );

    // Pick the channel the card actually offers: SCP03 (AES) when present,
    // else the card's SCP02 (double-length 3DES) — a card may advertise only
    // SCP02. `force_scp` pins that exact advertised variant (keeping its
    // `i_param`), so the key type imported here and the channel open_scp opens
    // cannot diverge. Each SCLL_PCSC_KEY_ENC/_MAC/_DEK is the AES-128/192/256
    // key (SCP03) or 16-byte 3DES key (SCP02) for its role; the length selects
    // the AES size.
    let scp = info
        .scp_supported
        .iter()
        .copied()
        .find(|v| matches!(v, ScpVariant::Scp03 { .. }))
        .or_else(|| info.scp_supported.first().copied())
        .expect("scp_supported is non-empty");
    // Import ENC/MAC/DEK independently — each from its own
    // SCLL_PCSC_KEY_ENC/_MAC/_DEK, so they may be distinct values.
    let kind = key_kind_for(scp, key_len);
    let backend = mgr.backend();
    let enc = backend
        .import_key(kind, &keys[0][..key_len])
        .expect("import ENC key");
    let mac = backend
        .import_key(kind, &keys[1][..key_len])
        .expect("import MAC key");
    let dek = backend
        .import_key(kind, &keys[2][..key_len])
        .expect("import DEK key");

    // Open at C-MAC + C-DECRYPTION (0x03) — the level both SCP02 and SCP03
    // support. (SCP03 can additionally request R-MAC/R-ENC at 0x10/0x20.)
    let args = OpenScpArgs {
        target_aid: info.isd_aid.as_bytes(),
        target_kind: ScpTargetKind::SecurityDomainAid,
        sd_keys: SdKeys { enc, mac, dek },
        advertised: info.scp_supported.as_slice(),
        force_scp: Some(scp),
        kvn: 0x00,
        requested_level: 0x03,
    };
    let effective = mgr.open_scp(&args).expect("open_scp");
    assert!(mgr.is_channel_open(), "channel not retained after open_scp");
    assert_eq!(effective.security_level_effective, 0x03);

    // One in-session GET STATUS validates wrap/unwrap on the wire.
    let status = mgr
        .get_card_status(info.isd_aid.as_bytes())
        .expect("get_card_status");
    println!("pcsc ISD life-cycle: {:?}", status.state);

    mgr.close_channel();
    assert!(!mgr.is_channel_open());
}

#[test]
fn key_kind_for_table() {
    // Pure mapping check — no reader/card needed, runs under `cargo test-pcsc`.
    use ScpVariant::{Scp02, Scp03};
    assert_eq!(key_kind_for(Scp03 { i_param: 0x70 }, 16), KeyKind::Aes128);
    assert_eq!(key_kind_for(Scp03 { i_param: 0x70 }, 24), KeyKind::Aes192);
    assert_eq!(key_kind_for(Scp03 { i_param: 0x70 }, 32), KeyKind::Aes256);
    assert_eq!(
        key_kind_for(Scp02 { i_param: 0x55 }, 16),
        KeyKind::TripleDesDouble
    );
}
