//! End-to-end on-target smoke (PDD §10.1 layer 4).
//!
//! Assembles a [`CardManager`] over the real [`RustCryptoBackend`] and the
//! TCP [`JcSimTransport`], drives `discover → open_scp → get_card_status` and
//! one in-session `GET STATUS`, and asserts the resolved §11 wire values are
//! accepted by a live card. This validates the production code path against
//! silicon/simulator — the byte-level pieces are already covered by the S1–S6
//! unit/KAT/replay layers.
//!
//! This test is **gated on `SCLL_JCSIM_ADDR`** (not `#[ignore]`): it auto-runs
//! when the variable points at a reachable `javacard-simulator-apdu-bridge` in
//! front of the Oracle Java Card simulator (the jcsim adapter speaks the
//! bridge's 4-byte-length framing, NOT the simulator directly), and skips
//! otherwise so the normal suite stays green. Opening the secure channel
//! additionally requires the keyset: all three of `SCLL_JCSIM_KEY_ENC`,
//! `SCLL_JCSIM_KEY_MAC` and `SCLL_JCSIM_KEY_DEK` must be set and non-empty
//! (32/48/64 hex each, same length — there is no default key); when they are not
//! all set this test is **not run**. For the simulator's GP default keys, pass
//! `404142434445464748494A4B4C4D4E4F` for each role. Run it together with the
//! transport-level `connect_selects_isd` via the workspace alias:
//!
//! ```text
//! SCLL_JCSIM_ADDR=127.0.0.1:10000 \
//!     SCLL_JCSIM_KEY_ENC=404142434445464748494A4B4C4D4E4F \
//!     SCLL_JCSIM_KEY_MAC=404142434445464748494A4B4C4D4E4F \
//!     SCLL_JCSIM_KEY_DEK=404142434445464748494A4B4C4D4E4F \
//!     cargo test-jcsim -- --nocapture
//! ```
//!
//! (`cargo test-jcsim` is defined in `.cargo/config.toml`; it enables the
//! `jcsim`/`std` features this file needs and selects both integration tests.)
//!
//! The whole file compiles to nothing unless both `jcsim` and `std` are on, so
//! a plain `cargo test --workspace` is unaffected.
#![cfg(all(feature = "jcsim", feature = "std"))]

use scll::backend::{KeyBackend, KeyKind};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::model::ScpVariant;
use scll::report::TransportName;
use scll::transport_jcsim::JcSimTransport;
use scll::workflow::{OpenScpArgs, SdKeys};
use scll::{report::ScpTargetKind, CardManager};
use scll_test_util::{skip_unless_jcsim, skip_unless_jcsim_key};

/// Deterministic test RNG. The host challenge only needs to vary per session
/// for the simulator to accept it; this is reproducible and NOT secure — a real
/// caller injects an OS/board CSPRNG.
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

/// Map the negotiated SCP and the supplied key length to a `KeyKind`. SCP03
/// (GP Amendment D v1.1.2) accepts AES-128/192/256, so the 16/24/32-byte key
/// length selects the AES size; SCP02 is double-length (two-key) 3DES, 16 bytes
/// only. A length the SCP can't use is a misconfiguration and panics. (Kept in
/// sync with the copy in `smoke_pcsc.rs`.)
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
fn jcsim_open_channel_and_read_status() {
    // Integration: auto-runs when SCLL_JCSIM_ADDR points at a running
    // javacard-simulator-apdu-bridge, otherwise skips (no `#[ignore]`).
    let addr = skip_unless_jcsim!();
    // Key gate next: all three SCLL_JCSIM_KEY_ENC/_MAC/_DEK must be set, else the
    // test is NOT run. Checked before connecting so an unconfigured host skips
    // without touching the bridge. The key length picks the imported key type
    // once the SCP variant is known below.
    let (keys, key_len) = skip_unless_jcsim_key!();
    let transport = JcSimTransport::connect(&addr)
        .unwrap_or_else(|e| panic!("connect to jcsim bridge at {addr} failed: {e:?}"));

    // Seed the host-challenge RNG with the wall clock so repeated runs differ.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let backend = RustCryptoBackend::new(SmokeRng(seed | 1));

    let mut mgr = CardManager::new(transport, backend);

    // Step 1 — transport must be live.
    let probe = mgr.probe(TransportName::Jcsim).expect("probe");
    assert!(
        !probe
            .effective
            .transport_capabilities
            .handles_t0_get_response
    );

    // Step 2 — discover: the simulator's ISD must answer SELECT and advertise SCP.
    let info = mgr.discover(None).expect("discover");
    assert!(!info.isd_aid.as_bytes().is_empty(), "no ISD AID resolved");
    assert!(
        !info.scp_supported.is_empty(),
        "card advertised no SCP variant"
    );

    // Pick the channel the card actually offers: SCP03 (AES) when present, else
    // its SCP02 (double-length 3DES). `force_scp` pins that exact advertised
    // variant (keeping its `i_param`) so the imported key type and the opened
    // channel cannot diverge. The key length (from SCLL_JCSIM_KEY_* above)
    // selects the AES size: 16 ⇒ AES-128 / SCP03 or 3DES / SCP02, 24/32 ⇒
    // AES-192/256 / SCP03.
    let scp = info
        .scp_supported
        .iter()
        .copied()
        .find(|v| matches!(v, ScpVariant::Scp03 { .. }))
        .or_else(|| info.scp_supported.first().copied())
        .expect("scp_supported is non-empty");
    // ENC/MAC/DEK were resolved from SCLL_JCSIM_KEY_ENC/_MAC/_DEK at the gate
    // above and are imported as three independent handles, so they may be
    // distinct values.
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

    // Step 9 — open at C-MAC + C-DECRYPTION (0x03), the level both SCP02 and
    // SCP03 support. (SCP03 can additionally request R-MAC/R-ENC at 0x10/0x20.)
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

    // Step 12 — one in-session GET STATUS validates wrap/unwrap on the wire.
    let status = mgr
        .get_card_status(info.isd_aid.as_bytes())
        .expect("get_card_status");
    println!("jcsim ISD life-cycle: {:?}", status.state);

    mgr.close_channel();
    assert!(!mgr.is_channel_open());
}
