//! `card-info` — read-only demo of the discovery/status APIs:
//!
//! 1. transport probe                      [no channel]
//! 2. discover                             [no channel]
//! 3. discover with expected ISD AID       [no channel]
//! 4. get card status                      [ISD]
//! 5. get card inventory                   [ISD]
//! 6. re-open with automatic SCP selection [ISD]
//!
//! Every report's non-fatal warnings are surfaced explicitly
//! (`report_warnings`), and the manager accessors (`is_channel_open`,
//! `session`) get a small demonstrative use after the first open.
//!
//! Requires only the common environment (transport selection + ISD keys); see
//! the crate docs in `src/lib.rs`. Nothing on the card is modified — the demo
//! is read-only and therefore inherently idempotent.

use std::process::ExitCode;

use scll::backend::KeyBackend;
use scll::error::ScllError;
use scll::report::{ScpTargetKind, TransportName};
use scll::transport::Transport;
use scll::workflow::OpenScpArgs;
use scll::CardManager;

use scll_examples::{
    banner, dump, key_kind_for, open_isd_original, pick_scp, report_warnings, run_demo,
    security_level, Be, ChannelRole, Config, Endpoint, Triple,
};

fn main() -> ExitCode {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return scll_examples::finish(Err(e)),
    };
    cfg.print("scll example: card-info (probe / discover / status / inventory)");
    let result = run_demo(&cfg.endpoint, &CardInfoDemo { cfg: &cfg });
    scll_examples::finish(result)
}

struct CardInfoDemo<'a> {
    cfg: &'a Config,
}

impl scll_examples::Demo for CardInfoDemo<'_> {
    fn run<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError> {
        let cfg = self.cfg;

        // 1 — transport probe.
        banner(1, "transport probe");
        let transport_name = match cfg.endpoint {
            Endpoint::Pcsc(_) => TransportName::Pcsc,
            Endpoint::Jcsim(_) => TransportName::Jcsim,
        };
        dump(&mgr.probe(transport_name)?);

        // 2 — discover (no channel). Decide which SCP to use for the channel.
        banner(2, "discover card");
        let info = mgr.discover(None)?;
        dump(&info);
        // Surface discovery warnings explicitly — missing OPTIONAL data is a
        // warning inside `CardInfo`, never an error (PDD §5.2).
        if info.discovery_warnings.is_empty() {
            println!("\n[discover: no warnings]");
        } else {
            println!("\n[discover: {} warning(s)]", info.discovery_warnings.len());
            for w in &info.discovery_warnings {
                println!("  - {w:?}");
            }
        }
        let isd_aid = info.isd_aid.as_bytes().to_vec();

        // 3 — discover again WITH the expected ISD AID: exercises the
        // `expected_isd_aid` pre-flight of §5.2. The AID passed is the one
        // discovery itself just returned, so the check must succeed — the
        // step stays read-only and idempotent (a mismatch would be an error).
        banner(3, "discover with expected ISD AID");
        let info2 = mgr.discover(Some(&isd_aid))?;
        println!("[expected-AID discovery confirmed ISD {:?}]", info2.isd_aid);
        // KIT-reported versions feed the resilient ISD open below: on jcsim,
        // INITIALIZE UPDATE with P1=0x00 can answer 6A88 after an
        // `isd-lifecycle` run (dangling default-KVN pointer, PDD §10.7), so
        // the original keys are also tried at the explicit reported versions.
        let reported_kvns: Vec<u8> = info.isd_keysets.iter().map(|k| k.kvn).collect();
        let scp = pick_scp(&info)?;
        println!("\n[selected SCP: {scp:?}]");

        // Import the ISD keys once; the read-only steps share one channel.
        let isd_kind = key_kind_for(scp, cfg.isd_enc.len());
        let b = mgr.backend();
        let isd = Triple {
            enc: b.import_key(isd_kind, &cfg.isd_enc)?,
            mac: b.import_key(isd_kind, &cfg.isd_mac)?,
            dek: b.import_key(isd_kind, &cfg.isd_dek)?,
        };

        let adv = info.scp_supported.as_slice();
        let isd_level = security_level(&cfg.endpoint, ChannelRole::Isd);
        let p = open_isd_original(
            mgr,
            "ISD",
            &isd_aid,
            isd,
            adv,
            scp,
            cfg.isd_kvn,
            &reported_kvns,
            None,
            isd_level,
        )?;
        println!("\n[ISD channel opened with key version 0x{:02X}]", p.kvn_effective);

        // Manager accessors — small demonstrative use (PDD §3.6): the
        // retained-channel flag and the session's negotiated protocol.
        assert!(mgr.is_channel_open());
        if let Some(s) = mgr.session() {
            println!("[retained session protocol: {:?}]", s.protocol());
        }

        // 4 — card status.
        banner(4, "get card status");
        let st = mgr.get_card_status(&isd_aid)?;
        dump(&st);
        report_warnings("get_card_status", &st.warnings);

        // 5 — inventory (every ELF / module / application / SD on the card).
        // `InventoryTruncated` here would mean the returned inventory is a
        // valid PREFIX of a card exceeding the capacity bounds (§5.12a).
        banner(5, "get card inventory");
        let inv = mgr.get_card_inventory(&isd_aid)?;
        dump(&inv);
        report_warnings("get_card_inventory", &inv.warnings);

        mgr.close_channel();

        // 6 — re-open the ISD channel letting the LIBRARY pick the SCP
        // variant (`force_scp: None`, the §4.3 selection rule) — every other
        // open in the examples forces the example's own `pick_scp` choice.
        // The key version is `p.kvn_requested`: the exact P1 the successful
        // resilient open sent moments ago, so it is known-addressable
        // (INITIALIZE UPDATE P1 addresses versions 0x01-0x7F only, GPCS
        // v2.3.1 §11.8.2.3 Table 11-67 — PDD §10.7 C1) and no registry
        // mutation happened in between.
        banner(6, "re-open with automatic SCP selection (force_scp: None)");
        let auto = mgr.open_scp(&OpenScpArgs {
            target_aid: &isd_aid,
            target_kind: ScpTargetKind::SecurityDomainAid,
            sd_keys: isd.keys(),
            advertised: adv,
            force_scp: None,
            kvn: p.kvn_requested,
            requested_level: isd_level,
        })?;
        dump(&auto);
        println!(
            "[library auto-selected {:?}; the example's pick_scp chose {:?}]",
            auto.scp_protocol_effective, scp
        );
        mgr.close_channel();
        Ok(())
    }
}
