//! `workflow-free` — the no_std-STYLE usage pattern: the workflow FREE
//! functions driven directly, with the [`ScpSession`] threaded explicitly
//! between calls, instead of going through [`CardManager`] (PDD §3.6; the
//! manager is a thin std convenience over exactly these calls). Read-only:
//! nothing on the card is created, modified, or deleted.
//!
//! 1. assemble a `CardManager`, probe, exercise the accessors
//!    (`transport()`, `transport_mut()`)                        [no channel]
//! 2. `into_parts()` — decompose into (transport, backend)      [no channel]
//! 3. `workflow::discover_card` (free)                          [no channel]
//! 4. `workflow::open_scp` (free) — the report carries the SESSION and the
//!    open-time WARNINGS as payload (the manager variant returns only the
//!    effective params and drops the warnings — PDD §10.8.1 audit note)
//! 5. `workflow::get_card_status` / `get_card_inventory` with the session
//!    passed as an explicit `&mut` between calls               [ISD]
//! 6. manual session close: hand the session ids back to the backend so the
//!    session-key slot is zeroized (what `close_channel` does internally)
//!
//! The channel open uses the same resilient key-version candidate order as
//! `open_isd_original` in the shared lib (configured `SCLL_ISD_KVN`, then
//! every KIT-reported version, then the P1 = 0x00 "first available"
//! selector), because INITIALIZE UPDATE P1 addresses versions 0x01-0x7F only
//! (GPCS v2.3.1 §11.8.2.3 Table 11-67) and jcsim's P1 = 0x00 default pointer
//! can dangle after key-registry mutation (PDD §10.7).

use std::process::ExitCode;

use rand_core::OsRng;
use scll::backend::{KeyBackend, Scp02Backend, Scp03Backend};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::error::ScllError;
use scll::report::{ScpTargetKind, TransportName};
use scll::scp::ScpSession;
use scll::transport::Transport;
use scll::transport_jcsim::JcSimTransport;
use scll::transport_pcsc::PcscTransport;
use scll::workflow::{self, OpenScpArgs};
use scll::CardManager;

use scll_examples::{
    banner, dump, key_kind_for, pick_scp, report_warnings, security_level, to_hex, Be,
    ChannelRole, Config, Endpoint, TracingTransport, Triple,
};

fn main() -> ExitCode {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return scll_examples::finish(Err(e)),
    };
    cfg.print("scll example: workflow-free (free functions, explicit session threading)");
    // The transport is constructed HERE (not via `run_demo`) because step 2
    // consumes the manager by value (`into_parts(self)`), which the shared
    // `Demo` runner's `&mut CardManager` interface cannot express.
    let result = match &cfg.endpoint {
        Endpoint::Pcsc(reader) => match PcscTransport::connect_selector(reader) {
            Ok(t) => run(TracingTransport::new(t), &cfg, TransportName::Pcsc)
                .map_err(|e| format!("{e}")),
            Err(e) => Err(format!("PC/SC connect failed for {reader:?}: {e:?}")),
        },
        Endpoint::Jcsim(addr) => match JcSimTransport::connect(addr) {
            Ok(t) => run(TracingTransport::new(t), &cfg, TransportName::Jcsim)
                .map_err(|e| format!("{e}")),
            Err(e) => Err(format!("jcsim connect failed for {addr}: {e:?}")),
        },
    };
    scll_examples::finish(result)
}

fn run<T: Transport>(transport: T, cfg: &Config, name: TransportName) -> Result<(), ScllError> {
    // 1 — the ownership-in side: assemble the manager, probe through it, and
    // exercise the remaining accessors (`is_channel_open`/`session()` are
    // demonstrated by `card-info`).
    banner(1, "CardManager assembly + accessors");
    let mut mgr = CardManager::new(transport, RustCryptoBackend::new(OsRng));
    dump(&mgr.probe(name)?);
    println!("[transport(): caps {:?}]", mgr.transport().capabilities());
    // `transport_mut()`: direct mutable access for operations the manager
    // does not wrap — here a manual card reset (discovery resets again, so
    // this is side-effect-free for the flow). Non-fatal by design.
    match mgr.transport_mut().reset() {
        Ok(atr) => println!("[transport_mut().reset(): ATR/ATS {}]", to_hex(&atr.bytes)),
        Err(e) => println!("[transport_mut().reset() not supported here: {e:?}]"),
    }

    // 2 — the ownership-out side.
    banner(2, "into_parts(): decompose into (transport, backend)");
    let (mut t, b): (T, Be) = mgr.into_parts();
    println!("[manager consumed; raw transport + backend recovered]");

    // 3 — free discovery.
    banner(3, "workflow::discover_card (free function)");
    let info = workflow::discover_card(&mut t, None)?;
    dump(&info);
    let isd_aid = info.isd_aid.as_bytes().to_vec();
    let scp = pick_scp(&info)?;
    println!("\n[selected SCP: {scp:?}]");

    // 4 — free channel open. Candidate order mirrors `open_isd_original`;
    // versions above 0x7F fall back to the 0x00 selector (Table 11-67).
    banner(4, "workflow::open_scp (free) — session + warnings as payload");
    let kind = key_kind_for(scp, cfg.isd_enc.len());
    let isd = Triple {
        enc: b.import_key(kind, &cfg.isd_enc)?,
        mac: b.import_key(kind, &cfg.isd_mac)?,
        dek: b.import_key(kind, &cfg.isd_dek)?,
    };
    let mut candidates: Vec<u8> = Vec::new();
    if cfg.isd_kvn != 0 {
        candidates.push(if cfg.isd_kvn <= 0x7F { cfg.isd_kvn } else { 0x00 });
    }
    for k in info.isd_keysets.iter().map(|s| s.kvn) {
        candidates.push(if k <= 0x7F { k } else { 0x00 });
    }
    candidates.push(0x00);
    candidates.dedup();
    let level = security_level(&cfg.endpoint, ChannelRole::Isd);
    let mut report = None;
    let mut last_err = ScllError::ScpProtocolUnsupported;
    for kvn in candidates {
        match workflow::open_scp(
            &mut t,
            &b,
            &OpenScpArgs {
                target_aid: &isd_aid,
                target_kind: ScpTargetKind::SecurityDomainAid,
                sd_keys: isd.keys(),
                advertised: info.scp_supported.as_slice(),
                force_scp: Some(scp),
                kvn,
                requested_level: level,
            },
        ) {
            Ok(r) => {
                report = Some(r);
                break;
            }
            Err(e) => {
                println!("[key version selector 0x{kvn:02X} did not open ({e})]");
                last_err = e;
            }
        }
    }
    let Some(report) = report else { return Err(last_err) };
    dump(&report.effective);
    // The free function KEEPS the open-time warnings; `CardManager::open_scp`
    // returns only `OpenScpParams` (§10.8.1 audit observation).
    report_warnings("open_scp", &report.warnings);
    let mut session = report.session;
    println!(
        "[session payload: kvn 0x{:02X}, i 0x{:02X}, effective level 0x{:02X}]",
        session.kvn(),
        session.i_param(),
        session.security_level()
    );

    // 5 — the session is threaded explicitly (`&mut`) through each call —
    // the sequence-counter / R-MAC chaining state lives inside it.
    banner(5, "workflow::get_card_status / get_card_inventory (explicit &mut session)");
    let st = workflow::get_card_status(&mut t, &b, &mut session, &isd_aid)?;
    dump(&st);
    report_warnings("get_card_status", &st.warnings);
    let inv = workflow::get_card_inventory(&mut t, &b, &mut session, &isd_aid)?;
    println!(
        "[inventory: {} security domain(s), {} application(s), {} ELF(s), truncated: {}]",
        inv.effective.security_domain_count,
        inv.effective.application_count,
        inv.effective.elf_count,
        inv.effective.truncated
    );
    report_warnings("get_card_inventory", &inv.warnings);

    // 6 — session hygiene: return the session ids to the backend so the
    // session-key slot is zeroized (exactly what `close_channel` does).
    banner(6, "manual session close (backend zeroizes the session-key slot)");
    match session {
        ScpSession::Scp03(s) => b.scp03_close_session(s.session()),
        ScpSession::Scp02(s) => b.scp02_close_session(s.session()),
    }
    println!("[session slot released]");
    Ok(())
}
