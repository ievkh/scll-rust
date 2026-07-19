//! `card-status` — demo of the card life-cycle API (`set_card_status`, PDD
//! §5.11; GPCS v2.3.1 §5.1.1 Figure 5-1 + §11.10):
//!
//! 1. transport probe                        [no channel]
//! 2. discover                               [no channel]
//! 3. get card status                        [ISD]
//! 4. same-state write → `LifecycleNoOp`     [ISD, GET STATUS only]
//! 5. illegal transition (no force) refused  [host-side, no APDU]
//! 6. illegal transition WITH force refused  [host-side, no APDU]
//! 7. TERMINATED target refused              [host-side, no APDU]
//! 8. opt-in forward transition              [ISD, `SCLL_LIFECYCLE_ADVANCE=1`]
//!
//! Safety model: the library validates every transition host-side
//! (`check_transition`) BEFORE building a SET STATUS APDU, so steps 4–7 send
//! no state-changing command at all — step 4's `current_state: None` triggers
//! one internal GET STATUS read, and steps 5–7 are pure host-side refusals.
//! The default run is therefore read-only and inherently idempotent.
//!
//! Step 8 is the only real SET STATUS and is DOUBLY gated: it requires
//! `SCLL_LIFECYCLE_ADVANCE=1` AND the jcsim transport. `OP_READY →
//! INITIALIZED` is irreversible (GPCS v2.3.1 §5.1.1.2), which is harmless on
//! the simulator (a bridge restart resets the card) but permanent on real
//! hardware — on PC/SC the flag is acknowledged and refused loudly. Re-running
//! with the flag is idempotent: once the card is INITIALIZED the step reports
//! the no-op instead of advancing further (it never targets SECURED).

use std::process::ExitCode;

use scll::backend::KeyBackend;
use scll::error::ScllError;
use scll::report::{CardLifeCycle, TransportName};
use scll::transport::Transport;
use scll::workflow::SetCardStatusArgs;
use scll::CardManager;

use scll_examples::{
    banner, dump, env_opt, key_kind_for, open_isd_original, pick_scp, report_warnings, run_demo,
    security_level, Be, ChannelRole, Config, Endpoint, Triple,
};

fn main() -> ExitCode {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return scll_examples::finish(Err(e)),
    };
    cfg.print("scll example: card-status (life-cycle read / no-op / refusals / opt-in advance)");
    let advance = env_opt("SCLL_LIFECYCLE_ADVANCE").as_deref() == Some("1");
    let result = run_demo(&cfg.endpoint, &CardStatusDemo { cfg: &cfg, advance });
    scll_examples::finish(result)
}

struct CardStatusDemo<'a> {
    cfg: &'a Config,
    advance: bool,
}

/// A target that `check_transition` refuses from `current` WITHOUT `force`.
/// For `OpReady` this is the skip-ahead to `SECURED` (spec-legal only with
/// `force`, GPCS v2.3.1 §5.1.2); for every other state, `OpReady` (backward,
/// §5.1.1 — forward provisioning is one-way).
fn illegal_without_force(current: CardLifeCycle) -> CardLifeCycle {
    match current {
        CardLifeCycle::OpReady => CardLifeCycle::Secured,
        _ => CardLifeCycle::OpReady,
    }
}

/// A target that stays refused EVEN WITH `force = true` — `force` only
/// unlocks the `OP_READY → SECURED` skip-ahead, never a backward or
/// otherwise-illegal move. From `OpReady` that is `CARD_LOCKED` (locking
/// requires `SECURED` first, §5.1.1.4); from every other state, `OpReady`.
fn illegal_even_with_force(current: CardLifeCycle) -> CardLifeCycle {
    match current {
        CardLifeCycle::OpReady => CardLifeCycle::CardLocked,
        _ => CardLifeCycle::OpReady,
    }
}

impl scll_examples::Demo for CardStatusDemo<'_> {
    fn run<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError> {
        let cfg = self.cfg;

        // 1 — transport probe.
        banner(1, "transport probe");
        let transport_name = match cfg.endpoint {
            Endpoint::Pcsc(_) => TransportName::Pcsc,
            Endpoint::Jcsim(_) => TransportName::Jcsim,
        };
        dump(&mgr.probe(transport_name)?);

        // 2 — discover; open the ISD management channel.
        banner(2, "discover card");
        let info = mgr.discover(None)?;
        dump(&info);
        let isd_aid = info.isd_aid.as_bytes().to_vec();
        let reported_kvns: Vec<u8> = info.isd_keysets.iter().map(|k| k.kvn).collect();
        let scp = pick_scp(&info)?;
        println!("\n[selected SCP: {scp:?}]");

        let isd_kind = key_kind_for(scp, cfg.isd_enc.len());
        let b = mgr.backend();
        let isd = Triple {
            enc: b.import_key(isd_kind, &cfg.isd_enc)?,
            mac: b.import_key(isd_kind, &cfg.isd_mac)?,
            dek: b.import_key(isd_kind, &cfg.isd_dek)?,
        };
        let adv = info.scp_supported.as_slice();
        let isd_level = security_level(&cfg.endpoint, ChannelRole::Isd);
        open_isd_original(
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

        // 3 — read the current state.
        banner(3, "get card status");
        let st = mgr.get_card_status(&isd_aid)?;
        dump(&st);
        report_warnings("get_card_status", &st.warnings);
        let current = st.state;

        // 4 — same-state write: the library detects the no-op host-side and
        // sends NO SET STATUS (the card would reject a same-state write,
        // GPCS v2.3.1 §11.10.2.2). `current_state: None` exercises the
        // internal GET STATUS read; the report carries `LifecycleNoOp`.
        banner(4, "same-state write (expect LifecycleNoOp, no SET STATUS APDU)");
        let noop = mgr.set_card_status(&SetCardStatusArgs {
            target_state: current,
            current_state: None,
            force: false,
            isd_aid: &isd_aid,
        })?;
        dump(&noop);
        report_warnings("set_card_status (no-op)", &noop.warnings);

        // 5 — an illegal transition WITHOUT force: refused host-side before
        // any APDU is built (`current_state: Some` — no extra read either).
        let bad = illegal_without_force(current);
        banner(5, "illegal transition without force (expect refusal, no APDU)");
        match mgr.set_card_status(&SetCardStatusArgs {
            target_state: bad,
            current_state: Some(current),
            force: false,
            isd_aid: &isd_aid,
        }) {
            Err(ScllError::IllegalLifecycleTransition) => {
                println!("[{current:?} -> {bad:?} without force: refused as expected]");
            }
            Err(other) => return Err(other),
            Ok(rep) => {
                println!("[UNEXPECTED SUCCESS: {rep:?}]");
                return Err(ScllError::IllegalLifecycleTransition);
            }
        }

        // 6 — the same class of refusal survives `force = true`: force only
        // unlocks the OP_READY -> SECURED skip-ahead (§5.1.2), never a
        // backward or otherwise-illegal transition.
        let bad_forced = illegal_even_with_force(current);
        banner(6, "illegal transition WITH force (still refused, no APDU)");
        match mgr.set_card_status(&SetCardStatusArgs {
            target_state: bad_forced,
            current_state: Some(current),
            force: true,
            isd_aid: &isd_aid,
        }) {
            Err(ScllError::IllegalLifecycleTransition) => {
                println!("[{current:?} -> {bad_forced:?} with force: refused as expected]");
            }
            Err(other) => return Err(other),
            Ok(rep) => {
                println!("[UNEXPECTED SUCCESS: {rep:?}]");
                return Err(ScllError::IllegalLifecycleTransition);
            }
        }

        // 7 — TERMINATED is never a set target, under any force (§5.1.1.5;
        // out of the library's scope by design, PDD §2.2).
        banner(7, "TERMINATED target (expect TerminateOutOfScope, no APDU)");
        match mgr.set_card_status(&SetCardStatusArgs {
            target_state: CardLifeCycle::Terminated,
            current_state: Some(current),
            force: true,
            isd_aid: &isd_aid,
        }) {
            Err(ScllError::TerminateOutOfScope) => {
                println!("[{current:?} -> Terminated with force: refused as expected]");
            }
            Err(other) => return Err(other),
            Ok(rep) => {
                println!("[UNEXPECTED SUCCESS: {rep:?}]");
                return Err(ScllError::TerminateOutOfScope);
            }
        }

        // 8 — the ONLY real SET STATUS, doubly gated (see module docs):
        // OP_READY -> INITIALIZED (P2 = 0x07, GPCS v2.3.1 Table 11-6 /
        // §11.10.2.2), jcsim-only, opt-in.
        banner(8, "opt-in forward transition (SCLL_LIFECYCLE_ADVANCE=1, jcsim only)");
        if !self.advance {
            println!("[SCLL_LIFECYCLE_ADVANCE not set — skipping the real transition]");
        } else if matches!(cfg.endpoint, Endpoint::Pcsc(_)) {
            println!(
                "[SCLL_LIFECYCLE_ADVANCE=1 but the transport is PC/SC — refusing: \
                 OP_READY -> INITIALIZED is irreversible on real hardware \
                 (GPCS v2.3.1 §5.1.1.2); this demo advances the simulator only]"
            );
        } else {
            match current {
                CardLifeCycle::OpReady => {
                    let rep = mgr.set_card_status(&SetCardStatusArgs {
                        target_state: CardLifeCycle::Initialized,
                        current_state: Some(current),
                        force: false,
                        isd_aid: &isd_aid,
                    })?;
                    dump(&rep);
                    report_warnings("set_card_status (advance)", &rep.warnings);
                    let after = mgr.get_card_status(&isd_aid)?;
                    println!("[state after advance: {:?}]", after.state);
                    if after.state != CardLifeCycle::Initialized {
                        println!("[read-back does not show INITIALIZED — investigate]");
                        return Err(ScllError::IllegalLifecycleTransition);
                    }
                }
                CardLifeCycle::Initialized => {
                    println!(
                        "[card already INITIALIZED — nothing to do (idempotent re-run); \
                         this demo never advances to SECURED]"
                    );
                }
                other => {
                    println!("[card is {other:?} — outside the OP_READY -> INITIALIZED scope]");
                }
            }
        }

        mgr.close_channel();
        Ok(())
    }
}
