//! `isd-lifecycle` — the applet + keyset-rotation workflow run directly on
//! the **ISD** (no SSD is created; the applet's associated Security Domain is
//! the ISD, so the cooperative applet's SCP03 channel authenticates with ISD
//! keysets):
//!
//!  1. probe                                     [no channel]
//!  2. discover                                  [no channel]
//!     pre-run recovery — see "Idempotency"      [ISD, key-ops level]
//!  3. load package (SD = ISD)                   [ISD, mgmt]
//!  4. install applet under the ISD              [ISD, mgmt]
//!  5. PUT ISD keyset 1 (Add, KVN 0x32)          [ISD, key-ops level]
//!  6. open applet channel (keyset 1) + HELLO    [APPLET#1]
//!  7. PUT ISD keyset 2 (Add, KVN 0x33)          [ISD, keyset 1, key-ops level]
//!  8. open applet channel (keyset 2) + HELLO    [APPLET#2]
//!  9. teardown — restore the initial card state [ISD, key-ops level]
//!
//! ## Opt-in options (v0.9q, both default-off — defaults are byte-identical
//! to the verified behaviour)
//! * `SCLL_ISD_AES256=1` — the demo keysets (KVN 0x32/0x33) use AES-256
//!   (32-byte values; the PUT KEY clear-key-length byte becomes 32 and the
//!   encrypted blocks 32 bytes, Amendment D §7.2). SCP03 targets only: on an
//!   SCP02 card (3DES keysets, GPCS v2.3.1 §E) the run aborts before any
//!   card mutation. If a run with the flag is interrupted mid-recovery,
//!   re-run with the SAME flag until the teardown completes: recovery may
//!   need to authenticate with the demo key VALUES this process imports.
//! * `SCLL_APPLET_LEVEL=<hex>` (e.g. `33`) — the requested security level
//!   for the two APPLET channels only (steps 6/8). Default: the
//!   `ChannelRole::Isd` matrix value (0x03 on jcsim, 0x33 on the P71). The
//!   library caps the request to the card's `i` (Amendment D §4.1 Table
//!   4-2). `SCLL_APPLET_LEVEL=33` on jcsim is the interesting case: the
//!   sim's documented R-MAC gap is specific to the GET STATUS `63xx` page
//!   reply on the ISD channel (PDD §10.7) — plain applet traffic at full
//!   0x33 is exactly what this option probes.
//!
//! Rotation follows the same **Add-then-delete** pattern as `ssd-lifecycle`
//! (option A): PUT KEY with P1 = 0x00 adds KVN 0x33 alongside 0x32 (GPCS
//! v2.3.1 §11.8, Table 11-66); the applet channel is proven under each; the
//! demo versions are then removed with KVN-only DELETEs (tag 'D2' only —
//! GPCS v2.3.1 §11.2.2.3.2).
//!
//! ## Idempotency (self-healing)
//! The run can be repeated indefinitely: the same cleanup routine executes
//! (a) before the main flow (recovering leftovers of a previous failed or
//! interrupted run), (b) as the teardown, and (c) best-effort after any
//! failure. It brings the card back to its initial state: applet + ELF
//! deleted, demo keysets 0x32/0x33 removed, original ISD keyset in place.
//!
//! **jcsim initial-key + default-pointer behaviour (established from live
//! traces, PDD §10.7):**
//! * only the **first** `PUT KEY` replaces the sim's factory keyset (classic
//!   initial-key replacement semantics) — so on a fresh sim, step 5 replaces
//!   the original 0x30 with keyset 1; **subsequent Adds coexist** (step 7
//!   yields {0x32, 0x33});
//! * the sim keeps a **default-KVN pointer** for INITIALIZE UPDATE with
//!   P1 = 0x00; it moves to the keyset that replaced the initial one and
//!   **dangles once that keyset is deleted** — IU with P1 = 0x00 then answers
//!   `6A88` even though keysets exist. Cleanup therefore never relies on
//!   P1 = 0x00 after mutating the key registry: the original keys are tried
//!   with **explicit** key versions too (the observed original KVN,
//!   `SCLL_ISD_KVN`, 0x30), and the whole flow reuses the KVN confirmed by
//!   the pre-run recovery.
//!
//! When the original ISD keys no longer authenticate under any candidate
//! version, cleanup authenticates with a demo keyset and **restores the
//! original keyset by value** (`PUT KEY Add` with the environment's ISD
//! keys), verifies by re-opening with the original keys at the restore
//! version, then deletes the demo versions. Note: after ISD demo runs on
//! jcsim the dangling default pointer may persist — if another binary fails
//! its INITIALIZE UPDATE with `6A88` at `SCLL_ISD_KVN=0x00`, pass
//! `SCLL_ISD_KVN=30` explicitly (or restart the sim).
//!
//! ## Safety guards
//! The demo must never destroy a keyset the card owns:
//! 1. refuses to start when `SCLL_ISD_KVN` equals 0x32 or 0x33;
//! 2. refuses when a channel opened with the **original** ISD keys reports an
//!    effective KVN of 0x32/0x33 (the card's own keyset sits at a demo
//!    version);
//! 3. versions 0x32/0x33 are owned by this demo **by contract**: cleanup
//!    deletes them whenever present (a loud line is printed first). Do not
//!    run the demo against a card whose 0x32/0x33 keysets belong to someone
//!    else.
//!
//! **Real-hardware note (JCOP, initial keys at KVN 0xFF):** GP initial-key
//! semantics mean step 5's first PUT KEY MAY permanently replace the ISD's
//! initial keyset. The teardown then restores the original key VALUES, but —
//! since PUT KEY can only create versions 0x01-0x7F (GPCS v2.3.1 §11.8.2.3)
//! — at KVN 0x30, not at 0xFF: the version changes while the key values are
//! preserved, and later runs find the new version via the KIT. Run this demo
//! on a real card only if that version change is acceptable.
//!
//! Environment: the common variables (see `src/lib.rs`) plus `SCLL_CAP`
//! (required) and optionally `SCLL_APPLET_AID`.

use std::process::ExitCode;

use scll::backend::{KeyBackend, KeyKind};
use scll::cap::InflateCtx;
use scll::error::ScllError;
use scll::model::ScpVariant;
use scll::report::{DeleteCascade, DeleteKeyReport, ScpTargetKind, TransportName};
use scll::transport::Transport;
use scll::workflow::{DeleteAppletArgs, InstallAppletArgs, LoadPackageArgs, PutSdKeysArgs};
use scll::CardManager;

use scll_examples::{
    banner, dump, env_opt, key_kind_for, open, open_isd_original, parse_u8, pick_scp,
    print_transmit, run_demo, security_level, Be, CapConfig, ChannelRole, Config, Endpoint,
    Triple, HELLO_CAPDU, ISD_KVN_1, ISD_KVN_2, JCSIM_FACTORY_KVN, KS1_DEK, KS1_DEK_256, KS1_ENC,
    KS1_ENC_256, KS1_MAC, KS1_MAC_256, KS2_DEK, KS2_DEK_256, KS2_ENC, KS2_ENC_256, KS2_MAC,
    KS2_MAC_256,
};

fn main() -> ExitCode {
    let (cfg, cap, opts) = match config() {
        Ok(v) => v,
        Err(e) => return scll_examples::finish(Err(e)),
    };
    cfg.print("scll example: isd-lifecycle (applet + ISD keyset rotation)");
    cap.print();
    opts.print();
    let demo = IsdDemo { cfg: &cfg, cap: &cap, opts: &opts };
    let result = run_demo(&cfg.endpoint, &demo);
    scll_examples::finish(result)
}

/// The two v0.9q opt-ins, both default-off (defaults reproduce the verified
/// patch-#35 behaviour byte-for-byte):
/// * `SCLL_ISD_AES256=1` — the DEMO keysets (KVN 0x32/0x33) become AES-256
///   (32-byte values, same byte patterns). SCP03 targets only; the run
///   aborts up front when the card negotiates SCP02 (3DES — AES key kinds do
///   not apply, GPCS v2.3.1 §E).
/// * `SCLL_APPLET_LEVEL=<hex>` (e.g. `33`) — requested security level for
///   the two APPLET channels only (default: the `ChannelRole::Isd` matrix
///   value). The library still caps the request to the card's `i`
///   (Amendment D §4.1 Table 4-2).
struct Options {
    aes256: bool,
    applet_level: Option<u8>,
}

impl Options {
    fn print(&self) {
        if self.aes256 {
            println!(
                "AES-256 demo keysets: ON (SCLL_ISD_AES256=1; SCP03 only). NOTE: if a \
                 run is interrupted mid-recovery, re-run with the SAME setting until \
                 the teardown completes — the demo keyset VALUES on the card must \
                 match the ones this process imports."
            );
        }
        if let Some(l) = self.applet_level {
            println!("applet-channel level override: 0x{l:02X} (SCLL_APPLET_LEVEL)");
        }
    }
}

fn config() -> Result<(Config, CapConfig, Options), String> {
    let cfg = Config::from_env()?;
    // Guard 1: the demo adds and later deletes keysets 0x32/0x33 on the ISD.
    // If the management channel itself authenticates with one of those
    // versions, the demo would replace/delete the live management keyset and
    // could permanently lock the ISD. Refuse up front.
    if cfg.isd_kvn == ISD_KVN_1 || cfg.isd_kvn == ISD_KVN_2 {
        return Err(format!(
            "SCLL_ISD_KVN=0x{:02X} collides with the demo keyset versions \
             (0x{ISD_KVN_1:02X}/0x{ISD_KVN_2:02X}); running would risk replacing or \
             deleting the ISD keyset this demo authenticates with — aborting",
            cfg.isd_kvn
        ));
    }
    let cap = CapConfig::from_env()?;
    let opts = Options {
        aes256: env_opt("SCLL_ISD_AES256").as_deref() == Some("1"),
        applet_level: match env_opt("SCLL_APPLET_LEVEL") {
            Some(s) => Some(parse_u8(&s)?),
            None => None,
        },
    };
    Ok((cfg, cap, opts))
}

struct IsdDemo<'a> {
    cfg: &'a Config,
    cap: &'a CapConfig,
    opts: &'a Options,
}

/// Everything the flow and the cleanup routine share.
struct Env<'a> {
    isd_aid: Vec<u8>,
    /// ISD key versions listed in the Key Information Template at discovery
    /// (pre-mutation — i.e. the card's original registry for this run).
    reported_kvns: Vec<u8>,
    adv: &'a [ScpVariant],
    scp: ScpVariant,
    isd_kind: KeyKind,
    /// Key kind of the DEMO keysets: AES-128 (or 3DES on SCP02) by default,
    /// AES-256 under `SCLL_ISD_AES256=1` (v0.9q).
    demo_kind: KeyKind,
    isd: Triple,
    ks1: Triple,
    ks2: Triple,
    isd_kvn: u8,
    isd_level: u8,
    keyops_level: u8,
    /// Requested level for the two APPLET channels: `isd_level` unless
    /// overridden via `SCLL_APPLET_LEVEL` (v0.9q).
    applet_level: u8,
}

impl scll_examples::Demo for IsdDemo<'_> {
    fn run<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError> {
        let cfg = self.cfg;

        // 1 — transport probe.
        banner(1, "transport probe");
        let transport_name = match cfg.endpoint {
            Endpoint::Pcsc(_) => TransportName::Pcsc,
            Endpoint::Jcsim(_) => TransportName::Jcsim,
        };
        dump(&mgr.probe(transport_name)?);

        // 2 — discover (no channel). Decide which SCP to use everywhere.
        banner(2, "discover card");
        let info = mgr.discover(None)?;
        dump(&info);
        let isd_aid = info.isd_aid.as_bytes().to_vec();
        // The KIT-reported key versions feed the recovery: `open_original`
        // tries the ORIGINAL keys against each of them (the factory version
        // differs per target — 0x30 on the plain jcsim, 0x03 on the
        // JCOP-mocking bridge, typically 0xFF on real cards).
        let reported_kvns: Vec<u8> = info.isd_keysets.iter().map(|k| k.kvn).collect();
        println!(
            "\n[ISD key versions reported by the card: {:?}]",
            reported_kvns
                .iter()
                .map(|k| format!("0x{k:02X}"))
                .collect::<Vec<_>>()
        );
        let scp = pick_scp(&info)?;
        println!("\n[selected SCP: {scp:?}]");

        // v0.9q opt-in: AES-256 demo keysets are SCP03-only — under SCP02 the
        // keyset type is two-key 3DES (GPCS v2.3.1 §E) and AES kinds do not
        // apply. Refuse up front rather than fail mid-flow.
        if self.opts.aes256 && !matches!(scp, ScpVariant::Scp03 { .. }) {
            println!(
                "[SCLL_ISD_AES256=1 requires an SCP03 target (AES keysets); this card \
                 negotiated {scp:?} — aborting before any card mutation]"
            );
            return Err(ScllError::ScpProtocolUnsupported);
        }

        // Import every key once; handles are reused across channel re-opens.
        let isd_kind = key_kind_for(scp, cfg.isd_enc.len());
        let demo_kind = if self.opts.aes256 {
            KeyKind::Aes256
        } else {
            key_kind_for(scp, 16)
        };
        let (k1e, k1m, k1d, k2e, k2m, k2d) = if self.opts.aes256 {
            (KS1_ENC_256, KS1_MAC_256, KS1_DEK_256, KS2_ENC_256, KS2_MAC_256, KS2_DEK_256)
        } else {
            (KS1_ENC, KS1_MAC, KS1_DEK, KS2_ENC, KS2_MAC, KS2_DEK)
        };
        let isd_level = security_level(&cfg.endpoint, ChannelRole::Isd);
        let applet_level = self.opts.applet_level.unwrap_or(isd_level);
        if applet_level != isd_level {
            println!(
                "[applet channels will REQUEST level 0x{applet_level:02X} instead of the \
                 default 0x{isd_level:02X}; the library caps the request to the card's i \
                 (Amendment D §4.1 Table 4-2)]"
            );
        }
        let b = mgr.backend();
        let env = Env {
            isd: Triple {
                enc: b.import_key(isd_kind, &cfg.isd_enc)?,
                mac: b.import_key(isd_kind, &cfg.isd_mac)?,
                dek: b.import_key(isd_kind, &cfg.isd_dek)?,
            },
            ks1: Triple {
                enc: b.import_key(demo_kind, k1e)?,
                mac: b.import_key(demo_kind, k1m)?,
                dek: b.import_key(demo_kind, k1d)?,
            },
            ks2: Triple {
                enc: b.import_key(demo_kind, k2e)?,
                mac: b.import_key(demo_kind, k2m)?,
                dek: b.import_key(demo_kind, k2d)?,
            },
            isd_aid,
            reported_kvns,
            adv: info.scp_supported.as_slice(),
            scp,
            isd_kind,
            demo_kind,
            isd_kvn: cfg.isd_kvn,
            // ISD management channel: full 0x33 on real hardware, 0x03 on
            // jcsim. ISD key-operation channels (PUT KEY / DELETE KEY): 0x03
            // on both — see `ChannelRole::IsdKeyOps` in `security_level`.
            isd_level,
            keyops_level: security_level(&cfg.endpoint, ChannelRole::IsdKeyOps),
            applet_level,
        };

        // Pre-run recovery: the same routine as the teardown. Ensures a clean
        // initial state even after a failed or interrupted previous run
        // (leftover applet/ELF, leftover demo keysets, or an original keyset
        // replaced by a demo one — jcsim initial-key replacement). Returns
        // the CONFIRMED original key version, which the whole flow then uses
        // explicitly (jcsim's IU P1=0x00 default-KVN pointer can dangle —
        // see the module docs).
        println!("\n[pre-run recovery — ensuring a clean initial card state]");
        let original_kvn = cleanup(mgr, &env, self.cap, None)?;
        // INITIALIZE UPDATE P1 addresses versions 0x01-0x7F only (GPCS
        // v2.3.1 §11.8.2.3 Table 11-67); an initial keyset at 0xFF (real
        // JCOP) is selected with P1=0x00 instead — the P71 answers 6A86 to
        // an explicit P1=0xFF.
        let original_sel = if original_kvn <= 0x7F { original_kvn } else { 0x00 };
        println!(
            "\n[original ISD keyset confirmed at KVN 0x{original_kvn:02X}; \
             P1 selector 0x{original_sel:02X}]"
        );

        // Main flow; on any failure, best-effort cleanup so nothing stays on
        // the card, then propagate the original error.
        match self.flow(mgr, &env, original_sel) {
            Ok(()) => {
                if cfg.keep {
                    println!("\n[SCLL_KEEP=1 set — skipping teardown (step 9)]");
                    return Ok(());
                }
                banner(9, "teardown — restore the initial card state");
                cleanup(mgr, &env, self.cap, Some(original_kvn)).map(|_| ())
            }
            Err(e) => {
                if cfg.keep {
                    println!("\n[run failed ({e}); SCLL_KEEP=1 set — skipping the failure cleanup]");
                    return Err(e);
                }
                println!("\n[run failed ({e}); best-effort cleanup so nothing stays on the card]");
                if let Err(c) = cleanup(mgr, &env, self.cap, Some(original_kvn)) {
                    println!("[cleanup itself failed ({c}); the next run's pre-run recovery will retry]");
                }
                Err(e)
            }
        }
    }
}

impl IsdDemo<'_> {
    /// Steps 3–8. `original_sel` is the INITIALIZE UPDATE P1 selector for
    /// the original keyset, derived from the version the pre-run recovery
    /// confirmed: the version itself when it is P1-addressable (0x01-0x7F),
    /// else 0x00 ("first available" — e.g. initial keys at 0xFF on real
    /// JCOP). Recovery already verified the confirmed version is not a demo
    /// version.
    #[allow(clippy::too_many_lines)] // linear demo script; splitting would obscure the sequence
    fn flow<T: Transport>(
        &self,
        mgr: &mut CardManager<T, Be>,
        env: &Env<'_>,
        original_sel: u8,
    ) -> Result<(), ScllError> {
        let cap = self.cap;

        // ── ISD management channel: load + install ────────────────────────────
        open(mgr, "ISD", &env.isd_aid, ScpTargetKind::SecurityDomainAid, env.isd.keys(), env.adv, env.scp, original_sel, env.isd_level)?;

        // 3 — load the applet package under the ISD itself: the INSTALL [for
        // load] Security-Domain-AID field carries the ISD AID, so the ELF is
        // associated with the ISD (GPCS v2.3.1 §11.5.2.3.2 — the field holds
        // the AID of the associated SD; for the ISD it may equally be the ISD
        // AID or empty). This is what a plain `gp --install <cap>` does.
        banner(3, "load package (SD = ISD)");
        let mut infl = InflateCtx::new();
        dump(&mgr.load_package(
            &LoadPackageArgs {
                target_sd_aid: &env.isd_aid,
                cap_zip: &cap.cap_bytes,
                lfdb_hash: &[], // Lh = 00; supply a SHA-256 here if your card requires it
            },
            &mut infl,
        )?);

        // 4 — install the applet. INSTALL [for install] carries no SD AID; the
        // instance inherits its parent SD from the ELF — here the ISD. The
        // cooperative applet therefore delegates its SCP03 to the ISD: its
        // channels below authenticate with ISD keysets.
        banner(4, "install applet (under ISD)");
        dump(&mgr.install_applet(&InstallAppletArgs {
            parent_sd_aid: &env.isd_aid,
            package_aid: &cap.package_aid,
            module_aid: &cap.module_aid,
            instance_aid: &cap.applet_aid,
            privileges: [0x00, 0x00, 0x00],
            system_install_params: &[],
            applet_install_params: &[],
        })?);
        mgr.close_channel();

        // ── ISD key-ops channel #1 (original ISD keys) ────────────────────────
        // 5 — Add keyset 1 (KVN 0x32) to the ISD's key registry. PUT KEY with
        // P1 = 0x00 (Add, KVN inside the data) — GPCS v2.3.1 §11.8.
        open(mgr, "ISD-keyops", &env.isd_aid, ScpTargetKind::SecurityDomainAid, env.isd.keys(), env.adv, env.scp, original_sel, env.keyops_level)?;
        // (Guard 2 — refusing when the original keys sit at a demo version —
        // already ran inside the pre-run recovery, which confirmed the
        // original key version behind `original_sel`.)
        banner(5, "PUT ISD keyset 1 (Add, KVN 0x32)");
        dump(&mgr.put_sd_keys(&PutSdKeysArgs {
            // SCP03: new keys travel encrypted under the session keyset's
            // static DEK (Amendment D v1.1.2 §6.2.6) — the channel opened with
            // the original ISD keys, so that is `isd.dek`. (For SCP02 the
            // engine uses the session-derived DEK internally — patch #15.)
            dek: env.isd.dek,
            new_keys: env.ks1.new_keyset_of(env.demo_kind),
            new_kvn: ISD_KVN_1,
            target_sd_aid: &env.isd_aid,
        })?);
        mgr.close_channel();

        // ── Applet channel #1 (ISD keyset 1) ──────────────────────────────────
        // The applet's SD is the ISD, so the ISD security level applies (the
        // jcsim SSD quirks documented on `ChannelRole::Ssd` do not).
        open(mgr, "APPLET#1", &cap.applet_aid, ScpTargetKind::ApplicationAid, env.ks1.keys(), env.adv, env.scp, ISD_KVN_1, env.applet_level)?;
        banner(6, "send HELLO over applet channel (keyset 1, KVN 0x32)");
        let r = mgr.transmit(HELLO_CAPDU)?;
        print_transmit(&r);
        mgr.close_channel();

        // ── ISD key-ops channel #2 (keyset 1) — rotate to keyset 2 ───────────
        // 7 — same Add-then-delete rotation pattern as the SSD demo: the
        // session authenticates with keyset 1 and adds keyset 2 (KVN 0x33);
        // the demo versions are removed in the teardown. New keys are wrapped
        // under keyset 1's static DEK (SCP03, Amendment D §6.2.6).
        open(mgr, "ISD-keyops", &env.isd_aid, ScpTargetKind::SecurityDomainAid, env.ks1.keys(), env.adv, env.scp, ISD_KVN_1, env.keyops_level)?;
        banner(7, "rotate ISD keyset 0x32 -> 0x33 via PUT KEY (Add)");
        dump(&mgr.put_sd_keys(&PutSdKeysArgs {
            dek: env.ks1.dek,
            new_keys: env.ks2.new_keyset_of(env.demo_kind),
            new_kvn: ISD_KVN_2,
            target_sd_aid: &env.isd_aid,
        })?);
        mgr.close_channel();

        // ── Applet channel #2 (ISD keyset 2, KVN 0x33) ────────────────────────
        open(mgr, "APPLET#2", &cap.applet_aid, ScpTargetKind::ApplicationAid, env.ks2.keys(), env.adv, env.scp, ISD_KVN_2, env.applet_level)?;
        banner(8, "send HELLO over applet channel (rotated keyset 2, KVN 0x33)");
        let r = mgr.transmit(HELLO_CAPDU)?;
        print_transmit(&r);
        mgr.close_channel();

        Ok(())
    }
}

/// Bring the card back to its initial state: applet + ELF deleted, demo
/// keysets 0x32/0x33 removed, original ISD keyset in place. Used as the
/// pre-run recovery, the teardown, and the after-failure cleanup — that
/// symmetry is what makes the demo idempotent.
///
/// `known_original_kvn` is the original keyset's version confirmed earlier
/// in this run; `None` on the very first attempt (pre-run recovery).
/// Returns the confirmed original key version on success.
fn cleanup<T: Transport>(
    mgr: &mut CardManager<T, Be>,
    env: &Env<'_>,
    cap: &CapConfig,
    known_original_kvn: Option<u8>,
) -> Result<u8, ScllError> {
    mgr.close_channel(); // a failed step may have left a channel open

    // Path A: the original ISD keys still authenticate (compliant card, or
    // nothing touched the keyset yet). Tries several key-version selectors —
    // see `open_original`.
    match open_isd_original(
        mgr, "ISD-cleanup", &env.isd_aid, env.isd, env.adv, env.scp, env.isd_kvn,
        &env.reported_kvns, known_original_kvn, env.keyops_level,
    ) {
        Ok(p) => {
            if p.kvn_effective == ISD_KVN_1 || p.kvn_effective == ISD_KVN_2 {
                println!(
                    "refusing cleanup: the original ISD keys authenticated at demo \
                     version 0x{:02X} — the card's own keyset sits at a demo version",
                    p.kvn_effective
                );
                return Err(ScllError::CannotDeleteActiveKeyset);
            }
            delete_applet_best_effort(mgr, cap);
            // Versions 0x32/0x33 are owned by this demo by contract (guard 3).
            println!("[removing demo keysets 0x{ISD_KVN_1:02X}/0x{ISD_KVN_2:02X} if present]");
            delete_keyset_tolerant(mgr, env, ISD_KVN_1)?;
            delete_keyset_tolerant(mgr, env, ISD_KVN_2)?;
            mgr.close_channel();
            println!("[cleanup done: original ISD keyset in place (KVN 0x{:02X})]", p.kvn_effective);
            Ok(p.kvn_effective)
        }
        // Path B: the original keys no longer authenticate under any
        // candidate version — on jcsim this means the first PUT KEY replaced
        // the factory keyset (initial-key semantics, module docs).
        // Authenticate with a demo keyset and restore the original by value.
        Err(first) => {
            println!(
                "\n[original ISD keys do not authenticate ({first}); trying the demo \
                 keysets — jcsim initial-key replacement (PDD §10.7)]"
            );
            let candidates = [(ISD_KVN_2, env.ks2, "keyset 2"), (ISD_KVN_1, env.ks1, "keyset 1")];
            for (kvn, keys, label) in candidates {
                let Ok(_p) = open(mgr, "ISD-cleanup(demo)", &env.isd_aid, ScpTargetKind::SecurityDomainAid, keys.keys(), env.adv, env.scp, kvn, env.keyops_level) else {
                    continue;
                };
                println!("[authenticated with demo {label} (KVN 0x{kvn:02X})]");
                delete_applet_best_effort(mgr, cap);
                // Remove the *other* demo version if it coexists (never the
                // active one — a session must not delete its own keyset).
                let other = if kvn == ISD_KVN_1 { ISD_KVN_2 } else { ISD_KVN_1 };
                delete_keyset_tolerant(mgr, env, other)?;
                // Restore the original keyset by value. On the quirky sim the
                // Add replaces the active demo keyset; on a compliant card it
                // coexists and the demo version is deleted right below.
                // Restore version preference: the KVN observed when the
                // original keys last authenticated; else the first non-demo
                // version the KIT reported at discovery (= the original
                // registry); else the configured `SCLL_ISD_KVN`; else the
                // plain-jcsim factory default.
                let preferred = known_original_kvn
                    .or_else(|| {
                        env.reported_kvns
                            .iter()
                            .copied()
                            .find(|&k| k != ISD_KVN_1 && k != ISD_KVN_2)
                    })
                    .unwrap_or(if env.isd_kvn != 0 {
                        env.isd_kvn
                    } else {
                        JCSIM_FACTORY_KVN
                    });
                // PUT KEY can only CREATE versions 0x01-0x7F (GPCS v2.3.1
                // §11.8.2.3, Table 11-67): an original keyset at e.g. 0xFF
                // (initial keys on real JCOP) cannot be recreated at its own
                // version — restore the original key VALUES at the factory
                // fallback version and say so loudly. Later runs find that
                // version via the KIT candidates, so idempotency holds.
                let restore_kvn = if (0x01..=0x7F).contains(&preferred) {
                    preferred
                } else {
                    println!(
                        "[original key version 0x{preferred:02X} cannot be \
                         recreated by PUT KEY (valid new-KVN range 01-7F); \
                         restoring the original key VALUES at KVN \
                         0x{JCSIM_FACTORY_KVN:02X} instead]"
                    );
                    JCSIM_FACTORY_KVN
                };
                println!("[restoring the original ISD keyset at KVN 0x{restore_kvn:02X} by value]");
                dump(&mgr.put_sd_keys(&PutSdKeysArgs {
                    dek: keys.dek,
                    new_keys: env.isd.new_keyset_of(env.isd_kind),
                    new_kvn: restore_kvn,
                    target_sd_aid: &env.isd_aid,
                })?);
                mgr.close_channel();
                // Verify: the original keys must authenticate again — at the
                // EXPLICIT restore version, never IU P1=0x00: deleting the
                // demo keyset above may have left jcsim's default-KVN pointer
                // dangling (module docs), so P1=0x00 can answer 6A88 even
                // though the restored keyset exists. Then remove any demo
                // version that survived (compliant-card path).
                let p = open(mgr, "ISD-verify", &env.isd_aid, ScpTargetKind::SecurityDomainAid, env.isd.keys(), env.adv, env.scp, restore_kvn, env.keyops_level)?;
                delete_keyset_tolerant(mgr, env, ISD_KVN_1)?;
                delete_keyset_tolerant(mgr, env, ISD_KVN_2)?;
                mgr.close_channel();
                println!("[cleanup done: original ISD keyset restored (KVN 0x{:02X})]", p.kvn_effective);
                return Ok(p.kvn_effective);
            }
            println!("[no known keyset authenticates — cannot recover this card state]");
            Err(first)
        }
    }
}

/// Best-effort applet + ELF removal (absence is the normal case in recovery).
fn delete_applet_best_effort<T: Transport>(mgr: &mut CardManager<T, Be>, cap: &CapConfig) {
    match mgr.delete_applet(&DeleteAppletArgs {
        instance_aid: &cap.applet_aid,
        elf_aid: Some(&cap.package_aid),
        cascade_elf: DeleteCascade::Always,
    }) {
        Ok(r) => dump(&r),
        Err(_) => println!("[applet/ELF not present — nothing to delete]"),
    }
}

/// KVN-only DELETE that treats "not found" as success (idempotency) but
/// propagates every other error.
fn delete_keyset_tolerant<T: Transport>(
    mgr: &mut CardManager<T, Be>,
    env: &Env<'_>,
    kvn: u8,
) -> Result<(), ScllError> {
    let r: Result<DeleteKeyReport, ScllError> = mgr.delete_sd_keyset(kvn, &env.isd_aid);
    match r {
        Ok(rep) => {
            println!("[deleted ISD keyset 0x{kvn:02X}]");
            dump(&rep);
            Ok(())
        }
        Err(ScllError::KeyNotFound) => {
            println!("[ISD keyset 0x{kvn:02X} not present]");
            Ok(())
        }
        Err(e) => Err(e),
    }
}
