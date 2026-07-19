//! `ssd-lifecycle` — the full **SSD** workflow (formerly the single
//! end-to-end example):
//!
//!  1. probe                                    [no channel]
//!  2. discover                                 [no channel]
//!  3. get card inventory (pick the SD package) [ISD]
//!  4. create SSD                               [ISD]
//!  5. PUT first SSD keyset → personalize SSD   [SSD, PUT-KEY level]  (direct channel, like gppro --connect)
//!  6. load package INTO the SSD                [ISD]   (INSTALL [for load] SD = SSD)
//!  7. install applet under the SSD             [ISD]   (instance inherits ELF's SD)
//!  8. open applet channel (keyset 1) + HELLO   [APPLET#1]
//!  9. PUT second SSD keyset (direct, Add)      [SSD, keyset 1]
//! 10. open applet channel (keyset 2) + HELLO   [APPLET#2]
//! 11. delete applet (+ cascade ELF IfLastInstance) [ISD]
//! 12. delete SSD (OnlyIfEmpty)                  [ISD]
//!
//! Because `CardManager` retains a single secure channel, the ISD management
//! channel is closed and re-opened around the SSD and applet channels.
//!
//! Idempotency: the run can be repeated indefinitely — the pre-clean in
//! step 4 removes leftovers of a previous failed or interrupted run, the
//! teardown (steps 11-12) removes everything on success, and a best-effort
//! cleanup removes everything on failure (unless `SCLL_KEEP=1`). The SSD's
//! key material needs no separate deletion: it is removed with the SSD
//! object (GPCS v2.3.1 §11.2, Table 11-22).
//!
//! Environment: the common variables (see `src/lib.rs`) plus `SCLL_CAP`
//! (required), and optionally `SCLL_SSD_AID` / `SCLL_APPLET_AID`.

use std::process::ExitCode;

use scll::backend::KeyBackend;
use scll::error::ScllError;
use scll::report::{DeleteCascade, ScpTargetKind, TransportName};
use scll::transport::Transport;
use scll::workflow::{
    CreateSsdArgs, DeleteAppletArgs, InstallAppletArgs, LoadPackageArgs, PutSdKeysArgs,
};
use scll::cap::InflateCtx;
use scll::CardManager;

use scll_examples::{
    banner, dump, env_opt, from_hex, key_kind_for, open, open_isd_original, pick_scp,
    print_transmit, run_demo, security_level, to_hex, Be, CapConfig, ChannelRole, Config, Endpoint,
    Triple, HELLO_CAPDU, KS1_DEK, KS1_ENC, KS1_MAC, KS2_DEK, KS2_ENC, KS2_MAC, KVN_1, KVN_2,
};

/// Default SSD instance AID (from the applet's env.example.sh). Override with
/// SCLL_SSD_AID. NOTE: NXP JCOP 4 P71 may require the SSD AID to sit under the
/// ISD's namespace — set SCLL_SSD_AID accordingly if create_ssd is rejected.
const DEFAULT_SSD_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x0F];

// GlobalPlatform Security-Domain package/module used to instantiate the SSD.
// Mirrors GlobalPlatformPro's `--domain` defaults: prefer the A0000000035350
// package when it is resident on the card, else the A0000001515350 GP package.
const SD_PKG_NEW: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x53, 0x50];
const SD_MOD_NEW: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x03, 0x53, 0x50, 0x41];
const SD_PKG_GP: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50];
const SD_MOD_GP: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x41];

fn main() -> ExitCode {
    let (cfg, cap, ssd_aid) = match config() {
        Ok(v) => v,
        Err(e) => return scll_examples::finish(Err(e)),
    };
    cfg.print("scll example: ssd-lifecycle (SSD + applet + keyset rotation)");
    cap.print();
    println!("SSD AID       : {}", to_hex(&ssd_aid));
    let demo = SsdDemo {
        cfg: &cfg,
        cap: &cap,
        ssd_aid: &ssd_aid,
    };
    let result = run_demo(&cfg.endpoint, &demo);
    scll_examples::finish(result)
}

fn config() -> Result<(Config, CapConfig, Vec<u8>), String> {
    let cfg = Config::from_env()?;
    let cap = CapConfig::from_env()?;
    let ssd_aid = match env_opt("SCLL_SSD_AID") {
        Some(s) => from_hex(&s)?,
        None => DEFAULT_SSD_AID.to_vec(),
    };
    Ok((cfg, cap, ssd_aid))
}

struct SsdDemo<'a> {
    cfg: &'a Config,
    cap: &'a CapConfig,
    ssd_aid: &'a [u8],
}

impl scll_examples::Demo for SsdDemo<'_> {
    fn run<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError> {
        // Idempotency: the pre-clean in step 4 recovers from previous failed
        // or interrupted runs; the teardown (steps 11-12) removes everything
        // on success; and this wrapper removes everything on failure, so no
        // run leaves data on the card (unless SCLL_KEEP=1 asks it to).
        match self.flow(mgr) {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.cfg.keep {
                    println!("\n[run failed ({e}); SCLL_KEEP=1 set — skipping the failure cleanup]");
                    return Err(e);
                }
                println!("\n[run failed ({e}); best-effort cleanup so nothing stays on the card]");
                if let Err(c) = emergency_cleanup(mgr, self.cfg, self.cap, self.ssd_aid) {
                    println!("[cleanup itself failed ({c}); the next run's pre-clean will retry]");
                }
                Err(e)
            }
        }
    }
}

impl SsdDemo<'_> {
    #[allow(clippy::too_many_lines)] // linear demo script; splitting would obscure the sequence
    fn flow<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError> {
        let (cfg, cap, ssd_aid) = (self.cfg, self.cap, self.ssd_aid);

        // 1 — transport probe.
        banner(1, "transport probe");
        let transport_name = match cfg.endpoint {
            Endpoint::Pcsc(_) => TransportName::Pcsc,
            Endpoint::Jcsim(_) => TransportName::Jcsim,
        };
        // Full 0x33 on real hardware; on jcsim the ISD drops R-MAC/R-ENC (0x03)
        // and SSD-backed channels drop to C-MAC-only (0x01). See the
        // *_security_level helpers. The library caps whatever we request to the
        // card's `i`.
        let isd_level = security_level(&cfg.endpoint, ChannelRole::Isd);
        let ssd_level = security_level(&cfg.endpoint, ChannelRole::Ssd);
        let ssd_putkey_level = security_level(&cfg.endpoint, ChannelRole::SsdPutKey);
        dump(&mgr.probe(transport_name)?);

        // 2 — discover (no channel). Decide which SCP to use everywhere.
        banner(2, "discover card");
        let info = mgr.discover(None)?;
        dump(&info);
        let isd_aid = info.isd_aid.as_bytes().to_vec();
        let scp = pick_scp(&info)?;
        let (scp_id, i_param) = match scp {
            scll::model::ScpVariant::Scp03 { i_param } => (0x03u8, i_param),
            scll::model::ScpVariant::Scp02 { i_param } => (0x02u8, i_param),
        };
        println!("\n[selected SCP: {scp:?} -> id=0x{scp_id:02X} i=0x{i_param:02X}]");

        // Import every key once; handles are reused across channel re-opens.
        let isd_kind = key_kind_for(scp, cfg.isd_enc.len());
        let ssd_kind = key_kind_for(scp, 16);
        let b = mgr.backend();
        let isd = Triple {
            enc: b.import_key(isd_kind, &cfg.isd_enc)?,
            mac: b.import_key(isd_kind, &cfg.isd_mac)?,
            dek: b.import_key(isd_kind, &cfg.isd_dek)?,
        };
        let ks1 = Triple {
            enc: b.import_key(ssd_kind, KS1_ENC)?,
            mac: b.import_key(ssd_kind, KS1_MAC)?,
            dek: b.import_key(ssd_kind, KS1_DEK)?,
        };
        let ks2 = Triple {
            enc: b.import_key(ssd_kind, KS2_ENC)?,
            mac: b.import_key(ssd_kind, KS2_MAC)?,
            dek: b.import_key(ssd_kind, KS2_DEK)?,
        };

        let adv = info.scp_supported.as_slice();

        // ── ISD management channel ────────────────────────────────────────────
        // Resilient open: on jcsim, INITIALIZE UPDATE with P1=0x00 can answer
        // 6A88 after an `isd-lifecycle` run (dangling default-KVN pointer,
        // PDD §10.7) — the original keys are also tried at the explicit
        // KIT-reported versions. The confirmed version is reused for every
        // later ISD channel in this run.
        let reported_kvns: Vec<u8> = info.isd_keysets.iter().map(|k| k.kvn).collect();
        let p = open_isd_original(mgr, "ISD", &isd_aid, isd, adv, scp, cfg.isd_kvn, &reported_kvns, None, isd_level)?;
        let original_kvn = p.kvn_effective;
        // INITIALIZE UPDATE P1 addresses versions 0x01-0x7F only (GPCS
        // v2.3.1 §11.8.2.3 Table 11-67); an initial keyset at 0xFF (real
        // JCOP) is selected with P1=0x00 instead — the P71 answers 6A86 to
        // an explicit P1=0xFF.
        let original_sel = if original_kvn <= 0x7F { original_kvn } else { 0x00 };
        println!(
            "\n[original ISD keyset confirmed at KVN 0x{original_kvn:02X}; \
             P1 selector 0x{original_sel:02X}]"
        );

        // 3 — inventory. Use it to pick the resident SD package for the SSD.
        banner(3, "get card inventory (pick the SD package)");
        let inv = mgr.get_card_inventory(&isd_aid)?;
        dump(&inv);
        let has_new_sd_pkg = inv
            .inventory
            .elfs
            .iter()
            .any(|e| e.aid.as_bytes() == SD_PKG_NEW);
        let (sd_pkg, sd_mod): (&[u8], &[u8]) = if has_new_sd_pkg {
            (SD_PKG_NEW, SD_MOD_NEW)
        } else {
            (SD_PKG_GP, SD_MOD_GP)
        };
        println!("\n[SSD will be instantiated from package {}]", to_hex(sd_pkg));

        // Best-effort pre-clean so the demo is re-runnable (ignore "not found").
        let _ = mgr.delete_applet(&DeleteAppletArgs {
            instance_aid: &cap.applet_aid,
            elf_aid: Some(&cap.package_aid),
            cascade_elf: DeleteCascade::Always,
        });
        let _ = mgr.delete_ssd(ssd_aid, DeleteCascade::Never);

        // 4 — create SSD. C9 install params carry:
        //   • SCP info TLV `81 02 <scp> <i>` (JCOP requires it), and
        //   • the extradition-rights block `82 02 20 20` — this is what gppro's
        //     `--allow-to` emits. WITHOUT it the card rejects INSTALL [for load]
        //     into the SSD with 6985 ("conditions of use not satisfied"): an SSD
        //     can only receive loaded/extradited content if it was created with
        //     the right to accept it. (GlobalPlatformPro wiki "Supplementary
        //     Security Domains"; issue #306. Bytes match the working gppro run.)
        // Privileges = Security Domain only (byte 1, 0x80); bytes 2-3 zero, so the
        // builder emits the minimal 1-byte form `01 80` (GPCS v2.3.1 §11.1.6),
        // which is what JCOP 4 P71 expects.
        banner(4, "create SSD");
        let install_params = [
            0xC9, 0x08, 0x81, 0x02, scp_id, i_param, 0x82, 0x02, 0x20, 0x20,
        ];
        dump(&mgr.create_ssd(&CreateSsdArgs {
            parent_sd_aid: &isd_aid,
            ssd_aid,
            elf_aid: sd_pkg,
            module_aid: sd_mod,
            privileges: [0x80, 0x00, 0x00],
            install_params: &install_params,
        })?);

        // 5 — personalize the SSD over a DIRECT SSD channel, exactly like gppro
        // (`gp --connect <SSD> … --new-keyver`). The freshly created SSD inherits
        // the ISD keys, so we authenticate to it with those and PUT its own keyset.
        // Two reasons this is NOT done parent-mediated over the ISD channel:
        //  • the sim crashes on parent-mediated (INSTALL [for personalization] +
        //    PUT KEY) for an SSD; and
        //  • the SSD path may need C-MAC-only on the sim (`ssd_level`) — see
        //    `ChannelRole::Ssd` in `security_level`.
        // GPCS v2.3.1 §11.8 (PUT KEY); DirectOnTargetSession = PUT KEY straight over
        // the SSD session, no INSTALL [for personalization].
        // Channel level: `ssd_putkey_level`, not `ssd_level` — PUT KEY specifically
        // needs R-MAC dropped on real hardware; see `ChannelRole::SsdPutKey`.
        mgr.close_channel(); // leave the ISD management channel
        banner(5, "PUT first SSD keyset (direct SSD channel)");
        // The fresh SSD inherits the ISD keyset INCLUDING its version, so the
        // resilient open is used here too, with the confirmed original
        // version tried first: on the JCOP-mocking bridge, INITIALIZE UPDATE
        // with P1=0x00 against the freshly created SSD answers 6A88 (the
        // inherited keyset must be addressed at its explicit version —
        // PDD §10.7), while the plain jcsim accepted P1=0x00 here.
        open_isd_original(mgr, "SSD-perso", ssd_aid, isd, adv, scp, cfg.isd_kvn, &[], Some(original_kvn), ssd_putkey_level)?;
        dump(&mgr.put_sd_keys(&PutSdKeysArgs {
            // `dek` is unused for this SCP02 DirectOnTargetSession call as of
            // patch #15 — the engine now encrypts under the SSD session's own
            // derived DEK instead. Left as the ISD DEK handle for API stability
            // and because it's still what SCP03 backends would need here.
            dek: isd.dek,
            // PUT KEY is Add-only (P1=0x00, KVN inside the data) — gppro uses
            // P1=00 here. The card has no replaceable registered keyset 0x30
            // yet (the default is inherited, not registered), so an in-place
            // replace (P1=0x30) returned 6A88 (removed in patch #29).
            new_keys: ks1.new_keyset(),
            new_kvn: KVN_1,
            target_sd_aid: ssd_aid,
        })?);
        mgr.close_channel(); // close the SSD personalization channel
        // Re-open the ISD management channel for the load + install (explicit
        // confirmed key version — see the first ISD open above).
        open(mgr, "ISD", &isd_aid, ScpTargetKind::SecurityDomainAid, isd.keys(), adv, scp, original_sel, isd_level)?;

        // 6 — load the applet package directly INTO the (now personalized) SSD. The
        // INSTALL [for load] SD-AID field carries the SSD, so the ELF is associated
        // with the SSD — exactly what `gp --install … --to <SSD>` emits (INSTALL
        // [for load] with SD = SSD, no separate extradition). GPCS v2.3.1
        // §11.5.2.3.2. Travels over the ISD's Authorized-Management channel.
        banner(6, "load package (into SSD)");
        let mut infl = InflateCtx::new();
        dump(&mgr.load_package(
            &LoadPackageArgs {
                target_sd_aid: ssd_aid,
                cap_zip: &cap.cap_bytes,
                lfdb_hash: &[], // Lh = 00; supply a SHA-256 here if your card requires it
            },
            &mut infl,
        )?);

        // 7 — install the applet. INSTALL [for install] carries no SD AID; the
        // instance inherits its parent SD from the ELF (now the SSD). `parent_sd_aid`
        // here is report metadata only — set to the SSD to mirror the on-card result.
        // (No standalone extradition: the ELF already lives in the SSD, so the
        // instance's SCP is delegated to the SSD.)
        banner(7, "install applet (under SSD)");
        dump(&mgr.install_applet(&InstallAppletArgs {
            parent_sd_aid: ssd_aid,
            package_aid: &cap.package_aid,
            module_aid: &cap.module_aid,
            instance_aid: &cap.applet_aid,
            privileges: [0x00, 0x00, 0x00],
            system_install_params: &[],
            applet_install_params: &[],
        })?);
        mgr.close_channel();

        // ── Applet channel #1 (SSD keyset 1) ──────────────────────────────────
        open(mgr, "APPLET#1", &cap.applet_aid, ScpTargetKind::ApplicationAid, ks1.keys(), adv, scp, KVN_1, ssd_level)?;
        banner(8, "send HELLO over applet channel (keyset 1)");
        let r = mgr.transmit(HELLO_CAPDU)?;
        print_transmit(&r);
        mgr.close_channel();

        // ── SSD channel (keyset 1) to add the second keyset — direct, PUT KEY level ──
        // (`ssd_putkey_level`, not `ssd_level` — same R-MAC restriction as step 5.)
        open(mgr, "SSD", ssd_aid, ScpTargetKind::SecurityDomainAid, ks1.keys(), adv, scp, KVN_1, ssd_putkey_level)?;
        // 9 — PUT the second SSD keyset (added alongside the first), direct over the
        // SSD session authenticated with keyset 1. Parent-mediated PUT KEY tears down
        // the simulator for SSDs, so every SSD key write uses a direct SSD channel;
        // the new keys are wrapped under keyset 1's DEK.
        banner(9, "rotate SSD keyset 0x30 -> 0x31 via PUT KEY (direct SSD channel)");
        dump(&mgr.put_sd_keys(&PutSdKeysArgs {
            // See the step-5 comment: `dek` is unused here too (session DEK used
            // instead, patch #15).
            dek: ks1.dek,
            new_keys: ks2.new_keyset(),
            new_kvn: KVN_2,
            target_sd_aid: ssd_aid,
        })?);
        mgr.close_channel();

        // PUT KEY Add (P1 = 0x00, GPCS v2.3.1 §11.8 Table 11-66) leaves KVN
        // 0x30 coexisting with the new 0x31. This example demonstrates rotation as
        // "add a new keyset, prove the applet authenticates under it" (step 10) —
        // it does not delete the old keyset: an explicit `DELETE [key]` on the
        // SSD's own channel consistently returns 6985 on this card (patches
        // #16/#17/#19; reproduced by gppro), and the object-scope SSD delete in
        // step 12 removes all its key material anyway (GPCS v2.3.1 §11.2,
        // Table 11-22). The ISD variant of this demo (`isd-lifecycle`) does
        // include explicit keyset deletion.

        // ── Applet channel #2 (SSD keyset 2, KVN 0x31) ────────────────────────
        // The extradited applet shares the SSD's key set, so after the rotation it
        // authenticates with keyset 2.
        open(mgr, "APPLET#2", &cap.applet_aid, ScpTargetKind::ApplicationAid, ks2.keys(), adv, scp, KVN_2, ssd_level)?;
        banner(10, "send HELLO over applet channel (rotated keyset 2, KVN 0x31)");
        let r = mgr.transmit(HELLO_CAPDU)?;
        print_transmit(&r);
        mgr.close_channel();

        if cfg.keep {
            println!("\n[SCLL_KEEP=1 set — skipping teardown (steps 11-12)]");
            return Ok(());
        }

        // ── Teardown, matching what the project's working `30-remove.sh`
        // reference script actually relies on (confirmed with USE_SSD=1 against
        // this card): delete applet + package over the ISD channel, then delete
        // the SSD itself over the ISD channel. No separate SSD key-set deletion —
        // deleting the SSD object removes its key material with it; GPCS doesn't
        // require key material to be explicitly purged before the object holding
        // it is deleted (GPCS v2.3.1 §11.2, Table 11-22 — DELETE [object]).
        open(mgr, "ISD", &isd_aid, ScpTargetKind::SecurityDomainAid, isd.keys(), adv, scp, original_sel, isd_level)?;
        banner(11, "delete applet (cascade ELF IfLastInstance) via ISD");
        // `IfLastInstance` (v0.9o): wire-identical to `Always` on this
        // single-instance demo — instance DELETE then ELF DELETE, both
        // P2=0x00 — but declares the intent, and a blocked cascade (another
        // instance still uses the ELF, `6985`) surfaces as
        // `ElfHasOtherInstances` instead of silently proceeding
        // (GPCS v2.3.1 §11.2, Table 11-26).
        dump(&mgr.delete_applet(&DeleteAppletArgs {
            instance_aid: &cap.applet_aid,
            elf_aid: Some(&cap.package_aid),
            cascade_elf: DeleteCascade::IfLastInstance,
        })?);
        banner(12, "delete SSD (OnlyIfEmpty, over ISD)");
        // `OnlyIfEmpty` (v0.9o): same no-cascade wire form (P2=0x00) as the
        // previous `Never` — cascade P2=0x80 draws 6A86 on this card for a
        // Security Domain (§10.7 C2), and gppro likewise uses P2=0x00
        // (`84 E4 00 00 .. 4F 08 <AID>`) — but states the verified §10.7
        // recommendation: the SSD was emptied in step 11, and a non-empty
        // SSD would answer `6985` -> `SsdHasApplets`. GPCS v2.3.1 §11.2,
        // Table 11-22.
        dump(&mgr.delete_ssd(ssd_aid, DeleteCascade::OnlyIfEmpty)?);
        mgr.close_channel();

        Ok(())
    }
}

/// Best-effort removal of everything the demo may have created — applet +
/// ELF, then the SSD object (which takes its key material with it, GPCS
/// v2.3.1 §11.2 Table 11-22). Used only on the failure path; the normal
/// teardown is steps 11-12 and the pre-clean in step 4 recovers from
/// interrupted runs. Self-contained: re-discovers and re-imports the ISD
/// keys because the failed flow's locals are gone.
fn emergency_cleanup<T: Transport>(
    mgr: &mut CardManager<T, Be>,
    cfg: &Config,
    cap: &CapConfig,
    ssd_aid: &[u8],
) -> Result<(), ScllError> {
    mgr.close_channel(); // a failed step may have left a channel open
    let info = mgr.discover(None)?;
    let isd_aid = info.isd_aid.as_bytes().to_vec();
    let scp = pick_scp(&info)?;
    let kind = key_kind_for(scp, cfg.isd_enc.len());
    let b = mgr.backend();
    let isd = Triple {
        enc: b.import_key(kind, &cfg.isd_enc)?,
        mac: b.import_key(kind, &cfg.isd_mac)?,
        dek: b.import_key(kind, &cfg.isd_dek)?,
    };
    let reported_kvns: Vec<u8> = info.isd_keysets.iter().map(|k| k.kvn).collect();
    open_isd_original(
        mgr,
        "ISD-cleanup",
        &isd_aid,
        isd,
        info.scp_supported.as_slice(),
        scp,
        cfg.isd_kvn,
        &reported_kvns,
        None,
        security_level(&cfg.endpoint, ChannelRole::Isd),
    )?;
    if mgr
        .delete_applet(&DeleteAppletArgs {
            instance_aid: &cap.applet_aid,
            elf_aid: Some(&cap.package_aid),
            cascade_elf: DeleteCascade::Always,
        })
        .is_ok()
    {
        println!("[deleted leftover applet/ELF]");
    } else {
        println!("[applet/ELF not present — nothing to delete]");
    }
    if mgr.delete_ssd(ssd_aid, DeleteCascade::Never).is_ok() {
        println!("[deleted leftover SSD (its key material goes with it)]");
    } else {
        println!("[SSD not present — nothing to delete]");
    }
    mgr.close_channel();
    Ok(())
}
