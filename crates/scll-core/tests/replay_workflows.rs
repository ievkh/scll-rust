//! Layer-3 replay/integration tests (PDD §10.1 layer 3, §10.3).
//!
//! Each test scripts a [`MockTransport`] from a synthetic, spec-faithful trace
//! (see `scll_test_support::fixtures`) and drives the *real* workflow functions
//! through it, asserting the exact C-APDU order and the resulting `*Report`.
//! Crypto is the deterministic [`StubBackend`] (wrap/unwrap echo), so every wire
//! byte is hand-computable; correctness of the crypto itself is the layer-2 KAT
//! job, not this layer. These traces are SYNTHETIC and must be re-recorded from
//! the jcsim / a real card before the exit gate is claimed on silicon (B2).

use scll_core::aid::Aid;
use scll_core::backend::{KeyHandle, KeyKind};
use scll_core::command::delete::{delete_key, delete_object};
use scll_core::command::get_status::{get_status, get_status_p2};
use scll_core::command::install::{install_for_install_make_selectable, PrivLen};
use scll_core::command::put_key::{put_key, KeyBlock};
use scll_core::command::select::select_by_aid;
use scll_core::model::ScpVariant;
use scll_core::report::{CardLifeCycle, DeleteCascade, ScpProtocol, ScpTargetKind};
use scll_core::scp::ScpSession;
use scll_core::workflow::transmit::transmit as send_apdu;
use scll_core::workflow::{
    create_ssd, delete_applet, delete_sd_keyset, discover_card, get_card_inventory,
    get_card_status, install_applet, open_scp, put_sd_keys, set_card_status, CreateSsdArgs,
    DeleteAppletArgs, InstallAppletArgs, NewKeyset, OpenScpArgs, PutSdKeysArgs, SdKeys,
    SetCardStatusArgs,
};
use scll_test_support::{fixtures, StubBackend, Trace};

const ISD: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
const SSD: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01];
const ELF: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50];
const MODULE: [u8; 8] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x01];
const INSTANCE: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C];

const OK: u16 = 0x9000;
const HOST_CRYPTO: [u8; 8] = [0xBB; 8];
const CARD_CRYPTO: [u8; 8] = [0xAA; 8];
const KCV: [u8; 3] = [0xC0, 0xC1, 0xC2];
const ENC_BLOCK: [u8; 16] = [0xE0; 16];

fn h0() -> KeyHandle {
    KeyHandle::new(0)
}
fn sd_keys() -> SdKeys {
    SdKeys {
        enc: h0(),
        mac: h0(),
        dek: h0(),
    }
}

/// EXTERNAL AUTHENTICATE wire bytes (the stub echoes the plaintext begin built):
/// `84 82 <level> 00 08 <host_cryptogram>`.
fn ea_wire(level: u8) -> Vec<u8> {
    let mut v = vec![0x84, 0x82, level, 0x00, 0x08];
    v.extend_from_slice(&HOST_CRYPTO);
    v
}

/// Drive `open_scp` over SCP03 and return the open session for further steps.
fn open_scp03(trace: &mut Trace) {
    *trace = trace
        .clone()
        .step(
            select_by_aid(&ISD).unwrap().as_slice(),
            &fixtures::rapdu(&fixtures::fci_with_aid(&ISD), OK),
        )
        .step(
            scll_core::scp::scp03::iu_command(0x00, &[0u8; 8])
                .unwrap()
                .as_slice(),
            &fixtures::rapdu(&fixtures::iu_scp03(0x00, 0x70, [9; 8], CARD_CRYPTO), OK),
        )
        .step(&ea_wire(0x33), &fixtures::sw(OK));
}

fn open_args<'a>(advertised: &'a [ScpVariant], target: &'a [u8]) -> OpenScpArgs<'a> {
    OpenScpArgs {
        target_aid: target,
        target_kind: ScpTargetKind::SecurityDomainAid,
        sd_keys: sd_keys(),
        advertised,
        force_scp: None,
        kvn: 0x00,
        requested_level: 0x33,
    }
}

#[test]
fn discover_happy_path_scp03() {
    let trace = Trace::new()
        .step(
            select_by_aid(&[]).unwrap().as_slice(),
            &fixtures::rapdu(&fixtures::fci_with_aid(&ISD), OK),
        )
        .step(
            &[0x80, 0xCA, 0x00, 0x66, 0x00],
            &fixtures::rapdu(&fixtures::crd_scp03(0x70), OK),
        )
        .step(
            &[0x80, 0xCA, 0x00, 0xE0, 0x00],
            &fixtures::rapdu(&fixtures::kit_aes_kvn1(), OK),
        )
        .step(
            &[0x80, 0xCA, 0x00, 0x67, 0x00],
            &fixtures::rapdu(&fixtures::cci_basic(), OK),
        )
        .step(&[0x80, 0xCA, 0x00, 0x42, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x00, 0x45, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x9F, 0x7F, 0x00], &fixtures::sw(0x6A88));
    let mut mock = trace.mock();

    let info = discover_card(&mut mock, None).expect("discover");
    mock.assert_drained();

    assert_eq!(info.isd_aid.as_bytes(), &ISD);
    assert_eq!(info.scp_supported.len(), 1);
    assert_eq!(info.scp_supported[0], ScpVariant::Scp03 { i_param: 0x70 });
    assert_eq!(info.scp_default, ScpVariant::Scp03 { i_param: 0x70 });
    assert_eq!(info.isd_keysets.len(), 1);
    assert_eq!(info.isd_keysets[0].kvn, 1);
    assert_eq!(info.isd_keysets[0].keys.len(), 3);
    assert_eq!(info.capabilities.max_logical_channels, 4);
    assert!(info.iin.is_none());
    assert!(info.cin.is_none());
}

#[test]
fn discover_missing_crd_falls_back_to_scp02() {
    let trace = Trace::new()
        .step(
            select_by_aid(&ISD).unwrap().as_slice(),
            &fixtures::rapdu(&fixtures::fci_with_aid(&ISD), OK),
        )
        .step(&[0x80, 0xCA, 0x00, 0x66, 0x00], &fixtures::sw(0x6A88)) // no CRD
        .step(&[0x80, 0xCA, 0x00, 0xE0, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x00, 0x67, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x00, 0x42, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x00, 0x45, 0x00], &fixtures::sw(0x6A88))
        .step(&[0x80, 0xCA, 0x9F, 0x7F, 0x00], &fixtures::sw(0x6A88));
    let mut mock = trace.mock();
    let info = discover_card(&mut mock, Some(&ISD)).expect("discover");
    mock.assert_drained();
    assert_eq!(info.scp_default, ScpVariant::Scp02 { i_param: 0x55 });
}

#[test]
fn open_scp03_reports_capped_level() {
    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let mut mock = trace.mock();
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];

    let report = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD)).expect("open_scp");
    mock.assert_drained();

    assert!(matches!(report.session, ScpSession::Scp03(_)));
    assert!(matches!(
        report.effective.scp_protocol_effective,
        ScpProtocol::Scp03
    ));
    assert_eq!(report.effective.security_level_effective, 0x33);
    assert_eq!(report.effective.i_param_effective, 0x70);
    assert_eq!(report.effective.kvn_effective, 0x00);
}

#[test]
fn full_chain_open_status_putkey_delete() {
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];

    // Expected in-session C-APDUs (stub echoes the plaintext the builders emit).
    let get_status_wire = get_status(0x80, &[]).unwrap();
    let blocks = [
        KeyBlock {
            key_type: 0x88,
            encrypted_key: &ENC_BLOCK,
            kcv: KCV,
            clear_key_len: 16,
        },
        KeyBlock {
            key_type: 0x88,
            encrypted_key: &ENC_BLOCK,
            kcv: KCV,
            clear_key_len: 16,
        },
        KeyBlock {
            key_type: 0x88,
            encrypted_key: &ENC_BLOCK,
            kcv: KCV,
            clear_key_len: 16,
        },
    ];
    let put_key_wire = put_key(0x00, 0x30, &blocks).unwrap(); // P1 = 0x00: Add
    let delete_key_wire = delete_key(None, Some(0x20)).unwrap(); // KVN-only ('D2')

    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let trace = trace
        .step(
            get_status_wire.as_slice(),
            &fixtures::rapdu(&fixtures::status_e3(0x0F), OK),
        )
        .step(
            put_key_wire.as_slice(),
            &fixtures::rapdu(&fixtures::put_key_echo(0x30, KCV), OK),
        )
        .step(delete_key_wire.as_slice(), &fixtures::sw(OK));
    let mut mock = trace.mock();

    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let status = get_card_status(&mut mock, &backend, &mut session, &ISD).expect("get_status");
    assert_eq!(status.state, CardLifeCycle::Secured);

    let put = put_sd_keys(
        &mut mock,
        &backend,
        &mut session,
        &PutSdKeysArgs {
            dek: h0(),
            new_keys: NewKeyset {
                enc: h0(),
                mac: h0(),
                dek: h0(),
                kind: KeyKind::Aes128,
            },
            new_kvn: 0x30,
            target_sd_aid: &ISD,
        },
    )
    .expect("put_sd_keys");
    assert_eq!(put.effective.new_kvn, 0x30);
    assert_eq!(&put.effective.kcvs[0..3], &KCV);

    let del =
        delete_sd_keyset(&mut mock, &backend, &mut session, 0x20, &ISD).expect("delete_sd_keyset");
    assert_eq!(del.effective.kvn, 0x20);

    mock.assert_drained();
}

/// §5.12a — `get_card_inventory` over the three GET STATUS scopes with `63 10`
/// paging. Exercises: ISD recorded once (de-duplicated out of the `0x40` scope),
/// SD-vs-application split by the Security Domain privilege bit, the `'CC'`
/// associated-SD default to the ISD, the `'C4'` application ELF AID, ELF modules
/// (`'84'`), and multi-page continuation in two scopes. Wire bytes and the
/// expected inventory were cross-checked against a standalone byte model.
#[test]
fn get_card_inventory_three_scopes_with_paging() {
    // Extra AIDs beyond the shared consts (ISD/SSD/ELF/MODULE/INSTANCE).
    const APP2: [u8; 7] = [0xD2, 0x76, 0x00, 0x01, 0x18, 0x00, 0x02];
    const ELF2: [u8; 6] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03];
    const ELF2_MOD1: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01];
    const ELF2_MOD2: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x02];

    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];

    // ISD: 3-byte privileges with the Security Domain bit (0x80) set.
    let isd_e3 = fixtures::status_e3_app(&ISD, 0x0F, &[0x9E, 0xFE, 0x80]);
    // Supplementary SD: SD bit set, no other privileges.
    let ssd_e3 = fixtures::status_e3_app(&SSD, 0x0F, &[0x80, 0x00, 0x00]);
    // Application instance (no SD bit), no '4F'-only associated SD ⇒ defaults ISD.
    let app1_e3 = fixtures::status_e3_app(&INSTANCE, 0x07, &[0x00, 0x00, 0x00]);
    // Application carrying a 'C4' ELF AID; built inline (fixtures omit 'C4').
    let app2_e3 = {
        let mut inner = std::vec::Vec::new();
        inner.extend_from_slice(&[0x4F, u8::try_from(APP2.len()).unwrap()]);
        inner.extend_from_slice(&APP2);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, 0x07]);
        inner.extend_from_slice(&[0xC5, 0x03, 0x00, 0x00, 0x00]);
        inner.extend_from_slice(&[0xC4, u8::try_from(ELF2.len()).unwrap()]);
        inner.extend_from_slice(&ELF2);
        let mut e = std::vec::Vec::new();
        e.extend_from_slice(&[0xE3, u8::try_from(inner.len()).unwrap()]);
        e.extend_from_slice(&inner);
        e
    };
    let elf1_e3 = fixtures::status_e3_elf(&ELF, 0x01, &ISD, &[&MODULE]);
    let elf2_e3 = fixtures::status_e3_elf(&ELF2, 0x01, &ISD, &[&ELF2_MOD1, &ELF2_MOD2]);

    // 0x40 page 1 includes a duplicate ISD entry, which must be de-duplicated.
    let scope40_page1 = [isd_e3.clone(), ssd_e3, app1_e3].concat();

    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let trace = trace
        // ISD scope (0x80): one page, ends 9000.
        .step(
            get_status_p2(0x80, 0x02, &[]).unwrap().as_slice(),
            &fixtures::rapdu(&isd_e3, OK),
        )
        // Apps + SDs (0x40): page 1 ⇒ 63 10, page 2 ⇒ 9000.
        .step(
            get_status_p2(0x40, 0x02, &[]).unwrap().as_slice(),
            &fixtures::rapdu(&scope40_page1, 0x6310),
        )
        .step(
            get_status_p2(0x40, 0x03, &[]).unwrap().as_slice(),
            &fixtures::rapdu(&app2_e3, OK),
        )
        // ELFs + modules (0x10): page 1 ⇒ 63 10, page 2 ⇒ 9000.
        .step(
            get_status_p2(0x10, 0x02, &[]).unwrap().as_slice(),
            &fixtures::rapdu(&elf1_e3, 0x6310),
        )
        .step(
            get_status_p2(0x10, 0x03, &[]).unwrap().as_slice(),
            &fixtures::rapdu(&elf2_e3, OK),
        );
    let mut mock = trace.mock();

    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let report =
        get_card_inventory(&mut mock, &backend, &mut session, &ISD).expect("get_card_inventory");
    mock.assert_drained();

    let inv = &report.inventory;

    // Security Domains: ISD (recorded once, no parent) + one SSD.
    assert_eq!(inv.security_domains.len(), 2);
    assert_eq!(inv.security_domains[0].aid.as_bytes(), &ISD);
    assert_eq!(inv.security_domains[0].life_cycle_state, 0x0F);
    assert_eq!(inv.security_domains[0].privileges, [0x9E, 0xFE, 0x80]);
    assert!(inv.security_domains[0].associated_sd_aid.is_none());
    assert_eq!(inv.security_domains[1].aid.as_bytes(), &SSD);
    // ISD must appear exactly once despite being echoed in the 0x40 scope too.
    let isd_hits = inv
        .security_domains
        .iter()
        .filter(|s| s.aid.as_bytes() == ISD.as_slice())
        .count();
    assert_eq!(isd_hits, 1);

    // Applications: APP1 (CC absent ⇒ parent defaults to ISD) + APP2 (with C4).
    assert_eq!(inv.applets.len(), 2);
    assert_eq!(inv.applets[0].aid.as_bytes(), &INSTANCE);
    assert_eq!(inv.applets[0].associated_sd_aid.as_bytes(), &ISD);
    assert!(inv.applets[0].associated_elf_aid.is_none());
    assert_eq!(inv.applets[1].aid.as_bytes(), &APP2);
    assert_eq!(
        inv.applets[1]
            .associated_elf_aid
            .as_ref()
            .map(Aid::as_bytes),
        Some(&ELF2[..])
    );

    // ELFs: ELF1 (1 module) + ELF2 (2 modules), associated SD = ISD.
    assert_eq!(inv.elfs.len(), 2);
    assert_eq!(inv.elfs[0].aid.as_bytes(), &ELF);
    assert_eq!(inv.elfs[0].associated_sd_aid.as_bytes(), &ISD);
    assert_eq!(inv.elfs[0].modules.len(), 1);
    assert_eq!(inv.elfs[0].modules[0].as_bytes(), &MODULE);
    assert_eq!(inv.elfs[1].aid.as_bytes(), &ELF2);
    assert_eq!(inv.elfs[1].modules.len(), 2);
    assert_eq!(inv.elfs[1].modules[1].as_bytes(), &ELF2_MOD2);

    // Nothing exceeded a capacity bound ⇒ no truncation warning.
    assert!(!report.effective.truncated);
    assert!(report.warnings.is_empty());
    assert_eq!(report.effective.security_domain_count, 2);
    assert_eq!(report.effective.application_count, 2);
    assert_eq!(report.effective.elf_count, 2);
    assert_eq!(report.effective.isd_aid.as_bytes(), &ISD);
}

/// Regression for a live NXP JCOP 4 P71 (SCP02 i=0x55) capture: `63 10`
/// response chaining split a GET STATUS entry **mid-TLV** — inside a module
/// AID's value, not on an `'E3'` entry boundary — which the old per-page
/// parser rejected with "TLV value runs past end of buffer" (CHANGELOG
/// patch #12; GPCS v2.3.1 §11.4 Table 11-38 chains at the byte level, not the
/// entry level). Splits the second module's AID 3 bytes from the end, i.e.
/// strictly inside its `'84'` value — the same shape as the real capture —
/// and checks `get_card_inventory` reassembles it correctly instead of
/// erroring or silently dropping the entry.
#[test]
fn get_card_inventory_paging_splits_entry_mid_tlv() {
    const MOD_A: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x01];
    const MOD_B: [u8; 7] = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x02];

    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];

    let elf_e3 = fixtures::status_e3_elf(&ELF, 0x01, &ISD, &[&MOD_A, &MOD_B]);
    // Split 3 bytes before the end — strictly inside MOD_B's 7-byte value,
    // not at any tag/length boundary.
    let split = elf_e3.len() - 3;
    let (page1, page2) = elf_e3.split_at(split);

    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let trace = trace
        // ISD scope (0x80) and Apps+SDs (0x40): empty, not under test here.
        .step(
            get_status_p2(0x80, 0x02, &[]).unwrap().as_slice(),
            &fixtures::sw(0x6A88),
        )
        .step(
            get_status_p2(0x40, 0x02, &[]).unwrap().as_slice(),
            &fixtures::sw(0x6A88),
        )
        // ELFs + modules (0x10): page 1 ends mid-TLV with 63 10; page 2
        // carries the remaining 3 bytes and completes with 9000.
        .step(
            get_status_p2(0x10, 0x02, &[]).unwrap().as_slice(),
            &fixtures::rapdu(page1, 0x6310),
        )
        .step(
            get_status_p2(0x10, 0x03, &[]).unwrap().as_slice(),
            &fixtures::rapdu(page2, OK),
        );
    let mut mock = trace.mock();

    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let report =
        get_card_inventory(&mut mock, &backend, &mut session, &ISD).expect("get_card_inventory");
    mock.assert_drained();

    let inv = &report.inventory;
    assert_eq!(inv.elfs.len(), 1);
    assert_eq!(inv.elfs[0].aid.as_bytes(), &ELF);
    assert_eq!(inv.elfs[0].modules.len(), 2);
    assert_eq!(inv.elfs[0].modules[0].as_bytes(), &MOD_A);
    assert_eq!(inv.elfs[0].modules[1].as_bytes(), &MOD_B);
    assert!(!report.effective.truncated);
    assert!(report.warnings.is_empty());
}

#[test]
fn set_card_status_same_state_is_no_op_no_apdu() {
    // Session opened, then SET STATUS to the state we say we are already in:
    // no APDU is sent (the no-op is detected before the wire).
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];
    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let mut mock = trace.mock();
    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let report = set_card_status(
        &mut mock,
        &backend,
        &mut session,
        &SetCardStatusArgs {
            target_state: CardLifeCycle::Secured,
            current_state: Some(CardLifeCycle::Secured),
            force: false,
            isd_aid: &ISD,
        },
    )
    .expect("set_card_status");
    assert!(report.effective.was_no_op);
    mock.assert_drained(); // nothing beyond the open exchange
}

#[test]
fn create_ssd_then_install_and_delete_applet() {
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];

    let install_params = [0xC9, 0x00]; // mandatory empty C9
    let create_wire = install_for_install_make_selectable(
        &ELF,
        &MODULE,
        &SSD,
        [0x80, 0x00, 0x00],
        PrivLen::Canonical,
        &install_params,
    )
    .unwrap();
    // install_applet assembles its own params: C9 00 (no system params here).
    let applet_install_wire = install_for_install_make_selectable(
        &ELF,
        &MODULE,
        &INSTANCE,
        [0x00, 0x00, 0x00],
        PrivLen::Canonical,
        &[0xC9, 0x00],
    )
    .unwrap();
    let delete_instance_wire = delete_object(&INSTANCE, false).unwrap();

    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let trace = trace
        .step(create_wire.as_slice(), &fixtures::sw(OK))
        .step(applet_install_wire.as_slice(), &fixtures::sw(OK))
        .step(delete_instance_wire.as_slice(), &fixtures::sw(OK));
    let mut mock = trace.mock();

    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let ssd = create_ssd(
        &mut mock,
        &backend,
        &mut session,
        &CreateSsdArgs {
            parent_sd_aid: &ISD,
            ssd_aid: &SSD,
            elf_aid: &ELF,
            module_aid: &MODULE,
            privileges: [0x80, 0x00, 0x00], // Security Domain only — allowed
            install_params: &install_params,
        },
        PrivLen::Canonical,
    )
    .expect("create_ssd");
    assert_eq!(ssd.effective.ssd_aid_effective.as_bytes(), &SSD);

    let inst = install_applet(
        &mut mock,
        &backend,
        &mut session,
        &InstallAppletArgs {
            parent_sd_aid: &ISD,
            package_aid: &ELF,
            module_aid: &MODULE,
            instance_aid: &INSTANCE,
            privileges: [0x00, 0x00, 0x00],
            system_install_params: &[],
            applet_install_params: &[],
        },
        PrivLen::Canonical,
    )
    .expect("install_applet");
    assert_eq!(inst.effective.instance_aid.as_bytes(), &INSTANCE);

    let del = delete_applet(
        &mut mock,
        &backend,
        &mut session,
        &DeleteAppletArgs {
            instance_aid: &INSTANCE,
            elf_aid: None,
            cascade_elf: DeleteCascade::Never,
        },
    )
    .expect("delete_applet");
    assert_eq!(del.effective.instances_removed.len(), 1);
    mock.assert_drained();
}

#[test]
fn create_ssd_refuses_delegated_management_privilege() {
    // DM privilege (0x20 in byte 1) must be refused before any APDU is sent.
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];
    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let mut mock = trace.mock();
    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;

    let result = create_ssd(
        &mut mock,
        &backend,
        &mut session,
        &CreateSsdArgs {
            parent_sd_aid: &ISD,
            ssd_aid: &SSD,
            elf_aid: &ELF,
            module_aid: &MODULE,
            privileges: [0x20, 0x00, 0x00],
            install_params: &[0xC9, 0x00],
        },
        PrivLen::Canonical,
    );
    assert!(matches!(
        result,
        Err(scll_core::error::ScllError::UnsupportedPrivilege)
    ));
    mock.assert_drained();
}

#[test]
fn transmit_round_trips_plaintext_over_session() {
    let backend = StubBackend::new();
    let advertised = [ScpVariant::Scp03 { i_param: 0x70 }];
    let app_capdu = [0x00, 0xA4, 0x04, 0x00, 0x00];
    let mut trace = Trace::new();
    open_scp03(&mut trace);
    let trace = trace.step(&app_capdu, &fixtures::rapdu(&[0xDE, 0xAD], OK));
    let mut mock = trace.mock();

    let mut session = open_scp(&mut mock, &backend, &open_args(&advertised, &ISD))
        .expect("open_scp")
        .session;
    let report = send_apdu(&mut mock, &backend, &mut session, &app_capdu).expect("transmit");
    assert_eq!(report.sw, OK);
    assert_eq!(report.rapdu.as_slice(), &[0xDE, 0xAD]);
    mock.assert_drained();
}
