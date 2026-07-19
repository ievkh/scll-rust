//! Per-function reports — PDD §7.
//!
//! The universal `OperationResult`/`EffectiveParams`/`OperationKind`/
//! `CommonParams`/`StepSpecific` envelope is removed (v0.6). Each workflow
//! function returns `Result<XReport, ScllError>`; the report carries the typed
//! payload, the *effective* parameters, and any non-fatal warnings. No per-call
//! timestamp/version (kept deterministic for snapshot tests, §10.3).
//!
//! `no_std` + heapless: every former `Vec` is a fixed-capacity `heapless::Vec`
//! sized from [`crate::limits`].

use heapless::Vec;

use crate::aid::Aid;
use crate::error::Warning;
use crate::limits::{
    CAPDU_MAX, HASH_MAX, INSTALL_PARAMS_MAX, MAX_REMOVED_OBJECTS, MAX_WARNINGS, RAPDU_MAX,
    TRANSPORT_NAME_MAX,
};
use crate::model::{CardInventory, KeyType};
use crate::scp::ScpSession;
use crate::transport::TransportCaps;

// --- Reports (one per workflow function) ---
#[derive(Debug)]
pub struct ProbeReport {
    pub effective: ProbeParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct PutKeysReport {
    pub effective: PutKeysParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct DeleteKeyReport {
    pub effective: DeleteKeyParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct CreateSsdReport {
    pub effective: CreateSsdParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct LoadPackageReport {
    pub effective: LoadPackageParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
/// Shared by `delete_ssd` and `delete_applet`.
#[derive(Debug)]
pub struct DeleteObjectReport {
    pub effective: DeleteObjectParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct InstallAppletReport {
    pub effective: InstallAppletParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
pub struct AppletTransmitReport {
    pub rapdu: Vec<u8, RAPDU_MAX>,
    pub sw: u16,
    pub effective: AppletTransmitParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct SetCardStatusReport {
    pub effective: SetCardStatusParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
#[derive(Debug)]
pub struct GetCardStatusReport {
    pub state: CardLifeCycle,
    pub effective: GetCardStatusParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
/// `get_card_inventory` (§5.12a) yields the enumerated object inventory as its
/// payload — Security Domains, Applications, and ELFs in one [`CardInventory`].
#[derive(Debug)]
pub struct GetCardInventoryReport {
    pub inventory: CardInventory,
    pub effective: GetCardInventoryParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}
/// `open_scp` additionally yields the session as its payload.
pub struct OpenScpReport {
    pub session: ScpSession,
    pub effective: OpenScpParams,
    pub warnings: Vec<Warning, MAX_WARNINGS>,
}

// Optional APDU trace lives on the report when enabled (keys redacted); omitted
// from the structs above for brevity, per §7.

// --- Effective-parameter payloads ---

#[derive(Debug)]
pub struct DiscoverCardParams {
    pub isd_select_strategy: IsdSelectStrategy,
    pub used_cached_isd_aid: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsdSelectStrategy {
    Empty,
    ByAid,
}

/// PUT KEY is Add-only over a session against the target SD itself (P1 =
/// `0x00`, GPCS v2.3.1 §11.8.2.1 Table 11-66) since patch #29 — the mode /
/// mechanism selectors were removed with the unverified Replace / Generate /
/// parent-mediated paths.
pub struct PutKeysParams {
    pub target_sd_aid: Aid,
    pub scp_protocol: ScpProtocol,
    pub new_kvn: u8,
    pub key_type: KeyType,
    pub key_length: u8,
    pub kcvs: [u8; 9], // 3 bytes × 3 keys (ENC, MAC, DEK)
}
#[derive(Debug, Clone, Copy)]
pub enum ScpProtocol {
    Scp02,
    Scp03,
}

/// DELETE KEY is KVN-only (single `'D2'` reference, GPCS v2.3.1 §11.2.2.3.2)
/// since patch #29 — the per-KID path was removed (`6A88` on JCOP 4 P71).
pub struct DeleteKeyParams {
    pub target_sd_aid: Aid,
    pub kvn: u8, // tag 'D2'; every key of this version is deleted
}

impl core::fmt::Debug for DeleteKeyParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeleteKeyParams")
            .field("target_sd_aid", &self.target_sd_aid)
            .field("kvn", &crate::hexfmt::HexByte(self.kvn))
            .finish()
    }
}

pub struct CreateSsdParams {
    pub ssd_aid_effective: Aid,
    pub aid_was_generated: bool,
    pub parent_sd_aid: Aid,
    pub privileges_used: [u8; 3],
    pub elf_aid_used: Aid,
    pub module_aid_used: Aid,
    pub install_params_used: Vec<u8, INSTALL_PARAMS_MAX>,
}

pub struct LoadPackageParams {
    pub package_aid: Aid,
    pub load_file_size: u32,
    pub hash_value: Vec<u8, HASH_MAX>,
    pub block_count: u16,
    pub target_sd_aid: Aid,
}

#[derive(Debug)]
pub struct DeleteObjectParams {
    pub target_aid: Aid,
    pub target_kind: DeleteTargetKind,
    pub cascade_requested: DeleteCascade,
    pub cascade_used: bool,
    pub instances_removed: Vec<Aid, MAX_REMOVED_OBJECTS>,
    pub elfs_removed: Vec<Aid, MAX_REMOVED_OBJECTS>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteTargetKind {
    Ssd,
    AppletInstance,
    ExecutableLoadFile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteCascade {
    Never,
    OnlyIfEmpty,
    IfLastInstance,
    Cascade,
    Always,
}

pub struct InstallAppletParams {
    pub instance_aid: Aid,
    pub package_aid_used: Aid,
    pub module_aid_used: Aid,
    pub privileges_used: [u8; 3],
    pub system_install_params: Vec<u8, INSTALL_PARAMS_MAX>,
    pub applet_install_params: Vec<u8, INSTALL_PARAMS_MAX>,
    pub parent_sd_aid: Aid,
}

pub struct OpenScpParams {
    pub target_aid: Aid,
    pub target_kind: ScpTargetKind,
    pub sd_aid_used_for_keys: Aid,
    pub scp_protocol_effective: ScpProtocol, // outcome of §4.3 selection
    pub kvn_requested: u8,
    pub kvn_effective: u8,
    pub i_param_effective: u8,
    pub security_level_requested: u8,
    pub security_level_effective: u8,
    pub session_id: u64,
    pub invoker_aid_used: Aid,
}

// Manual `Debug`: the key version numbers, the SCP `i` parameter, and the
// security level are protocol scalars whose hex/bitmask form is the
// meaningful one for smart-card debugging (e.g. KVN `0x30`, i = `0x70`,
// level `0x13` = C-MAC|C-DECRYPTION|R-MAC per GPCS v2.3.1 §E, Table 10-1),
// not the derive's decimal `48`/`112`/`19`. All other fields keep their
// normal `Debug`.
impl core::fmt::Debug for OpenScpParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenScpParams")
            .field("target_aid", &self.target_aid)
            .field("target_kind", &self.target_kind)
            .field("sd_aid_used_for_keys", &self.sd_aid_used_for_keys)
            .field("scp_protocol_effective", &self.scp_protocol_effective)
            .field("kvn_requested", &crate::hexfmt::HexByte(self.kvn_requested))
            .field("kvn_effective", &crate::hexfmt::HexByte(self.kvn_effective))
            .field(
                "i_param_effective",
                &crate::hexfmt::HexByte(self.i_param_effective),
            )
            .field(
                "security_level_requested",
                &crate::hexfmt::HexByte(self.security_level_requested),
            )
            .field(
                "security_level_effective",
                &crate::hexfmt::HexByte(self.security_level_effective),
            )
            .field("session_id", &self.session_id)
            .field("invoker_aid_used", &self.invoker_aid_used)
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpTargetKind {
    SecurityDomainAid,
    ApplicationAid,
}

pub struct AppletTransmitParams {
    pub session_id: u64,
    pub capdu_plaintext_len: u16,
    pub rapdu_plaintext_len: u16,
    pub sw: [u8; 2],
    pub sec_level: u8,
    pub scp_protocol: ScpProtocol,
}

#[derive(Debug)]
pub struct SetCardStatusParams {
    pub state_before: CardLifeCycle,
    pub target_state: CardLifeCycle,
    pub p1_status_type: u8, // ISD scope (conventionally 0x80)
    pub p2_state_byte: u8,  // e.g. 0x0F SECURED, 0x7F CARD_LOCKED
    pub was_no_op: bool,
    pub force_used: bool,
    pub irreversible: bool,
}

#[derive(Debug)]
pub struct GetCardStatusParams {
    pub raw_state_byte: u8,
    pub decoded_state: CardLifeCycle,
    pub isd_aid: Aid,
}

/// Effective parameters of a `get_card_inventory` run (§5.12a). The counts are
/// the *retained* totals (after any capacity truncation); `truncated` is set
/// when a `CardInventory` bound or the per-scope page cap was hit, mirroring
/// the `WarningKind::InventoryTruncated` on the report.
#[derive(Debug)]
pub struct GetCardInventoryParams {
    pub isd_aid: Aid,
    pub security_domain_count: usize,
    pub application_count: usize,
    pub elf_count: usize,
    pub truncated: bool,
}

/// Card life-cycle state (GPCS v2.3.1 Table 11-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardLifeCycle {
    OpReady,     // 0x01
    Initialized, // 0x07
    Secured,     // 0x0F
    CardLocked,  // 0x7F
    Terminated,  // 0xFF (read-only; never a set target — §2.2)
    Unknown(u8), // raises WarningKind::UnknownLifecycleByte
}

#[derive(Debug)]
pub struct ProbeParams {
    pub transport_name: TransportName,
    pub transport_capabilities: TransportCaps,
}

/// Transport identity (was a `String`). The known transports are a static set,
/// so an enum is alloc-free and exhaustively matchable; `Other` keeps
/// caller-supplied transports open. The `Other` buffer is the only heap-free
/// string left on this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportName {
    Pcsc,
    Jcsim,
    User,
    Other(heapless::String<TRANSPORT_NAME_MAX>),
}

/// One recorded APDU (opt-in trace; keys/key-derived material redacted).
pub struct ApduRecord {
    pub direction: ApduDirection,
    pub cla_ins_p1_p2: [u8; 4],
    pub lc: u16,
    pub plaintext_data: Option<Vec<u8, CAPDU_MAX>>, // pre-wrap if session active
    pub wire_data: Vec<u8, CAPDU_MAX>,              // post-wrap actually transmitted
    pub le: Option<u8>,
    pub sw: Option<[u8; 2]>,
    pub timestamp_us: u64,
}
pub enum ApduDirection {
    CommandToCard,
    ResponseFromCard,
}

// ─── Debug impls: render raw byte fields as hex strings (AIDs handled by `Aid`) ──

impl core::fmt::Debug for CreateSsdParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreateSsdParams")
            .field("ssd_aid_effective", &self.ssd_aid_effective)
            .field("aid_was_generated", &self.aid_was_generated)
            .field("parent_sd_aid", &self.parent_sd_aid)
            .field(
                "privileges_used",
                &crate::hexfmt::HexBytes(&self.privileges_used[..]),
            )
            .field("elf_aid_used", &self.elf_aid_used)
            .field("module_aid_used", &self.module_aid_used)
            .field(
                "install_params_used",
                &crate::hexfmt::HexBytes(self.install_params_used.as_slice()),
            )
            .finish()
    }
}

impl core::fmt::Debug for LoadPackageParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadPackageParams")
            .field("package_aid", &self.package_aid)
            .field("load_file_size", &self.load_file_size)
            .field(
                "hash_value",
                &crate::hexfmt::HexBytes(self.hash_value.as_slice()),
            )
            .field("block_count", &self.block_count)
            .field("target_sd_aid", &self.target_sd_aid)
            .finish()
    }
}

impl core::fmt::Debug for InstallAppletParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InstallAppletParams")
            .field("instance_aid", &self.instance_aid)
            .field("package_aid_used", &self.package_aid_used)
            .field("module_aid_used", &self.module_aid_used)
            .field(
                "privileges_used",
                &crate::hexfmt::HexBytes(&self.privileges_used[..]),
            )
            .field(
                "system_install_params",
                &crate::hexfmt::HexBytes(self.system_install_params.as_slice()),
            )
            .field(
                "applet_install_params",
                &crate::hexfmt::HexBytes(self.applet_install_params.as_slice()),
            )
            .field("parent_sd_aid", &self.parent_sd_aid)
            .finish()
    }
}

impl core::fmt::Debug for PutKeysParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PutKeysParams")
            .field("target_sd_aid", &self.target_sd_aid)
            .field("scp_protocol", &self.scp_protocol)
            .field("new_kvn", &crate::hexfmt::HexByte(self.new_kvn))
            .field("key_type", &self.key_type)
            .field("key_length", &self.key_length)
            .field("kcvs", &crate::hexfmt::HexBytes(&self.kcvs[..]))
            .finish()
    }
}

impl core::fmt::Debug for AppletTransmitReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppletTransmitReport")
            .field("rapdu", &crate::hexfmt::HexBytes(self.rapdu.as_slice()))
            .field("sw", &format_args!("0x{:04X}", self.sw))
            .field("effective", &self.effective)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl core::fmt::Debug for AppletTransmitParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppletTransmitParams")
            .field("session_id", &self.session_id)
            .field("capdu_plaintext_len", &self.capdu_plaintext_len)
            .field("rapdu_plaintext_len", &self.rapdu_plaintext_len)
            .field("sw", &crate::hexfmt::HexBytes(&self.sw[..]))
            .field("sec_level", &self.sec_level)
            .field("scp_protocol", &self.scp_protocol)
            .finish()
    }
}
