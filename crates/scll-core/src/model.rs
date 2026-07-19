//! Public card model — PDD §6. Returned by `discover_card` (§5.2). Read-only.
//!
//! `no_std` + heapless: every former `Vec`/`String` is a fixed-capacity
//! `heapless::Vec`/`heapless::String`; capacities live in [`crate::limits`].
//! `Aid` is the validating newtype (5..=16 bytes; ISO/IEC 7816-5).

use core::fmt;

use heapless::{String, Vec};

use crate::limits::MAX_APPLETS;

use crate::aid::Aid;
use crate::command::install::PrivLen;
use crate::limits::{
    ATR_ATS_MAX, CIN_MAX, GETDATA_RAW_MAX, IIN_MAX, MAX_CIPHERS, MAX_ELFS, MAX_KEYSETS,
    MAX_KEYS_PER_SET, MAX_MODULES_PER_ELF, MAX_PRIVILEGE_BYTES, MAX_QUIRKS, MAX_SCP_VARIANTS,
    MAX_SDS, MAX_WARNINGS, OTHER_DETAIL_MAX,
};
use crate::transport::TransportProtocol;

/// Everything the card willingly reports before SCP authentication (§5.2).
pub struct CardInfo {
    // Basic identity
    pub isd_aid: Aid,
    pub atr_or_ats: Vec<u8, ATR_ATS_MAX>,
    pub transport_protocol: TransportProtocol,

    // SCP capability — drives session-open logic (§4.3)
    pub scp_supported: Vec<ScpVariant, MAX_SCP_VARIANTS>, // every (scp_id, i) advertised
    pub scp_default: ScpVariant,                          // first listed in CRD '64'

    // ISD key inventory — drives PUT KEY pre-flight
    pub isd_keysets: Vec<Keyset, MAX_KEYSETS>, // grouped by KVN
    pub isd_key_template_format: KeyTemplateFormat,

    // Card capability — drives channel choice, cipher selection
    pub capabilities: CardCapabilities,
    pub card_recognition_data_raw: Vec<u8, GETDATA_RAW_MAX>, // raw '66' for diagnostics

    // Optional identifying data
    pub iin: Option<Vec<u8, IIN_MAX>>, // GET DATA '0042'
    pub cin: Option<Vec<u8, CIN_MAX>>, // GET DATA '0045'
    pub card_image_number: Option<Vec<u8, CIN_MAX>>, // alias of cin if present
    pub jc_platform_version: Option<(u8, u8, u8)>,

    // Card-implementation quirk: GP Privileges field encoding length, chosen at
    // discovery from CPLC (NXP JCOP → 1-byte, else canonical 3-byte). PDD §5.2.
    pub privilege_encoding: PrivLen,

    // Diagnostic
    pub quirks_detected: Vec<String<OTHER_DETAIL_MAX>, MAX_QUIRKS>,
    pub discovery_warnings: Vec<DiscoveryWarning, MAX_WARNINGS>,
}

/// Object inventory snapshot — the payload of `get_card_inventory`
/// (`GetCardInventoryReport`, PDD §5.12a). A point-in-time view, stale after the
/// next management operation.
#[derive(Debug)]
pub struct CardInventory {
    pub security_domains: Vec<SecurityDomainEntry, MAX_SDS>,
    pub applets: Vec<ApplicationEntry, MAX_APPLETS>,
    pub elfs: Vec<ExecutableLoadFileEntry, MAX_ELFS>,
}

/// One advertised secure-channel variant (scp id + `i` parameter).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScpVariant {
    Scp02 { i_param: u8 }, // i = 0x55 typical modern default
    Scp03 { i_param: u8 }, // i = 0x70 typical modern default
}

impl fmt::Debug for ScpVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, i) = match self {
            ScpVariant::Scp02 { i_param } => ("Scp02", i_param),
            ScpVariant::Scp03 { i_param } => ("Scp03", i_param),
        };
        f.debug_struct(name)
            .field("i_param", &format_args!("{i:#04x}"))
            .finish()
    }
}

/// A keyset grouped by Key Version Number.
pub struct Keyset {
    pub kvn: u8,
    pub keys: Vec<KeyInfo, MAX_KEYS_PER_SET>, // typically 3 entries (KID 1,2,3)
}

// Manual `Debug`: the KVN is a protocol scalar whose hex form is the
// meaningful one (KVN `0x30`, not the derive's decimal `48`) — same rationale
// and style as `KeyInfo::kid` below and `OpenScpParams` (v0.9o).
impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyset")
            .field("kvn", &format_args!("{:#04x}", self.kvn))
            .field("keys", &self.keys)
            .finish()
    }
}

/// One key slot from the Key Information Template (`'00E0'`).
///
/// v0.9k: the Extended-format `key_usage`/`key_access` placeholder fields were
/// removed — the extended sub-template decode was never implemented, so they
/// were structurally always `None` (an extended entry is still *detected* and
/// reported via [`KeyTemplateFormat::Extended`]).
pub struct KeyInfo {
    pub kid: u8,
    pub key_type: KeyType,
    pub key_length: u8,
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("kid", &format_args!("{:#04x}", self.kid))
            .field("key_type", &self.key_type)
            .field("key_length", &self.key_length)
            .finish()
    }
}

/// GP key-type byte decode (§5.2 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Des,                // 0x80, SCP02
    Aes,                // 0x88, SCP03
    RsaPublic,          // 0xA1
    RsaPrivateCrt,      // 0xA2
    RsaPrivateExponent, // 0xA3
    EccPublic,          // 0xB0
    EccPrivate,         // 0xB1
    EccParametersRef,   // 0xB2
    Other(u8),
}

/// Key Information Template format.
#[derive(Debug)]
pub enum KeyTemplateFormat {
    Basic,    // GPCS 2.2 single-byte fields
    Extended, // GPCS 2.3+ B9-tagged sub-template
}

/// Parsed Card Capability Information (`'67'`, §H.4).
pub struct CardCapabilities {
    pub max_logical_channels: u8, // default 1 if absent
    pub ciphers_supported: Vec<CipherAlg, MAX_CIPHERS>,
    pub privileges_supported: Vec<u8, MAX_PRIVILEGE_BYTES>,
    pub memory_total_bytes: Option<u32>,
    pub memory_free_bytes: Option<u32>,
    pub cci_raw: Vec<u8, GETDATA_RAW_MAX>, // raw '67' for diagnostics
}

/// Cipher algorithms advertised in CCI `'A1'`.
#[non_exhaustive]
#[derive(Debug)]
pub enum CipherAlg {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Other(String<OTHER_DETAIL_MAX>),
}

/// Security Domain registry entry.
pub struct SecurityDomainEntry {
    pub aid: Aid,
    pub life_cycle_state: u8, // raw GP life-cycle byte
    pub privileges: [u8; 3],
    pub associated_sd_aid: Option<Aid>, // present for SSDs; None for ISD
}

/// Application (applet instance) registry entry.
pub struct ApplicationEntry {
    pub aid: Aid,
    pub life_cycle_state: u8,
    pub privileges: [u8; 3],
    pub associated_sd_aid: Aid,          // applets always have a parent SD
    pub associated_elf_aid: Option<Aid>, // the app's ELF; present if card exposes tag 'C4'
}

/// Executable Load File registry entry.
#[derive(Debug)]
pub struct ExecutableLoadFileEntry {
    pub aid: Aid,
    pub life_cycle_state: u8,
    pub associated_sd_aid: Aid,
    pub modules: Vec<Aid, MAX_MODULES_PER_ELF>, // class AIDs inside this ELF
}

/// Typed discovery warning — discovery never errors on missing optional data.
#[non_exhaustive]
#[derive(Debug)]
pub enum DiscoveryWarning {
    CardRecognitionDataMissing,
    KeyInformationTemplateMissing,
    CardCapabilityInfoMissing,
    UnknownLifecycleByte(u8),
    GetStatusParseFailed,
    Other(String<OTHER_DETAIL_MAX>),
}

// ─── Debug impls: render raw byte fields as hex strings (AIDs handled by `Aid`) ──

impl core::fmt::Debug for CardInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CardInfo")
            .field("isd_aid", &self.isd_aid)
            .field(
                "atr_or_ats",
                &crate::hexfmt::HexBytes(self.atr_or_ats.as_slice()),
            )
            .field("transport_protocol", &self.transport_protocol)
            .field("scp_supported", &self.scp_supported)
            .field("scp_default", &self.scp_default)
            .field("isd_keysets", &self.isd_keysets)
            .field("isd_key_template_format", &self.isd_key_template_format)
            .field("capabilities", &self.capabilities)
            .field(
                "card_recognition_data_raw",
                &crate::hexfmt::HexBytes(self.card_recognition_data_raw.as_slice()),
            )
            .field("iin", &self.iin.as_deref().map(crate::hexfmt::HexBytes))
            .field("cin", &self.cin.as_deref().map(crate::hexfmt::HexBytes))
            .field(
                "card_image_number",
                &self
                    .card_image_number
                    .as_deref()
                    .map(crate::hexfmt::HexBytes),
            )
            .field("jc_platform_version", &self.jc_platform_version)
            .field("privilege_encoding", &self.privilege_encoding)
            .field("quirks_detected", &self.quirks_detected)
            .field("discovery_warnings", &self.discovery_warnings)
            .finish()
    }
}

impl core::fmt::Debug for CardCapabilities {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CardCapabilities")
            .field("max_logical_channels", &self.max_logical_channels)
            .field("ciphers_supported", &self.ciphers_supported)
            .field(
                "privileges_supported",
                &crate::hexfmt::HexBytes(self.privileges_supported.as_slice()),
            )
            .field("memory_total_bytes", &self.memory_total_bytes)
            .field("memory_free_bytes", &self.memory_free_bytes)
            .field("cci_raw", &crate::hexfmt::HexBytes(self.cci_raw.as_slice()))
            .finish()
    }
}

impl core::fmt::Debug for SecurityDomainEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityDomainEntry")
            .field("aid", &self.aid)
            .field("life_cycle_state", &self.life_cycle_state)
            .field("privileges", &crate::hexfmt::HexBytes(&self.privileges[..]))
            .field("associated_sd_aid", &self.associated_sd_aid)
            .finish()
    }
}

impl core::fmt::Debug for ApplicationEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApplicationEntry")
            .field("aid", &self.aid)
            .field("life_cycle_state", &self.life_cycle_state)
            .field("privileges", &crate::hexfmt::HexBytes(&self.privileges[..]))
            .field("associated_sd_aid", &self.associated_sd_aid)
            .field("associated_elf_aid", &self.associated_elf_aid)
            .finish()
    }
}
