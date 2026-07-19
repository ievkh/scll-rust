//! Card-response parsers — PDD §5.2 (discover) and §5.12 (`get_card_status`).
//!
//! Pure, fuzzable (§10.5 target #2): these consume bytes a malicious or buggy
//! card controls, so every function is **total** — malformed input yields a
//! typed [`TlvError`], never a panic (no `unwrap` on a bounded `heapless`
//! push). They sit one layer above [`crate::tlv`]: each walks the BER-TLV
//! template and decodes it into the public [`crate::model`] / [`crate::report`]
//! types.
//!
//! Four templates, all decoded here:
//!   * **Card Recognition Data** `'66'` → advertised SCP variants
//!     (GPCS v2.3.1 §H.2 — the `'64'` OID's last two octets are `scp_id`/`i`).
//!   * **Key Information Template** `'00E0'` → keysets grouped by KVN
//!     (GPCS v2.3.1 §11.3.3.1).
//!   * **Card Capability Information** `'67'` → [`CardCapabilities`]
//!     (GPCS v2.3.1 §H.4).
//!   * **`GET STATUS` GP Registry entry** `'E3'` → [`CardLifeCycle`]
//!     (GPCS v2.3.1 §11.4, Table 11-36; life-cycle byte is `'9F70'`).
//!
//! **Absent vs malformed.** A *missing* optional element is not an error: it
//! yields an empty list / `None` / the documented default, and the discovery
//! workflow (§5.2) turns that into a [`crate::error::WarningKind`], not a hard
//! failure. Only a structurally broken template (a real BER-TLV violation, or
//! more objects than the bounded model can hold) is reported as [`TlvError`].
//! Unknown *semantic* bytes (an unrecognised key type or life-cycle byte) are
//! absorbed into the model's `Other` / `Unknown` variants, never errors.

use heapless::Vec;

use crate::limits::{
    GETDATA_RAW_MAX, MAX_KEYSETS, MAX_KEYS_PER_SET, MAX_MODULES_PER_ELF, MAX_PRIVILEGE_BYTES,
    MAX_REGISTRY_ENTRIES, MAX_SCP_VARIANTS,
};
use crate::model::{CardCapabilities, KeyInfo, KeyTemplateFormat, KeyType, Keyset, ScpVariant};
use crate::report::CardLifeCycle;
use crate::tlv::{self, Tlv, TlvError};

// ---- Template / sub-tag constants (GPCS v2.3.1 §H / §11) -------------------

/// Card Recognition Data template (GET DATA `'66'`; GPCS §H.2).
const TAG_CRD: u32 = 0x66;
/// BER-TLV discretionary data carrying the CRD OIDs, nested in `'66'` (§H.2).
const TAG_CRD_BODY: u32 = 0x73;
/// `'64'` = "Secure Channel Protocol of the ISD and its implementation
/// options"; its `'06'` OID's final two octets are `(scp_id, i)` (§H.2).
const TAG_SCP_ENTRY: u32 = 0x64;
/// ASN.1 OBJECT IDENTIFIER tag.
const TAG_OID: u32 = 0x06;

/// Key Information Template (GET DATA `'00E0'`; GPCS §11.3.3.1).
const TAG_KEY_TEMPLATE: u32 = 0xE0;
/// One Key Information Data entry inside `'E0'`.
const TAG_KEY_ENTRY: u32 = 0xC0;
/// Extended-format marker following `KVN|KID` inside a `'C0'` (GPCS 2.3+).
const KEY_EXTENDED_MARKER: u8 = 0xB9;

/// Card Capability Information template (GET DATA `'67'`; GPCS §H.4).
const TAG_CCI: u32 = 0x67;
/// CCI sub-tag: number of logical channels (§H.4).
const TAG_CCI_CHANNELS: u32 = 0xA0;
/// CCI sub-tag: privileges supported (§H.4).
const TAG_CCI_PRIVILEGES: u32 = 0xA3;

/// `GlobalPlatform` Registry entry returned by `GET STATUS` (Table 11-36).
const TAG_GP_REGISTRY: u32 = 0xE3;
/// Life Cycle State, inside `'E3'`, length 1 (Table 11-36 / Table 11-6).
const TAG_LIFE_CYCLE: u32 = 0x9F70;
/// AID of the entry — ISD / Application / SD / ELF (`'4F'`, Table 11-36).
const TAG_AID: u32 = 0x4F;
/// Privileges of an Application / Security Domain (`'C5'`, 1 or 3 bytes;
/// Table 11-36, §11.1.2 / Tables 11-7..11-9). Absent for ELF entries.
const TAG_PRIVILEGES: u32 = 0xC5;
/// Associated Security Domain AID (`'CC'`, Table 11-36): the SD an Application
/// or ELF is associated with. (Not the ELF an Application loaded from.)
const TAG_ASSOC_SD_AID: u32 = 0xCC;
/// Application's Executable Load File AID (`'C4'`, Table 11-36): the ELF an
/// Application instance was installed from.
const TAG_ELF_AID: u32 = 0xC4;
/// Executable Module AID (`'84'`, Table 11-37): a class inside an ELF, returned
/// (possibly repeated) for the P1 `0x10` scope.
const TAG_MODULE_AID: u32 = 0x84;

// ---- GP key-type bytes (§5.2 step 4) --------------------------------------

const KEY_TYPE_DES: u8 = 0x80;
const KEY_TYPE_AES: u8 = 0x88;
const KEY_TYPE_RSA_PUBLIC: u8 = 0xA1;
const KEY_TYPE_RSA_PRIVATE_CRT: u8 = 0xA2;
const KEY_TYPE_RSA_PRIVATE_EXP: u8 = 0xA3;
const KEY_TYPE_ECC_PUBLIC: u8 = 0xB0;
const KEY_TYPE_ECC_PRIVATE: u8 = 0xB1;
const KEY_TYPE_ECC_PARAMS_REF: u8 = 0xB2;

// ---- Card Recognition Data '66' -------------------------------------------

/// Advertised secure-channel capability decoded from Card Recognition Data.
/// `scp[0]` is the card's default (first `'64'` listed); the discovery workflow
/// applies the §4.3 selection rule over the full list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardRecognition {
    /// Every representable `(scp_id, i)` the card advertises, in CRD order.
    /// SCP01 and any other non-SCP02/03 id is dropped (unrepresentable, and
    /// §5.2 refuses SCP01); an empty list ⇒ no usable SCP advertised.
    pub scp: Vec<ScpVariant, MAX_SCP_VARIANTS>,
}

/// Parse Card Recognition Data (the value of GET DATA `'66'`; GPCS §H.2).
///
/// Accepts the response either wrapped in the outer `'66'` tag or as a bare
/// `'73'` body. Each `'64'` entry's `'06'` OID encodes the SCP as its final two
/// octets `(scp_id, i)` (e.g. OID `2A864886FC6B 04 02 55` ⇒ SCP02, `i=0x55`).
///
/// # Errors
/// Returns [`TlvError`] if the template (or a nested OID) is not well-formed
/// BER-TLV, or [`TlvError::TooMany`] if more than [`MAX_SCP_VARIANTS`] usable
/// variants are advertised.
pub fn parse_card_recognition(data: &[u8]) -> Result<CardRecognition, TlvError> {
    let mut out = CardRecognition::default();
    if data.is_empty() {
        return Ok(out);
    }
    let top = tlv::parse(data)?;
    // CRD is normally wrapped in '66'; some cards return the '73' body directly.
    let body = if let Some(v66) = find(&top, TAG_CRD) {
        let wrapped = tlv::parse(v66)?;
        find(&wrapped, TAG_CRD_BODY)
    } else {
        find(&top, TAG_CRD_BODY)
    };
    let Some(body) = body else {
        return Ok(out); // no '73' template present
    };
    let entries = tlv::parse(body)?;
    for entry in entries.iter().filter(|t| t.tag == TAG_SCP_ENTRY) {
        let oid_tlvs = tlv::parse(entry.value)?;
        let Some(oid) = find(&oid_tlvs, TAG_OID) else {
            continue;
        };
        // Last two arcs of {globalPlatform 4 scp i} are (scp_id, i).
        if let [.., scp_id, i] = oid {
            if let Some(variant) = scp_variant(*scp_id, *i) {
                out.scp.push(variant).map_err(|_| TlvError::TooMany)?;
            }
        }
    }
    Ok(out)
}

/// Map a `(scp_id, i)` pair to a representable [`ScpVariant`]. SCP01 (and any
/// other id) is unrepresentable here and dropped — the workflow refuses SCP01
/// (§5.2) and treats an empty list as `ScpProtocolUnsupported`.
fn scp_variant(scp_id: u8, i_param: u8) -> Option<ScpVariant> {
    match scp_id {
        0x02 => Some(ScpVariant::Scp02 { i_param }),
        0x03 => Some(ScpVariant::Scp03 { i_param }),
        _ => None,
    }
}

// ---- Key Information Template '00E0' --------------------------------------

/// Decoded Key Information Template: keysets grouped by Key Version Number.
/// `format` is [`KeyTemplateFormat::Extended`] if any entry used the `'B9'`
/// sub-template, else [`KeyTemplateFormat::Basic`].
pub struct KeyInformation {
    pub format: KeyTemplateFormat,
    pub keysets: Vec<Keyset, MAX_KEYSETS>,
}

/// Parse the Key Information Template (value of GET DATA `'00E0'`; §11.3.3.1).
///
/// Accepts the response either wrapped in the outer `'E0'` tag or as a bare
/// sequence of `'C0'` Key Information Data entries. Each `'C0'` is
/// `KVN | KID | (KeyType KeyLength)+` in basic format, or `KVN | KID | 'B9' …`
/// in extended format. Entries are grouped into [`Keyset`]s by KVN.
///
/// # Errors
/// Returns [`TlvError`] if the template is not well-formed BER-TLV, or
/// [`TlvError::TooMany`] if the entries exceed [`MAX_KEYSETS`] /
/// [`MAX_KEYS_PER_SET`].
pub fn parse_key_information(data: &[u8]) -> Result<KeyInformation, TlvError> {
    let mut format = KeyTemplateFormat::Basic;
    let mut keysets: Vec<Keyset, MAX_KEYSETS> = Vec::new();
    if data.is_empty() {
        return Ok(KeyInformation { format, keysets });
    }
    let top = tlv::parse(data)?;
    let body = find(&top, TAG_KEY_TEMPLATE).unwrap_or(data);
    let entries = tlv::parse(body)?;
    for entry in entries.iter().filter(|t| t.tag == TAG_KEY_ENTRY) {
        let value = entry.value;
        // Need at least KID + KVN; a shorter entry is degenerate — skip it.
        // GPCS v2.3.1 §11.3.3.1, Table 11-70: the 'C0' Key Information Data
        // carries the **Key Identifier first, then the Key Version Number**
        // (confirmed against gppro's GPKeyInfo parsing and a live jcsim KIT
        // `C0 04 01 30 88 10` whose INITIALIZE UPDATE reports KVN 0x30).
        let (Some(&kid), Some(&kvn)) = (value.first(), value.get(1)) else {
            continue;
        };
        let rest = &value[2..];
        if rest.first() == Some(&KEY_EXTENDED_MARKER) {
            // Extended format: the sub-template's internal layout is not
            // pinned by the PDD; the slot is recorded with type `Other` and
            // the template flagged Extended (full decode out of scope, v0.9k).
            format = KeyTemplateFormat::Extended;
            push_key(
                &mut keysets,
                kvn,
                KeyInfo {
                    kid,
                    key_type: KeyType::Other(KEY_EXTENDED_MARKER),
                    key_length: 0,
                },
            )?;
        } else {
            // Basic format: one or more (KeyType, KeyLength) pairs.
            for pair in rest.chunks_exact(2) {
                push_key(
                    &mut keysets,
                    kvn,
                    KeyInfo {
                        kid,
                        key_type: decode_key_type(pair[0]),
                        key_length: pair[1],
                    },
                )?;
            }
        }
    }
    Ok(KeyInformation { format, keysets })
}

/// Insert a [`KeyInfo`] under its KVN, creating the [`Keyset`] if new.
fn push_key(keysets: &mut Vec<Keyset, MAX_KEYSETS>, kvn: u8, key: KeyInfo) -> Result<(), TlvError> {
    if let Some(set) = keysets.iter_mut().find(|s| s.kvn == kvn) {
        return set.keys.push(key).map_err(|_| TlvError::TooMany);
    }
    let mut keys: Vec<KeyInfo, MAX_KEYS_PER_SET> = Vec::new();
    // Cannot fail: a fresh Vec has room for one element.
    keys.push(key).map_err(|_| TlvError::TooMany)?;
    keysets
        .push(Keyset { kvn, keys })
        .map_err(|_| TlvError::TooMany)
}

/// Decode the GP key-type byte (§5.2 step 4); unknown ⇒ [`KeyType::Other`].
fn decode_key_type(byte: u8) -> KeyType {
    match byte {
        KEY_TYPE_DES => KeyType::Des,
        KEY_TYPE_AES => KeyType::Aes,
        KEY_TYPE_RSA_PUBLIC => KeyType::RsaPublic,
        KEY_TYPE_RSA_PRIVATE_CRT => KeyType::RsaPrivateCrt,
        KEY_TYPE_RSA_PRIVATE_EXP => KeyType::RsaPrivateExponent,
        KEY_TYPE_ECC_PUBLIC => KeyType::EccPublic,
        KEY_TYPE_ECC_PRIVATE => KeyType::EccPrivate,
        KEY_TYPE_ECC_PARAMS_REF => KeyType::EccParametersRef,
        other => KeyType::Other(other),
    }
}

// ---- Card Capability Information '67' --------------------------------------

/// Parse Card Capability Information (value of GET DATA `'67'`; GPCS §H.4).
///
/// Decodes the structurally unambiguous sub-tags — `'A0'` logical channels and
/// `'A3'` privileges — and always preserves the raw `'67'` value in
/// [`CardCapabilities::cci_raw`] for diagnostics. The `'A1'` cipher list,
/// `'A2'` SCP options and `'A4'` memory sub-tags have value encodings that are
/// not pinned by the PDD / public spec excerpts, so they are left undecoded
/// (`ciphers_supported` empty, `memory_*` `None`) rather than guessed; their
/// bytes remain available via `cci_raw` (see manifest / §5.2 step 5).
///
/// # Errors
/// Returns [`TlvError`] if the template is not well-formed BER-TLV.
pub fn parse_card_capabilities(data: &[u8]) -> Result<CardCapabilities, TlvError> {
    let mut caps = CardCapabilities {
        max_logical_channels: 1, // §5.2: default 1 when 'A0' absent
        ciphers_supported: Vec::new(),
        privileges_supported: Vec::new(),
        memory_total_bytes: None,
        memory_free_bytes: None,
        cci_raw: Vec::new(),
    };
    let raw_len = data.len().min(GETDATA_RAW_MAX);
    // Cannot fail: raw_len <= GETDATA_RAW_MAX, the buffer's capacity.
    let _ = caps.cci_raw.extend_from_slice(&data[..raw_len]);
    if data.is_empty() {
        return Ok(caps);
    }
    let top = tlv::parse(data)?;
    let body = find(&top, TAG_CCI).unwrap_or(data);
    let subs = tlv::parse(body)?;
    if let Some(channels) = find(&subs, TAG_CCI_CHANNELS) {
        if let Some(&n) = channels.first() {
            caps.max_logical_channels = n;
        }
    }
    if let Some(privileges) = find(&subs, TAG_CCI_PRIVILEGES) {
        let n = privileges.len().min(MAX_PRIVILEGE_BYTES);
        // Cannot fail: n <= MAX_PRIVILEGE_BYTES, the buffer's capacity.
        let _ = caps
            .privileges_supported
            .extend_from_slice(&privileges[..n]);
    }
    Ok(caps)
}

// ---- GET STATUS GP Registry entry 'E3' ------------------------------------

/// Parse the single ISD `GlobalPlatform` Registry entry from a `GET STATUS`
/// response and decode its life-cycle byte (`'E3'` → `'9F70'`; Table 11-36 /
/// Table 11-6).
///
/// Returns `Ok(None)` when no `'E3'` / `'9F70'` is present (the §5.12 workflow
/// maps that to `WarningKind::GetStatusParseFailed` + `CardLifeCycle::Unknown`).
/// An unrecognised life-cycle byte decodes to [`CardLifeCycle::Unknown`], not an
/// error.
///
/// # Errors
/// Returns [`TlvError`] if the response is not well-formed BER-TLV.
pub fn parse_status_e3(data: &[u8]) -> Result<Option<CardLifeCycle>, TlvError> {
    if data.is_empty() {
        return Ok(None);
    }
    let top = tlv::parse(data)?;
    let Some(registry) = find(&top, TAG_GP_REGISTRY) else {
        return Ok(None);
    };
    let fields = tlv::parse(registry)?;
    let Some(life_cycle) = find(&fields, TAG_LIFE_CYCLE) else {
        return Ok(None);
    };
    Ok(life_cycle.first().map(|&b| decode_life_cycle(b)))
}

/// Decode the raw `'9F70'` life-cycle byte (Table 11-6).
fn decode_life_cycle(byte: u8) -> CardLifeCycle {
    match byte {
        0x01 => CardLifeCycle::OpReady,
        0x07 => CardLifeCycle::Initialized,
        0x0F => CardLifeCycle::Secured,
        0x7F => CardLifeCycle::CardLocked,
        0xFF => CardLifeCycle::Terminated,
        other => CardLifeCycle::Unknown(other),
    }
}

// ---- GET STATUS full registry (§5.12a) ------------------------------------

/// One decoded `GlobalPlatform` Registry `'E3'` entry — the scope-agnostic
/// shape the `get_card_inventory` workflow (§5.12a) maps into the typed
/// [`crate::model`] entries (Security Domain / Application / ELF).
///
/// Borrows the parsed response (`'a`): the AIDs are zero-copy slices into the
/// GET STATUS page. The workflow validates each into an owning
/// [`crate::aid::Aid`] within the page's lifetime. `life_cycle` is the raw
/// `'9F70'` byte (decode is the model's concern); `privileges` is the `'C5'`
/// value padded/truncated to the model's fixed 3 bytes (a 1-byte legacy `'C5'`
/// becomes `[b, 0, 0]` — the Security Domain bit stays in byte 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry<'a> {
    /// `'4F'` — the entry's AID (empty slice if the card omits it, which the
    /// workflow then skips as malformed).
    pub aid: &'a [u8],
    /// `'9F70'` — raw life-cycle byte (0 if absent; see [`decode_life_cycle`]).
    pub life_cycle: u8,
    /// `'C5'` — privileges, padded/truncated to 3 bytes (all-zero if absent, as
    /// for an ELF entry).
    pub privileges: [u8; 3],
    /// `'CC'` — associated Security Domain AID, when present.
    pub associated_sd_aid: Option<&'a [u8]>,
    /// `'C4'` — the Application's Executable Load File AID, when present.
    pub elf_aid: Option<&'a [u8]>,
    /// `'84'` — Executable Module AIDs inside an ELF (P1 `0x10` scope),
    /// truncated at [`MAX_MODULES_PER_ELF`].
    pub modules: Vec<&'a [u8], MAX_MODULES_PER_ELF>,
}

/// Parse **one GET STATUS page** into its `'E3'` registry entries
/// (Table 11-36 / 11-37). Total and fuzzable (§10.5): malformed input yields a
/// typed [`TlvError`], never a panic. Used by the `get_card_inventory` workflow
/// (§5.12a), which calls it once per page (`63 10` continuation) per P1 scope
/// and maps each [`RegistryEntry`] into the typed model.
///
/// Each `'E3'` is decoded leniently: a missing `'4F'` yields an empty AID
/// (the workflow skips it), a missing `'9F70'` yields `0`, repeated `'84'`
/// module tags are collected (capped at [`MAX_MODULES_PER_ELF`]). Capacity
/// overflow — more than [`MAX_REGISTRY_ENTRIES`] entries in one page, or more
/// than [`MAX_MODULES_PER_ELF`] modules in one ELF — **truncates** rather than
/// erroring (the listing stays useful; the workflow surfaces
/// `WarningKind::InventoryTruncated`). Only a structurally broken BER-TLV is a
/// [`TlvError`].
///
/// # Errors
/// Returns [`TlvError`] if the page (or a nested `'E3'`) is not well-formed
/// BER-TLV.
pub fn parse_status_registry(
    data: &[u8],
) -> Result<Vec<RegistryEntry<'_>, MAX_REGISTRY_ENTRIES>, TlvError> {
    let mut out: Vec<RegistryEntry, MAX_REGISTRY_ENTRIES> = Vec::new();
    if data.is_empty() {
        return Ok(out);
    }
    let top = tlv::parse(data)?;
    for e3 in top.iter().filter(|t| t.tag == TAG_GP_REGISTRY) {
        let fields = tlv::parse(e3.value)?;
        let aid = find(&fields, TAG_AID).unwrap_or(&[]);
        let life_cycle = find(&fields, TAG_LIFE_CYCLE)
            .and_then(|v| v.first().copied())
            .unwrap_or(0);
        let privileges = privileges_to_3(find(&fields, TAG_PRIVILEGES));
        let associated_sd_aid = find(&fields, TAG_ASSOC_SD_AID);
        let elf_aid = find(&fields, TAG_ELF_AID);
        let mut modules: Vec<&[u8], MAX_MODULES_PER_ELF> = Vec::new();
        for m in fields.iter().filter(|t| t.tag == TAG_MODULE_AID) {
            if modules.push(m.value).is_err() {
                break; // more modules than the model holds → truncate (no panic)
            }
        }
        let entry = RegistryEntry {
            aid,
            life_cycle,
            privileges,
            associated_sd_aid,
            elf_aid,
            modules,
        };
        if out.push(entry).is_err() {
            break; // more entries than one page can hold → truncate (no panic)
        }
    }
    Ok(out)
}

/// Pad/truncate a `'C5'` privileges value to the model's fixed 3 bytes. A
/// 1-byte legacy `'C5'` becomes `[b, 0, 0]`; absent ⇒ all-zero. (Tables
/// 11-7..11-9: the Security Domain bit is byte 1 / b8, so it survives either
/// encoding.)
fn privileges_to_3(value: Option<&[u8]>) -> [u8; 3] {
    let mut p = [0u8; 3];
    if let Some(b) = value {
        let n = b.len().min(3);
        p[..n].copy_from_slice(&b[..n]);
    }
    p
}

// ---- shared --------------------------------------------------------------

/// Return the value of the first TLV with `tag`. The returned slice borrows the
/// original input (`'a`), not the `tlvs` list, so it outlives a local parse.
fn find<'a>(tlvs: &[Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Card Recognition Data '66' =====================================

    /// Real CRD dump (`JavaCard` OS forum / 0x9000 blog): SCP02, i=0x55.
    const CRD_SCP02_55: &[u8] = &[
        0x66, 0x4C, 0x73, 0x4A, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, 0x0C,
        0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x01, 0x01, 0x63, 0x09, 0x06,
        0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
        0x86, 0xFC, 0x6B, 0x04, 0x02, 0x55, 0x65, 0x0B, 0x06, 0x09, 0x2B, 0x85, 0x10, 0x86, 0x48,
        0x64, 0x02, 0x01, 0x03, 0x66, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02,
        0x6E, 0x01, 0x02,
    ];

    #[test]
    fn crd_decodes_scp02_i55() {
        let crd = parse_card_recognition(CRD_SCP02_55).unwrap();
        assert_eq!(crd.scp.len(), 1);
        assert_eq!(crd.scp[0], ScpVariant::Scp02 { i_param: 0x55 });
    }

    #[test]
    fn crd_decodes_scp03_i70() {
        // Minimal '66'→'73'→'64'→'06' with OID tail 03 70 (SCP03, i=0x70).
        let crd = [
            0x66, 0x0E, 0x73, 0x0C, 0x64, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B,
            0x03, 0x70,
        ];
        let r = parse_card_recognition(&crd).unwrap();
        assert_eq!(r.scp[0], ScpVariant::Scp03 { i_param: 0x70 });
    }

    #[test]
    fn crd_multiple_variants_preserve_order() {
        // '73' with two '64' entries: SCP02/55 then SCP03/70.
        let crd = [
            0x73, 0x10, 0x64, 0x06, 0x06, 0x04, 0x00, 0x00, 0x02, 0x55, 0x64, 0x06, 0x06, 0x04,
            0x00, 0x00, 0x03, 0x70,
        ];
        let r = parse_card_recognition(&crd).unwrap();
        assert_eq!(r.scp.len(), 2);
        assert_eq!(r.scp[0], ScpVariant::Scp02 { i_param: 0x55 });
        assert_eq!(r.scp[1], ScpVariant::Scp03 { i_param: 0x70 });
    }

    #[test]
    fn crd_drops_scp01() {
        // '64' OID tail 01 05 ⇒ SCP01, which is unrepresentable and dropped.
        let crd = [0x73, 0x08, 0x64, 0x06, 0x06, 0x04, 0x00, 0x00, 0x01, 0x05];
        assert!(parse_card_recognition(&crd).unwrap().scp.is_empty());
    }

    #[test]
    fn crd_empty_input_is_empty_not_error() {
        assert!(parse_card_recognition(&[]).unwrap().scp.is_empty());
    }

    #[test]
    fn crd_no_template_is_empty_not_error() {
        // Well-formed TLV but no '73' body (just a stray '5C' tag list).
        assert!(parse_card_recognition(&[0x5C, 0x01, 0x9F])
            .unwrap()
            .scp
            .is_empty());
    }

    #[test]
    fn crd_entry_without_oid_is_skipped() {
        // '64' present but holds a non-'06' child ⇒ skipped, no error.
        let crd = [0x73, 0x06, 0x64, 0x04, 0x80, 0x02, 0x00, 0x00];
        assert!(parse_card_recognition(&crd).unwrap().scp.is_empty());
    }

    #[test]
    fn crd_oid_shorter_than_two_octets_is_skipped() {
        let crd = [0x73, 0x05, 0x64, 0x03, 0x06, 0x01, 0x2A];
        assert!(parse_card_recognition(&crd).unwrap().scp.is_empty());
    }

    #[test]
    fn crd_malformed_tlv_is_rejected() {
        // '66' claims 5 bytes but only 1 follows.
        assert_eq!(
            parse_card_recognition(&[0x66, 0x05, 0x00]),
            Err(TlvError::Truncated)
        );
    }

    // ===== Key Information Template '00E0' ================================

    #[test]
    fn key_info_basic_single_keyset_three_kids() {
        // 'E0' { 'C0'{01 01 88 10} 'C0'{02 01 88 10} 'C0'{03 01 88 10} } —
        // KIDs 1/2/3 at KVN 1, AES, 16-byte (matches a modern SCP03 keyset;
        // 'C0' carries KID first, then KVN — GPCS v2.3.1 Table 11-70).
        let data = [
            0xE0, 0x12, 0xC0, 0x04, 0x01, 0x01, 0x88, 0x10, 0xC0, 0x04, 0x02, 0x01, 0x88, 0x10,
            0xC0, 0x04, 0x03, 0x01, 0x88, 0x10,
        ];
        let info = parse_key_information(&data).unwrap();
        assert!(matches!(info.format, KeyTemplateFormat::Basic));
        assert_eq!(info.keysets.len(), 1);
        assert_eq!(info.keysets[0].kvn, 1);
        assert_eq!(info.keysets[0].keys.len(), 3);
        assert_eq!(info.keysets[0].keys[0].kid, 1);
        assert!(matches!(info.keysets[0].keys[0].key_type, KeyType::Aes));
        assert_eq!(info.keysets[0].keys[2].key_length, 0x10);
    }

    #[test]
    fn key_info_groups_by_kvn() {
        let data = [
            0xE0, 0x0E, 0xC0, 0x04, 0x01, 0x01, 0x80, 0x10, 0xC0, 0x04, 0x01, 0x02, 0x88, 0x10,
            0xC0, 0x00, // a degenerate empty 'C0' — skipped, no panic
        ];
        let info = parse_key_information(&data).unwrap();
        assert_eq!(info.keysets.len(), 2);
        assert!(matches!(info.keysets[0].keys[0].key_type, KeyType::Des));
        assert!(matches!(info.keysets[1].keys[0].key_type, KeyType::Aes));
    }

    #[test]
    fn key_info_multi_component_pairs() {
        // One 'C0' with KID|KVN then two (type,len) pairs (e.g. RSA pub+priv).
        let data = [0xE0, 0x08, 0xC0, 0x06, 0x10, 0x01, 0xA1, 0x80, 0xA2, 0x80];
        let info = parse_key_information(&data).unwrap();
        assert_eq!(info.keysets[0].keys.len(), 2);
        assert!(matches!(
            info.keysets[0].keys[0].key_type,
            KeyType::RsaPublic
        ));
        assert!(matches!(
            info.keysets[0].keys[1].key_type,
            KeyType::RsaPrivateCrt
        ));
    }

    #[test]
    fn key_info_extended_format_sets_flag() {
        // 'C0' { KID KVN 'B9' Lb .. } ⇒ Extended flag; sub-template not decoded.
        let data = [0xE0, 0x06, 0xC0, 0x04, 0x01, 0x01, 0xB9, 0x00];
        let info = parse_key_information(&data).unwrap();
        assert!(matches!(info.format, KeyTemplateFormat::Extended));
        assert_eq!(info.keysets[0].keys[0].kid, 1);
        assert!(matches!(
            info.keysets[0].keys[0].key_type,
            KeyType::Other(0xB9)
        ));
    }

    #[test]
    fn key_info_unknown_type_is_other() {
        // 'C0' { KID=05 KVN=09 KeyType=0x42 (unknown) KeyLength=08 }.
        let data = [0xE0, 0x06, 0xC0, 0x04, 0x05, 0x09, 0x42, 0x08];
        let info = parse_key_information(&data).unwrap();
        assert!(matches!(
            info.keysets[0].keys[0].key_type,
            KeyType::Other(0x42)
        ));
    }

    #[test]
    fn key_info_bare_c0_without_e0_wrapper() {
        let data = [0xC0, 0x04, 0x01, 0x01, 0x88, 0x10];
        let info = parse_key_information(&data).unwrap();
        assert_eq!(info.keysets[0].keys[0].kid, 1);
    }

    #[test]
    fn key_info_empty_is_empty_not_error() {
        let info = parse_key_information(&[]).unwrap();
        assert!(info.keysets.is_empty());
    }

    #[test]
    fn key_info_malformed_tlv_is_rejected() {
        assert!(matches!(
            parse_key_information(&[0xE0, 0x05, 0xC0]),
            Err(TlvError::Truncated)
        ));
    }

    // ===== Card Capability Information '67' ===============================

    #[test]
    fn cci_decodes_channels_and_privileges_and_keeps_raw() {
        // '67' { 'A0'{04} 'A3'{80 00 00} } — 4 channels, ISD privilege byte.
        let data = [0x67, 0x08, 0xA0, 0x01, 0x04, 0xA3, 0x03, 0x80, 0x00, 0x00];
        let caps = parse_card_capabilities(&data).unwrap();
        assert_eq!(caps.max_logical_channels, 4);
        assert_eq!(caps.privileges_supported.len(), 3);
        assert_eq!(caps.privileges_supported[0], 0x80);
        assert_eq!(caps.cci_raw.len(), data.len());
        // Undecoded by design (see fn docs): empty / None, raw retained.
        assert!(caps.ciphers_supported.is_empty());
        assert!(caps.memory_total_bytes.is_none());
    }

    #[test]
    fn cci_defaults_to_one_channel_when_a0_absent() {
        let data = [0x67, 0x05, 0xA3, 0x03, 0x80, 0x00, 0x00];
        let caps = parse_card_capabilities(&data).unwrap();
        assert_eq!(caps.max_logical_channels, 1);
    }

    #[test]
    fn cci_empty_a0_keeps_default_channel() {
        let data = [0x67, 0x02, 0xA0, 0x00];
        let caps = parse_card_capabilities(&data).unwrap();
        assert_eq!(caps.max_logical_channels, 1);
    }

    #[test]
    fn cci_bare_subtags_without_67_wrapper() {
        let data = [0xA0, 0x01, 0x02];
        let caps = parse_card_capabilities(&data).unwrap();
        assert_eq!(caps.max_logical_channels, 2);
    }

    #[test]
    fn cci_empty_is_defaults_not_error() {
        let caps = parse_card_capabilities(&[]).unwrap();
        assert_eq!(caps.max_logical_channels, 1);
        assert!(caps.cci_raw.is_empty());
    }

    #[test]
    fn cci_malformed_tlv_is_rejected() {
        assert!(matches!(
            parse_card_capabilities(&[0x67, 0x05, 0xA0]),
            Err(TlvError::Truncated)
        ));
    }

    // ===== GET STATUS GP Registry entry 'E3' =============================

    #[test]
    fn e3_decodes_each_known_lifecycle_byte() {
        for (raw, expect) in [
            (0x01u8, CardLifeCycle::OpReady),
            (0x07, CardLifeCycle::Initialized),
            (0x0F, CardLifeCycle::Secured),
            (0x7F, CardLifeCycle::CardLocked),
            (0xFF, CardLifeCycle::Terminated),
        ] {
            // 'E3' { '4F'{A0000000030000} '9F70'{raw} }
            let data = [
                0xE3, 0x0D, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x9F, 0x70, 0x01,
                raw,
            ];
            assert_eq!(parse_status_e3(&data).unwrap(), Some(expect));
        }
    }

    #[test]
    fn e3_unknown_byte_maps_to_unknown() {
        let data = [0xE3, 0x04, 0x9F, 0x70, 0x01, 0x42];
        assert_eq!(
            parse_status_e3(&data).unwrap(),
            Some(CardLifeCycle::Unknown(0x42))
        );
    }

    #[test]
    fn e3_absent_template_is_none() {
        // Well-formed TLV, but no 'E3'.
        assert_eq!(parse_status_e3(&[0x4F, 0x00]).unwrap(), None);
    }

    #[test]
    fn e3_without_9f70_is_none() {
        let data = [0xE3, 0x02, 0x4F, 0x00];
        assert_eq!(parse_status_e3(&data).unwrap(), None);
    }

    #[test]
    fn e3_empty_9f70_is_none() {
        let data = [0xE3, 0x03, 0x9F, 0x70, 0x00];
        assert_eq!(parse_status_e3(&data).unwrap(), None);
    }

    #[test]
    fn e3_empty_input_is_none() {
        assert_eq!(parse_status_e3(&[]).unwrap(), None);
    }

    #[test]
    fn e3_malformed_tlv_is_rejected() {
        assert_eq!(
            parse_status_e3(&[0xE3, 0x05, 0x9F]),
            Err(TlvError::Truncated)
        );
    }

    // ===== GET STATUS full registry (§5.12a) ==============================

    /// `E3{ 4F<aid> 9F70<lc> C5<priv> }` — the App/SD entry shape.
    fn e3_app(aid: &[u8], lc: u8, privs: &[u8]) -> std::vec::Vec<u8> {
        let mut inner = std::vec::Vec::new();
        inner.push(0x4F);
        inner.push(u8::try_from(aid.len()).unwrap());
        inner.extend_from_slice(aid);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, lc]);
        inner.push(0xC5);
        inner.push(u8::try_from(privs.len()).unwrap());
        inner.extend_from_slice(privs);
        let mut v = std::vec::Vec::new();
        v.push(0xE3);
        v.push(u8::try_from(inner.len()).unwrap());
        v.extend_from_slice(&inner);
        v
    }

    #[test]
    fn registry_decodes_isd_with_full_3byte_privileges() {
        // ISD entry: AID A0000000030000, OP_READY (0x01), all-3-byte privs.
        let aid = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00];
        let e = e3_app(&aid, 0x01, &[0x9E, 0xFE, 0x80]);
        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].aid, &aid);
        assert_eq!(r[0].life_cycle, 0x01);
        assert_eq!(r[0].privileges, [0x9E, 0xFE, 0x80]);
        assert!(r[0].modules.is_empty());
    }

    #[test]
    fn registry_pads_one_byte_privileges_into_byte_zero() {
        // Legacy 1-byte C5 = 0x80 ⇒ [0x80, 0, 0]; SD bit survives in byte 0.
        let e = e3_app(&[0xA0, 0x00, 0x00, 0x00, 0x18], 0x07, &[0x80]);
        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r[0].privileges, [0x80, 0x00, 0x00]);
    }

    #[test]
    fn registry_decodes_two_entries_in_one_page() {
        let a = e3_app(&[0xA0, 0x00, 0x00, 0x00, 0x11], 0x07, &[0x00, 0x00, 0x00]);
        let b = e3_app(&[0xA0, 0x00, 0x00, 0x00, 0x22], 0x0F, &[0x80, 0x00, 0x00]);
        let mut page = a;
        page.extend_from_slice(&b);
        let r = parse_status_registry(&page).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].life_cycle, 0x07);
        assert_eq!(r[1].privileges, [0x80, 0x00, 0x00]);
    }

    #[test]
    fn registry_decodes_elf_with_associated_sd_and_modules() {
        // E3{ 4F<elf> 9F70<lc> CC<sd> 84<mod1> 84<mod2> } — P1=0x10 scope.
        let elf = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01];
        let sd = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00];
        let m1 = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
        let m2 = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x02];
        let mut inner = std::vec::Vec::new();
        inner.push(0x4F);
        inner.push(u8::try_from(elf.len()).unwrap());
        inner.extend_from_slice(&elf);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, 0x01]);
        inner.push(0xCC);
        inner.push(u8::try_from(sd.len()).unwrap());
        inner.extend_from_slice(&sd);
        for m in [&m1[..], &m2[..]] {
            inner.push(0x84);
            inner.push(u8::try_from(m.len()).unwrap());
            inner.extend_from_slice(m);
        }
        let mut e = std::vec::Vec::new();
        e.push(0xE3);
        e.push(u8::try_from(inner.len()).unwrap());
        e.extend_from_slice(&inner);

        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r[0].aid, &elf);
        assert_eq!(r[0].associated_sd_aid, Some(&sd[..]));
        assert_eq!(r[0].modules.len(), 2);
        assert_eq!(r[0].modules[0], &m1);
        assert_eq!(r[0].modules[1], &m2);
    }

    #[test]
    fn registry_decodes_application_elf_aid_tag_c4() {
        // E3{ 4F<inst> 9F70 C5<priv> C4<elf> } — application's load file AID.
        let inst = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C];
        let elf = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03];
        let mut inner = std::vec::Vec::new();
        inner.push(0x4F);
        inner.push(u8::try_from(inst.len()).unwrap());
        inner.extend_from_slice(&inst);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, 0x07]);
        inner.extend_from_slice(&[0xC5, 0x01, 0x00]);
        inner.push(0xC4);
        inner.push(u8::try_from(elf.len()).unwrap());
        inner.extend_from_slice(&elf);
        let mut e = std::vec::Vec::new();
        e.push(0xE3);
        e.push(u8::try_from(inner.len()).unwrap());
        e.extend_from_slice(&inner);

        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r[0].elf_aid, Some(&elf[..]));
        assert_eq!(r[0].associated_sd_aid, None);
    }

    #[test]
    fn registry_missing_4f_yields_empty_aid_not_error() {
        // E3{ 9F70 01 0F } — no '4F'; workflow treats an empty AID as skip.
        let e = [0xE3, 0x04, 0x9F, 0x70, 0x01, 0x0F];
        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].aid.is_empty());
        assert_eq!(r[0].life_cycle, 0x0F);
    }

    #[test]
    fn registry_empty_page_is_empty_not_error() {
        assert!(parse_status_registry(&[]).unwrap().is_empty());
    }

    #[test]
    fn registry_no_e3_is_empty_not_error() {
        // Well-formed TLV but no 'E3' (e.g. a card returning just '4F 00').
        assert!(parse_status_registry(&[0x4F, 0x00]).unwrap().is_empty());
    }

    #[test]
    fn registry_malformed_tlv_is_rejected() {
        assert_eq!(
            parse_status_registry(&[0xE3, 0x05, 0x4F]),
            Err(TlvError::Truncated)
        );
    }

    #[test]
    fn registry_truncates_excess_modules_without_panic() {
        // One ELF entry with MAX_MODULES_PER_ELF + 4 module tags ⇒ capped.
        use crate::limits::MAX_MODULES_PER_ELF;
        let elf = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x09];
        let mut inner = std::vec::Vec::new();
        inner.push(0x4F);
        inner.push(u8::try_from(elf.len()).unwrap());
        inner.extend_from_slice(&elf);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, 0x01]);
        for i in 0..(MAX_MODULES_PER_ELF + 4) {
            // 5-byte module AID, distinct last byte.
            inner.extend_from_slice(&[
                0x84,
                0x05,
                0xA0,
                0x00,
                0x00,
                0x01,
                u8::try_from(i).unwrap(),
            ]);
        }
        let mut e = std::vec::Vec::new();
        e.push(0xE3);
        // Body exceeds 127 B (≥17 module TLVs), so use long-form length 81 LL.
        if inner.len() < 0x80 {
            e.push(u8::try_from(inner.len()).unwrap());
        } else {
            e.push(0x81);
            e.push(u8::try_from(inner.len()).unwrap());
        }
        e.extend_from_slice(&inner);
        let r = parse_status_registry(&e).unwrap();
        assert_eq!(r[0].modules.len(), MAX_MODULES_PER_ELF);
    }
}
