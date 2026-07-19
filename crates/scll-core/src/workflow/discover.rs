//! Step 2 — `discover_card` (PDD §5.2).
//!
//! Reads everything the card willingly tells you **before** SCP auth: ATR/ATS,
//! ISD SELECT (FCI tag `'84'`), CRD `'66'` (§H.2), Key Information Template
//! `'00E0'` (§11.3.3.1), CCI `'67'` (§H.4), optional IIN/CIN. Never errors on
//! missing optional data — records a [`DiscoveryWarning`] and proceeds.
//! Idempotent; modifies no card state.

use heapless::{String, Vec};

use crate::aid::Aid;
use crate::command::get_data::get_data;
use crate::command::install::PrivLen;
use crate::error::ScllError;
use crate::limits::{
    ATR_ATS_MAX, CIN_MAX, GETDATA_RAW_MAX, IIN_MAX, MAX_QUIRKS, MAX_SCP_VARIANTS, MAX_WARNINGS,
    OTHER_DETAIL_MAX, RAPDU_MAX,
};
use crate::model::{CardCapabilities, CardInfo, DiscoveryWarning, ScpVariant};
use crate::response::{parse_card_capabilities, parse_card_recognition, parse_key_information};
use crate::transport::Transport;
use crate::workflow::session::{self, SW_OK, SW_REF_NOT_FOUND};

/// GET DATA object tags (PDD §5.2).
const TAG_CRD: u16 = 0x0066;
const TAG_KIT: u16 = 0x00E0;
const TAG_CCI: u16 = 0x0067;
const TAG_IIN: u16 = 0x0042;
const TAG_CIN: u16 = 0x0045;
const TAG_CPLC: u16 = 0x9F7F;

/// The §4.3 fall-back when a card advertises no Card Recognition Data: assume
/// SCP02 with `i = 0x55` (PDD §5.2 failure table / §4.3).
const FALLBACK_SCP: ScpVariant = ScpVariant::Scp02 { i_param: 0x55 };

/// CPLC IC Fabricator = NXP (open vendor maps: javaemvreader / `GlobalPlatformPro`).
const CPLC_ICFAB_NXP: u16 = 0x4790;
/// CPLC Operating System ID high byte for NXP JCOP.
const CPLC_OSID_JCOP_HI: u8 = 0x47;

/// Strip the GET DATA `'9F7F'` TLV wrapper (if present) to the CPLC value.
/// Accepts either the raw value or a `9F 7F <len> …` framed response.
fn cplc_value(data: &[u8]) -> &[u8] {
    if data.len() >= 3 && data[0] == 0x9F && data[1] == 0x7F {
        let len = data[2] as usize;
        if data.len() >= 3 + len {
            return &data[3..3 + len];
        }
    }
    data
}

/// Choose the GP Privileges encoding from CPLC. NXP JCOP silicon (`ICFabricator`
/// 0x4790 *and* `OperatingSystemID` high byte 0x47) rejects the 3-byte field for
/// a byte-1-only privilege and requires the 1-byte form; everything else —
/// including the all-zero simulator CPLC — gets the spec-canonical 3-byte form
/// (GPCS v2.3.1 §11.1.2). CPLC value layout: `ICFabricator`[0..2], `ICType`[2..4],
/// `OperatingSystemID`[4..6] (ISO/IEC 7816-6).
fn priv_len_from_cplc(value: &[u8]) -> PrivLen {
    if value.len() >= 6
        && u16::from_be_bytes([value[0], value[1]]) == CPLC_ICFAB_NXP
        && value[4] == CPLC_OSID_JCOP_HI
    {
        PrivLen::Jcop1Byte
    } else {
        PrivLen::Canonical
    }
}

/// Discover card capabilities with no authentication. The report IS the
/// [`CardInfo`] (§6/§7).
///
/// # Errors
/// Returns an [`ScllError`] if a transport exchange fails, the card rejects the
/// ISD SELECT ([`ScllError::CardNotUsable`] on `6A82`), or no ISD AID can be
/// resolved ([`ScllError::IsdAidNotFound`]); missing *optional* data is
/// recorded as a [`DiscoveryWarning`], never an error.
pub fn discover_card(
    t: &mut dyn Transport,
    expected_isd_aid: Option<&[u8]>,
) -> Result<CardInfo, ScllError> {
    let mut warnings: Vec<DiscoveryWarning, MAX_WARNINGS> = Vec::new();
    let quirks: Vec<String<OTHER_DETAIL_MAX>, MAX_QUIRKS> = Vec::new();

    // 1) Reset and read ATR/ATS.
    let atr = t.reset().map_err(|e| session::map_transport(&e))?;
    let mut atr_or_ats: Vec<u8, ATR_ATS_MAX> = Vec::new();
    let _ = atr_or_ats.extend_from_slice(&atr.bytes);
    let transport_protocol = atr.protocol;

    // 2) SELECT the ISD (empty SELECT ⇒ default application; GPCS §5.2.2).
    let fci = session::select(t, expected_isd_aid.unwrap_or(&[]))?;
    let isd_aid = resolve_isd_aid(expected_isd_aid, &fci)?;

    // 3) Card Recognition Data '66'.
    let mut card_recognition_data_raw: Vec<u8, GETDATA_RAW_MAX> = Vec::new();
    let mut scp_supported: Vec<ScpVariant, MAX_SCP_VARIANTS> = Vec::new();
    match optional_get_data(t, TAG_CRD)? {
        Some(data) => {
            let n = data.len().min(GETDATA_RAW_MAX);
            let _ = card_recognition_data_raw.extend_from_slice(&data[..n]);
            let crd = parse_card_recognition(&data)?;
            for v in &crd.scp {
                let _ = scp_supported.push(*v);
            }
            if scp_supported.is_empty() {
                let _ = warnings.push(DiscoveryWarning::CardRecognitionDataMissing);
            }
        }
        None => {
            let _ = warnings.push(DiscoveryWarning::CardRecognitionDataMissing);
        }
    }
    // §4.3 fall-back: no usable SCP advertised ⇒ assume SCP02 i=0x55.
    if scp_supported.is_empty() {
        let _ = scp_supported.push(FALLBACK_SCP);
    }
    let scp_default = scp_supported[0];

    // 4) Key Information Template '00E0'.
    let kit = optional_get_data(t, TAG_KIT)?;
    let (isd_keysets, isd_key_template_format) = if let Some(data) = kit {
        let info = parse_key_information(&data)?;
        (info.keysets, info.format)
    } else {
        let _ = warnings.push(DiscoveryWarning::KeyInformationTemplateMissing);
        let info = parse_key_information(&[])?;
        (info.keysets, info.format)
    };

    // 5) Card Capability Information '67' (optional).
    let capabilities: CardCapabilities = if let Some(data) = optional_get_data(t, TAG_CCI)? {
        parse_card_capabilities(&data)?
    } else {
        let _ = warnings.push(DiscoveryWarning::CardCapabilityInfoMissing);
        parse_card_capabilities(&[])?
    };

    // 6) Optional IIN / CIN (diagnostic only).
    let iin = optional_get_data(t, TAG_IIN)?.and_then(|d| copy_opt::<IIN_MAX>(d.as_slice()));
    let cin = optional_get_data(t, TAG_CIN)?.and_then(|d| copy_opt::<CIN_MAX>(d.as_slice()));
    let card_image_number = cin.clone();

    // 7) CPLC '9F7F' (optional) — detect NXP JCOP, which requires the 1-byte
    //    Privileges encoding for SD creation (PDD §5.2 / §5.4; GPCS §11.1.2).
    let privilege_encoding = match optional_get_data(t, TAG_CPLC)? {
        Some(data) => priv_len_from_cplc(cplc_value(&data)),
        None => PrivLen::Canonical,
    };

    Ok(CardInfo {
        isd_aid,
        atr_or_ats,
        transport_protocol,
        scp_supported,
        scp_default,
        isd_keysets,
        isd_key_template_format,
        capabilities,
        card_recognition_data_raw,
        iin,
        cin,
        card_image_number,
        jc_platform_version: None,
        privilege_encoding,
        quirks_detected: quirks,
        discovery_warnings: warnings,
    })
}

/// Resolve the ISD AID: prefer the caller-supplied value, else the FCI `'84'`
/// DF name. Returns [`ScllError::IsdAidNotFound`] if neither is available.
fn resolve_isd_aid(expected: Option<&[u8]>, fci: &[u8]) -> Result<Aid, ScllError> {
    if let Some(e) = expected {
        return Aid::new(e);
    }
    match session::fci_df_name(fci)? {
        Some(name) => Aid::new(name),
        None => Err(ScllError::IsdAidNotFound),
    }
}

/// GET DATA that treats `6A88` (and an empty `9000`) as "absent" rather than an
/// error: `Some(data)` only for a non-empty `9000` payload.
fn optional_get_data(
    t: &mut dyn Transport,
    tag: u16,
) -> Result<Option<Vec<u8, RAPDU_MAX>>, ScllError> {
    let capdu = get_data(tag)?;
    let (data, sw) = session::transmit_plain(t, &capdu)?;
    match sw {
        SW_OK if !data.is_empty() => Ok(Some(data)),
        SW_OK | SW_REF_NOT_FOUND => Ok(None),
        other => Err(ScllError::from_general_sw(other)),
    }
}

/// Copy a slice into a fresh bounded buffer, or `None` if it would overflow.
fn copy_opt<const N: usize>(src: &[u8]) -> Option<Vec<u8, N>> {
    let mut v = Vec::new();
    v.extend_from_slice(src).ok()?;
    Some(v)
}
