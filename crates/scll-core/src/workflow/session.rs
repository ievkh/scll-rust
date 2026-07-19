//! Shared workflow plumbing — transport exchange + SCP wrap/unwrap (PDD §5.9/§5.10).
//!
//! These helpers are the single point where a built C-APDU plaintext meets the
//! `Transport` and (for an open channel) the backend's wrap/unwrap. Keeping
//! them here means every workflow drives the wire identically:
//!   * `transmit_plain` — pre-auth exchange (SELECT, GET DATA, the IU/EA of
//!     `open_scp`): send raw, split `data ‖ SW`.
//!   * `transmit_in_session` — over an open [`ScpSession`]: wrap the plaintext
//!     (C-MAC, optional C-ENC), send, verify/strip the response, split
//!     `data ‖ SW`. The fail-closed tear-down on an unwrap failure lives in the
//!     backend (Fork F3); this helper only propagates the error.
//!
//! `no_std`: alloc-free; the split borrows into bounded `heapless` buffers.

use heapless::Vec;

use crate::backend::{Scp02Backend, Scp03Backend};
use crate::command::select::select_by_aid;
use crate::error::ScllError;
use crate::limits::RAPDU_MAX;
use crate::scp::ScpSession;
use crate::tlv::{self, Tlv};
use crate::transport::{Transport, TransportError};

/// Status word `9000` — normal completion (ISO/IEC 7816-4; GPCS v2.3.1).
pub(crate) const SW_OK: u16 = 0x9000;
/// `6A88` — referenced data / object not found (optional GET DATA absence,
/// missing ELF/keyset; meaning is per-command, GPCS v2.3.1 Table 11-x).
pub(crate) const SW_REF_NOT_FOUND: u16 = 0x6A88;
/// `6A82` — application/file not found (empty SELECT on a TERMINATED or
/// misconfigured card, PDD §5.2 failure table).
pub(crate) const SW_FILE_NOT_FOUND: u16 = 0x6A82;
/// `6A80` — incorrect parameters in the command data (a duplicate AID on
/// INSTALL commonly surfaces here, GPCS v2.3.1 §11.5).
pub(crate) const SW_WRONG_DATA: u16 = 0x6A80;
/// `6985` — conditions of use not satisfied (per-command: illegal life-cycle
/// transition for SET STATUS, non-empty target for a non-cascading DELETE).
pub(crate) const SW_CONDITIONS: u16 = 0x6985;
/// `6310` — GET STATUS "more data" warning (GPCS v2.3.1 Table 11-38): the
/// registry did not fit in one response; re-issue with P2's next-occurrence bit
/// (`get_status_p2(.., P2_NEXT_TLV, ..)`) to continue (PDD §5.12a).
pub(crate) const SW_MORE_DATA: u16 = 0x6310;

/// Map a [`TransportError`] to its [`ScllError`] (PDD §3.2 / §8).
pub(crate) fn map_transport(err: &TransportError) -> ScllError {
    match err {
        TransportError::CardRemoved => ScllError::CardRemoved,
        TransportError::ReaderGone => ScllError::ReaderGone,
        TransportError::Timeout => ScllError::Timeout,
        TransportError::ProtocolError | TransportError::Other(_) => ScllError::TransportUnavailable,
    }
}

/// Split an R-APDU (`data ‖ SW1 SW2`) into the data field and the 16-bit SW.
/// A response shorter than the two SW bytes is a protocol violation; it is
/// surfaced as `Card { sw: 0 }` (real cards always return at least the SW).
pub(crate) fn split_sw(rapdu: &[u8]) -> Result<(Vec<u8, RAPDU_MAX>, u16), ScllError> {
    let n = rapdu.len();
    if n < 2 {
        return Err(ScllError::Card { sw: 0x0000 });
    }
    let sw = u16::from_be_bytes([rapdu[n - 2], rapdu[n - 1]]);
    let mut data = Vec::new();
    // Cannot fail: the source R-APDU is itself ≤ RAPDU_MAX.
    data.extend_from_slice(&rapdu[..n - 2])
        .map_err(|()| ScllError::Card { sw })?;
    Ok((data, sw))
}

/// Send one raw C-APDU (no SCP wrapping) and split `data ‖ SW`. Used pre-auth
/// (SELECT, GET DATA) and for the IU/EA exchange of `open_scp`, where wrapping
/// is either not yet active or already applied by the SCP state machine.
///
/// # Errors
/// Returns the mapped [`ScllError`] if the transport exchange fails, or
/// [`ScllError::Card`] for a response too short to carry an SW.
pub(crate) fn transmit_plain(
    t: &mut dyn Transport,
    capdu: &[u8],
) -> Result<(Vec<u8, RAPDU_MAX>, u16), ScllError> {
    let rapdu = t.transmit(capdu).map_err(|e| map_transport(&e))?;
    split_sw(&rapdu)
}

/// SELECT by AID (empty ⇒ default application) and require `9000`.
///
/// Returns the FCI data field on success. An empty SELECT that returns `6A82`
/// is mapped to [`ScllError::CardNotUsable`] (PDD §5.2); any other non-`9000`
/// SW maps through [`ScllError::from_general_sw`].
///
/// # Errors
/// [`ScllError::CardNotUsable`] on `6A82`, a mapped [`ScllError`] on another
/// non-success SW, or a transport error.
pub(crate) fn select(t: &mut dyn Transport, aid: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, ScllError> {
    let capdu = select_by_aid(aid)?;
    let (data, sw) = transmit_plain(t, &capdu)?;
    match sw {
        SW_OK => Ok(data),
        SW_FILE_NOT_FOUND => Err(ScllError::CardNotUsable),
        other => Err(ScllError::from_general_sw(other)),
    }
}

/// FCI template tag in a SELECT response (ISO/IEC 7816-4:2020 §7.4;
/// GPCS v2.3.1 §11.1.4).
const TAG_FCI: u32 = 0x6F;
/// DF name tag inside the FCI — the application's *full* registered AID
/// (ISO/IEC 7816-4 §7.4.3.3; GPCS v2.3.1 §11.1.4 SELECT response Table 11-x).
const TAG_DF_NAME: u32 = 0x84;

/// Extract the DF name (tag `'84'`, the application's full AID) from a SELECT
/// response FCI — whether wrapped in the `'6F'` template or present bare. The
/// returned slice borrows `fci` (TLV parsing is zero-copy); `Ok(None)` if the
/// FCI carries no `'84'`.
///
/// GPCS v2.3.1 §11.1.4 / ISO/IEC 7816-4 §7.4.3.3: tag `'84'` of the SELECT FCI
/// is the registered DF name, i.e. the full AID the card matched — which a
/// caller may not know if it `SELECTed` with a partial (RID-only / truncated)
/// AID. Used by `discover_card` to resolve the ISD AID and by `open_scp` to
/// recover the invoker AID for the §6.2.2.1 pseudo-random challenge check.
///
/// # Errors
/// Propagates [`ScllError`] from a malformed TLV structure (`open_scp` treats
/// that as "absent" and falls back to its SELECT target; `discover_card`
/// propagates it).
pub(crate) fn fci_df_name(fci: &[u8]) -> Result<Option<&[u8]>, ScllError> {
    if fci.is_empty() {
        return Ok(None);
    }
    let top = tlv::parse(fci)?;
    if let Some(inner) = find(&top, TAG_FCI) {
        let parsed = tlv::parse(inner)?;
        return Ok(find(&parsed, TAG_DF_NAME));
    }
    Ok(find(&top, TAG_DF_NAME))
}

/// First TLV value matching `tag`, borrowing the parsed list's input lifetime.
fn find<'a>(tlvs: &[Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

/// Wrap a plaintext C-APDU for the open `session`, transmit it, verify/strip
/// the response, and split `data ‖ SW`. The security level fixed at channel
/// open governs C-MAC / C-ENC / R-MAC (no per-call level, §4.1).
///
/// # Errors
/// Propagates [`ScllError::Backend`] from wrap/unwrap (the backend tears the
/// session down on an unwrap failure, Fork F3), a mapped transport error, or
/// [`ScllError::Card`] for a malformed (too-short) response.
pub(crate) fn transmit_in_session<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    capdu_plaintext: &[u8],
) -> Result<(Vec<u8, RAPDU_MAX>, u16), ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let wrapped = match session {
        ScpSession::Scp03(s) => s.wrap_command(backend, capdu_plaintext)?,
        ScpSession::Scp02(s) => s.wrap_command(backend, capdu_plaintext)?,
    };
    let rapdu = t.transmit(&wrapped).map_err(|e| map_transport(&e))?;
    let unwrapped = match session {
        ScpSession::Scp03(s) => s.unwrap_response(backend, &rapdu)?,
        ScpSession::Scp02(s) => s.unwrap_response(backend, &rapdu)?,
    };
    split_sw(&unwrapped)
}

#[cfg(test)]
mod tests {
    use super::fci_df_name;

    /// A full 8-byte AID and the 5-byte RID-only prefix a caller might SELECT.
    const FULL_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C];
    const PARTIAL_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x62];

    /// `6F La 84 Lb <aid>` — the FCI shape a card returns to SELECT.
    fn fci_wrapped(aid: &[u8]) -> std::vec::Vec<u8> {
        let la = u8::try_from(aid.len()).expect("AID fits u8");
        let mut v = std::vec::Vec::new();
        v.extend_from_slice(&[0x6F, la + 2, 0x84, la]);
        v.extend_from_slice(aid);
        v
    }

    #[test]
    fn wrapped_6f_84_yields_full_aid_even_for_partial_select() {
        // The §6.2.2.1 case: SELECT used a partial AID, but the FCI carries the
        // full registered AID under tag '84' — and that is what we must recover.
        let fci = fci_wrapped(FULL_AID);
        assert_eq!(fci_df_name(&fci).unwrap(), Some(FULL_AID));
        assert_ne!(fci_df_name(&fci).unwrap(), Some(PARTIAL_AID));
    }

    #[test]
    fn bare_84_without_outer_6f_resolves() {
        let la = u8::try_from(FULL_AID.len()).expect("AID fits u8");
        let mut bare = std::vec::Vec::new();
        bare.extend_from_slice(&[0x84, la]);
        bare.extend_from_slice(FULL_AID);
        assert_eq!(fci_df_name(&bare).unwrap(), Some(FULL_AID));
    }

    #[test]
    fn tag_84_among_siblings_inside_6f() {
        // 6F { 84 <aid> , 9F70 01 07 } — '84' must be found alongside others.
        let la = u8::try_from(FULL_AID.len()).expect("AID fits u8");
        let inner_len = 2 + FULL_AID.len() + 4; // (84 La aid) + (9F70 01 07)
        let mut fci = std::vec::Vec::new();
        fci.extend_from_slice(&[0x6F, u8::try_from(inner_len).unwrap(), 0x84, la]);
        fci.extend_from_slice(FULL_AID);
        fci.extend_from_slice(&[0x9F, 0x70, 0x01, 0x07]);
        assert_eq!(fci_df_name(&fci).unwrap(), Some(FULL_AID));
    }

    #[test]
    fn fci_without_tag_84_is_none() {
        // 6F { 85 01 FF } — no DF name ⇒ caller falls back to its SELECT target.
        let fci = [0x6F, 0x03, 0x85, 0x01, 0xFF];
        assert_eq!(fci_df_name(&fci).unwrap(), None);
    }

    #[test]
    fn empty_fci_is_none() {
        assert_eq!(fci_df_name(&[]).unwrap(), None);
    }

    #[test]
    fn malformed_fci_is_an_error() {
        // '84' claims 16 bytes but the value is truncated — a TLV error, which
        // `open_scp` maps to a fall-back rather than aborting the channel open.
        let bad = [0x6F, 0x05, 0x84, 0x10, 0x00];
        assert!(fci_df_name(&bad).is_err());
    }
}
