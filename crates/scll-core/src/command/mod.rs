//! `GlobalPlatform` APDU builders — PDD §5 (pure; §3.5).
//!
//! Each submodule builds the C-APDU **plaintext**; SCP wrapping (`CLA | 0x04`,
//! C-MAC, optional C-ENC) is applied later by the session/backend. Verified
//! wire values are documented per submodule against GPCS v2.3.1 §11.
//!
//! `no_std`: builders return a fixed-capacity [`Capdu`] instead of `Vec<u8>`.
//! Because a `heapless` push is fallible, the builders are total — oversized
//! input returns [`BuildError::Overflow`] rather than panicking (the no-panic
//! invariant, §10.5) — so each now returns `Result<Capdu, BuildError>`.
//!
//! All builders share the [`build`] short-APDU framer and the [`push`] /
//! [`push_lv`] helpers below (private to this module; visible to the
//! submodules). `build` lays out the ISO/IEC 7816-4:2020 §5.1 short-APDU cases:
//! empty data ⇒ no `Lc` (Case 1/2), `le` ⇒ a trailing `Le = 00` ("all
//! available"). Only SET STATUS omits `Le` (Case 1/3, Table 11-85).

use heapless::Vec;

use crate::limits::CAPDU_MAX;

pub mod delete; // DELETE (INS E4): object + key scope — §5.3.3/§5.5/§5.8, GPCS §11.2
pub mod get_data; // GET DATA '66'/'67'/'00E0'/IIN/CIN — §5.2
pub mod get_status; // GET STATUS (INS F2) — §5.12, GPCS §11.4
pub mod install; // INSTALL (INS E6): for Load/Install/Personalization — §5.4/§5.4a/§5.6/§5.7
pub mod load;
pub mod put_key; // PUT KEY (INS D8) — §5.3.1, GPCS §11.8
pub mod rmac_session; // BEGIN/END R-MAC SESSION (INS 7A/78) — SCP02, GPCS App E
pub mod select; // SELECT — ISO/IEC 7816-4; §5.2/§5.9
pub mod set_status; // SET STATUS (INS F0) — §5.11, GPCS §11.10 // LOAD (INS E8) — §5.4a, GPCS §11.6

/// A built short C-APDU plaintext buffer (≤ `CAPDU_MAX`). SCP wrapping (C-MAC,
/// optional C-ENC) is applied later by the session, which may grow it — still
/// within `CAPDU_MAX` for short APDUs.
pub type Capdu = Vec<u8, CAPDU_MAX>;

/// Command-builder failure. Builders are total (no panic on any input): inputs
/// that would exceed the short-APDU buffer return `Overflow`.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// Inputs would exceed the short-APDU plaintext buffer (`CAPDU_MAX`).
    #[error("inputs exceed short-APDU buffer")]
    Overflow,
    /// `delete_key` was called with neither `kid` nor `kvn`. GPCS v2.3.1
    /// Table 11-24 makes both `'D0'`/`'D2'` Conditional, but at least one must
    /// be present (an empty DELETE [key] data field selects nothing).
    #[error("DELETE [key] needs at least one of kid/kvn")]
    EmptyKeyScope,
}

/// Assemble a short C-APDU plaintext: 4-byte header, optional `Lc`+data,
/// optional `Le`.
///
/// Empty `data` ⇒ no `Lc`/data bytes (ISO/IEC 7816-4:2020 §5.1, Case 1/2).
/// `le = true` appends a single `0x00` (`Le`, "all available"). Total: any
/// `data` longer than a short `Lc` (255) yields [`BuildError::Overflow`]
/// instead of panicking.
fn build(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: bool) -> Result<Capdu, BuildError> {
    let mut apdu = Capdu::new();
    push(&mut apdu, &[cla, ins, p1, p2])?;
    if !data.is_empty() {
        let lc = u8::try_from(data.len()).map_err(|_| BuildError::Overflow)?;
        push(&mut apdu, &[lc])?;
        push(&mut apdu, data)?;
    }
    if le {
        push(&mut apdu, &[0x00])?;
    }
    Ok(apdu)
}

/// Append `src` to `out`, mapping the `heapless` capacity error to `Overflow`.
fn push(out: &mut Capdu, src: &[u8]) -> Result<(), BuildError> {
    out.extend_from_slice(src)
        .map_err(|()| BuildError::Overflow)
}

/// Append a 1-byte-length-prefixed field `len ‖ bytes` — the INSTALL field
/// layout and the value half of a 1-byte-length BER-TLV. `bytes` longer than
/// 255 ⇒ [`BuildError::Overflow`].
fn push_lv(out: &mut Capdu, bytes: &[u8]) -> Result<(), BuildError> {
    let len = u8::try_from(bytes.len()).map_err(|_| BuildError::Overflow)?;
    push(out, &[len])?;
    push(out, bytes)
}
