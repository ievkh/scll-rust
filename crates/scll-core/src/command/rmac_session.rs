//! BEGIN / END R-MAC SESSION (CLA 80, INS 7A / 78) — SCP02 response integrity.
//!
//! These frame an SCP02 R-MAC session: `BEGIN R-MAC SESSION` tells the card to
//! start appending an R-MAC to each response, and `END R-MAC SESSION` retrieves
//! (and optionally ends) the accumulated R-MAC. They build the **plaintext**
//! C-APDU only; the session/backend applies `CLA | 0x04` + C-MAC afterwards (the
//! commands must themselves be sent inside the secure channel).
//!
//! Coding (GPCS v2.3.1 Appendix E; the parameter tables mirror Amendment D
//! §7.x for SCP03, and are cross-checked byte-for-byte against the `skythen/scp02`
//! Go reference, `beginRMACSession`/`EndRMACSession`):
//!   * BEGIN: INS `0x7A`, P1 `0x10` (each response carries an R-MAC — for SCP02
//!     which has no response encryption, `0x30`/R-ENC does not apply), P2 `0x00`.
//!     The data field is an LV-coded 'data' element (`len ‖ data`). The card does
//!     not interpret 'data' but folds it into the R-MAC, letting the host inject
//!     a challenge; the LV total is ≤ 25 bytes, so `data` is `1..=24` bytes.
//!   * END: INS `0x78`, P1 `0x00`, P2 `0x03` (end the session **and** return the
//!     R-MAC) or `0x01` (return the current R-MAC without ending). No data field;
//!     `Le = 00` requests the 8-byte R-MAC in the response.

use crate::command::{build, push_lv, BuildError, Capdu};

/// P1: begin an R-MAC session in which each response carries an R-MAC.
const BEGIN_P1_RMAC: u8 = 0x10;
/// P2: end the R-MAC session and return the accumulated R-MAC.
const END_P2_END_AND_RETURN: u8 = 0x03;
/// P2: return the current R-MAC without ending the session.
const END_P2_RETURN_ONLY: u8 = 0x01;

/// Build a `BEGIN R-MAC SESSION` (CLA 80, INS 7A) plaintext C-APDU.
///
/// `data` is the caller's optional R-MAC challenge, sent LV-coded (`len ‖ data`)
/// and folded into the card's R-MAC. It must be `1..=24` bytes.
///
/// # Errors
/// [`BuildError::Overflow`] if `data` is empty or longer than 24 bytes.
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn begin_rmac_session(data: &[u8]) -> Result<Capdu, BuildError> {
    if data.is_empty() || data.len() > 24 {
        return Err(BuildError::Overflow);
    }
    let mut field = Capdu::new();
    push_lv(&mut field, data)?; // 'data' element: len ‖ data
    build(0x80, 0x7A, BEGIN_P1_RMAC, 0x00, &field, true)
}

/// Build an `END R-MAC SESSION` (CLA 80, INS 78) plaintext C-APDU. `end_session`
/// selects P2 `0x03` (end and return the R-MAC) vs `0x01` (return only). The
/// response returns the 8-byte R-MAC, so `Le = 00` is present.
#[must_use]
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn end_rmac_session(end_session: bool) -> Capdu {
    let p2 = if end_session {
        END_P2_END_AND_RETURN
    } else {
        END_P2_RETURN_ONLY
    };
    // 80 78 00 P2 00 — four-byte header + Le, no data field. Five bytes is far
    // under CAPDU_MAX, so the push cannot fail (no-panic invariant, §10.5).
    let mut apdu = Capdu::new();
    let _ = apdu.extend_from_slice(&[0x80, 0x78, 0x00, p2, 0x00]);
    apdu
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn begin_wraps_data_lv_with_p1_10() {
        // 80 7A 10 00 | Lc=04 | LV(03 A1 B2 C3) | Le=00
        let apdu = begin_rmac_session(&[0xA1, 0xB2, 0xC3]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0x7A, 0x10, 0x00, 0x04, 0x03, 0xA1, 0xB2, 0xC3, 0x00])
        );
    }

    #[test]
    fn begin_rejects_empty_and_oversized_data() {
        assert_eq!(begin_rmac_session(&[]), Err(BuildError::Overflow));
        assert_eq!(begin_rmac_session(&[0u8; 25]), Err(BuildError::Overflow));
        // Boundary: 24 data bytes → 25-byte LV, still valid.
        assert!(begin_rmac_session(&[0u8; 24]).is_ok());
    }

    #[test]
    fn end_p2_selects_end_vs_return_only() {
        // End + return: 80 78 00 03 00
        assert_eq!(
            HexSlice(&end_rmac_session(true)),
            HexSlice([0x80, 0x78, 0x00, 0x03, 0x00])
        );
        // Return only: 80 78 00 01 00
        assert_eq!(
            HexSlice(&end_rmac_session(false)),
            HexSlice([0x80, 0x78, 0x00, 0x01, 0x00])
        );
    }
}
