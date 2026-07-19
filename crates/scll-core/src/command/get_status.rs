//! GET STATUS (CLA 80, INS F2) — PDD §5.12, GPCS v2.3.1 §11.4.
//!
//! Card/ISD scope: P1 `0x80` (Table 11-33), P2 `0x02` (Table 11-34: b2=1 modern
//! TLV, b1=0 first/all), Data `'4F' 00` match-all (Table 11-35). Response is a
//! `'E3'` registry entry carrying `'9F70'` life-cycle (len 1), `'4F'` AID,
//! `'C5'` privileges (Table 11-36, §11.4.3.1) — **verified**.

use crate::command::{build, push, push_lv, BuildError, Capdu};

/// P2 = get **first/all** occurrence(s) + modern TLV response (Table 11-34:
/// b1=0 first/all, b2=1 TLV). The opening value of a paged GET STATUS.
pub const P2_FIRST_TLV: u8 = 0x02;
/// P2 = get **next** occurrence + modern TLV response (Table 11-34: b1=1 next,
/// b2=1 TLV). Sent to continue after a `63 10` "more data" warning
/// (Table 11-38) when enumerating the registry across pages (PDD §5.12a).
pub const P2_NEXT_TLV: u8 = 0x03;

/// Build a GET STATUS for an arbitrary P1 scope and `'4F'`-tagged AID qualifier,
/// with P2 fixed at [`P2_FIRST_TLV`] (`0x02`).
///
/// `CLA=80 INS=F2`, Data = `'4F' len <aid_qualifier>` (Table 11-35; `'4F'` is
/// Mandatory). An empty `aid_qualifier` yields `'4F' 00` = match-all
/// (§11.4.2.3). `Le=00`. Thin wrapper over [`get_status_p2`].
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
pub fn get_status(p1: u8, aid_qualifier: &[u8]) -> Result<Capdu, BuildError> {
    get_status_p2(p1, P2_FIRST_TLV, aid_qualifier)
}

/// Build a GET STATUS with an explicit P2 — the paginating form used by
/// `get_card_inventory` (PDD §5.12a) to send [`P2_FIRST_TLV`] for the first page
/// and [`P2_NEXT_TLV`] to continue after `63 10`.
///
/// `CLA=80 INS=F2`, Data = `'4F' len <aid_qualifier>` (Table 11-35), `Le=00`.
/// P1/P2 are passed through verbatim; the caller owns their meaning
/// (Tables 11-33 / 11-34).
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
pub fn get_status_p2(p1: u8, p2: u8, aid_qualifier: &[u8]) -> Result<Capdu, BuildError> {
    let mut data = Capdu::new();
    push(&mut data, &[0x4F])?;
    push_lv(&mut data, aid_qualifier)?;
    build(0x80, 0xF2, p1, p2, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn isd_match_all_is_the_verified_4f00_form() {
        // PDD §5.12 verified ISD GET STATUS: 80 F2 80 02 02 4F00 00.
        let apdu = get_status(0x80, &[]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0xF2, 0x80, 0x02, 0x02, 0x4F, 0x00, 0x00])
        );
    }

    #[test]
    fn qualifier_is_tlv_tagged_under_4f() {
        // Applications/SSD scope P1=0x40 with a partial-AID search qualifier.
        let apdu = get_status(0x40, &[0xA0, 0x00]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0xF2, 0x40, 0x02, 0x04, 0x4F, 0x02, 0xA0, 0x00, 0x00])
        );
    }

    #[test]
    fn oversized_qualifier_overflows_lc() {
        // '4F' + len + 255 bytes = 257-byte data field → exceeds short Lc.
        let big = [0x11u8; 255];
        assert_eq!(get_status(0x80, &big), Err(BuildError::Overflow));
    }

    #[test]
    fn p2_next_form_paginates_with_03() {
        // The §5.12a continuation: same scope, P2 = 0x03 (next + TLV).
        let apdu = get_status_p2(0x40, P2_NEXT_TLV, &[]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x80, 0xF2, 0x40, 0x03, 0x02, 0x4F, 0x00, 0x00])
        );
    }

    #[test]
    fn get_status_is_the_first_tlv_form_of_p2() {
        // get_status(..) must equal get_status_p2(.., 0x02, ..) for every scope.
        for p1 in [0x80u8, 0x40, 0x20, 0x10] {
            assert_eq!(get_status(p1, &[]), get_status_p2(p1, P2_FIRST_TLV, &[]));
        }
    }
}
