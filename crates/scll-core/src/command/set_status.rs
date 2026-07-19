//! SET STATUS (CLA 84, INS F0) — PDD §5.11, GPCS v2.3.1 §11.10.
//!
//! Card/ISD scope (**verified**, §11.10.2.1–.3):
//! - P1 = `0x80` (Table 11-86: ISD = b8b7b6 `100`).
//! - P2 = target card life-cycle byte (Table 11-6): `INITIALIZED 0x07`,
//!   `SECURED 0x0F`, `CARD_LOCKED 0x7F`; unlock → `0x0F`.
//! - Data = raw, untagged ISD AID; **ignored** when P1=`0x80` (empty also legal).

use crate::command::{build, BuildError, Capdu};

/// Build a SET STATUS for card/ISD scope (P1 fixed `0x80`).
///
/// `CLA=84 INS=F0 P1=80`, `P2 = p2_state` (Table 11-6 card life-cycle byte).
/// Data = the raw, untagged ISD AID; the card ignores it under P1=`0x80`
/// (§11.10.2.3) but it is sent for cross-card compatibility (empty is also
/// legal). **No `Le`** (Table 11-85, Case 1/3) — the only builder here that
/// omits it.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
pub fn set_card_status(p2_state: u8, isd_aid: &[u8]) -> Result<Capdu, BuildError> {
    build(0x84, 0xF0, 0x80, p2_state, isd_aid, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn secured_with_isd_aid_has_no_le() {
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let apdu = set_card_status(0x0F, &aid).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xF0, 0x80, 0x0F, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51])
        );
    }

    #[test]
    fn empty_aid_is_case_1_header_only() {
        // Data ignored under P1=0x80, so an empty data field is spec-legal.
        let apdu = set_card_status(0x07, &[]).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x84, 0xF0, 0x80, 0x07]));
    }

    #[test]
    fn card_locked_byte_maps_to_p2() {
        let apdu = set_card_status(0x7F, &[]).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x84, 0xF0, 0x80, 0x7F]));
    }

    #[test]
    fn oversized_aid_overflows() {
        let big = [0x00u8; 256];
        assert_eq!(set_card_status(0x0F, &big), Err(BuildError::Overflow));
    }
}
