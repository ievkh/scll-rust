//! GET DATA (CLA 80, INS CA) — PDD §5.2.
//!
//! Tags: `'66'` Card Recognition Data (§H.2), `'67'` Card Capability Information
//! (§H.4), `'00E0'` Key Information Template (§11.3.3.1), `'0042'` IIN,
//! `'0045'` CIN.

use crate::command::{build, BuildError, Capdu};

/// Build a GET DATA for the given 2-byte tag (P1P2).
///
/// `CLA=80 INS=CA`, P1P2 = the object tag big-endian (e.g. `'0066'` CRD,
/// `'00E0'` KIT, `'0067'` CCI, `'0042'` IIN, `'0045'` CIN). No command data;
/// `Le=00` (Case 2S).
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
pub fn get_data(tag_p1p2: u16) -> Result<Capdu, BuildError> {
    let [p1, p2] = tag_p1p2.to_be_bytes();
    build(0x80, 0xCA, p1, p2, &[], true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use scll_test_util::HexSlice;

    #[test]
    fn card_recognition_data_tag_66() {
        let apdu = get_data(0x0066).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x80, 0xCA, 0x00, 0x66, 0x00]));
    }

    #[test]
    fn key_information_template_tag_00e0() {
        let apdu = get_data(0x00E0).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x80, 0xCA, 0x00, 0xE0, 0x00]));
    }

    #[test]
    fn iin_tag_0042_splits_both_p1_p2_bytes() {
        // Exercises a non-zero P1 byte so the big-endian split is checked.
        let apdu = get_data(0x0042).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x80, 0xCA, 0x00, 0x42, 0x00]));
    }

    #[test]
    fn high_tag_byte_is_p1() {
        let apdu = get_data(0x9F7F).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x80, 0xCA, 0x9F, 0x7F, 0x00]));
    }

    proptest! {
        /// For any tag, the APDU is exactly header ‖ P1P2(tag) ‖ Le.
        #[test]
        fn is_header_tag_le(tag in any::<u16>()) {
            let apdu = get_data(tag).unwrap();
            let [p1, p2] = tag.to_be_bytes();
            let expected = [0x80, 0xCA, p1, p2, 0x00];
            prop_assert_eq!(apdu.as_slice(), expected.as_slice());
        }
    }
}
