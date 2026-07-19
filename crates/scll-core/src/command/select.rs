//! SELECT (CLA 00, INS A4, P1 04, P2 00) — PDD §5.2/§5.9.

use crate::command::{build, BuildError, Capdu};

/// Build a SELECT-by-AID. Empty `aid` selects the default application (ISD on a
/// GP-compliant card, GPCS v2.3.1 §5.2.2).
///
/// `CLA=00 INS=A4 P1=04` (select by name, first/only occurrence) `P2=00`.
/// Empty `aid` ⇒ Case 2S `00 A4 04 00 00`; a 5..=16-byte AID ⇒ Case 4S
/// `00 A4 04 00 Lc <aid> 00`.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn select_by_aid(aid: &[u8]) -> Result<Capdu, BuildError> {
    build(0x00, 0xA4, 0x04, 0x00, aid, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use scll_test_util::HexSlice;

    #[test]
    fn empty_aid_selects_default_application() {
        // GPCS §5.2.2: empty SELECT returns the default-selected application.
        let apdu = select_by_aid(&[]).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice([0x00, 0xA4, 0x04, 0x00, 0x00]));
    }

    #[test]
    fn by_aid_wraps_header_lc_and_le() {
        // Canonical ISD RID shape (GPCS A000000151…), 5-byte AID.
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let apdu = select_by_aid(&aid).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00])
        );
    }

    #[test]
    fn oversized_input_returns_overflow_not_panic() {
        // 256 bytes cannot fit a 1-byte short Lc → total, no panic.
        let big = [0xABu8; 256];
        assert_eq!(select_by_aid(&big), Err(BuildError::Overflow));
    }

    proptest! {
        /// Any short-length AID frames a Case-4S APDU with a matching Lc/body.
        #[test]
        fn round_trips_any_short_aid(aid in proptest::collection::vec(any::<u8>(), 1..=255)) {
            let apdu = select_by_aid(&aid).unwrap();
            prop_assert_eq!(&apdu[0..4], &[0x00, 0xA4, 0x04, 0x00]);
            prop_assert_eq!(usize::from(apdu[4]), aid.len());
            prop_assert_eq!(&apdu[5..5 + aid.len()], aid.as_slice());
            prop_assert_eq!(*apdu.last().unwrap(), 0x00);
        }

        /// Total: never panics for any input length, oversized included.
        #[test]
        fn never_panics(aid in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = select_by_aid(&aid);
        }
    }
}
