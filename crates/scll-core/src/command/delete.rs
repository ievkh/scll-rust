//! DELETE (CLA 84, INS E4) — PDD §5.3.3 (key) / §5.5 / §5.8 (object), GPCS §11.2.
//!
//! Object scope: Data `'4F' len AID`; P2 `0x00` delete-object, `0x80` cascade
//! (Table 11-22). Key scope: P1 `0x00` last/only (Table 11-21), P2 `0x00`
//! delete-object, Data `'D0' KID` / `'D2' KVN` (both Conditional, Table 11-24);
//! omit one tag for multi-key delete; response single `'00'` (§11.2.3.1).
//! All **verified** against GPCS v2.3.1.

use crate::command::{build, push, push_lv, BuildError, Capdu};

/// Build DELETE [object] for an AID (P2 selects cascade).
///
/// `CLA=84 INS=E4 P1=00`. P2 = `0x80` (delete object + related, e.g. an SD's
/// contents) when `cascade`, else `0x00` (delete object only) — Table 11-22.
/// Data = `'4F' len <aid>`. `Le=00`.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn delete_object(aid: &[u8], cascade: bool) -> Result<Capdu, BuildError> {
    let mut data = Capdu::new();
    push(&mut data, &[0x4F])?;
    push_lv(&mut data, aid)?;
    let p2 = if cascade { 0x80 } else { 0x00 };
    build(0x84, 0xE4, 0x00, p2, &data, true)
}

/// Build DELETE [key]. `kid` → tag `'D0'`, `kvn` → tag `'D2'`; `None` omits the
/// tag (multi-key delete, GPCS Table 11-24). Supplying both deletes a single
/// key. Omission is encoded by leaving the tag off the wire — never a
/// `0xFF`/`0x00` sentinel byte.
///
/// `CLA=84 INS=E4 P1=00 P2=00`, Data = `['D0' 01 kid] ['D2' 01 kvn]`. `Le=00`.
///
/// # Errors
/// Returns [`BuildError::EmptyKeyScope`] if both `kid` and `kvn` are `None`
/// (Table 11-24 needs at least one), or [`BuildError::Overflow`] if the encoded
/// inputs would exceed the short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn delete_key(kid: Option<u8>, kvn: Option<u8>) -> Result<Capdu, BuildError> {
    if kid.is_none() && kvn.is_none() {
        return Err(BuildError::EmptyKeyScope);
    }
    let mut data = Capdu::new();
    if let Some(kid) = kid {
        push(&mut data, &[0xD0, 0x01, kid])?;
    }
    if let Some(kvn) = kvn {
        push(&mut data, &[0xD2, 0x01, kvn])?;
    }
    build(0x84, 0xE4, 0x00, 0x00, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use scll_test_util::HexSlice;

    #[test]
    fn delete_object_only_uses_p2_00() {
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let apdu = delete_object(&aid, false).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([
                0x84, 0xE4, 0x00, 0x00, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00
            ])
        );
    }

    #[test]
    fn delete_object_cascade_uses_p2_80() {
        let aid = [0xA0, 0x00, 0x00, 0x01, 0x51];
        let apdu = delete_object(&aid, true).unwrap();
        assert_eq!(apdu[3], 0x80); // cascade bit
    }

    #[test]
    fn delete_single_key_carries_both_tags_d0_then_d2() {
        let apdu = delete_key(Some(0x01), Some(0x30)).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xE4, 0x00, 0x00, 0x06, 0xD0, 0x01, 0x01, 0xD2, 0x01, 0x30, 0x00])
        );
    }

    #[test]
    fn delete_all_kvns_for_a_kid_omits_d2() {
        let apdu = delete_key(Some(0x02), None).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xE4, 0x00, 0x00, 0x03, 0xD0, 0x01, 0x02, 0x00])
        );
    }

    #[test]
    fn delete_all_kids_for_a_kvn_omits_d0() {
        let apdu = delete_key(None, Some(0x30)).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xE4, 0x00, 0x00, 0x03, 0xD2, 0x01, 0x30, 0x00])
        );
    }

    #[test]
    fn delete_key_needs_at_least_one_scope() {
        assert_eq!(delete_key(None, None), Err(BuildError::EmptyKeyScope));
    }

    #[test]
    fn oversized_object_aid_overflows() {
        let big = [0x00u8; 255];
        assert_eq!(delete_object(&big, false), Err(BuildError::Overflow));
    }

    proptest! {
        /// Both-None always errs; otherwise the present tags land in order.
        #[test]
        fn key_scope_combinations(
            kid in proptest::option::of(any::<u8>()),
            kvn in proptest::option::of(any::<u8>()),
        ) {
            if kid.is_none() && kvn.is_none() {
                prop_assert_eq!(delete_key(kid, kvn), Err(BuildError::EmptyKeyScope));
            } else {
                let apdu = delete_key(kid, kvn).unwrap();
                prop_assert_eq!(&apdu[0..4], &[0x84, 0xE4, 0x00, 0x00]);
                let body = &apdu[5..apdu.len() - 1]; // strip header+Lc and Le
                if let Some(k) = kid {
                    prop_assert_eq!(&body[0..3], &[0xD0, 0x01, k]);
                }
                if let Some(v) = kvn {
                    prop_assert_eq!(&body[body.len() - 3..], &[0xD2, 0x01, v]);
                }
            }
        }
    }
}
