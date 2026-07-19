//! `Aid` newtype — Application Identifier (PDD §6).
//!
//! 5..=16 bytes, validated on construction (RID 5 B + PIX ≤ 11 B,
//! ISO/IEC 7816-5; AID structure also ISO/IEC 7816-4:2020 §8).
//!
//! `no_std`/heapless: backed by `heapless::Vec<u8, AID_MAX>` instead of `Vec`.
//! The constructor now takes `&[u8]` (the previous `impl Into<Vec<u8>>` bound
//! pulled in `alloc`).

use heapless::Vec;

use crate::error::ScllError;
use crate::limits::AID_MAX;

/// Smallest legal AID: a 5-byte RID with an empty PIX (ISO/IEC 7816-5).
const AID_MIN: usize = 5;

/// Validated AID. Construction enforces the 5..=16 byte length.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Aid(Vec<u8, AID_MAX>);

impl core::fmt::Debug for Aid {
    /// Renders as `Aid("A0000001515344")` — the AID bytes as an uppercase hex
    /// string rather than a decimal array.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aid({:?})", crate::hexfmt::HexBytes(&self.0))
    }
}

impl Aid {
    /// Build an `Aid`, rejecting lengths outside 5..=16.
    ///
    /// # Errors
    /// Returns [`ScllError::InvalidAid`] if `bytes` is not a valid AID length
    /// (outside 5..=16 bytes; RID 5 B + PIX ≤ 11 B, ISO/IEC 7816-5).
    pub fn new(bytes: &[u8]) -> Result<Self, ScllError> {
        if !(AID_MIN..=AID_MAX).contains(&bytes.len()) {
            return Err(ScllError::InvalidAid { len: bytes.len() });
        }
        // Cannot fail: the bound above guarantees `bytes.len() <= AID_MAX`.
        let mut v = Vec::new();
        v.extend_from_slice(bytes)
            .map_err(|()| ScllError::InvalidAid { len: bytes.len() })?;
        Ok(Self(v))
    }

    /// Borrow the raw AID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn accepts_every_length_in_range() {
        for len in AID_MIN..=AID_MAX {
            let n = u8::try_from(len).expect("len <= AID_MAX fits u8");
            let raw: heapless::Vec<u8, AID_MAX> = (0..n).collect();
            let aid = Aid::new(&raw).expect("5..=16 bytes must be accepted");
            assert_eq!(HexSlice(aid.as_bytes()), HexSlice(&raw));
        }
    }

    #[test]
    fn rejects_too_short() {
        for len in 0..AID_MIN {
            let n = u8::try_from(len).expect("len < AID_MIN fits u8");
            let raw: heapless::Vec<u8, AID_MAX> = (0..n).collect();
            assert!(
                matches!(Aid::new(&raw), Err(ScllError::InvalidAid { len: got }) if got == len),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_too_long() {
        for len in (AID_MAX + 1)..=(AID_MAX + 4) {
            // Build an over-length input without exceeding the heapless buffer.
            let raw: [u8; AID_MAX + 4] =
                core::array::from_fn(|i| u8::try_from(i).expect("index < 20 fits u8"));
            assert!(
                matches!(Aid::new(&raw[..len]), Err(ScllError::InvalidAid { len: got }) if got == len),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn as_bytes_round_trips_a_realistic_rid() {
        // ISD AID example shape: 5-byte RID + 4-byte PIX (GPCS A000000151…).
        let raw = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x00];
        let aid = Aid::new(&raw).unwrap();
        assert_eq!(HexSlice(aid.as_bytes()), HexSlice(&raw));
    }
}
