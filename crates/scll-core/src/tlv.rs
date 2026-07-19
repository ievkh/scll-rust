//! BER-TLV parse/encode (PDD §3.5). Pure, fuzzable (§10.5 target #2).
//!
//! Used by the card-response parsers: CRD `'66'`, CCI `'67'`, key-info template
//! `'00E0'`, and `GET STATUS` `'E3'`. Property obligation (§10.4):
//! `parse ∘ encode == identity`.
//!
//! `no_std`, zero-copy: [`Tlv`] borrows its `value` from the input rather than
//! owning it (no per-object heap/inline buffer; nested templates recurse on
//! `tlv.value` for free). [`parse`] returns a bounded `heapless::Vec` of
//! borrows; [`encode`] writes into a caller buffer. Both are total — malformed
//! or oversized input yields a typed [`TlvError`], never a panic (§10.5).
//!
//! Tag/length encoding follows ISO/IEC 7816-4:2020 §5.2.2 (BER-TLV, the same
//! basic encoding rules as ITU-T X.690). The tag is stored as the raw, big-
//! endian concatenation of its identifier octets in a `u32` (e.g. `'9F70'` →
//! `0x0000_9F70`, `'E0'` → `0x0000_00E0`), which is how GP templates are keyed.
//! Tags wider than four octets are out of range for GP and rejected. The parser
//! is a lenient BER reader (it accepts non-minimal long-form lengths, which BER
//! permits); the encoder always emits the minimal canonical form, so its output
//! always re-parses.

use heapless::Vec;

use crate::limits::MAX_TLVS;

/// A parsed tag-length-value triple (tag may be multi-byte, e.g. `'9F70'`).
/// `value` borrows into the slice passed to [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

/// Low 5 bits of the leading tag octet all set ⇒ the tag continues into further
/// octets (ISO/IEC 7816-4 §5.2.2.1 / X.690 §8.1.2.4).
const TAG_MULTIBYTE: u8 = 0x1F;
/// b8 of a subsequent tag octet set ⇒ another tag octet follows.
const TAG_MORE: u8 = 0x80;
/// Largest tag width we represent (a `u32` holds four identifier octets).
const TAG_MAX_OCTETS: usize = 4;
/// b8 of the leading length octet set ⇒ long form; low 7 bits give the count.
const LEN_LONG: u8 = 0x80;

/// Parse a sequence of top-level BER-TLV objects from a byte slice. Values
/// borrow from `input`. Returns `TlvError::TooMany` if more than [`MAX_TLVS`]
/// objects are present (rather than allocating or panicking).
///
/// # Errors
/// Returns [`TlvError::Truncated`] / [`TlvError::BadLength`] for malformed
/// input, or [`TlvError::TooMany`] if more than [`MAX_TLVS`] top-level objects
/// are present.
pub fn parse(input: &[u8]) -> Result<Vec<Tlv<'_>, MAX_TLVS>, TlvError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = parse_tag(input, &mut pos)?;
        let len = parse_len(input, &mut pos)?;
        let end = pos.checked_add(len).ok_or(TlvError::Truncated)?;
        if end > input.len() {
            return Err(TlvError::Truncated);
        }
        out.push(Tlv {
            tag,
            value: &input[pos..end],
        })
        .map_err(|_| TlvError::TooMany)?;
        pos = end;
    }
    Ok(out)
}

/// Encode a sequence of BER-TLV objects into `out`, returning the number of
/// bytes written. `TlvError::Overflow` if `out` is too small (the caller sizes
/// the scratch — typically a command data field ≤ 255 B).
///
/// # Errors
/// Returns [`TlvError::Overflow`] if `out` is too small to hold the encoded
/// objects.
pub fn encode(items: &[Tlv<'_>], out: &mut [u8]) -> Result<usize, TlvError> {
    let mut pos = 0usize;
    for item in items {
        pos = write_tag(item.tag, out, pos)?;
        pos = write_len(item.value.len(), out, pos)?;
        pos = write_bytes(out, pos, item.value)?;
    }
    Ok(pos)
}

/// Read one (possibly multi-octet) tag, advancing `*pos`.
fn parse_tag(input: &[u8], pos: &mut usize) -> Result<u32, TlvError> {
    let b0 = *input.get(*pos).ok_or(TlvError::Truncated)?;
    *pos += 1;
    let mut tag = u32::from(b0);
    if b0 & TAG_MULTIBYTE == TAG_MULTIBYTE {
        let mut octets = 1usize;
        loop {
            let b = *input.get(*pos).ok_or(TlvError::Truncated)?;
            *pos += 1;
            octets += 1;
            if octets > TAG_MAX_OCTETS {
                return Err(TlvError::BadLength);
            }
            tag = (tag << 8) | u32::from(b);
            if b & TAG_MORE == 0 {
                break;
            }
        }
    }
    Ok(tag)
}

/// Read a definite BER length (short or long form), advancing `*pos`.
fn parse_len(input: &[u8], pos: &mut usize) -> Result<usize, TlvError> {
    let b0 = *input.get(*pos).ok_or(TlvError::Truncated)?;
    *pos += 1;
    if b0 & LEN_LONG == 0 {
        return Ok(usize::from(b0));
    }
    let count = usize::from(b0 & !LEN_LONG);
    // `0x80` = indefinite form (not permitted in DER and unused by GP); a count
    // wider than a `usize` cannot index the buffer. Either ⇒ malformed.
    if count == 0 || count > core::mem::size_of::<usize>() {
        return Err(TlvError::BadLength);
    }
    let mut len = 0usize;
    for _ in 0..count {
        let b = *input.get(*pos).ok_or(TlvError::Truncated)?;
        *pos += 1;
        len = (len << 8) | usize::from(b);
    }
    Ok(len)
}

/// Write a tag as its minimal big-endian identifier octets.
fn write_tag(tag: u32, out: &mut [u8], pos: usize) -> Result<usize, TlvError> {
    let bytes = tag.to_be_bytes();
    // First significant octet; for `tag == 0` emit the single octet `0x00`.
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    write_bytes(out, pos, &bytes[start..])
}

/// Write a definite BER length in its minimal canonical form.
fn write_len(len: usize, out: &mut [u8], pos: usize) -> Result<usize, TlvError> {
    if len < usize::from(LEN_LONG) {
        // `len < 0x80`, so the conversion cannot fail.
        let b = u8::try_from(len).map_err(|_| TlvError::Overflow)?;
        return write_bytes(out, pos, &[b]);
    }
    let bytes = len.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let body = &bytes[start..];
    // `body.len() <= size_of::<usize>() <= 8`, so it fits the low 7 bits.
    let count = u8::try_from(body.len()).map_err(|_| TlvError::Overflow)?;
    let pos = write_bytes(out, pos, &[LEN_LONG | count])?;
    write_bytes(out, pos, body)
}

/// Copy `src` into `out` at `pos`, bounds-checked; returns the new position.
fn write_bytes(out: &mut [u8], pos: usize, src: &[u8]) -> Result<usize, TlvError> {
    let end = pos.checked_add(src.len()).ok_or(TlvError::Overflow)?;
    if end > out.len() {
        return Err(TlvError::Overflow);
    }
    out[pos..end].copy_from_slice(src);
    Ok(end)
}

/// TLV parse/encode failure.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlvError {
    /// Length field runs past the end of the buffer.
    #[error("TLV value runs past end of buffer")]
    Truncated,
    /// Malformed length encoding (e.g. reserved long-form, non-minimal).
    #[error("malformed TLV length encoding")]
    BadLength,
    /// More than `MAX_TLVS` top-level objects in the input.
    #[error("more than MAX_TLVS top-level TLV objects")]
    TooMany,
    /// `encode` output buffer too small.
    #[error("encode output buffer too small")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use scll_test_util::HexSlice;

    // ---- Concrete GP-shaped vectors --------------------------------------

    #[test]
    fn parses_two_single_byte_tag_objects() {
        // '4F' (AID) len 2 + '9F70' (life-cycle) len 1.
        let input = [0x4F, 0x02, 0xA0, 0x00, 0x9F, 0x70, 0x01, 0x07];
        let tlvs = parse(&input).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tag, 0x4F);
        assert_eq!(HexSlice(tlvs[0].value), HexSlice(&[0xA0, 0x00]));
        assert_eq!(tlvs[1].tag, 0x9F70);
        assert_eq!(HexSlice(tlvs[1].value), HexSlice(&[0x07]));
    }

    #[test]
    fn parses_long_form_length() {
        // '66' with a 130-byte value via long form 0x81 0x82.
        let mut input = heapless::Vec::<u8, 300>::new();
        input.extend_from_slice(&[0x66, 0x81, 0x82]).unwrap();
        input.extend_from_slice(&[0xAB; 0x82]).unwrap();
        let tlvs = parse(&input).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x66);
        assert_eq!(tlvs[0].value.len(), 0x82);
    }

    #[test]
    fn empty_input_yields_no_objects() {
        assert_eq!(parse(&[]).unwrap().len(), 0);
    }

    // ---- Malformed input is rejected, never panics (§10.5) ---------------

    #[test]
    fn truncated_value_is_rejected() {
        assert_eq!(parse(&[0x4F, 0x05, 0x01, 0x02]), Err(TlvError::Truncated));
    }

    #[test]
    fn truncated_tag_is_rejected() {
        // Leading octet signals continuation, but the buffer ends.
        assert_eq!(parse(&[0x9F]), Err(TlvError::Truncated));
    }

    #[test]
    fn missing_length_octet_is_rejected() {
        assert_eq!(parse(&[0x4F]), Err(TlvError::Truncated));
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert_eq!(parse(&[0x4F, 0x80, 0x01]), Err(TlvError::BadLength));
    }

    #[test]
    fn oversized_tag_is_rejected() {
        // Five continuation octets cannot fit a u32 tag.
        assert_eq!(
            parse(&[0x1F, 0x81, 0x81, 0x81, 0x81, 0x01]),
            Err(TlvError::BadLength)
        );
    }

    #[test]
    fn long_form_length_octets_exceeding_usize_rejected() {
        // 0x80 | 9 ⇒ nine length octets, wider than any usize.
        assert_eq!(parse(&[0x4F, 0x89]), Err(TlvError::BadLength));
    }

    #[test]
    fn too_many_objects_is_rejected() {
        // (MAX_TLVS + 1) minimal one-byte-value objects.
        let mut input = heapless::Vec::<u8, { (MAX_TLVS + 1) * 3 }>::new();
        for _ in 0..=MAX_TLVS {
            input.extend_from_slice(&[0x80, 0x01, 0x00]).unwrap();
        }
        assert_eq!(parse(&input), Err(TlvError::TooMany));
    }

    // ---- encode ----------------------------------------------------------

    #[test]
    fn encode_emits_canonical_long_form() {
        let value = [0xAB; 0x82];
        let items = [Tlv {
            tag: 0x66,
            value: &value,
        }];
        let mut out = [0u8; 300];
        let n = encode(&items, &mut out).unwrap();
        assert_eq!(HexSlice(&out[..3]), HexSlice(&[0x66, 0x81, 0x82]));
        assert_eq!(n, 3 + 0x82);
    }

    #[test]
    fn encode_overflow_is_reported_not_panicked() {
        let items = [Tlv {
            tag: 0x4F,
            value: &[1, 2, 3, 4],
        }];
        let mut out = [0u8; 3]; // too small for tag+len+4
        assert_eq!(encode(&items, &mut out), Err(TlvError::Overflow));
    }

    // ---- Properties (§10.4) ---------------------------------------------

    /// A round-trippable tag: either a single octet that does not signal
    /// continuation, or a two-octet tag (`0x9Fxx`, `xx` terminating).
    fn tag_strategy() -> impl Strategy<Value = u32> {
        prop_oneof![
            (0u32..=0xFF).prop_filter("not a continuation tag", |t| t & 0x1F != 0x1F),
            (0u32..=0x7F).prop_map(|lo| 0x9F00 | lo),
        ]
    }

    fn tlv_items() -> impl Strategy<Value = std::vec::Vec<(u32, std::vec::Vec<u8>)>> {
        proptest::collection::vec(
            (
                tag_strategy(),
                proptest::collection::vec(any::<u8>(), 0..=64),
            ),
            0..=MAX_TLVS,
        )
    }

    proptest! {
        /// `parse ∘ encode == identity` (§10.4).
        #[test]
        fn parse_after_encode_is_identity(items in tlv_items()) {
            let tlvs: std::vec::Vec<Tlv> =
                items.iter().map(|(t, v)| Tlv { tag: *t, value: v }).collect();
            let mut out = [0u8; 64 * 70];
            let n = encode(&tlvs, &mut out).unwrap();
            let parsed = parse(&out[..n]).unwrap();
            prop_assert_eq!(parsed.len(), tlvs.len());
            for (got, want) in parsed.iter().zip(tlvs.iter()) {
                prop_assert_eq!(got.tag, want.tag);
                prop_assert_eq!(got.value, want.value);
            }
        }

        /// The encoder never emits a byte string the parser rejects.
        #[test]
        fn encoder_output_always_parses(items in tlv_items()) {
            let tlvs: std::vec::Vec<Tlv> =
                items.iter().map(|(t, v)| Tlv { tag: *t, value: v }).collect();
            let mut out = [0u8; 64 * 70];
            let n = encode(&tlvs, &mut out).unwrap();
            prop_assert!(parse(&out[..n]).is_ok());
        }

        /// Parsing arbitrary bytes never panics: always Ok or a typed error.
        #[test]
        fn parse_arbitrary_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes);
        }
    }
}
