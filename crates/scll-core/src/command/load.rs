//! LOAD (CLA 84, INS E8) — PDD §5.4a, GPCS v2.3.1 §11.6.
//!
//! P1: `0x00` more blocks, `0x80` last block. P2: block number from `0x00`.
//! Chunk size ≤ `LOAD_BLOCK_DATA` (223 B) plaintext (short APDU); ≤ 256 blocks.
//!
//! Scope note: `load_block` is a pure per-block APDU framer. The first block's
//! `'C4'` (Load File) BER wrapper carries the length of the **whole** assembled
//! Load File Data Block, which a per-block framer cannot know, so it is **not**
//! added here. It is the first bytes of the LFDB byte stream produced upstream
//! by the CAP/LFDB streamer (`cap::LoadFileDataBlock::next_block`, S3) — so the
//! first chunk handed to this framer already begins with `'C4' len …`. This
//! keeps the fixed `(block_no, last, chunk)` signature and the "never hold the
//! whole LFDB in RAM" contract (§5.4a).

use crate::command::{build, BuildError, Capdu};

/// Build one LOAD block. `block_no` is the P2 counter; `last` sets P1 `0x80`
/// (otherwise `0x00`, "more blocks"). `chunk` is one streamed LFDB slice
/// (≤ `LOAD_BLOCK_DATA`); see the module note on the `'C4'` wrapper.
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
#[allow(clippy::module_name_repetitions)] // GP command name; intentional public API
pub fn load_block(block_no: u8, last: bool, chunk: &[u8]) -> Result<Capdu, BuildError> {
    let p1 = if last { 0x80 } else { 0x00 };
    build(0x84, 0xE8, p1, block_no, chunk, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    #[test]
    fn intermediate_block_uses_p1_00() {
        let apdu = load_block(0x00, false, &[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xE8, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00])
        );
    }

    #[test]
    fn last_block_sets_p1_80_and_carries_block_number() {
        let apdu = load_block(0x05, true, &[0xAA]).unwrap();
        assert_eq!(
            HexSlice(&apdu),
            HexSlice([0x84, 0xE8, 0x80, 0x05, 0x01, 0xAA, 0x00])
        );
    }

    #[test]
    fn full_block_chunk_fits() {
        use crate::limits::LOAD_BLOCK_DATA;
        let chunk = [0x5Au8; LOAD_BLOCK_DATA];
        let apdu = load_block(0x10, false, &chunk).unwrap();
        // header(4) + Lc(1) + LOAD_BLOCK_DATA + Le(1).
        assert_eq!(apdu.len(), 4 + 1 + LOAD_BLOCK_DATA + 1);
        assert_eq!(apdu[4] as usize, LOAD_BLOCK_DATA); // Lc
    }

    #[test]
    fn oversized_chunk_overflows() {
        let big = [0x00u8; 256];
        assert_eq!(load_block(0x00, false, &big), Err(BuildError::Overflow));
    }
}
