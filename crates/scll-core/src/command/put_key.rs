//! PUT KEY (CLA 84, INS D8) — PDD §5.3.1, GPCS v2.3.1 §11.8.
//!
//! P1 = KVN when replacing, `0x00` when adding (KVN inside data). P2 = `0x81`
//! (multi-key bit + first KID `0x01`). Data = `new_kvn | key_block{ENC,MAC,DEK}`,
//! each block `key_type | len | encrypted_key | kcv_len | kcv`. Card echoes
//! `new_kvn | KCV_ENC | KCV_MAC | KCV_DEK`.

use crate::command::{build, push, BuildError, Capdu};

/// SCP03 AES key type (GPCS Amendment D). AES key blocks carry an extra inner
/// length byte (the clear-key length); 3DES blocks (`0x80`) do not.
const KEY_TYPE_AES: u8 = 0x88;

/// One encrypted key block plus its KCV (built from backend output). The
/// encrypted key already borrows (`&[u8]`) — no alloc here.
pub struct KeyBlock<'a> {
    pub key_type: u8, // 0x88 AES (SCP03) | 0x80 3DES (SCP02)
    pub encrypted_key: &'a [u8],
    pub kcv: [u8; 3],
    /// Plaintext key length in bytes (16/24/32 for AES). Emitted as the AES
    /// clear-key-length byte (Amendment D §7.2); ignored for 3DES blocks. This
    /// differs from `encrypted_key.len()` for AES-192 (24-byte key, 32-byte
    /// ciphertext).
    pub clear_key_len: u8,
}

/// Build the PUT KEY C-APDU plaintext for a 3-key set.
///
/// `CLA=84 INS=D8`, `P1 = p1` (caller passes `new_kvn` to replace or `0x00` to
/// add), P2 fixed `0x81` (multiple-key + first KID `0x01`). Data =
/// `new_kvn ‖ key_block{ENC,MAC,DEK}` (GPCS §11.8.2.3.1).
///
/// Per key block:
/// * **SCP03 AES** (`key_type == 0x88`, GPCS Amendment D v1.1.x §7.2):
///   `key_type ‖ block_len ‖ aes_key_len ‖ enc_key ‖ 0x03 ‖ KCV`, where the
///   encrypted key value is preceded by the clear AES key length and
///   `block_len = 1 + len(enc_key)`. (For AES-128 the clear length equals the
///   16-byte ciphertext length.) Omitting `aes_key_len` makes JCOP / the JCDK
///   simulator reject the command (observed `6A88`).
/// * **SCP02 3DES** (`key_type == 0x80`): `key_type ‖ len(enc_key) ‖ enc_key ‖
///   0x03 ‖ KCV` — no inner length.
///
/// The KCV length is fixed at 3 ([`crate::limits::KCV_LEN`], matching
/// `KeyBlock::kcv: [u8; 3]`).
///
/// # Errors
/// Returns [`BuildError::Overflow`] if the encoded inputs would exceed the
/// short-APDU plaintext buffer (`CAPDU_MAX`).
pub fn put_key(p1: u8, new_kvn: u8, blocks: &[KeyBlock<'_>; 3]) -> Result<Capdu, BuildError> {
    let mut data = Capdu::new();
    push(&mut data, &[new_kvn])?;
    for block in blocks {
        let enc_len = u8::try_from(block.encrypted_key.len()).map_err(|_| BuildError::Overflow)?;
        if block.key_type == KEY_TYPE_AES {
            // AES: block length covers the inner clear-key-length byte + the
            // (possibly padded) ciphertext. The inner byte is the PLAINTEXT key
            // length (16/24/32), which differs from `enc_len` for AES-192.
            let block_len = enc_len.checked_add(1).ok_or(BuildError::Overflow)?;
            push(&mut data, &[block.key_type, block_len, block.clear_key_len])?;
        } else {
            push(&mut data, &[block.key_type, enc_len])?;
        }
        push(&mut data, block.encrypted_key)?;
        // KCV_len is fixed at 3 (limits::KCV_LEN); KeyBlock::kcv is [u8; 3].
        push(&mut data, &[0x03])?;
        push(&mut data, &block.kcv)?;
    }
    build(0x84, 0xD8, p1, 0x81, &data, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    fn aes_block(enc: &[u8], kcv: [u8; 3]) -> KeyBlock<'_> {
        // 128-style fixtures where the clear length equals the (un-padded)
        // ciphertext length; the 192/256 cases below set them independently.
        KeyBlock {
            key_type: 0x88,
            encrypted_key: enc,
            kcv,
            clear_key_len: u8::try_from(enc.len()).unwrap(),
        }
    }

    fn aes_block_clear(enc: &[u8], clear_key_len: u8, kcv: [u8; 3]) -> KeyBlock<'_> {
        KeyBlock {
            key_type: 0x88,
            encrypted_key: enc,
            kcv,
            clear_key_len,
        }
    }

    #[test]
    fn replace_three_aes_blocks_golden() {
        // Compact (2-byte) encrypted values so the full data field is spellable.
        let enc = [0xDE, 0xAD];
        let blocks = [
            aes_block(&enc, [0x01, 0x02, 0x03]),
            aes_block(&enc, [0x01, 0x02, 0x03]),
            aes_block(&enc, [0x01, 0x02, 0x03]),
        ];
        let apdu = put_key(0x30, 0x30, &blocks).unwrap();
        // AES block: key_type ‖ block_len(=1+enc) ‖ clear_len(=enc len here) ‖ enc ‖ KCV_len ‖ KCV
        let block = [0x88, 0x03, 0x02, 0xDE, 0xAD, 0x03, 0x01, 0x02, 0x03];
        let mut expected = heapless::Vec::<u8, 64>::new();
        // 84 D8 P1=30 P2=81 Lc=0x1C(28) | new_kvn=30 | block×3 | Le=00
        expected
            .extend_from_slice(&[0x84, 0xD8, 0x30, 0x81, 0x1C, 0x30])
            .unwrap();
        for _ in 0..3 {
            expected.extend_from_slice(&block).unwrap();
        }
        expected.extend_from_slice(&[0x00]).unwrap();
        assert_eq!(HexSlice(&apdu), HexSlice(&expected));
    }

    #[test]
    fn add_uses_p1_00_and_kvn_inside_data() {
        let enc = [0x11; 16];
        let blocks = [
            aes_block(&enc, [0xAA, 0xBB, 0xCC]),
            aes_block(&enc, [0xAA, 0xBB, 0xCC]),
            aes_block(&enc, [0xAA, 0xBB, 0xCC]),
        ];
        let apdu = put_key(0x00, 0x31, &blocks).unwrap();
        assert_eq!(&apdu[0..4], &[0x84, 0xD8, 0x00, 0x81]); // P1=00 add, P2=81
        assert_eq!(apdu[5], 0x31); // new_kvn is the first data byte
        assert_eq!(apdu[6], 0x88); // first block key_type
        assert_eq!(apdu[7], 0x11); // block len = 1 + len(enc) = 1 + 16
        assert_eq!(apdu[8], 0x10); // AES clear-key length = 16
        assert_eq!(apdu[25], 0x03); // KCV_len (after 16-byte key)
        assert_eq!(&apdu[26..29], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(*apdu.last().unwrap(), 0x00); // Le
    }

    #[test]
    fn aes192_and_aes256_clear_length_byte() {
        // AES-192's 24-byte key is 0x80-padded to a 32-byte ciphertext, the same
        // length as AES-256, so only the inner clear-key-length byte tells them
        // apart: 0x18 (24) vs 0x20 (32). Amendment D §7.2. Layout per block:
        // [6]=key_type [7]=block_len(=1+32) [8]=clear_len [9..41]=enc …
        let enc = [0x11u8; 32];

        let b192 = [
            aes_block_clear(&enc, 24, [1, 2, 3]),
            aes_block_clear(&enc, 24, [1, 2, 3]),
            aes_block_clear(&enc, 24, [1, 2, 3]),
        ];
        let a192 = put_key(0x00, 0x31, &b192).unwrap();
        assert_eq!(a192[6], 0x88); // key_type AES
        assert_eq!(a192[7], 0x21); // block_len = 1 + 32
        assert_eq!(a192[8], 0x18); // clear-key length = 24 (NOT the 32-byte ciphertext)

        let b256 = [
            aes_block_clear(&enc, 32, [1, 2, 3]),
            aes_block_clear(&enc, 32, [1, 2, 3]),
            aes_block_clear(&enc, 32, [1, 2, 3]),
        ];
        let a256 = put_key(0x00, 0x31, &b256).unwrap();
        assert_eq!(a256[7], 0x21); // block_len = 1 + 32
        assert_eq!(a256[8], 0x20); // clear-key length = 32
    }

    #[test]
    fn oversized_key_value_overflows() {
        let enc = [0x00u8; 255];
        let blocks = [
            aes_block(&enc, [0; 3]),
            aes_block(&enc, [0; 3]),
            aes_block(&enc, [0; 3]),
        ];
        assert_eq!(put_key(0x30, 0x30, &blocks), Err(BuildError::Overflow));
    }
}
