//! Primitive crypto used by the SCP03 flows — kept in one place so the KAT
//! suite can exercise it directly and the trait impls stay thin.
//!
//! All functions are `no_std` and allocation-free. AES is dispatched by key
//! length (128/192/256) via the [`per_aes`] macro, which expands to fully
//! concrete `RustCrypto` types (no generic trait-bound plumbing). Anchors:
//!
//! * AES — FIPS-197 (the `aes` crate).
//! * AES-CMAC — NIST SP 800-38B / RFC 4493 (the `cmac` crate), used as the PRF.
//! * KDF — NIST SP 800-108r1 counter mode, the scheme Amendment D v1.1.2 §4.1.5
//!   builds on: each block is `Label(11×'00' ‖ constant) ‖ '00' ‖ L(2, bits) ‖
//!   i(1) ‖ Context`, MAC'd under the input key; blocks are concatenated and
//!   truncated to the requested length.

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac};
use des::{Des, TdesEde2};

use heapless::String;
use scll_core::error::BackendError;
use scll_core::limits::OTHER_DETAIL_MAX;

/// AES block size in bytes (also the CMAC tag / MAC-chaining length).
pub(crate) const BLOCK: usize = 16;

/// Build a [`BackendError::Crypto`] with a short, key-free detail string
/// (silently truncated if it would exceed the cap — all call sites are short).
pub(crate) fn crypto_err(msg: &str) -> BackendError {
    let mut s = String::<OTHER_DETAIL_MAX>::new();
    let _ = s.push_str(msg);
    BackendError::Crypto(s)
}

/// Dispatch a concrete-typed block of code over the three AES key lengths.
/// `$c` is bound to the concrete cipher type inside the block.
macro_rules! per_aes {
    ($key:expr, $c:ident => $body:block) => {
        match $key.len() {
            16 => {
                type $c = Aes128;
                $body
            }
            24 => {
                type $c = Aes192;
                $body
            }
            32 => {
                type $c = Aes256;
                $body
            }
            _ => Err(crypto_err("unsupported AES key length")),
        }
    };
}

/// AES-CMAC (SP 800-38B) over `data`, written to `out` (16 bytes). `key` is
/// 16/24/32 bytes.
pub(crate) fn aes_cmac(key: &[u8], data: &[u8], out: &mut [u8; BLOCK]) -> Result<(), BackendError> {
    per_aes!(key, C => {
        let mut mac = <Cmac<C> as Mac>::new_from_slice(key)
            .map_err(|_| crypto_err("cmac key length"))?;
        mac.update(data);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    })
}

/// Single-block AES-ECB encryption of `block_in` → `out` (used for KCV and the
/// SCP03 C-ENC/R-ENC ICV derivation, Amendment D §6.2.4/§6.2.6/§6.2.7).
///
/// Implemented as AES-CBC with a zero IV over exactly one block: the CBC first
/// block is `E(P ⊕ IV) = E(P ⊕ 0) = E(P)`, i.e. identical to single-block ECB.
/// This keeps the whole module on the `cbc` + `cmac` APIs (no bare block-cipher
/// trait surface).
pub(crate) fn aes_ecb_block(
    key: &[u8],
    block_in: &[u8; BLOCK],
    out: &mut [u8; BLOCK],
) -> Result<(), BackendError> {
    let mut buf = *block_in;
    let zero_iv = [0u8; BLOCK];
    let n = aes_cbc_encrypt(key, &zero_iv, &mut buf, BLOCK)?;
    debug_assert_eq!(n, BLOCK);
    out.copy_from_slice(&buf);
    Ok(())
}

/// AES-CBC encrypt `msg_len` bytes already present (and block-aligned) at the
/// front of `buf`, in place, with no padding. Returns the ciphertext length.
pub(crate) fn aes_cbc_encrypt(
    key: &[u8],
    iv: &[u8; BLOCK],
    buf: &mut [u8],
    msg_len: usize,
) -> Result<usize, BackendError> {
    per_aes!(key, C => {
        let ct = cbc::Encryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| crypto_err("cbc key/iv"))?
            .encrypt_padded_mut::<NoPadding>(buf, msg_len)
            .map_err(|_| crypto_err("cbc encrypt"))?;
        Ok(ct.len())
    })
}

/// AES-CBC decrypt the whole `buf` in place, no padding. Returns the plaintext
/// length (equal to `buf.len()`).
pub(crate) fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8; BLOCK],
    buf: &mut [u8],
) -> Result<usize, BackendError> {
    per_aes!(key, C => {
        let pt = cbc::Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| crypto_err("cbc key/iv"))?
            .decrypt_padded_mut::<NoPadding>(buf)
            .map_err(|_| crypto_err("cbc decrypt"))?;
        Ok(pt.len())
    })
}

/// NIST SP 800-108r1 counter-mode KDF with an AES-CMAC PRF (Amendment D
/// §4.1.5). Fills `out` (length drives the block count: 1 block for ≤16 bytes,
/// 2 for ≤32). `l_bits` is the value placed in the `L` field (output length in
/// bits, e.g. `0x0080` for AES-128, `0x0040` for an 8-byte cryptogram).
pub(crate) fn kdf(
    key: &[u8],
    constant: u8,
    l_bits: u16,
    context: &[u8],
    out: &mut [u8],
) -> Result<(), BackendError> {
    // block = label(11×'00' ‖ constant) ‖ '00' ‖ L(2) ‖ i(1) ‖ context
    // Capacity: 12 + 1 + 2 + 1 + context. SCP03 context is 16 bytes → 32.
    let mut block: heapless::Vec<u8, 64> = heapless::Vec::new();
    let l = l_bits.to_be_bytes();
    let mut counter: u8 = 1;
    let mut written = 0usize;
    while written < out.len() {
        block.clear();
        block
            .extend_from_slice(&[0u8; 11])
            .map_err(|()| crypto_err("kdf overflow"))?;
        block
            .extend_from_slice(&[constant, 0x00, l[0], l[1], counter])
            .map_err(|()| crypto_err("kdf overflow"))?;
        block
            .extend_from_slice(context)
            .map_err(|()| crypto_err("kdf overflow"))?;

        let mut tag = [0u8; BLOCK];
        aes_cmac(key, &block, &mut tag)?;

        let take = core::cmp::min(BLOCK, out.len() - written);
        out[written..written + take].copy_from_slice(&tag[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// ISO/IEC 7816-4 padding: append `0x80` then `0x00`s to the next AES block
/// boundary. `buf[..len]` holds the message; returns the padded length. Always
/// adds at least the `0x80` byte (so a block-aligned input grows by a full
/// block) — matching Amendment D command/response data encryption.
pub(crate) fn pad80(buf: &mut [u8], len: usize) -> Result<usize, BackendError> {
    let padded = len + (BLOCK - (len % BLOCK));
    if padded > buf.len() {
        return Err(crypto_err("pad overflow"));
    }
    buf[len] = 0x80;
    for b in &mut buf[len + 1..padded] {
        *b = 0x00;
    }
    Ok(padded)
}

/// Strip ISO/IEC 7816-4 padding: find the trailing `0x80` after any `0x00`s.
/// Returns the unpadded length, or an error if no `0x80` marker is present.
pub(crate) fn unpad80(buf: &[u8]) -> Result<usize, BackendError> {
    let mut i = buf.len();
    while i > 0 {
        i -= 1;
        match buf[i] {
            0x00 => {}
            0x80 => return Ok(i),
            _ => return Err(crypto_err("bad pad")),
        }
    }
    Err(crypto_err("bad pad"))
}

// =========================================================================
// 3DES primitives for SCP02 (GPCS v2.3.1 §E; ISO/IEC 9797-1:2011 Algorithm 3)
// =========================================================================
//
// On the same cipher-0.4 line as the AES helpers above: `des::{Des, TdesEde2}`
// are cipher-0.4 block ciphers driven through the `cbc` API (the same
// `encrypt_padded_mut::<NoPadding>` surface used for AES-CBC). `TdesEde2` is
// two-key triple-DES (16-byte key, K1‖K2, E_K1∘D_K2∘E_K1) — GP's `DESede` with
// a 16-byte key. ECB is realised as single-block CBC with a zero IV
// (E(P⊕0)=E(P)), exactly as [`aes_ecb_block`] does, so no `ecb` crate is pulled.

/// DES / 3DES block size in bytes.
pub(crate) const DES_BLOCK: usize = 8;

/// 3DES-EDE2-CBC encrypt the `msg_len` (block-aligned) bytes at the front of
/// `buf` in place, no padding. `key` is 16 bytes. Returns the ciphertext length.
pub(crate) fn tdes_cbc_encrypt(
    key: &[u8],
    iv: [u8; DES_BLOCK],
    buf: &mut [u8],
    msg_len: usize,
) -> Result<usize, BackendError> {
    let ct = cbc::Encryptor::<TdesEde2>::new_from_slices(key, &iv)
        .map_err(|_| crypto_err("3des cbc key/iv"))?
        .encrypt_padded_mut::<NoPadding>(buf, msg_len)
        .map_err(|_| crypto_err("3des cbc encrypt"))?;
    Ok(ct.len())
}

/// 3DES-EDE2-CBC decrypt the whole `buf` in place, no padding. Returns the
/// plaintext length (equal to `buf.len()`). Test-only: SCP02 responses are never
/// encrypted, so production code never decrypts — this exists for the
/// round-trip KAT.
#[cfg(test)]
pub(crate) fn tdes_cbc_decrypt(
    key: &[u8],
    iv: [u8; DES_BLOCK],
    buf: &mut [u8],
) -> Result<usize, BackendError> {
    let pt = cbc::Decryptor::<TdesEde2>::new_from_slices(key, &iv)
        .map_err(|_| crypto_err("3des cbc key/iv"))?
        .decrypt_padded_mut::<NoPadding>(buf)
        .map_err(|_| crypto_err("3des cbc decrypt"))?;
    Ok(pt.len())
}

/// Single-DES-CBC encrypt the `msg_len` (block-aligned) bytes at the front of
/// `buf` in place, no padding, under the 8-byte key `k1`. Returns the length.
fn des_cbc_encrypt(
    k1: &[u8],
    iv: [u8; DES_BLOCK],
    buf: &mut [u8],
    msg_len: usize,
) -> Result<usize, BackendError> {
    let ct = cbc::Encryptor::<Des>::new_from_slices(k1, &iv)
        .map_err(|_| crypto_err("des cbc key/iv"))?
        .encrypt_padded_mut::<NoPadding>(buf, msg_len)
        .map_err(|_| crypto_err("des cbc encrypt"))?;
    Ok(ct.len())
}

/// 3DES-EDE2-ECB of one block (KCV; single-block key encryption). Realised as
/// single-block CBC with a zero IV. `key` is 16 bytes.
pub(crate) fn tdes_ecb_block(
    key: &[u8],
    block_in: [u8; DES_BLOCK],
    out: &mut [u8; DES_BLOCK],
) -> Result<(), BackendError> {
    let mut buf = block_in;
    let n = tdes_cbc_encrypt(key, [0u8; DES_BLOCK], &mut buf, DES_BLOCK)?;
    debug_assert_eq!(n, DES_BLOCK);
    out.copy_from_slice(&buf);
    Ok(())
}

/// Single-DES-ECB of one block under the 8-byte key `k1` (SCP02 ICV encryption,
/// GPCS §E.4.4 / `GPCrypto.des_ecb`). Realised as single-block CBC, zero IV.
pub(crate) fn des_ecb_block(
    k1: &[u8],
    block_in: [u8; DES_BLOCK],
    out: &mut [u8; DES_BLOCK],
) -> Result<(), BackendError> {
    let mut buf = block_in;
    let n = des_cbc_encrypt(k1, [0u8; DES_BLOCK], &mut buf, DES_BLOCK)?;
    debug_assert_eq!(n, DES_BLOCK);
    out.copy_from_slice(&buf);
    Ok(())
}

/// ISO/IEC 7816-4 padding to an 8-byte boundary (the SCP02 block). Mandatory
/// `0x80` marker — a block-aligned input grows by a full block. `buf[..len]`
/// holds the message; returns the padded length.
pub(crate) fn pad80_8(buf: &mut [u8], len: usize) -> Result<usize, BackendError> {
    let padded = len + (DES_BLOCK - (len % DES_BLOCK));
    if padded > buf.len() {
        return Err(crypto_err("3des pad overflow"));
    }
    buf[len] = 0x80;
    for b in &mut buf[len + 1..padded] {
        *b = 0x00;
    }
    Ok(padded)
}

/// Full 3DES-CBC single-signature MAC (`GPCrypto.mac_3des`): ISO/IEC 7816-4 pad
/// to 8, 3DES-EDE2-CBC under `key` from chaining value `iv`, return the last
/// block. Used for the SCP02 card/host cryptograms (GPCS §E.5.1; `iv` = zero).
/// `scratch` must hold the padded message (caller-sized).
pub(crate) fn tdes_mac(
    key: &[u8],
    iv: [u8; DES_BLOCK],
    data: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; DES_BLOCK], BackendError> {
    scratch
        .get_mut(..data.len())
        .ok_or_else(|| crypto_err("mac input too large"))?
        .copy_from_slice(data);
    let padded = pad80_8(scratch, data.len())?;
    let n = tdes_cbc_encrypt(key, iv, scratch, padded)?;
    let mut out = [0u8; DES_BLOCK];
    out.copy_from_slice(&scratch[n - DES_BLOCK..n]);
    Ok(out)
}

/// SCP02 C-MAC / R-MAC — ISO/IEC 9797-1:2011 MAC Algorithm 3, the "Retail MAC"
/// (`GPCrypto.mac_des_3des`): ISO/IEC 7816-4 pad to 8; single-DES-CBC chain
/// under K1 (= `key16[..8]`) over all but the last block, starting from the
/// chaining value `iv`; then 3DES-EDE2-CBC the last block under the chained IV;
/// the resulting block is the 8-byte MAC. `iv` is the C-MAC chaining value
/// (zero for the first command; the encrypted previous MAC thereafter).
/// `scratch` must hold the padded message (caller-sized).
pub(crate) fn retail_mac(
    key16: &[u8],
    iv: [u8; DES_BLOCK],
    data: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; DES_BLOCK], BackendError> {
    scratch
        .get_mut(..data.len())
        .ok_or_else(|| crypto_err("retail-mac input too large"))?
        .copy_from_slice(data);
    let padded = pad80_8(scratch, data.len())?;

    let mut chain = iv;
    if padded > DES_BLOCK {
        // single-DES CBC over all but the last block; keep its last ciphertext
        // block as the IV for the final 3DES transform.
        let head = padded - DES_BLOCK;
        let n = des_cbc_encrypt(&key16[..DES_BLOCK], chain, &mut scratch[..head], head)?;
        chain.copy_from_slice(&scratch[n - DES_BLOCK..n]);
    }
    // 3DES-EDE2-CBC of the (still-plaintext) last block under the chained IV.
    let mut last = [0u8; DES_BLOCK];
    last.copy_from_slice(&scratch[padded - DES_BLOCK..padded]);
    let n = tdes_cbc_encrypt(key16, chain, &mut last, DES_BLOCK)?;
    debug_assert_eq!(n, DES_BLOCK);
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    fn hx(s: &str) -> heapless::Vec<u8, 64> {
        let mut v = heapless::Vec::new();
        let mut i = 0;
        while i < s.len() {
            v.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .unwrap();
            i += 2;
        }
        v
    }

    #[test]
    fn aes128_ecb_matches_fips197() {
        // FIPS-197 §C.1 AES-128 example.
        let key = hx("000102030405060708090a0b0c0d0e0f");
        let pt = hx("00112233445566778899aabbccddeeff");
        let mut blk = [0u8; BLOCK];
        blk.copy_from_slice(&pt);
        let mut out = [0u8; BLOCK];
        aes_ecb_block(&key, &blk, &mut out).unwrap();
        assert_eq!(
            HexSlice(out),
            HexSlice(hx("69c4e0d86a7b0430d8cdb78070b4c55a"))
        );
    }

    #[test]
    fn aes_cmac_matches_rfc4493() {
        // RFC 4493 AES-CMAC test vectors (the SP 800-38B examples).
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let mut t = [0u8; BLOCK];

        aes_cmac(&key, &[], &mut t).unwrap();
        assert_eq!(
            HexSlice(t),
            HexSlice(hx("bb1d6929e95937287fa37d129b756746"))
        );

        aes_cmac(&key, &hx("6bc1bee22e409f96e93d7e117393172a"), &mut t).unwrap();
        assert_eq!(
            HexSlice(t),
            HexSlice(hx("070a16b46b4d4144f79bdd9dd04a287c"))
        );

        aes_cmac(
            &key,
            &hx("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
            &mut t,
        )
        .unwrap();
        assert_eq!(
            HexSlice(t),
            HexSlice(hx("dfa66747de9ae63030ca32611497c827"))
        );
    }

    #[test]
    fn cbc_round_trips_no_padding() {
        let key = hx("404142434445464748494a4b4c4d4e4f");
        let iv = [0u8; BLOCK];
        let mut buf = hx("0f0e0d0c0b0a09080706050403020100");
        let pt = buf.clone();
        let n = aes_cbc_encrypt(&key, &iv, &mut buf, BLOCK).unwrap();
        assert_eq!(n, BLOCK);
        // SCP03 PUT KEY block (verified against the Python reference).
        assert_eq!(
            HexSlice(&buf),
            HexSlice(hx("fac3af9fb177982eaba2e63d9ef03986"))
        );
        aes_cbc_decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(HexSlice(&buf), HexSlice(&pt));
    }

    #[test]
    fn pad_round_trip() {
        let mut buf = [0u8; 32];
        buf[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let n = pad80(&mut buf, 5).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf[5], 0x80);
        assert_eq!(unpad80(&buf[..n]).unwrap(), 5);
    }

    #[test]
    fn unpad_rejects_missing_marker() {
        assert!(unpad80(&[0u8; 16]).is_err());
        assert!(unpad80(&[1u8; 16]).is_err());
    }

    #[test]
    #[allow(clippy::similar_names)] // s_enc / s_mac / s_rmac are the GP key names
    fn kdf_derives_scp03_session_keys() {
        // Amendment D §4.1.5 KDF with the GP default keyset 40..4F and the
        // fixed challenges from the reference (tests/vectors/scp03_ref.py).
        let key = hx("404142434445464748494a4b4c4d4e4f");
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(&hx("0001020304050607"));
        ctx[8..].copy_from_slice(&hx("08090a0b0c0d0e0f"));

        let mut s_enc = [0u8; 16];
        let mut s_mac = [0u8; 16];
        let mut s_rmac = [0u8; 16];
        kdf(&key, 0x04, 0x0080, &ctx, &mut s_enc).unwrap();
        kdf(&key, 0x06, 0x0080, &ctx, &mut s_mac).unwrap();
        kdf(&key, 0x07, 0x0080, &ctx, &mut s_rmac).unwrap();
        assert_eq!(
            HexSlice(s_enc),
            HexSlice(hx("eb845bbc703969a9b312a5f8e4834aa2"))
        );
        assert_eq!(
            HexSlice(s_mac),
            HexSlice(hx("94d9141c5e50a39ef3939b9a4616c910"))
        );
        assert_eq!(
            HexSlice(s_rmac),
            HexSlice(hx("f034ed3222d3466ee1531f3fa3561def"))
        );
    }

    #[test]
    fn kcv_matches_amendment_d() {
        // KCV = AES-ECB(key, 16×'01')[0..3] (Amendment D §4.1.4).
        let key = hx("404142434445464748494a4b4c4d4e4f");
        let mut out = [0u8; BLOCK];
        aes_ecb_block(&key, &[0x01u8; BLOCK], &mut out).unwrap();
        assert_eq!(HexSlice(&out[..3]), HexSlice(hx("504a77")));
    }

    // ------------------------- 3DES / SCP02 primitives -------------------------

    #[test]
    fn single_des_matches_fips81() {
        // FIPS-81 single-DES KAT: key 0123456789ABCDEF, PT "Now is t" ->
        // 3FA40E8A984D4815. Single-DES is exercised via [`des_ecb_block`]
        // (K1-only ECB), the same path SCP02 ICV encryption uses.
        let mut out = [0u8; DES_BLOCK];
        let mut blk = [0u8; DES_BLOCK];
        blk.copy_from_slice(&hx("4e6f772069732074"));
        des_ecb_block(&hx("0123456789abcdef"), blk, &mut out).unwrap();
        assert_eq!(HexSlice(out), HexSlice(hx("3fa40e8a984d4815")));
    }

    #[test]
    fn tdes_ecb_block_and_kcv() {
        // Two-key 3DES (EDE2) ECB of one block, and the SCP02 KCV
        // (= 3DES-ECB(8×00)[0..3]). Values from tests/vectors/scp02_ref.py
        // (GP default key 40..4F). The KCV is also what GPCS §E / gppro print.
        let key = hx("404142434445464748494a4b4c4d4e4f");
        let mut out = [0u8; DES_BLOCK];
        tdes_ecb_block(&key, [0u8; DES_BLOCK], &mut out).unwrap();
        assert_eq!(HexSlice(&out[..3]), HexSlice(hx("8baf47"))); // KCV(base)
    }

    #[test]
    fn tdes_cbc_round_trips() {
        let key = hx("404142434445464748494a4b4c4d4e4f");
        let iv = [0u8; DES_BLOCK];
        let pt = hx("0f0e0d0c0b0a09080706050403020100");
        let mut buf = pt.clone();
        let n = tdes_cbc_encrypt(&key, iv, &mut buf, pt.len()).unwrap();
        assert_eq!(n, pt.len());
        tdes_cbc_decrypt(&key, iv, &mut buf).unwrap();
        assert_eq!(HexSlice(&buf), HexSlice(&pt));
    }

    #[test]
    fn pad80_8_always_adds() {
        // ISO/IEC 7816-4 over the 8-byte block: a block-aligned input grows by
        // a whole block; a short input pads to the next boundary.
        let mut buf = [0u8; 24];
        buf[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(pad80_8(&mut buf, 8).unwrap(), 16);
        assert_eq!(buf[8], 0x80);
        buf = [0u8; 24];
        buf[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(pad80_8(&mut buf, 5).unwrap(), 8);
        assert_eq!(buf[5], 0x80);
    }

    #[test]
    fn tdes_mac_cryptogram() {
        // SCP02 card cryptogram = mac_3des(host‖card, S-ENC, 0) over the
        // single (>1) block case. Inputs/expected from scp02_ref.py.
        let s_enc = hx("25c9794a1205ff244f5fa0378d2f8d59");
        let mut data = [0u8; 14];
        data[..8].copy_from_slice(&hx("0001020304050607")); // host (8)
        data[8..].copy_from_slice(&hx("08090a0b0c0d")); // card (6)
        let mut scratch = [0u8; 24];
        let mac = tdes_mac(&s_enc, [0u8; DES_BLOCK], &data, &mut scratch).unwrap();
        assert_eq!(HexSlice(mac), HexSlice(hx("6daa8d379958426f"))); // CARD_CRYPTO
    }

    #[test]
    fn retail_mac_matches_reference() {
        // ISO/IEC 9797-1 Alg. 3 over the EXTERNAL AUTHENTICATE MAC input
        // (13 bytes -> two blocks, exercising the single-DES chain + 3DES
        // final). S-MAC and expected C-MAC from scp02_ref.py.
        let s_mac = hx("9bed98891580c3b245fe9ec58bfa8d2a");
        // MAC input: 84 82 03 00 10 || host_cryptogram(8)
        let mut data = [0u8; 13];
        data[..5].copy_from_slice(&hx("8482030010"));
        data[5..].copy_from_slice(&hx("362b63c93d629cfa"));
        let mut scratch = [0u8; 24];
        let mac = retail_mac(&s_mac, [0u8; DES_BLOCK], &data, &mut scratch).unwrap();
        assert_eq!(HexSlice(mac), HexSlice(hx("560f0b92db3192d3"))); // EA C-MAC
    }
}
