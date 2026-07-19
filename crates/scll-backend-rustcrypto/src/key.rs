//! `KeyBackend` + `ExportableKeyBackend` impls (PDD §3.3).
//!
//! KCV (§5.3.1): AES → `AES-ECB(key, 16×0x01)[0..3]` (Amendment D §4.1.4);
//! 3DES double-length (SCP02) → `3DES-ECB(key, 8×0x00)[0..3]` (GPCS §E). RNG
//! source is the injected `R` (Fork B), accessed under the critical-section
//! mutex.
//!
//! `no_std`: `random_bytes` fills a caller buffer; `export_key_dangerous`
//! returns a drop-zeroizing `ExportedKey`.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use scll_core::backend::{ExportableKeyBackend, ExportedKey, KeyBackend, KeyHandle, KeyKind};
use scll_core::error::BackendError;
use scll_core::limits::{KEY_BYTES_MAX, OTHER_DETAIL_MAX};

use crate::crypto::{aes_ecb_block, crypto_err, tdes_ecb_block, BLOCK, DES_BLOCK};
use crate::{BackendState, KeySlot, RustCryptoBackend, MAX_KEY_SLOTS};

/// Expected raw-byte length for a key kind. `None` ⇒ an unknown future kind.
fn key_len(kind: KeyKind) -> Option<usize> {
    match kind {
        // AES-128 and two-key 3DES (SCP02, GPCS §E) are both 16-byte.
        KeyKind::Aes128 | KeyKind::TripleDesDouble => Some(16),
        KeyKind::Aes192 => Some(24),
        KeyKind::Aes256 => Some(32),
        _ => None, // KeyKind is #[non_exhaustive]
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> RustCryptoBackend<R> {
    /// Store a key in the first free slot, returning its handle.
    fn store_key(
        state: &mut BackendState<R>,
        kind: KeyKind,
        bytes: &[u8],
    ) -> Result<KeyHandle, BackendError> {
        let idx = state
            .keys
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| BackendError::KeyGen(short("key table full")))?;
        let mut buf = Zeroizing::new([0u8; KEY_BYTES_MAX]);
        buf[..bytes.len()].copy_from_slice(bytes);
        state.keys[idx] = Some(KeySlot {
            kind,
            bytes: buf,
            #[allow(clippy::cast_possible_truncation)] // bytes.len() ≤ KEY_BYTES_MAX (32)
            len: bytes.len() as u8,
        });
        debug_assert!(idx < MAX_KEY_SLOTS);
        #[allow(clippy::cast_possible_truncation)] // idx < MAX_KEY_SLOTS (16)
        Ok(KeyHandle::new(idx as u16))
    }
}

/// Build a short, key-free detail string for a `BackendError` arm that takes one.
fn short(msg: &str) -> heapless::String<OTHER_DETAIL_MAX> {
    let mut s = heapless::String::new();
    let _ = s.push_str(msg);
    s
}

impl<R: RngCore + CryptoRng + Send + 'static> KeyBackend for RustCryptoBackend<R> {
    fn import_key(&self, kind: KeyKind, bytes: &[u8]) -> Result<KeyHandle, BackendError> {
        let expected =
            key_len(kind).ok_or_else(|| BackendError::Unsupported(short("unknown key kind")))?;
        if bytes.len() != expected {
            return Err(BackendError::KeyImport(short("byte length != key kind")));
        }
        self.with_state(|st| Self::store_key(st, kind, bytes))
    }

    fn generate_key(&self, kind: KeyKind) -> Result<KeyHandle, BackendError> {
        let len =
            key_len(kind).ok_or_else(|| BackendError::Unsupported(short("unknown key kind")))?;
        self.with_state(|st| {
            let mut bytes = Zeroizing::new([0u8; KEY_BYTES_MAX]);
            st.rng.fill_bytes(&mut bytes[..len]);
            Self::store_key(st, kind, &bytes[..len])
        })
    }

    fn compute_kcv(&self, h: &KeyHandle) -> Result<[u8; 3], BackendError> {
        self.with_state(|st| {
            let slot = st
                .keys
                .get(usize::from(h.index()))
                .and_then(Option::as_ref)
                .ok_or_else(|| crypto_err("key handle invalid"))?;
            match slot.kind {
                KeyKind::Aes128 | KeyKind::Aes192 | KeyKind::Aes256 => {
                    // Amendment D §4.1.4: KCV = AES-ECB(key, 16×'01')[0..3].
                    let mut out = [0u8; BLOCK];
                    aes_ecb_block(slot.key(), &[0x01u8; BLOCK], &mut out)?;
                    Ok([out[0], out[1], out[2]])
                }
                KeyKind::TripleDesDouble => {
                    // GPCS §E: KCV = 3DES-ECB(key, 8×'00')[0..3].
                    let mut out = [0u8; DES_BLOCK];
                    tdes_ecb_block(slot.key(), [0x00u8; DES_BLOCK], &mut out)?;
                    Ok([out[0], out[1], out[2]])
                }
                _ => Err(BackendError::Unsupported(short("unknown key kind"))),
            }
        })
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), BackendError> {
        self.with_state(|st| st.rng.fill_bytes(out));
        Ok(())
    }

    /// Constant-time byte-slice equality (for cryptogram / MAC comparison).
    /// Unequal lengths short-circuit (lengths are not secret); equal-length
    /// inputs fold all bytes before deciding, with a `black_box` barrier to
    /// discourage the optimiser from reintroducing an early exit.
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        core::hint::black_box(diff) == 0
    }
}

impl<R: RngCore + CryptoRng + Send + 'static> ExportableKeyBackend for RustCryptoBackend<R> {
    fn export_key_dangerous(&self, h: &KeyHandle) -> Result<ExportedKey, BackendError> {
        self.with_state(|st| {
            let slot = st
                .keys
                .get(usize::from(h.index()))
                .and_then(Option::as_ref)
                .ok_or_else(|| crypto_err("key handle invalid"))?;
            ExportedKey::from_slice(slot.key()).ok_or_else(|| crypto_err("key too large"))
        })
    }
}
