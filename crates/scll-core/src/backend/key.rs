//! `KeyBackend` (+ optional `ExportableKeyBackend`) and opaque key handles — §3.3.
//!
//! `no_std`: `random_bytes` fills a caller-supplied buffer (no alloc, no forced
//! capacity — `n` is `out.len()`); `export_key_dangerous` returns an
//! [`ExportedKey`] — a fixed-capacity, drop-zeroizing secret-bytes type. (We do
//! not use `Zeroizing<heapless::Vec<..>>`: heapless 0.8 has no `zeroize`
//! feature, so `heapless::Vec` is not `Zeroize`; the dedicated type keeps us on
//! heapless 0.8 / MSRV 1.81.)

use zeroize::Zeroize;

use crate::error::BackendError;
use crate::limits::KEY_BYTES_MAX;

/// Backend-defined opaque key reference. With the software backend (and the
/// recommended embedded pattern) this is an **index into a fixed key-slot table
/// the backend owns**; another backend may reinterpret the value. Opaque to
/// callers — no key material crosses this boundary except via
/// [`ExportableKeyBackend`]. The `new`/`index` accessors are backend-facing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHandle(u16);

impl KeyHandle {
    /// Construct a handle from a backend slot index.
    #[must_use]
    pub const fn new(index: u16) -> Self {
        Self(index)
    }
    /// The backend slot index this handle refers to.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.0
    }
}

/// Algorithm/length class for an imported or generated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyKind {
    Aes128,
    Aes192,
    Aes256,
    TripleDesDouble, // 3DES double-length (SCP02)
}

impl KeyKind {
    /// The plaintext key length in bytes: AES-128/192/256 → 16/24/32; two-key
    /// 3DES → 16. This is the value carried in the SCP03 AES PUT KEY block's
    /// clear-key-length byte (Amendment D §7.2), which is distinct from the
    /// *encrypted* length — a 24-byte AES-192 key is padded to 32 ciphertext
    /// bytes, so the two only coincide for AES-128 and AES-256.
    #[must_use]
    pub const fn clear_len(self) -> usize {
        match self {
            KeyKind::Aes192 => 24,
            KeyKind::Aes256 => 32,
            KeyKind::Aes128 | KeyKind::TripleDesDouble => 16,
        }
    }
}

/// Key handles, randomness, KCV, constant-time compare. Required by every backend.
pub trait KeyBackend: Send + Sync + 'static {
    /// Import raw key `bytes` of `kind`, returning an opaque [`KeyHandle`].
    ///
    /// # Errors
    /// Returns [`BackendError::KeyImport`] if `bytes` does not match `kind`, or
    /// if the backend's key-slot table is full.
    fn import_key(&self, kind: KeyKind, bytes: &[u8]) -> Result<KeyHandle, BackendError>;
    /// Generate a fresh key of `kind`, returning an opaque [`KeyHandle`].
    ///
    /// # Errors
    /// Returns [`BackendError::KeyGen`] (or [`BackendError::Rng`]) if generation
    /// fails or no slot is free.
    fn generate_key(&self, kind: KeyKind) -> Result<KeyHandle, BackendError>;
    /// Compute the GP Key Check Value (3 bytes) for the referenced key.
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if `h` does not refer to a live key, or
    /// the KCV computation fails.
    fn compute_kcv(&self, h: &KeyHandle) -> Result<[u8; 3], BackendError>;
    /// Fill `out` with cryptographically secure random bytes. The count is
    /// `out.len()` (was the alloc-returning `random_bytes(n) -> Vec<u8>`).
    ///
    /// # Errors
    /// Returns [`BackendError::Rng`] if the underlying CSPRNG fails.
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), BackendError>;
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool;
}

/// Plaintext key material returned by [`ExportableKeyBackend::export_key_dangerous`]
/// (software backends only). Holds up to [`KEY_BYTES_MAX`] bytes and **zeroizes
/// the buffer on drop**. Dangerous by construction: do not copy the bytes into
/// an unprotected location. Replaces `Zeroizing<heapless::Vec<..>>` so the core
/// stays on heapless 0.8 (which has no `zeroize` feature).
pub struct ExportedKey {
    bytes: [u8; KEY_BYTES_MAX],
    len: usize,
}

impl ExportedKey {
    /// Build from a key slice. Returns `None` if `src` exceeds [`KEY_BYTES_MAX`].
    #[must_use]
    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() > KEY_BYTES_MAX {
            return None;
        }
        let mut bytes = [0u8; KEY_BYTES_MAX];
        bytes[..src.len()].copy_from_slice(src);
        Some(Self {
            bytes,
            len: src.len(),
        })
    }

    /// The meaningful key bytes (length matches the key type, e.g. 16/24/32).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Zeroize for ExportedKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

impl Drop for ExportedKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::ops::Deref for ExportedKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// OPTIONAL. Plaintext export of a key the backend holds. A software backend
/// (`RustCrypto`) implements this; an HSM/PKCS#11 backend does NOT — so "keys
/// never leave the token" is enforced by the type system, not a runtime error.
pub trait ExportableKeyBackend: KeyBackend {
    /// Export the plaintext bytes of the key referenced by `h` (software
    /// backends only).
    ///
    /// # Errors
    /// Returns [`BackendError::Crypto`] if `h` does not refer to a live,
    /// exportable key, or [`BackendError::Unsupported`] if export is refused.
    fn export_key_dangerous(&self, h: &KeyHandle) -> Result<ExportedKey, BackendError>;
}
