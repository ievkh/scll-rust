//! Split crypto-backend traits — PDD §3.3 / §3.6.
//!
//! High-level / SCP-aware: each backend implements the SCP02/SCP03 crypto flows
//! in full; `scll-core` orchestrates state but performs no crypto. This is what
//! lets HSM/PKCS#11 keys never leave the token (§3.6).
//!
//! Two locked consequences are baked in:
//! - Key material never crosses the API as bytes — callers hold opaque
//!   [`KeyHandle`]s; `*_encrypt_put_key_payload` takes a new-key **handle**.
//! - Security level is fixed at channel-open and stored in the session, so
//!   `wrap`/`unwrap` take no per-call `level` (§4.1).
//!
//! The default `CardManager` requires `KeyBackend + Scp03Backend + Scp02Backend`
//! (§3.6); an advanced `Scp03Only` manager can drop the SCP02 bound.
//!
//! (Unchanged by the v0.9 `no_std` conversion: only module declarations and
//! re-exports. The opaque types it re-exports — `KeyHandle`, `Scp03Session`,
//! `Scp02Session` — kept their names; only their internals became slot indices.)

mod key;
mod scp02;
mod scp03;

pub use key::{ExportableKeyBackend, ExportedKey, KeyBackend, KeyHandle, KeyKind};
pub use scp02::{Scp02Backend, Scp02Session};
pub use scp03::{Scp03Backend, Scp03Session, ScpMode};
