//! Typed error and warning surface — PDD §8.
//!
//! Errors are a real enum from day one (no stringly-typed codes), so tests can
//! assert exact variants and the SW→error mapping can be exhaustively checked.
//! The v0.5 category prefixes (`T_`/`S_`/`K_`/`C_`/`L_`/`P_`/`I_`/`V_`) survive
//! only as the comment groupings below.
//!
//! `no_std`: the `thiserror::Error` derive is kept — `error_in_core` is stable
//! since Rust 1.81, and `thiserror` ≥2 with `default-features = false` derives
//! `core::error::Error`. Former `String`/`Vec<u8>` payloads are fixed-capacity
//! `heapless` collections sized from [`crate::limits`].

use heapless::{String, Vec};

use crate::cap::CapError;
use crate::command::BuildError;
use crate::limits::{MAX_KEYTYPE_SUPPORTED, OTHER_DETAIL_MAX, WARNING_DETAIL_MAX};
use crate::tlv::TlvError;

/// Fatal error returned by every public workflow function (`Result<XReport, ScllError>`).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ScllError {
    // --- Transport (was T_*) ---
    #[error("transport unavailable")]
    TransportUnavailable,
    #[error("card removed")]
    CardRemoved,
    #[error("reader gone")]
    ReaderGone,
    #[error("transport timeout")]
    Timeout,

    // --- Secure channel (was S_*) ---
    #[error("no SCP protocol the library supports")]
    ScpProtocolUnsupported,
    #[error("no common security level")]
    NoCommonSecurityLevel,
    #[error("KVN mismatch (card vs supplied keys)")]
    KvnMismatch,
    #[error("card cryptogram verification failed")]
    CardCryptogramFail,
    #[error("pseudo-random card challenge verification failed")]
    CardChallengeFail,
    #[error("EXTERNAL AUTHENTICATE failed (sw={sw:#06x})")]
    ExternalAuthFail { sw: u16 },
    #[error("security status not satisfied")]
    SecurityStatusNotSatisfied,
    #[error("no secure channel is open on this manager")]
    NoOpenChannel, // CardManager in-session method called before open_scp (PDD §3.6)

    // --- Keys (was K_*) ---
    #[error("referenced key not found")]
    KeyNotFound,
    #[error("key type unsupported")]
    KeyTypeUnsupported {
        offered: u8,
        supported: Vec<u8, MAX_KEYTYPE_SUPPORTED>,
    },
    #[error("key check value mismatch")]
    KeyCheckValueMismatch,
    #[error("cannot delete the active keyset")]
    CannotDeleteActiveKeyset,

    // --- Content / CAP (was C_*) ---
    #[error("AID length {len} out of range (must be 5..=16 bytes)")]
    InvalidAid { len: usize },
    #[error("AID already exists")]
    AidAlreadyExists,
    #[error("package AID already exists")]
    PackageAidExists,
    #[error("package not found")]
    PackageNotFound,
    #[error("resident SD module not found")]
    ResidentSdNotFound,
    #[error("load file too large for short APDUs")]
    LoadTooLarge,
    #[error("SSD still has applets")]
    SsdHasApplets,
    #[error("ELF has other instances")]
    ElfHasOtherInstances,

    // --- Life-cycle (was L_*) ---
    #[error("card not usable (misconfigured or TERMINATED)")]
    CardNotUsable,
    #[error("illegal life-cycle transition")]
    IllegalLifecycleTransition,
    #[error("conditions of use not satisfied")]
    ConditionsNotSatisfied,
    #[error("ISD AID not found")]
    IsdAidNotFound,
    #[error("session is not against the ISD")]
    SessionNotIsd,
    #[error("target no longer exists")]
    TargetNoLongerExists,
    #[error("TERMINATED is out of scope as a set target")]
    TerminateOutOfScope,

    // --- Privilege (was P_*) ---
    #[error("parent lacks Authorized Management")]
    ParentLacksAm,
    #[error("unsupported privilege")]
    UnsupportedPrivilege,

    // --- Card said no, with an SW the library does not map to a specific case ---
    #[error("card returned status word {sw:#06x}")]
    Card { sw: u16 },

    // --- Internal parse / build (wrapped sub-errors; `?` from those layers) ---
    #[error("malformed card response: {0}")]
    MalformedResponse(#[from] TlvError),
    #[error("APDU build error: {0}")]
    Build(#[from] BuildError),
    #[error("CAP parse error: {0}")]
    Cap(#[from] CapError),

    // --- Backend / crypto / key-handle (was V_*) ---
    #[error(transparent)]
    Backend(#[from] BackendError),
}

impl ScllError {
    /// Map a *context-free* command status word to its [`ScllError`].
    ///
    /// This covers only the **general** error conditions of GPCS v2.3.1
    /// Table 11-10 — the two status words whose meaning is invariant across
    /// every GP command (`6982` security status, `6985` conditions of use).
    /// Everything else falls through to the [`ScllError::Card`] catch-all, so
    /// the mapping is *total*: every `u16` yields exactly one variant.
    ///
    /// Per-command refinements are deliberately **not** decided here. The same
    /// SW means different things per command — e.g. `6985` is
    /// `IllegalLifecycleTransition` for SET STATUS (Table 11-87) but
    /// `ElfHasOtherInstances` for DELETE (Table 11-26); `6A88` is
    /// `IsdAidNotFound`, `KeyNotFound`, or `PackageNotFound` by context. Those
    /// live in the workflow layer, which inspects the SW before delegating the
    /// residue to this general mapper (PDD §8 status-word coverage).
    ///
    /// Note: `9000` (success) is not an error; callers check for success before
    /// calling this. Passing it returns `Card { sw: 0x9000 }` (harmless).
    #[must_use]
    pub fn from_general_sw(sw: u16) -> ScllError {
        match sw {
            // GPCS v2.3.1 Table 11-10 (general error conditions).
            0x6982 => ScllError::SecurityStatusNotSatisfied,
            0x6985 => ScllError::ConditionsNotSatisfied,
            // Sole catch-all (PDD §8): no dedicated, context-free variant.
            other => ScllError::Card { sw: other },
        }
    }
}

/// Non-fatal warning attached to a report's `warnings` (PDD §7/§8).
#[derive(Debug, Clone)]
pub struct Warning {
    pub kind: WarningKind,
    pub detail: String<WARNING_DETAIL_MAX>,
}

/// Typed warning kinds (PDD §8). No `String` codes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WarningKind {
    CardRecognitionDataMissing, // was D_*
    KeyInformationTemplateMissing,
    CardCapabilityInfoMissing,
    UnknownLifecycleByte(u8),
    GetStatusParseFailed,
    LifecycleNoOp, // was L_LifecycleNoOp
    /// `get_card_inventory` (§5.12a) reached a `CardInventory` capacity bound
    /// (`MAX_SDS` / `MAX_APPLETS` / `MAX_ELFS`) or the per-scope page cap
    /// (`MAX_STATUS_PAGES`) before the card was exhausted; the returned
    /// inventory is a valid prefix, not the full card content.
    InventoryTruncated,
}

/// Coarse error surface returned by every backend trait method (PDD §3.3/§8).
/// Carries an opaque `detail` so software and HSM/PKCS#11 backends can attach
/// context without leaking key material.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BackendError {
    #[error("key import failed: {0}")]
    KeyImport(String<OTHER_DETAIL_MAX>), // was V_KeyImport
    #[error("key generation failed: {0}")]
    KeyGen(String<OTHER_DETAIL_MAX>), // was V_KeyGen
    #[error("crypto operation failed: {0}")]
    Crypto(String<OTHER_DETAIL_MAX>), // was V_Crypto
    #[error("RNG failure: {0}")]
    Rng(String<OTHER_DETAIL_MAX>), // was V_Rng
    #[error("operation unsupported by this backend: {0}")]
    Unsupported(String<OTHER_DETAIL_MAX>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two dedicated arms map exactly, and the mapping is *total* with
    /// `Card { sw }` as the sole catch-all: every other `u16` round-trips its
    /// own `sw` through `Card`. Exhaustive over the whole `u16` space (PDD §8).
    #[test]
    fn general_sw_map_is_total_with_card_as_sole_catch_all() {
        for sw in 0x0000u16..=0xFFFF {
            match ScllError::from_general_sw(sw) {
                ScllError::SecurityStatusNotSatisfied => assert_eq!(sw, 0x6982),
                ScllError::ConditionsNotSatisfied => assert_eq!(sw, 0x6985),
                ScllError::Card { sw: got } => {
                    assert_eq!(got, sw, "Card must carry the input sw verbatim");
                    assert!(
                        sw != 0x6982 && sw != 0x6985,
                        "dedicated SWs must not fall through"
                    );
                }
                other => panic!("sw {sw:#06x} mapped to an unexpected variant: {other:?}"),
            }
        }
    }

    #[test]
    fn dedicated_general_sws_map_to_their_variants() {
        assert!(matches!(
            ScllError::from_general_sw(0x6982),
            ScllError::SecurityStatusNotSatisfied
        ));
        assert!(matches!(
            ScllError::from_general_sw(0x6985),
            ScllError::ConditionsNotSatisfied
        ));
    }

    #[test]
    fn success_word_is_not_special_cased() {
        // 9000 is success, not an error; the general mapper has no opinion and
        // returns the catch-all carrying the verbatim sw.
        assert!(matches!(
            ScllError::from_general_sw(0x9000),
            ScllError::Card { sw: 0x9000 }
        ));
    }
}
