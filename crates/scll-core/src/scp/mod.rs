//! SCP version selection + session handle — PDD §4.3 / §5.9.
//!
//! Selection rule (§4.3): prefer SCP03 with an in-scope `i` (random or
//! pseudo-random; see [`scp03::i_supported`]) — highest advertised — else
//! SCP02; else `ScllError::ScpProtocolUnsupported`. Missing CRD → assume
//! `Scp02 { i = 0x55 }` with a warning. A caller may override via
//! `force_scp_version` (not recommended).
//!
//! (Unchanged by the v0.9 `no_std` conversion: `ScpSession` wraps the state
//! types regardless of their internals; in v0.9 `scp03::Scp03State` /
//! `scp02::Scp02State` carry the backend session handle — see `scp/scp03.rs`,
//! `scp/scp02.rs`. `select` is alloc-free.)

pub mod scp02;
pub mod scp03;

use crate::model::ScpVariant;

/// Open secure-channel handle, protocol-tagged (PDD §5.9 return type).
pub enum ScpSession {
    Scp03(scp03::Scp03State),
    Scp02(scp02::Scp02State),
}

impl ScpSession {
    /// The effective (capped) security level fixed at channel open (§4.1).
    #[must_use]
    pub fn security_level(&self) -> u8 {
        match self {
            ScpSession::Scp03(s) => s.security_level(),
            ScpSession::Scp02(s) => s.security_level(),
        }
    }

    /// The negotiated SCP `i` parameter.
    #[must_use]
    pub fn i_param(&self) -> u8 {
        match self {
            ScpSession::Scp03(s) => s.i_param(),
            ScpSession::Scp02(s) => s.i_param(),
        }
    }

    /// The key version number the card authenticated with at channel open.
    #[must_use]
    pub fn kvn(&self) -> u8 {
        match self {
            ScpSession::Scp03(s) => s.kvn(),
            ScpSession::Scp02(s) => s.kvn(),
        }
    }

    /// Which SCP protocol this session runs (for report population, §7).
    #[must_use]
    pub fn protocol(&self) -> crate::report::ScpProtocol {
        match self {
            ScpSession::Scp03(_) => crate::report::ScpProtocol::Scp03,
            ScpSession::Scp02(_) => crate::report::ScpProtocol::Scp02,
        }
    }

    /// A stable, deterministic session identifier derived from the backend
    /// session-slot index (§7 reports carry no timestamp/version, §10.3).
    #[must_use]
    pub fn session_id(&self) -> u64 {
        match self {
            ScpSession::Scp03(s) => u64::from(s.session().index()),
            ScpSession::Scp02(s) => u64::from(s.session().index()),
        }
    }
}

/// Apply the §4.3 selection rule to the card's advertised variants: a caller
/// `force` override wins; otherwise prefer SCP03 with an in-scope `i` (random
/// or pseudo-random; see [`scp03::i_supported`]) — highest advertised — else
/// the first SCP02 variant, else `None`. (The "missing CRD → assume
/// `Scp02 { i = 0x55 }` with a warning" fallback is the workflow's job — it
/// applies before calling this with a non-empty list.)
#[must_use]
pub fn select(advertised: &[ScpVariant], force: Option<ScpVariant>) -> Option<ScpVariant> {
    if let Some(forced) = force {
        return Some(forced);
    }
    // Prefer SCP03; among in-scope `i` values pick the highest advertised.
    let best_scp03 = advertised
        .iter()
        .filter_map(|v| match v {
            ScpVariant::Scp03 { i_param } if scp03::i_supported(*i_param) => Some(*i_param),
            _ => None,
        })
        .max();
    if let Some(i_param) = best_scp03 {
        return Some(ScpVariant::Scp03 { i_param });
    }
    // Otherwise the first advertised SCP02 variant.
    advertised.iter().find_map(|v| match v {
        ScpVariant::Scp02 { i_param } => Some(ScpVariant::Scp02 { i_param: *i_param }),
        ScpVariant::Scp03 { .. } => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_highest_scp03() {
        let adv = [
            ScpVariant::Scp02 { i_param: 0x55 },
            ScpVariant::Scp03 { i_param: 0x30 },
            ScpVariant::Scp03 { i_param: 0x70 },
        ];
        assert_eq!(
            select(&adv, None),
            Some(ScpVariant::Scp03 { i_param: 0x70 })
        );
    }

    #[test]
    fn falls_back_to_scp02_when_no_scp03() {
        let adv = [ScpVariant::Scp02 { i_param: 0x55 }];
        assert_eq!(
            select(&adv, None),
            Some(ScpVariant::Scp02 { i_param: 0x55 })
        );
    }

    #[test]
    fn ignores_out_of_scope_scp03_i() {
        // An SCP03 i with an out-of-scope bit (0x04 = RFU) is not selectable;
        // SCP02 wins instead. (S8/S16 × random/pseudo configs ARE in scope.)
        let adv = [
            ScpVariant::Scp03 { i_param: 0x04 },
            ScpVariant::Scp02 { i_param: 0x15 },
        ];
        assert_eq!(
            select(&adv, None),
            Some(ScpVariant::Scp02 { i_param: 0x15 })
        );
    }

    #[test]
    fn selects_s16_scp03() {
        // S16 SCP03 (0x78) is in scope and preferred over SCP02.
        let adv = [
            ScpVariant::Scp02 { i_param: 0x55 },
            ScpVariant::Scp03 { i_param: 0x78 },
        ];
        assert_eq!(
            select(&adv, None),
            Some(ScpVariant::Scp03 { i_param: 0x78 })
        );
    }

    #[test]
    fn selects_random_challenge_scp03() {
        // Random-challenge SCP03 (0x60) is in scope and preferred over SCP02.
        let adv = [
            ScpVariant::Scp02 { i_param: 0x55 },
            ScpVariant::Scp03 { i_param: 0x60 },
        ];
        assert_eq!(
            select(&adv, None),
            Some(ScpVariant::Scp03 { i_param: 0x60 })
        );
    }

    #[test]
    fn force_overrides_selection() {
        let adv = [ScpVariant::Scp03 { i_param: 0x70 }];
        let forced = ScpVariant::Scp02 { i_param: 0x55 };
        assert_eq!(select(&adv, Some(forced)), Some(forced));
    }

    #[test]
    fn empty_yields_none() {
        assert_eq!(select(&[], None), None);
    }
}
