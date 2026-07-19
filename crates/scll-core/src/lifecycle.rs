//! Card (ISD) life-cycle transition state machine — PDD §5.11.
//!
//! Verified against GPCS v2.3.1 §5.1.1.1–.5 and Figure 5-1 (PDF p. 54):
//! - `OP_READY → INITIALIZED → SECURED` irreversible (§5.1.1.2/.3).
//! - `SECURED ↔ CARD_LOCKED` reversible (§5.1.1.4).
//! - any → `TERMINATED` irreversible (§5.1.1.5) — **refused** as a set target (§2.2).
//! - Skip-ahead to `SECURED` is spec-legal (§5.1.2) — gated behind `force`.
//! - Same-state = no-op (card rejects per §11.10.2.2); detected before any APDU.
//!
//! P2 target bytes are the Card Life Cycle Coding of GPCS v2.3.1 Table 11-6
//! (`INITIALIZED = 0x07`, `SECURED = 0x0F`, `CARD_LOCKED = 0x7F`), as required
//! by SET STATUS §11.10.2.2.

use crate::error::ScllError;
use crate::report::CardLifeCycle;

/// SET STATUS P2 byte for `INITIALIZED` (GPCS v2.3.1 Table 11-6).
const P2_INITIALIZED: u8 = 0x07;
/// SET STATUS P2 byte for `SECURED` (GPCS v2.3.1 Table 11-6).
const P2_SECURED: u8 = 0x0F;
/// SET STATUS P2 byte for `CARD_LOCKED` (GPCS v2.3.1 Table 11-6).
const P2_CARD_LOCKED: u8 = 0x7F;

/// Validate a requested transition against the verified matrix.
/// `force` permits skip-ahead to `SECURED`; never bypasses the `TERMINATED`
/// refusal or backward-transition refusal.
///
/// # Errors
/// Returns [`ScllError::IllegalLifecycleTransition`] for a backward or
/// otherwise illegal transition, or [`ScllError::TerminateOutOfScope`] if
/// `target` is `TERMINATED` (refused as a set target).
pub fn check_transition(
    current: CardLifeCycle,
    target: CardLifeCycle,
    force: bool,
) -> Result<TransitionPlan, ScllError> {
    use CardLifeCycle::{CardLocked, Initialized, OpReady, Secured, Terminated, Unknown};

    // TERMINATED is never a valid set target, under any `force` (§2.2 / §5.1.1.5).
    if matches!(target, Terminated) {
        return Err(ScllError::TerminateOutOfScope);
    }
    // An unknown byte is not a settable target state.
    if matches!(target, Unknown(_)) {
        return Err(ScllError::IllegalLifecycleTransition);
    }
    // Same state ⇒ no-op; the card rejects a same-state SET STATUS (§11.10.2.2),
    // so the library reports it without sending an APDU.
    if current == target {
        return Ok(TransitionPlan::NoOp);
    }
    // TERMINATED is final: no transition leaves it. Unknown current state cannot
    // be validated against the matrix, so it is refused conservatively.
    if matches!(current, Terminated | Unknown(_)) {
        return Err(ScllError::IllegalLifecycleTransition);
    }

    let p2 = match (current, target) {
        (OpReady, Initialized) => P2_INITIALIZED, // forward (§5.1.1.2)
        (Initialized | CardLocked, Secured) => P2_SECURED, // forward / unlock (§5.1.1.3/.4)
        (OpReady, Secured) if force => P2_SECURED, // skip-ahead, force only (§5.1.2)
        (Secured, CardLocked) => P2_CARD_LOCKED,  // lock (§5.1.1.4)
        _ => return Err(ScllError::IllegalLifecycleTransition), // backward / skip-ahead w/o force
    };
    Ok(TransitionPlan::Apply { p2 })
}

/// Outcome of a legality check: either a no-op, or the P2 byte to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionPlan {
    NoOp,             // already in target — emit WarningKind::LifecycleNoOp, send nothing
    Apply { p2: u8 }, // e.g. 0x07 INITIALIZED, 0x0F SECURED, 0x7F CARD_LOCKED
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::CardLifeCycle::{
        CardLocked, Initialized, OpReady, Secured, Terminated, Unknown,
    };

    const VALID: [CardLifeCycle; 4] = [OpReady, Initialized, Secured, CardLocked];

    #[test]
    fn terminated_is_never_a_target_under_any_force() {
        for &current in &[
            OpReady,
            Initialized,
            Secured,
            CardLocked,
            Terminated,
            Unknown(0x42),
        ] {
            for force in [false, true] {
                assert!(matches!(
                    check_transition(current, Terminated, force),
                    Err(ScllError::TerminateOutOfScope)
                ));
            }
        }
    }

    #[test]
    fn forward_provisioning_is_one_way() {
        assert_eq!(
            check_transition(OpReady, Initialized, false).unwrap(),
            TransitionPlan::Apply { p2: 0x07 }
        );
        assert_eq!(
            check_transition(Initialized, Secured, false).unwrap(),
            TransitionPlan::Apply { p2: 0x0F }
        );
        // Backward is refused, with or without force.
        for force in [false, true] {
            for &(from, to) in &[
                (Initialized, OpReady),
                (Secured, Initialized),
                (Secured, OpReady),
                (CardLocked, Initialized),
                (CardLocked, OpReady),
            ] {
                assert!(matches!(
                    check_transition(from, to, force),
                    Err(ScllError::IllegalLifecycleTransition)
                ));
            }
        }
    }

    #[test]
    fn skip_ahead_to_secured_requires_force() {
        assert!(matches!(
            check_transition(OpReady, Secured, false),
            Err(ScllError::IllegalLifecycleTransition)
        ));
        assert_eq!(
            check_transition(OpReady, Secured, true).unwrap(),
            TransitionPlan::Apply { p2: 0x0F }
        );
    }

    #[test]
    fn lock_and_unlock_are_reversible() {
        assert_eq!(
            check_transition(Secured, CardLocked, false).unwrap(),
            TransitionPlan::Apply { p2: 0x7F }
        );
        assert_eq!(
            check_transition(CardLocked, Secured, false).unwrap(),
            TransitionPlan::Apply { p2: 0x0F }
        );
    }

    #[test]
    fn same_state_is_a_no_op() {
        for &s in &VALID {
            assert_eq!(check_transition(s, s, false).unwrap(), TransitionPlan::NoOp);
        }
    }

    #[test]
    fn unknown_states_are_refused() {
        // Unknown target.
        assert!(matches!(
            check_transition(Secured, Unknown(0x99), false),
            Err(ScllError::IllegalLifecycleTransition)
        ));
        // Unknown current (valid, non-terminated target).
        assert!(matches!(
            check_transition(Unknown(0x99), Secured, true),
            Err(ScllError::IllegalLifecycleTransition)
        ));
    }

    #[test]
    fn nothing_leaves_terminated() {
        for &to in &VALID {
            assert!(matches!(
                check_transition(Terminated, to, true),
                Err(ScllError::IllegalLifecycleTransition)
            ));
        }
    }
}
