//! `MockTransport` — a scripted [`scll_core::Transport`] for hardware-free tests.
//!
//! Holds an ordered queue of expected C-APDU → canned R-APDU exchanges. Each
//! [`Transport::transmit`] call pops the next exchange, asserts the incoming
//! C-APDU matches the scripted bytes (panicking with a hex dump on mismatch),
//! and returns the canned R-APDU. Because it implements the real
//! [`scll_core::Transport`] trait, replay tests exercise the production code
//! path with no parallel mock interface (PDD §10.3).

use std::collections::VecDeque;

use heapless::Vec;
use scll_core::limits::RAPDU_MAX;
use scll_core::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};

/// One scripted exchange: the C-APDU the caller is expected to send next, and
/// the R-APDU the mock returns for it.
struct Exchange {
    expected_capdu: std::vec::Vec<u8>,
    rapdu: Vec<u8, RAPDU_MAX>,
}

/// A scripted [`Transport`] that returns canned R-APDUs in order and asserts the
/// caller sends the expected C-APDUs.
///
/// Construct with [`MockTransport::new`]; tune the reported capabilities,
/// protocol, or reset answer with the `with_*` builders. After driving a
/// workflow, call [`MockTransport::assert_drained`] to confirm every scripted
/// exchange was consumed.
#[allow(clippy::module_name_repetitions)] // public type name intentionally carries the `Transport` role
pub struct MockTransport {
    script: VecDeque<Exchange>,
    caps: TransportCaps,
    protocol: TransportProtocol,
    atr: AtrAts,
}

impl MockTransport {
    /// Build a mock from an ordered list of `(expected C-APDU, R-APDU)` pairs.
    ///
    /// Defaults mirror a contact JCOP-style card as the jcsim transport reports
    /// it: T=1, contact, `handles_t0_get_response = false`, and a synthetic
    /// empty ATR tagged T=1. Override via [`MockTransport::with_caps`],
    /// [`MockTransport::with_protocol`], or [`MockTransport::with_atr`].
    ///
    /// # Panics
    /// Panics if any scripted R-APDU is longer than [`RAPDU_MAX`] bytes: such a
    /// vector could never appear on a short-APDU wire, so it is a test-authoring
    /// bug surfaced eagerly here rather than at `transmit` time.
    #[must_use]
    pub fn new(exchanges: &[(&[u8], &[u8])]) -> Self {
        let script = exchanges
            .iter()
            .map(|&(capdu, rapdu)| Exchange {
                expected_capdu: capdu.to_vec(),
                rapdu: Vec::from_slice(rapdu).expect("scripted R-APDU exceeds RAPDU_MAX"),
            })
            .collect();
        Self {
            script,
            caps: default_caps(),
            protocol: TransportProtocol::T1,
            atr: synthetic_atr(),
        }
    }

    /// Override the [`TransportCaps`] reported by [`Transport::capabilities`].
    #[must_use]
    pub fn with_caps(mut self, caps: TransportCaps) -> Self {
        self.caps = caps;
        self
    }

    /// Override the protocol reported by [`Transport::protocol`].
    #[must_use]
    pub fn with_protocol(mut self, protocol: TransportProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Override the [`AtrAts`] returned by [`Transport::reset`].
    #[must_use]
    pub fn with_atr(mut self, atr: AtrAts) -> Self {
        self.atr = atr;
        self
    }

    /// Number of scripted exchanges not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.script.len()
    }

    /// True once every scripted exchange has been consumed.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.script.is_empty()
    }

    /// Assert that every scripted exchange was consumed.
    ///
    /// # Panics
    /// Panics if any scripted exchange remains, naming the count — a workflow
    /// that sent fewer C-APDUs than scripted is usually a regression.
    pub fn assert_drained(&self) {
        assert!(
            self.is_drained(),
            "MockTransport: {} scripted exchange(s) left unconsumed",
            self.remaining()
        );
    }
}

impl Transport for MockTransport {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> {
        let Exchange {
            expected_capdu,
            rapdu,
        } = self
            .script
            .pop_front()
            .expect("MockTransport: transmit called with no scripted exchanges left");
        assert!(
            capdu == expected_capdu.as_slice(),
            "MockTransport: unexpected C-APDU\n  expected: {:02X?}\n  received: {:02X?}",
            expected_capdu.as_slice(),
            capdu,
        );
        Ok(rapdu)
    }

    fn capabilities(&self) -> TransportCaps {
        self.caps.clone()
    }

    fn reset(&mut self) -> Result<AtrAts, TransportError> {
        Ok(self.atr.clone())
    }

    fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    fn is_connected(&self) -> bool {
        true
    }
}

/// Default capabilities: T=1, contact, no T=0 GET RESPONSE handling.
fn default_caps() -> TransportCaps {
    TransportCaps {
        handles_t0_get_response: false,
        protocol: TransportProtocol::T1,
        contactless: false,
    }
}

/// Synthetic empty ATR tagged T=1 (matches the jcsim transport's `reset`).
fn synthetic_atr() -> AtrAts {
    AtrAts {
        bytes: Vec::new(),
        protocol: TransportProtocol::T1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELECT: &[u8] = &[0x00, 0xA4, 0x04, 0x00, 0x00];
    const SW_OK: &[u8] = &[0x90, 0x00];

    #[test]
    fn round_trip_drives_real_transport_trait() {
        let mut mock = MockTransport::new(&[(SELECT, SW_OK)]);
        // Drive through `&mut dyn Transport` to prove the real trait is exercised.
        let t: &mut dyn Transport = &mut mock;
        let rapdu = t.transmit(SELECT).expect("transmit");
        assert_eq!(rapdu.as_slice(), SW_OK);
        assert!(mock.is_drained());
        mock.assert_drained();
    }

    #[test]
    fn capability_protocol_and_liveness_defaults() {
        let mock = MockTransport::new(&[]);
        let caps = mock.capabilities();
        assert!(!caps.handles_t0_get_response);
        assert!(!caps.contactless);
        assert_eq!(caps.protocol, TransportProtocol::T1);
        assert_eq!(mock.protocol(), TransportProtocol::T1);
        assert!(mock.is_connected());
        assert_eq!(mock.remaining(), 0);
        assert!(mock.is_drained());
    }

    #[test]
    fn reset_returns_synthetic_t1_atr() {
        let mut mock = MockTransport::new(&[]);
        let atr = mock.reset().expect("reset");
        assert!(atr.bytes.is_empty());
        assert_eq!(atr.protocol, TransportProtocol::T1);
    }

    #[test]
    fn builders_override_defaults() {
        let mock = MockTransport::new(&[]).with_protocol(TransportProtocol::TCl);
        assert_eq!(mock.protocol(), TransportProtocol::TCl);
    }

    #[test]
    #[should_panic(expected = "unexpected C-APDU")]
    fn unexpected_capdu_panics() {
        let mut mock = MockTransport::new(&[(SELECT, SW_OK)]);
        let _ = mock.transmit(&[0xDE, 0xAD]);
    }

    #[test]
    #[should_panic(expected = "no scripted exchanges left")]
    fn transmit_past_end_panics() {
        let mut mock = MockTransport::new(&[]);
        let _ = mock.transmit(SELECT);
    }
}
