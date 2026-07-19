//! `Trace` — an owning, ordered list of scripted C-APDU → R-APDU exchanges that
//! produces a [`crate::MockTransport`] (PDD §10.3, replay layer).
//!
//! [`MockTransport::new`] borrows `&[(&[u8], &[u8])]` and copies the bytes in,
//! so a test can build a `Trace` from owned buffers (recorded or synthetic) and
//! hand out a fresh mock per run. The mock asserts the workflow sends exactly
//! the scripted C-APDUs in order; `assert_drained` confirms none are left.

use crate::MockTransport;

/// One scripted exchange with owned buffers.
type Pair = (std::vec::Vec<u8>, std::vec::Vec<u8>);

/// An owning, ordered APDU trace. Build with [`Trace::new`] + [`Trace::step`],
/// then [`Trace::mock`] for a [`MockTransport`].
#[derive(Debug, Default, Clone)]
pub struct Trace {
    steps: std::vec::Vec<Pair>,
}

impl Trace {
    /// An empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            steps: std::vec::Vec::new(),
        }
    }

    /// Append one `(expected C-APDU, R-APDU)` exchange (bytes copied in).
    #[must_use]
    pub fn step(mut self, capdu: &[u8], rapdu: &[u8]) -> Self {
        self.steps.push((capdu.to_vec(), rapdu.to_vec()));
        self
    }

    /// Number of scripted exchanges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True if the trace has no exchanges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Build a fresh [`MockTransport`] scripted from this trace.
    #[must_use]
    pub fn mock(&self) -> MockTransport {
        let refs: std::vec::Vec<(&[u8], &[u8])> = self
            .steps
            .iter()
            .map(|(c, r)| (c.as_slice(), r.as_slice()))
            .collect();
        MockTransport::new(&refs)
    }
}
