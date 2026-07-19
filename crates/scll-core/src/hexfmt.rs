//! Hex formatting helper for `Debug` output.
//!
//! Raw byte fields (AIDs, ATR/ATS, install parameters, APDU data, KCVs, …)
//! derive-print as decimal arrays like `[160, 0, 0, 1]`, which is unreadable for
//! smart-card debugging. [`HexBytes`] renders them as an uppercase hex string in
//! quotes, e.g. `"A0000001"`. It is `pub(crate)`: types embed it inside their own
//! manual `Debug` impls (see `aid.rs`, `model.rs`, `report.rs`).

use core::fmt;

/// `Debug`-formats a byte slice as a quoted uppercase hex string.
///
/// `HexBytes(&[0xA0, 0x00])` ⇒ `"A000"`; empty ⇒ `""`.
pub(crate) struct HexBytes<'a>(pub &'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        f.write_str("\"")
    }
}

/// `Debug`-formats a single byte as a `0x`-prefixed two-digit uppercase hex
/// literal.
///
/// `HexByte(0x30)` ⇒ `0x30`; `HexByte(0)` ⇒ `0x00`. Used for protocol scalars
/// (key version numbers, SCP `i` parameter, …) where the hex value is the
/// meaningful form for smart-card debugging rather than the decimal `48`/`112`.
pub(crate) struct HexByte(pub u8);

impl fmt::Debug for HexByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:02X}", self.0)
    }
}
