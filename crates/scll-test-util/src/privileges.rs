//! `Privileges` — a `no_std`, alloc-free [`core::fmt::Display`] newtype that
//! renders a 3-byte `GlobalPlatform` privileges value as the comma-separated
//! privilege names (the `gp --list` style), decoding raw `[u8; 3]` to names
//! purely in test/diagnostic code.
//!
//! `scll-core` keeps privileges as the raw `[u8; 3]` the card returns (PDD
//! Fork 6); name decoding lives here so the alloc-free core never carries a
//! string table. Bit assignments are GPCS v2.3.1 Tables 11-7 (byte 1), 11-8
//! (byte 2), and 11-9 (byte 3).
//!
//! This is a standalone module: when the workspace's `Dump` facility lands, the
//! [`Privileges`] newtype folds into it unchanged (it already implements
//! `Display`/`Debug` over a borrowed `&[u8; 3]`).
//!
//! ```
//! use scll_test_util::Privileges;
//! // ISD-style: Security Domain + Card Reset + Authorized Management.
//! let p = Privileges(&[0x84u8, 0x40, 0x00]);
//! assert!(p.is_security_domain());
//! ```

use core::fmt;

/// Privilege-name table, indexed `[byte][bit]` where `bit` 0 = b8 (`0x80`) down
/// to `bit` 7 = b1 (`0x01`). `None` marks an RFU position (GPCS v2.3.1
/// Tables 11-7/11-8/11-9). Rendered high-bit-first so output matches the
/// conventional `gp --list` ordering.
const NAMES: [[Option<&str>; 8]; 3] = [
    // Byte 1 — Table 11-7.
    [
        Some("SecurityDomain"),          // b8 0x80
        Some("DAPVerification"),         // b7 0x40
        Some("DelegatedManagement"),     // b6 0x20
        Some("CardLock"),                // b5 0x10
        Some("CardTerminate"),           // b4 0x08
        Some("CardReset"),               // b3 0x04 (Default Selected)
        Some("CVMManagement"),           // b2 0x02
        Some("MandatedDAPVerification"), // b1 0x01
    ],
    // Byte 2 — Table 11-8.
    [
        Some("TrustedPath"),          // b8 0x80
        Some("AuthorizedManagement"), // b7 0x40
        Some("TokenVerification"),    // b6 0x20
        Some("GlobalDelete"),         // b5 0x10
        Some("GlobalLock"),           // b4 0x08
        Some("GlobalRegistry"),       // b3 0x04
        Some("FinalApplication"),     // b2 0x02
        Some("GlobalService"),        // b1 0x01
    ],
    // Byte 3 — Table 11-9.
    [
        Some("ReceiptGeneration"),         // b8 0x80
        Some("CipheredLoadFileDataBlock"), // b7 0x40
        Some("ContactlessActivation"),     // b6 0x20
        Some("ContactlessSelfActivation"), // b5 0x10
        None,                              // b4 0x08 RFU
        None,                              // b3 0x04 RFU
        None,                              // b2 0x02 RFU
        None,                              // b1 0x01 RFU
    ],
];

/// Display/Debug wrapper over a borrowed 3-byte privileges value. Formats as the
/// comma-separated set privilege names, or `<none>` when no bit is set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Privileges<'a>(pub &'a [u8; 3]);

impl Privileges<'_> {
    /// True iff the Security Domain privilege bit (byte 1 / b8) is set — the
    /// same discriminator `get_card_inventory` uses to split SDs from
    /// Applications (GPCS v2.3.1 Table 11-7).
    #[must_use]
    pub fn is_security_domain(&self) -> bool {
        self.0[0] & 0x80 != 0
    }
}

impl fmt::Display for Privileges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;
        for (&byte, row) in self.0.iter().zip(NAMES.iter()) {
            for (bit_idx, name) in row.iter().enumerate() {
                let mask = 0x80u8 >> bit_idx;
                if byte & mask == 0 {
                    continue;
                }
                if let Some(name) = name {
                    if wrote {
                        f.write_str(", ")?;
                    }
                    f.write_str(name)?;
                    wrote = true;
                }
            }
        }
        if !wrote {
            f.write_str("<none>")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Privileges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // e.g. `Privileges(84 40 00: SecurityDomain, CardReset, AuthorizedManagement)`
        write!(
            f,
            "Privileges({:02X} {:02X} {:02X}: {self})",
            self.0[0], self.0[1], self.0[2]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    /// Minimal alloc-free `core::fmt::Write` sink so these tests stay `no_std`
    /// (this crate's `std` feature is off by default).
    struct FmtBuf {
        buf: [u8; 256],
        len: usize,
    }
    impl FmtBuf {
        fn new() -> Self {
            Self {
                buf: [0; 256],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }
    impl Write for FmtBuf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let b = s.as_bytes();
            let end = self.len + b.len();
            if end > self.buf.len() {
                return Err(fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(b);
            self.len = end;
            Ok(())
        }
    }
    fn show(p: [u8; 3]) -> FmtBuf {
        let mut b = FmtBuf::new();
        write!(b, "{}", Privileges(&p)).unwrap();
        b
    }

    #[test]
    fn empty_privileges_render_none() {
        assert_eq!(show([0x00, 0x00, 0x00]).as_str(), "<none>");
    }

    #[test]
    fn security_domain_bit_is_byte0_high() {
        assert!(Privileges(&[0x80, 0x00, 0x00]).is_security_domain());
        assert!(!Privileges(&[0x40, 0x00, 0x00]).is_security_domain());
        assert_eq!(show([0x80, 0x00, 0x00]).as_str(), "SecurityDomain");
    }

    #[test]
    fn names_span_all_three_bytes_high_bit_first() {
        // byte1 b8 (SD) + byte2 b7 (AuthMgmt) + byte3 b8 (ReceiptGen).
        assert_eq!(
            show([0x80, 0x40, 0x80]).as_str(),
            "SecurityDomain, AuthorizedManagement, ReceiptGeneration"
        );
    }

    #[test]
    fn rfu_bits_in_byte3_are_ignored() {
        // Only RFU bits set in byte 3 ⇒ nothing nameable from it.
        assert_eq!(show([0x00, 0x00, 0x0F]).as_str(), "<none>");
    }

    #[test]
    fn debug_shows_hex_then_names() {
        let mut b = FmtBuf::new();
        write!(b, "{:?}", Privileges(&[0x84, 0x40, 0x00])).unwrap();
        let d = b.as_str();
        assert!(d.starts_with("Privileges(84 40 00: "));
        assert!(d.contains("SecurityDomain"));
        assert!(d.contains("CardReset"));
        assert!(d.contains("AuthorizedManagement"));
    }
}
