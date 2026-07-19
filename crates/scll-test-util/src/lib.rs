//! Test-only utilities shared across the `scll` workspace crates.
//!
//! This crate exposes [`HexSlice`], a thin newtype whose `Debug` formats bytes
//! as uppercase, two-digit-per-byte hex, and [`Privileges`], a `Display`/`Debug`
//! newtype that decodes a raw `[u8; 3]` `GlobalPlatform` privileges value to its
//! privilege names (GPCS v2.3.1 Tables 11-7..11-9) for readable inventory dumps.
//! Wrapping comparands in `HexSlice` makes `assert_eq!` / `assert_ne!` failures
//! print byte buffers as hex (e.g. `[6F, 61, 84]`) instead of the default
//! decimal, which is far easier to read for APDUs, keys, and TLVs.
//!
//! It is `no_std` (uses only [`core::fmt`]) so it can be used from the test
//! modules of the alloc-free `scll-core` / `scll-backend-rustcrypto` crates as
//! well as the `std` transport crates. It is pulled in only as a
//! `dev-dependency`, so it never enters any production or `no_std` build graph.
//!
//! ```
//! use scll_test_util::HexSlice;
//!
//! // Both sides may have different concrete byte-buffer types.
//! assert_eq!(HexSlice([0x90u8, 0x00]), HexSlice(&[0x90u8, 0x00]));
//! ```
#![cfg_attr(not(test), no_std)]

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

mod privileges;
pub use privileges::Privileges;

/// Address of a running `javacard-simulator-apdu-bridge` taken from the
/// `SCLL_JCSIM_ADDR` environment variable, or `None` when it is unset or empty.
///
/// Integration tests that need a live bridge call this (via
/// [`skip_unless_jcsim!`]) so they auto-run when a bridge is configured and skip
/// otherwise — no `#[ignore]` / `--ignored` dance, and `cargo test` stays green
/// when the variable is absent.
#[cfg(feature = "std")]
#[must_use]
pub fn jcsim_addr() -> Option<std::string::String> {
    std::env::var("SCLL_JCSIM_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Resolve the jcsim bridge address or skip the current `#[test]`.
///
/// Expands to the address `String` when `SCLL_JCSIM_ADDR` is set; otherwise
/// prints a one-line skip notice and `return`s from the calling test. (Stable
/// libtest has no first-class "skipped" status, so a skipped test reports as
/// passed; the notice is visible under `--nocapture`.)
///
/// ```ignore
/// #[test]
/// fn my_integration_test() {
///     let addr = scll_test_util::skip_unless_jcsim!();
///     let transport = JcSimTransport::connect(&addr).unwrap();
///     // ...
/// }
/// ```
#[cfg(feature = "std")]
#[macro_export]
macro_rules! skip_unless_jcsim {
    () => {
        match $crate::jcsim_addr() {
            ::core::option::Option::Some(addr) => addr,
            ::core::option::Option::None => {
                std::eprintln!(
                    "SKIP {}: set SCLL_JCSIM_ADDR=<host:port> (a running \
                     javacard-simulator-apdu-bridge) to run this integration test",
                    module_path!()
                );
                return;
            }
        }
    };
}

/// Reader selector for the PC/SC smoke test, taken from the `SCLL_PCSC`
/// environment variable, or `None` when unset or empty. The value is the
/// `<name-substring>[@<index>]` selector consumed by
/// `PcscTransport::connect_selector` (a reader-name substring, plus an optional
/// 0-based index to disambiguate multiple matches — PC/SC encodes the slot in
/// the reader name, so there is no separate slot argument).
#[cfg(feature = "std")]
#[must_use]
pub fn pcsc_spec() -> Option<std::string::String> {
    std::env::var("SCLL_PCSC").ok().filter(|s| !s.is_empty())
}

/// Three ENC/MAC/DEK keys (each a 16/24/32-byte value in a 32-byte zero-padded
/// buffer) plus their common length. Index `[0]` = ENC, `[1]` = MAC, `[2]` =
/// DEK; import `&buf[..len]`. Produce one with [`decode_key_set`] or
/// [`required_role_key_set`].
pub type KeySet = ([[u8; 32]; 3], usize);

/// Read an environment variable, treating unset or empty as `None`.
#[cfg(feature = "std")]
fn env_nonempty(name: &str) -> Option<std::string::String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Decode an explicit ENC/MAC/DEK hex triple into a [`KeySet`]. Each key is
/// 32/48/64 hex (16/24/32 bytes); all three must be the same length, since a GP
/// keyset shares one key type across ENC/MAC/DEK.
///
/// # Errors
/// If any key is not 32/48/64 hex / contains a non-hex character, or the three
/// keys differ in length.
pub fn decode_key_set(enc: &str, mac: &str, dek: &str) -> Result<KeySet, &'static str> {
    let (ke, le) = parse_key_hex(enc)?;
    let (km, lm) = parse_key_hex(mac)?;
    let (kd, ld) = parse_key_hex(dek)?;
    if le != lm || le != ld {
        return Err("ENC/MAC/DEK keys must all be the same length");
    }
    Ok(([ke, km, kd], le))
}

/// Resolve an ENC/MAC/DEK [`KeySet`] from the three **required** per-role
/// variables `<base>_ENC`, `<base>_MAC`, `<base>_DEK`. There is no `<base>`
/// fallback and no built-in default key: each of the three must be set and
/// non-empty for the key set to resolve. Used for both targets — the jcsim
/// simulator and a real PC/SC card alike must be driven with operator-supplied
/// keys (GPCS v2.3.1 §11: a wrong key fails EXTERNAL AUTHENTICATE and burns a
/// security-domain retry, so the keys are never defaulted silently).
///
/// Returns:
/// * `None` — none of the three is set: keys are simply not configured, so the
///   caller skips its key-requiring test (the suite stays green on hosts with
///   no provisioned keys).
/// * `Some(Err(msg))` — a misconfiguration the caller surfaces as a panic: some
///   but not all three are set (`msg` names the ones still missing), or a value
///   is not 32/48/64 hex, or the three differ in length.
/// * `Some(Ok(keyset))` — all three present and valid; `[0]` = ENC, `[1]` = MAC,
///   `[2]` = DEK, import `&buf[..len]`.
#[cfg(feature = "std")]
#[must_use]
pub fn required_role_key_set(base: &str) -> Option<Result<KeySet, std::string::String>> {
    let names = [
        [base, "_ENC"].concat(),
        [base, "_MAC"].concat(),
        [base, "_DEK"].concat(),
    ];
    let vals = [
        env_nonempty(&names[0]),
        env_nonempty(&names[1]),
        env_nonempty(&names[2]),
    ];
    match &vals {
        // Nothing configured → not a key run; the caller skips.
        [None, None, None] => None,
        // All three present → decode (a hex/length error becomes the message).
        [Some(enc), Some(mac), Some(dek)] => {
            Some(decode_key_set(enc, mac, dek).map_err(std::string::String::from))
        }
        // Partial → name the variables that are still missing.
        _ => {
            let mut missing = std::string::String::new();
            for (name, val) in names.iter().zip(vals.iter()) {
                if val.is_none() {
                    if !missing.is_empty() {
                        missing.push_str(", ");
                    }
                    missing.push_str(name);
                }
            }
            Some(Err(std::format!(
                "all three of {base}_ENC/_MAC/_DEK are required; not set: {missing}"
            )))
        }
    }
}

/// Decode 32, 48, or 64 hex characters (case-insensitive, no separators) into a
/// 16-, 24-, or 32-byte key, returned as a fixed 32-byte buffer plus the actual
/// length — the form each `SCLL_{JCSIM,PCSC}_KEY_{ENC,MAC,DEK}` variable takes.
/// The length distinguishes the key type the caller imports: 16 = AES-128
/// (SCP03) or double-length 3DES (SCP02), 24 = AES-192, 32 = AES-256 (SCP03
/// supports all three AES sizes per GP Amendment D v1.1.2; the GP default test
/// value is the 16-byte `404142…4F`, GPCS v2.3.1 §11). Only `out[..len]` is
/// meaningful; the tail stays zero.
///
/// # Errors
/// Returns a static message if the input is not 32/48/64 characters or contains
/// a non-hex character.
pub fn parse_key_hex(s: &str) -> Result<([u8; 32], usize), &'static str> {
    let b = s.as_bytes();
    let len = match b.len() {
        32 => 16,
        48 => 24,
        64 => 32,
        _ => return Err("expected 32, 48, or 64 hex characters (16/24/32-byte key)"),
    };
    let mut out = [0u8; 32];
    for (o, pair) in out[..len].iter_mut().zip(b.chunks_exact(2)) {
        *o = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok((out, len))
}

/// Decode a single ASCII hex digit to its 0..=15 value.
fn hex_nibble(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("non-hex character in key"),
    }
}

/// Resolve the `SCLL_PCSC` reader selector or skip the current `#[test]`.
///
/// Expands to the selector `String` when `SCLL_PCSC` is set and non-empty;
/// otherwise prints a one-line skip notice and `return`s from the calling test.
/// (Stable libtest reports a skipped test as passed; the notice is visible under
/// `--nocapture`.)
///
/// ```ignore
/// #[test]
/// fn my_pcsc_test() {
///     let spec = scll_test_util::skip_unless_pcsc!();
///     let transport = PcscTransport::connect_selector(&spec).unwrap();
///     // ...
/// }
/// ```
#[cfg(feature = "std")]
#[macro_export]
macro_rules! skip_unless_pcsc {
    () => {
        match $crate::pcsc_spec() {
            ::core::option::Option::Some(spec) => spec,
            ::core::option::Option::None => {
                std::eprintln!(
                    "SKIP {}: set SCLL_PCSC=<reader-name-substring>[@<index>] (a reader \
                     with a card present) to run this PC/SC integration test",
                    module_path!()
                );
                return;
            }
        }
    };
}

/// Resolve the PC/SC ENC/MAC/DEK key set or skip the current `#[test]`.
///
/// Expands to a [`KeySet`] (`([[u8; 32]; 3], usize)`: the ENC/MAC/DEK buffers
/// plus their common length) when all three of `SCLL_PCSC_KEY_ENC`,
/// `SCLL_PCSC_KEY_MAC` and `SCLL_PCSC_KEY_DEK` are set and non-empty; the caller
/// imports `&keys[i][..len]` and picks the key type from `len` and the
/// negotiated SCP. When none of the three is set the calling test is **not run**
/// — a one-line notice is printed and the test `return`s, so a key-requiring
/// step never fires EXTERNAL AUTHENTICATE at a real card without an
/// operator-supplied key (a failed authentication increments the security
/// domain's retry counter, GPCS v2.3.1 §11). A misconfiguration — only some of
/// the three set, a value not 32/48/64 hex, or the three differing in length —
/// panics. (There is no `SCLL_PCSC_KEY` base variable and no default key.)
#[cfg(feature = "std")]
#[macro_export]
macro_rules! skip_unless_pcsc_key {
    () => {
        match $crate::required_role_key_set("SCLL_PCSC_KEY") {
            ::core::option::Option::Some(::core::result::Result::Ok(keys)) => keys,
            ::core::option::Option::Some(::core::result::Result::Err(e)) => {
                std::panic!("SCLL_PCSC_KEY_ENC/_MAC/_DEK invalid: {}", e)
            }
            ::core::option::Option::None => {
                std::eprintln!(
                    "SKIP {}: the key-requiring PC/SC test was NOT run — set all three of \
                     SCLL_PCSC_KEY_ENC, SCLL_PCSC_KEY_MAC and SCLL_PCSC_KEY_DEK \
                     (32/48/64 hex each, same length) to run it",
                    module_path!()
                );
                return;
            }
        }
    };
}

/// Resolve the jcsim ENC/MAC/DEK key set or skip the current `#[test]`.
///
/// The jcsim analogue of [`skip_unless_pcsc_key!`]. Expands to a [`KeySet`] when
/// all three of `SCLL_JCSIM_KEY_ENC`, `SCLL_JCSIM_KEY_MAC` and
/// `SCLL_JCSIM_KEY_DEK` are set and non-empty (the caller imports
/// `&keys[i][..len]` and picks the key type from `len` and the negotiated SCP).
/// When none of the three is set the calling test is **not run** — a one-line
/// notice is printed and the test `return`s. A misconfiguration — only some of
/// the three set, a value not 32/48/64 hex, or the three differing in length —
/// panics. (There is no `SCLL_JCSIM_KEY` base variable and no default key: the
/// simulator's GP default keys must be passed explicitly when that is what the
/// card holds, e.g. `404142434445464748494A4B4C4D4E4F` for each role.)
#[cfg(feature = "std")]
#[macro_export]
macro_rules! skip_unless_jcsim_key {
    () => {
        match $crate::required_role_key_set("SCLL_JCSIM_KEY") {
            ::core::option::Option::Some(::core::result::Result::Ok(keys)) => keys,
            ::core::option::Option::Some(::core::result::Result::Err(e)) => {
                std::panic!("SCLL_JCSIM_KEY_ENC/_MAC/_DEK invalid: {}", e)
            }
            ::core::option::Option::None => {
                std::eprintln!(
                    "SKIP {}: the key-requiring jcsim test was NOT run — set all three of \
                     SCLL_JCSIM_KEY_ENC, SCLL_JCSIM_KEY_MAC and SCLL_JCSIM_KEY_DEK \
                     (32/48/64 hex each, same length) to run it",
                    module_path!()
                );
                return;
            }
        }
    };
}

/// Wrapper that gives any byte buffer an uppercase, two-digit-per-byte hex
/// `Debug` representation (e.g. `[6F, 61, 84]`).
///
/// `T` is anything that borrows as `&[u8]` — `&[u8]`, `[u8; N]`, `&[u8; N]`,
/// `heapless::Vec<u8, N>`, `alloc::vec::Vec<u8>`, and so on — so the two sides
/// of an assertion may even have different concrete types.
///
/// ```
/// use scll_test_util::HexSlice;
///
/// let resp = [0x6Fu8, 0x61, 0x84];
/// let expected: &[u8] = &[0x6F, 0x61, 0x84];
/// assert_eq!(HexSlice(&resp), HexSlice(expected));
/// ```
pub struct HexSlice<T>(pub T);

impl<T: AsRef<[u8]>> fmt::Debug for HexSlice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X?}", self.0.as_ref())
    }
}

impl<A: AsRef<[u8]>, B: AsRef<[u8]>> PartialEq<HexSlice<B>> for HexSlice<A> {
    fn eq(&self, other: &HexSlice<B>) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_key_hex;

    #[test]
    fn parse_key_hex_decodes_16_byte_default_gp_key() {
        // GlobalPlatform default static test key (GPCS v2.3.1 §11 examples).
        let (k, len) = parse_key_hex("404142434445464748494A4B4C4D4E4F").unwrap();
        assert_eq!(len, 16);
        assert_eq!(
            &k[..len],
            &[
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                0x4E, 0x4F
            ]
        );
    }

    #[test]
    fn parse_key_hex_decodes_24_and_32_byte_keys() {
        let (k24, l24) = parse_key_hex(&"AB".repeat(24)).unwrap();
        assert_eq!(l24, 24);
        assert!(k24[..24].iter().all(|&b| b == 0xAB));
        assert_eq!(&k24[24..], &[0u8; 8]); // tail stays zero

        let (k32, l32) = parse_key_hex(&"CD".repeat(32)).unwrap();
        assert_eq!(l32, 32);
        assert!(k32.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn parse_key_hex_is_case_insensitive() {
        assert_eq!(
            parse_key_hex("404142434445464748494a4b4c4d4e4f").unwrap(),
            parse_key_hex("404142434445464748494A4B4C4D4E4F").unwrap()
        );
    }

    #[test]
    fn parse_key_hex_rejects_bad_length() {
        assert!(parse_key_hex("").is_err());
        assert!(parse_key_hex("40").is_err());
        assert!(parse_key_hex(&"AB".repeat(20)).is_err()); // 40 hex / 20 bytes
        assert!(parse_key_hex(&"AB".repeat(28)).is_err()); // 56 hex / 28 bytes
        assert!(parse_key_hex(&"AB".repeat(33)).is_err()); // 66 hex / 33 bytes
    }

    #[test]
    fn parse_key_hex_rejects_non_hex() {
        // 32 chars, but contains a non-hex digit.
        assert!(parse_key_hex("Z04142434445464748494A4B4C4D4E4F").is_err());
    }

    #[test]
    fn decode_key_set_accepts_distinct_keys() {
        use super::decode_key_set;
        let enc = "00".repeat(16);
        let mac = "11".repeat(16);
        let dek = "22".repeat(16);
        let ([ke, km, kd], len) = decode_key_set(&enc, &mac, &dek).unwrap();
        assert_eq!(len, 16);
        assert!(ke[..16].iter().all(|&b| b == 0x00));
        assert!(km[..16].iter().all(|&b| b == 0x11));
        assert!(kd[..16].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn decode_key_set_rejects_mixed_lengths() {
        use super::decode_key_set;
        // ENC 16 bytes, MAC 24 bytes → rejected.
        assert!(decode_key_set(&"AB".repeat(16), &"AB".repeat(24), &"AB".repeat(16)).is_err());
    }
}
