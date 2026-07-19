//! # scll-transport-pcsc
//!
//! PC/SC [`Transport`] adapter (Linux/host production, PDD §3.1/§3.2). Wraps the
//! [`pcsc`] crate; reader enumeration is this crate's concern. A `std` host
//! crate — not part of an embedded build — but it produces the bounded
//! `heapless` return types of the converted [`Transport`] trait (the R-APDU is
//! copied into `heapless::Vec<u8, RAPDU_MAX>`).
//!
//! ## Connection policy (locked decisions)
//! * **Reader selection.** [`PcscTransport::connect_first`] connects to the
//!   first reader that has a card present (skipping readers that report
//!   [`pcsc::Error::NoSmartcard`]); [`PcscTransport::connect`] takes an exact
//!   reader name.
//! * **Connect parameters.** [`ShareMode::Shared`] + [`Protocols::ANY`] — the
//!   resource manager negotiates `T=0`/`T=1`, and `Shared` cooperates with
//!   other PC/SC clients (e.g. `pcscd`, a PKCS#11 module). Each `transmit` is
//!   wrapped in an `SCardBeginTransaction`/`SCardEndTransaction` pair (via
//!   [`pcsc::Card::transaction`]) so a single exchange is not interleaved.
//! * **`reset`.** Warm reset via `SCardReconnect` with
//!   [`Disposition::ResetCard`], then the fresh ATR + negotiated protocol are
//!   read back with `SCardStatus` ([`pcsc::Card::status2_owned`]).
//! * **`capabilities`.** `handles_t0_get_response = true`: under PC/SC the
//!   reader driver (IFD handler) performs the `T=0`/`T=1` protocol-specific
//!   TPDU exchange, including the `T=0` `GET RESPONSE` chaining. `protocol` is
//!   the live negotiated value from the last connect/reset (not a hardcode);
//!   `contactless` is derived from it (always `false` in practice — PC/SC
//!   surfaces contactless cards as `T=1`, so [`TransportProtocol::TCl`] does not
//!   arise on this path).
//!
//! ## Caveats
//! * **Per-APDU timeout is unenforced.** `SCardTransmit` (via
//!   [`pcsc::Card::transmit`]) has no per-call timeout and blocks until the
//!   reader/driver returns; this adapter relies on PC/SC's own blocking
//!   behaviour rather than spawning a watchdog thread (keeps the crate
//!   `#![forbid(unsafe_code)]` and thread-free).
//! * **The transaction is per-APDU.** It guards a single C-APDU/R-APDU pair, not
//!   a multi-command sequence; the [`Transport`] trait exposes one APDU at a
//!   time, so a secure-channel handshake spanning several APDUs is not held
//!   under one transaction. In practice the library is the sole card user during
//!   provisioning.
//! * **An over-length response** (PC/SC `InsufficientBuffer`, i.e. a reply that
//!   does not fit `RAPDU_MAX`) is reported as [`TransportError::ProtocolError`]
//!   rather than truncated.

#![forbid(unsafe_code)]

use core::fmt::Write as _;
use std::ffi::CString;

use heapless::Vec;

use pcsc::{Context, Disposition, Protocols, Scope, ShareMode};

use scll_core::limits::{OTHER_DETAIL_MAX, RAPDU_MAX};
use scll_core::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};

/// PC/SC-backed transport.
///
/// Holds an open [`pcsc::Card`] and the protocol negotiated at connect/reset.
/// The [`pcsc::Card`] keeps its own reference-counted PC/SC context alive, so
/// the originating [`Context`] need not be stored.
pub struct PcscTransport {
    card: pcsc::Card,
    protocol: TransportProtocol,
}

impl PcscTransport {
    /// Connect to the first reader that has a card present (reader enumeration
    /// is the transport's responsibility, §3.2).
    ///
    /// Readers are tried in PC/SC enumeration order; a reader reporting
    /// [`pcsc::Error::NoSmartcard`] is skipped. Uses [`ShareMode::Shared`] +
    /// [`Protocols::ANY`].
    ///
    /// # Errors
    /// [`TransportError`] if the PC/SC context cannot be established, the reader
    /// list cannot be read, a non-`NoSmartcard` connect error occurs, or no
    /// reader currently has a card present.
    pub fn connect_first() -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(map_pcsc_err)?;
        let readers = ctx.list_readers_owned().map_err(map_pcsc_err)?;
        for reader in readers {
            match ctx.connect(&reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => return Self::from_card(card),
                // No card in this reader — try the next one.
                Err(pcsc::Error::NoSmartcard) => {}
                Err(e) => return Err(map_pcsc_err(e)),
            }
        }
        Err(other_msg("no PC/SC reader with a card present"))
    }

    /// Connect to a named reader (exact match) using [`ShareMode::Shared`] +
    /// [`Protocols::ANY`].
    ///
    /// # Errors
    /// [`TransportError`] if the PC/SC context cannot be established, the name
    /// contains an interior NUL byte, or the reader cannot be opened (e.g. no
    /// card present, unknown reader name).
    pub fn connect(reader_name: &str) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(map_pcsc_err)?;
        let name = CString::new(reader_name)
            .map_err(|_| other_msg("reader name contains an interior NUL byte"))?;
        let card = ctx
            .connect(&name, ShareMode::Shared, Protocols::ANY)
            .map_err(map_pcsc_err)?;
        Self::from_card(card)
    }

    /// Connect to a reader chosen by a selector string of the form
    /// `<name-substring>[@<index>]` — the form the smoke tests read from the
    /// `SCLL_PCSC` environment variable (§3.2).
    ///
    /// * The reader whose PC/SC name *contains* `<name-substring>` is used; an
    ///   empty substring matches every reader.
    /// * An optional trailing `@<index>` (0-based) disambiguates when several
    ///   readers match. PC/SC has no separate slot argument — it encodes the
    ///   slot in the reader-name string — so this index, applied over the
    ///   substring-matched readers in enumeration order, is how a host with
    ///   multiple readers/slots is addressed. `@<index>` is recognised only
    ///   when the text after the last `@` is a non-empty run of ASCII digits
    ///   that parses as a [`usize`]; otherwise the whole string (including any
    ///   `@`) is the name and the first match is used.
    ///
    /// Uses [`ShareMode::Shared`] + [`Protocols::ANY`], like the other
    /// constructors.
    ///
    /// # Errors
    /// [`TransportError`] if the PC/SC context cannot be established, the reader
    /// list cannot be read, no reader matches the selector (or the index is out
    /// of range), or the chosen reader cannot be opened (e.g. no card present).
    pub fn connect_selector(spec: &str) -> Result<Self, TransportError> {
        let (substr, index) = parse_selector(spec);
        let ctx = Context::establish(Scope::User).map_err(map_pcsc_err)?;
        let readers = ctx.list_readers_owned().map_err(map_pcsc_err)?;
        let chosen = readers
            .iter()
            .filter(|r| r.to_string_lossy().contains(substr))
            .nth(index.unwrap_or(0))
            .ok_or_else(|| other_msg("no PC/SC reader matched SCLL_PCSC selector"))?;
        let card = ctx
            .connect(chosen, ShareMode::Shared, Protocols::ANY)
            .map_err(map_pcsc_err)?;
        Self::from_card(card)
    }

    /// Build a transport from an open card, recording the negotiated protocol.
    fn from_card(card: pcsc::Card) -> Result<Self, TransportError> {
        let status = card.status2_owned().map_err(map_pcsc_err)?;
        let protocol = map_protocol(status.protocol2());
        Ok(Self { card, protocol })
    }
}

impl Transport for PcscTransport {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> {
        // PC/SC writes the R-APDU into a caller buffer; copy it into the bounded
        // heapless return. A response longer than RAPDU_MAX must not occur for
        // short APDUs; PC/SC signals it as InsufficientBuffer, which maps to
        // ProtocolError (never truncated).
        let mut scratch = [0u8; RAPDU_MAX];
        let mut out = Vec::new();
        {
            // Wrap the single exchange in an SCardBeginTransaction /
            // SCardEndTransaction pair; the Transaction's Drop ends it with
            // Disposition::LeaveCard (no reset between APDUs).
            let tx = self.card.transaction().map_err(map_pcsc_err)?;
            let resp = tx.transmit(capdu, &mut scratch).map_err(map_pcsc_err)?;
            out.extend_from_slice(resp)
                .map_err(|()| TransportError::ProtocolError)?;
        }
        Ok(out)
    }

    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            // The PC/SC reader driver (IFD handler) performs the protocol-specific
            // T=0/T=1 TPDU exchange, including T=0 GET RESPONSE chaining.
            handles_t0_get_response: true,
            protocol: self.protocol,
            // PC/SC surfaces contactless cards as T=1, so this is effectively
            // always false; kept as a derivation for the rare TCl mapping.
            contactless: matches!(self.protocol, TransportProtocol::TCl),
        }
    }

    fn reset(&mut self) -> Result<AtrAts, TransportError> {
        // Warm reset: SCardReconnect(RESET), then read the fresh ATR + negotiated
        // protocol back via SCardStatus.
        self.card
            .reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .map_err(map_pcsc_err)?;
        let status = self.card.status2_owned().map_err(map_pcsc_err)?;
        let protocol = map_protocol(status.protocol2());
        self.protocol = protocol;
        let mut bytes = Vec::new();
        bytes
            .extend_from_slice(status.atr())
            .map_err(|()| TransportError::ProtocolError)?;
        Ok(AtrAts { bytes, protocol })
    }

    fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    fn is_connected(&self) -> bool {
        // SCardStatus liveness query (sends no APDU). A transient state such as a
        // card reset still leaves the handle usable, so only a definitive
        // card/reader-gone result is reported as not-connected (an actually dead
        // card then fails at the next transmit, where it is handled).
        match self.card.status2_owned() {
            Ok(_) => true,
            Err(e) => !matches!(
                map_pcsc_err(e),
                TransportError::CardRemoved | TransportError::ReaderGone
            ),
        }
    }
}

/// Map a [`pcsc::Protocol`] (the negotiated card protocol from `SCardStatus`)
/// to the library's [`TransportProtocol`].
///
/// Only `T0` is mapped explicitly; `T1`, `RAW`, `T15`, an unrecognised value, or
/// a direct (protocol-less) connection all map to `T1`. PC/SC reports
/// contactless cards as `T=1`, so [`TransportProtocol::TCl`] is never produced
/// here.
fn map_protocol(protocol: Option<pcsc::Protocol>) -> TransportProtocol {
    match protocol {
        Some(pcsc::Protocol::T0) => TransportProtocol::T0,
        _ => TransportProtocol::T1,
    }
}

/// Map a [`pcsc::Error`] to the transport failure taxonomy (§3.2). Variants not
/// matched fall through to `Other` with a debug rendering.
fn map_pcsc_err(e: pcsc::Error) -> TransportError {
    match e {
        pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard => TransportError::CardRemoved,
        pcsc::Error::ReaderUnavailable | pcsc::Error::NoService | pcsc::Error::ServiceStopped => {
            TransportError::ReaderGone
        }
        pcsc::Error::Timeout => TransportError::Timeout,
        // Response did not fit the bounded receive buffer (over-length R-APDU).
        pcsc::Error::InsufficientBuffer => TransportError::ProtocolError,
        other => {
            let mut s = heapless::String::<OTHER_DETAIL_MAX>::new();
            let _ = write!(s, "{other:?}");
            TransportError::Other(s)
        }
    }
}

/// Build a `TransportError::Other` from a short message (dropped if it would
/// overflow `OTHER_DETAIL_MAX`; all call sites here are well under the cap).
fn other_msg(msg: &str) -> TransportError {
    let mut s = heapless::String::<OTHER_DETAIL_MAX>::new();
    let _ = s.push_str(msg);
    TransportError::Other(s)
}

/// Split a `SCLL_PCSC` selector into `(name-substring, optional 0-based index)`.
///
/// A trailing `@<index>` is recognised only when the run after the **last**
/// `@` is non-empty, all ASCII digits, and parses as a [`usize`]; otherwise the
/// whole input (including any `@`) is the name and the index is `None`. This
/// makes a reader literally named `…@2`, an empty index (`name@`), or an
/// out-of-range/overflowing index degrade to a plain name match rather than
/// mis-parsing.
fn parse_selector(spec: &str) -> (&str, Option<usize>) {
    if let Some(at) = spec.rfind('@') {
        let suffix = &spec[at + 1..];
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(idx) = suffix.parse::<usize>() {
                return (&spec[..at], Some(idx));
            }
        }
    }
    (spec, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::HexSlice;

    // Hardware smoke test: requires a PC/SC reader with a card present. Sends a
    // SELECT for the ISD (AID A000000003000000) and checks a 2-byte SW trails.
    #[test]
    #[ignore = "hardware: requires a PC/SC reader with a card present"]
    fn connect_selects_isd() {
        let capdu = [0x00u8, 0xA4, 0x04, 0x00, 0x00];
        let rapdu = [
            0x6Fu8, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x04,
            0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00,
        ];
        let mut t = PcscTransport::connect_first().unwrap();

        let caps = t.capabilities();
        assert!(caps.handles_t0_get_response);

        let atr = t.reset().unwrap();
        assert!(!atr.bytes.is_empty());

        let resp = t.transmit(&capdu).unwrap();
        assert!(resp.len() >= 2);
        assert!(t.is_connected());
        assert_eq!(HexSlice(resp.as_slice()), HexSlice(&rapdu));
    }

    #[test]
    fn maps_pcsc_errors_to_taxonomy() {
        let m = map_pcsc_err;
        assert!(matches!(
            m(pcsc::Error::RemovedCard),
            TransportError::CardRemoved
        ));
        assert!(matches!(
            m(pcsc::Error::NoSmartcard),
            TransportError::CardRemoved
        ));
        assert!(matches!(
            m(pcsc::Error::ReaderUnavailable),
            TransportError::ReaderGone
        ));
        assert!(matches!(
            m(pcsc::Error::NoService),
            TransportError::ReaderGone
        ));
        assert!(matches!(
            m(pcsc::Error::ServiceStopped),
            TransportError::ReaderGone
        ));
        assert!(matches!(m(pcsc::Error::Timeout), TransportError::Timeout));
        assert!(matches!(
            m(pcsc::Error::InsufficientBuffer),
            TransportError::ProtocolError
        ));
        // Anything else → Other(detail).
        assert!(matches!(
            m(pcsc::Error::UnknownReader),
            TransportError::Other(_)
        ));
    }

    #[test]
    fn maps_negotiated_protocol() {
        assert_eq!(
            map_protocol(Some(pcsc::Protocol::T0)),
            TransportProtocol::T0
        );
        assert_eq!(
            map_protocol(Some(pcsc::Protocol::T1)),
            TransportProtocol::T1
        );
        // Direct / protocol-less connection defaults to T1.
        assert_eq!(map_protocol(None), TransportProtocol::T1);
    }

    #[test]
    fn parse_selector_cases() {
        // Plain name, no index.
        assert_eq!(parse_selector("Identiv"), ("Identiv", None));
        // Name + 0-based index ("slot").
        assert_eq!(parse_selector("Identiv@0"), ("Identiv", Some(0)));
        assert_eq!(parse_selector("Identiv@1"), ("Identiv", Some(1)));
        assert_eq!(parse_selector("name@00"), ("name", Some(0)));
        // Empty name + index => match any reader, pick the index-th.
        assert_eq!(parse_selector("@2"), ("", Some(2)));
        // A full PC/SC reader name (which itself ends in the slot digits) has
        // no `@`, so it is taken verbatim.
        let full = "Identiv uTrust 3700 F CL Reader [CCID Interface] 00 00";
        assert_eq!(parse_selector(full), (full, None));
        // `@` whose suffix is not all-digits is part of the name.
        assert_eq!(parse_selector("Reader@Home 3"), ("Reader@Home 3", None));
        // Only the LAST `@<digits>` is the index.
        assert_eq!(parse_selector("Reader@Home@1"), ("Reader@Home", Some(1)));
        // Empty suffix is not an index.
        assert_eq!(parse_selector("weird@"), ("weird@", None));
        // An index that overflows `usize` degrades to a plain name match.
        let huge = "name@999999999999999999999999999999";
        assert_eq!(parse_selector(huge), (huge, None));
    }

    #[test]
    fn other_msg_is_bounded() {
        let long = "x".repeat(OTHER_DETAIL_MAX * 2);
        let TransportError::Other(s) = other_msg(&long) else {
            panic!("expected Other");
        };
        assert!(s.len() <= OTHER_DETAIL_MAX);
    }
}
