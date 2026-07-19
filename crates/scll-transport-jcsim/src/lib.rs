//! # scll-transport-jcsim
//!
//! TCP [`Transport`] adapter (PDD §3.1/§3.2) that speaks the
//! `javacard-simulator-apdu-bridge` wire protocol rather than connecting to
//! the Oracle Java Card simulator directly. The bridge exposes a minimal
//! length-prefixed APDU service: every frame is a 4-byte big-endian length
//! followed by the raw APDU bytes, identical in both directions, with a hard
//! 65535-byte payload ceiling (bridge `docs/protocol.md`, `FrameIo.java`).
//!
//! The bridge has no card-reset and no ATR channel, and accepts a single
//! client at a time (`TcpApduServer.java`). Consequences for this adapter:
//! * [`JcSimTransport::reset`] cannot reset the simulated card or read a real
//!   ATR; it drops and re-opens the TCP connection and returns a synthetic
//!   empty ATR tagged [`TransportProtocol::T1`].
//! * [`JcSimTransport::capabilities`] reports `T1`, contact, and **no**
//!   transparent T=0 GET RESPONSE handling — the bridge forwards exactly one
//!   APDU per frame and the simulator link is T=1.
//!
//! `std` host crate: the R-APDU is copied into a bounded
//! `heapless::Vec<u8, RAPDU_MAX>`; an over-length response is reported as
//! [`TransportError::ProtocolError`] rather than truncated.

#![forbid(unsafe_code)]

use core::fmt::{Debug, Write as _};
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};

use heapless::Vec;

use scll_core::limits::{OTHER_DETAIL_MAX, RAPDU_MAX};
use scll_core::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};

/// Default bridge endpoint (`127.0.0.1:10000`, the bridge's default listen port).
pub const DEFAULT_ADDR: &str = "127.0.0.1:10000";

/// Default per-APDU read/write timeout, applied to the socket on connect.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bridge frame payload ceiling (`FrameIo.MAX_FRAME_SIZE`).
const MAX_FRAME: usize = 65_535;

/// TCP [`Transport`] to the javacard-simulator-apdu-bridge.
pub struct JcSimTransport {
    stream: TcpStream,
    addr: SocketAddr,
    timeout: Duration,
    connected: bool,
}

impl JcSimTransport {
    /// Connect to the bridge at `addr` (e.g. [`DEFAULT_ADDR`]) using
    /// [`DEFAULT_TIMEOUT`] for the per-APDU read/write timeout.
    ///
    /// # Errors
    /// [`TransportError`] if `addr` cannot be resolved or the TCP connection
    /// cannot be established.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        Self::connect_with_timeout(addr, DEFAULT_TIMEOUT)
    }

    /// Connect to the bridge at `addr` with a caller-chosen per-APDU
    /// read/write `timeout`.
    ///
    /// # Errors
    /// [`TransportError`] if `addr` cannot be resolved or the TCP connection
    /// cannot be established.
    pub fn connect_with_timeout(addr: &str, timeout: Duration) -> Result<Self, TransportError> {
        let sa = addr
            .to_socket_addrs()
            .map_err(|e| other(&e))?
            .next()
            .ok_or_else(|| {
                let mut s = heapless::String::<OTHER_DETAIL_MAX>::new();
                let _ = write!(s, "unresolved address: {addr}");
                TransportError::Other(s)
            })?;
        let stream = open(&sa, timeout)?;
        Ok(Self {
            stream,
            addr: sa,
            timeout,
            connected: true,
        })
    }

    /// Map an I/O error and mark the transport disconnected.
    fn fail(&mut self, e: &io::Error) -> TransportError {
        self.connected = false;
        map_io_err(e)
    }
}

impl Transport for JcSimTransport {
    fn transmit(&mut self, capdu: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> {
        // The trait contract is one short C-APDU; refuse anything the bridge
        // could not frame rather than silently corrupting the stream.
        let len = u32::try_from(capdu.len())
            .ok()
            .filter(|&n| (n as usize) <= MAX_FRAME)
            .ok_or(TransportError::ProtocolError)?;

        // Request frame: 4-byte BE length + APDU.
        self.stream
            .write_all(&len.to_be_bytes())
            .and_then(|()| self.stream.write_all(capdu))
            .and_then(|()| self.stream.flush())
            .map_err(|e| self.fail(&e))?;

        // Response frame: 4-byte BE length, then that many APDU bytes.
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| self.fail(&e))?;
        let rlen = u32::from_be_bytes(len_buf) as usize;
        if rlen > RAPDU_MAX {
            // A short-APDU response can never exceed RAPDU_MAX; refuse rather
            // than truncate (matches the pcsc adapter contract).
            return Err(TransportError::ProtocolError);
        }

        let mut scratch = [0u8; RAPDU_MAX];
        self.stream
            .read_exact(&mut scratch[..rlen])
            .map_err(|e| self.fail(&e))?;

        let mut out = Vec::new();
        out.extend_from_slice(&scratch[..rlen])
            .map_err(|()| TransportError::ProtocolError)?;
        Ok(out)
    }

    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            // The bridge forwards exactly one APDU per frame and does NOT chain
            // T=0 GET RESPONSE; the simulator link is T=1.
            handles_t0_get_response: false,
            protocol: TransportProtocol::T1,
            contactless: false,
        }
    }

    fn reset(&mut self) -> Result<AtrAts, TransportError> {
        // The bridge exposes neither a card reset nor an ATR (docs/protocol.md).
        // The closest available action is to drop and re-open the single-client
        // TCP connection. Shut the old socket first so the bridge frees its slot
        // before we reconnect (TcpApduServer rejects a second live client).
        let _ = self.stream.shutdown(Shutdown::Both);
        self.connected = false;
        self.stream = open(&self.addr, self.timeout)?;
        self.connected = true;
        Ok(AtrAts {
            bytes: Vec::new(),
            protocol: TransportProtocol::T1,
        })
    }

    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::T1
    }

    fn is_connected(&self) -> bool {
        self.connected && self.stream.peer_addr().is_ok()
    }
}

/// Open a TCP stream to `sa` and apply the per-APDU read/write timeouts.
fn open(sa: &SocketAddr, timeout: Duration) -> Result<TcpStream, TransportError> {
    let stream = TcpStream::connect_timeout(sa, timeout).map_err(|e| map_io_err(&e))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| other(&e))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| other(&e))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Map an [`io::Error`] to the transport failure taxonomy (§3.2). The bridge is
/// the whole reader/card stack, so a dropped connection is `ReaderGone`.
fn map_io_err(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TransportError::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected => TransportError::ReaderGone,
        _ => other(e),
    }
}

/// Build a `TransportError::Other` with a bounded debug rendering.
fn other(e: &dyn Debug) -> TransportError {
    let mut s = heapless::String::<OTHER_DETAIL_MAX>::new();
    let _ = write!(s, "{e:?}");
    TransportError::Other(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scll_test_util::{skip_unless_jcsim, HexSlice};
    use std::net::TcpListener;
    use std::thread;

    fn read_frame(s: &mut TcpStream) -> std::vec::Vec<u8> {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let n = u32::from_be_bytes(len) as usize;
        let mut body = std::vec![0u8; n];
        s.read_exact(&mut body).unwrap();
        body
    }

    fn write_frame(s: &mut TcpStream, data: &[u8]) {
        let len = u32::try_from(data.len()).unwrap();
        s.write_all(&len.to_be_bytes()).unwrap();
        s.write_all(data).unwrap();
        s.flush().unwrap();
    }

    #[test]
    fn connect_selects_isd() {
        // Integration: auto-runs when SCLL_JCSIM_ADDR points at a running
        // javacard-simulator-apdu-bridge, otherwise skips (keeps the workspace
        // suite green without a bridge). See `skip_unless_jcsim!`.
        let addr = skip_unless_jcsim!();
        let capdu = [0x00u8, 0xA4, 0x04, 0x00, 0x00];
        let rapdu = [
            0x6Fu8, 0x61, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x55,
            0x73, 0x4B, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, 0x0B, 0x06,
            0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x02, 0x63, 0x09, 0x06, 0x07,
            0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
            0x86, 0xFC, 0x6B, 0x04, 0x03, 0x70, 0x65, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86,
            0xFC, 0x6B, 0x05, 0x07, 0x02, 0x01, 0x00, 0x66, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01,
            0x04, 0x01, 0x2A, 0x02, 0x6E, 0x01, 0x03, 0x9F, 0x6E, 0x01, 0x01, 0x9F, 0x65, 0x01,
            0xFE, 0x90, 0x00,
        ];

        let mut t = JcSimTransport::connect(&addr).unwrap();

        let caps = t.capabilities();
        assert!(!caps.handles_t0_get_response);
        assert_eq!(caps.protocol, TransportProtocol::T1);
        assert!(!caps.contactless);

        let resp = t.transmit(&capdu).unwrap();
        assert_eq!(HexSlice(resp.as_slice()), HexSlice(&rapdu));
    }

    #[test]
    fn transmit_round_trips_a_framed_apdu() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let capdu = [0x00u8, 0xA4, 0x04, 0x00, 0x00];
        let rapdu = [0x6Fu8, 0x00, 0x90, 0x00];

        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let got = read_frame(&mut s);
            assert_eq!(got, capdu);

            write_frame(&mut s, &rapdu);
        });

        let mut t = JcSimTransport::connect(&addr.to_string()).unwrap();

        let caps = t.capabilities();
        assert!(!caps.handles_t0_get_response);
        assert_eq!(caps.protocol, TransportProtocol::T1);
        assert!(!caps.contactless);

        let resp = t.transmit(&capdu).unwrap();
        assert_eq!(resp.as_slice(), &rapdu);
        srv.join().unwrap();
    }

    #[test]
    fn oversized_response_is_protocol_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_frame(&mut s);
            // Claim RAPDU_MAX + 1 bytes; the adapter must refuse before reading.
            let len = u32::try_from(RAPDU_MAX + 1).unwrap();
            s.write_all(&len.to_be_bytes()).unwrap();
            s.flush().unwrap();
        });

        let mut t = JcSimTransport::connect(&addr.to_string()).unwrap();
        let err = t.transmit(&[0x00, 0xCA, 0x00, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, TransportError::ProtocolError));
        srv.join().unwrap();
    }

    #[test]
    fn reset_reconnects_and_reports_t1() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = thread::spawn(move || {
            // Accept the initial connection, then the reset's reconnection.
            let (s1, _) = listener.accept().unwrap();
            let (s2, _) = listener.accept().unwrap();
            // Keep both alive until the test has observed the reconnect.
            thread::sleep(Duration::from_millis(50));
            drop((s1, s2));
        });

        let mut t = JcSimTransport::connect(&addr.to_string()).unwrap();
        let atr = t.reset().unwrap();
        assert!(atr.bytes.is_empty());
        assert_eq!(atr.protocol, TransportProtocol::T1);
        assert_eq!(t.protocol(), TransportProtocol::T1);
        srv.join().unwrap();
    }
}
