//! Shared plumbing for the scll example binaries (`src/bin/*.rs`), using the
//! **default RustCrypto backend** and either the **PC/SC** or **jcsim**
//! transport. Each binary demonstrates one slice of the `CardManager` API:
//!
//! * `card-info`      — transport probe, discover, card status, inventory.
//! * `ssd-lifecycle`  — SSD create → personalize → load/install applet →
//!   keyset rotation → applet APDUs → teardown.
//! * `isd-lifecycle`  — the same applet + keyset-rotation lifecycle run
//!   directly on the **ISD** (no SSD), including keyset removal.
//!
//! Target applet: `ievkh/javacard-scp03-cooperative-applet` (delegates SCP to
//! its associated Security Domain; the custom `HELLO` C-APDU is taken from that
//! repo's `scripts/20-send-hello.sh`).
//!
//! ## Transport selection
//! Set `SCLL_TRANSPORT=pcsc|jcsim` to choose explicitly, or just set the
//! connection variable for one transport and it is auto-selected:
//! * **PC/SC**  — `SCLL_PCSC` set ⇒ real reader.
//! * **jcsim**  — `SCLL_JCSIM_ADDR` set ⇒ Oracle Java Card simulator via the
//!   `javacard-simulator-apdu-bridge`.
//!
//! ## Environment (common to all binaries)
//! | Variable              | Meaning                                                        |
//! |-----------------------|----------------------------------------------------------------|
//! | `SCLL_TRANSPORT`      | optional: `pcsc` or `jcsim` (else inferred from the vars below) |
//! | `SCLL_PCSC`           | PC/SC reader-name substring, optional `@<index>`               |
//! | `SCLL_PCSC_KEY_ENC/_MAC/_DEK` | **ISD** keys for PC/SC, hex (16/24/32 bytes, equal length) |
//! | `SCLL_JCSIM_ADDR`     | jcsim bridge `host:port` (e.g. `127.0.0.1:10000`)              |
//! | `SCLL_JCSIM_KEY_ENC/_MAC/_DEK` | **ISD** keys for jcsim, hex (sim GP default: `4041…4F`)   |
//! | `SCLL_ISD_KVN`        | optional ISD keyset version for the management channel (default `0x00`) |
//! | `SCLL_KEEP`           | set to `1` to skip the teardown steps                          |
//! | `SCLL_APDU_TRACE`     | set to `1` to hex-dump every C-APDU/R-APDU on the PC/SC path to stderr |
//!
//! The lifecycle binaries additionally read `SCLL_CAP` (path to the applet CAP
//! file, required), `SCLL_APPLET_AID` (optional instance-AID override) and —
//! for the SSD binary only — `SCLL_SSD_AID`.
//!
//! The `SCLL_*_KEY_*` values are the **ISD** keys that open the management
//! channel. The two demo keysets written by the lifecycle binaries (to the SSD
//! or to the ISD, KVN `0x30`/`0x31`) are the predefined constants below.

use std::process::ExitCode;

use rand_core::OsRng;
use scll::backend::{KeyHandle, KeyKind};
use scll::backend_rustcrypto::RustCryptoBackend;
use scll::cap::{self, InflateCtx};
use scll::error::{ScllError, Warning};
use scll::limits::RAPDU_MAX;
use scll::model::ScpVariant;
use scll::report::{OpenScpParams, ScpTargetKind};
use scll::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};
use scll::transport_jcsim::JcSimTransport;
use scll::transport_pcsc::PcscTransport;
use scll::workflow::{NewKeyset, OpenScpArgs, SdKeys};
use scll::CardManager;

/// The crypto backend is fixed (default RustCrypto + OS CSPRNG); the transport
/// varies, so the lifecycles are generic over `T: Transport`.
pub type Be = RustCryptoBackend<OsRng>;

// ─── Predefined constants ────────────────────────────────────────────────────

/// Custom HELLO C-APDU (CLA=80 INS=F0 P1=00 P2=00 Lc=05 "Hello").
/// Source: javacard-scp03-cooperative-applet/scripts/20-send-hello.sh.
pub const HELLO_CAPDU: &[u8] = &[0x80, 0xF0, 0x00, 0x00, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F];

/// First demo keyset **version for the SSD demo** (`ssd-lifecycle`); the key
/// byte constants below are shared by both lifecycle demos. 16-byte keys ⇒
/// AES-128 (SCP03) or 3DES-2key (SCP02).
pub const KVN_1: u8 = 0x30;
/// Keyset-1 ENC key bytes.
pub const KS1_ENC: &[u8] = &[0x40; 16];
/// Keyset-1 MAC key bytes.
pub const KS1_MAC: &[u8] = &[0x41; 16];
/// Keyset-1 DEK key bytes.
pub const KS1_DEK: &[u8] = &[0x42; 16];

/// Second demo keyset **version for the SSD demo** (the rotation target).
pub const KVN_2: u8 = 0x31;

/// Demo keyset versions for the **ISD demo** (`isd-lifecycle`). Deliberately
/// NOT 0x30/0x31: unlike a freshly created SSD, the ISD already carries the
/// card's own keyset(s), and on the Oracle JCDK simulator the ISD default
/// keyset version **is 0x30** (KIT `'C0'{01 30 88 10}…`, confirmed by
/// INITIALIZE UPDATE) — reusing it would collide with, and can destroy, the
/// live management keyset. 0x32/0x33 avoid the versions seen on the available
/// targets; `isd-lifecycle` additionally guards at run time against whatever
/// versions the card actually reports/uses.
pub const ISD_KVN_1: u8 = 0x32;
/// Second ISD-demo keyset version (the rotation target). See [`ISD_KVN_1`].
pub const ISD_KVN_2: u8 = 0x33;

/// The plain-jcsim ISD factory key version — a LAST-RESORT candidate for
/// [`open_isd_original`] when nothing better is known. The factory KVN
/// varies per target: 0x30 on the plain jcsim, 0x03 on the JCOP-mocking
/// bridge, typically 0xFF on real cards — which is why the primary candidate
/// source is the Key Information Template reported at discovery.
pub const JCSIM_FACTORY_KVN: u8 = 0x30;
/// Keyset-2 ENC key bytes.
pub const KS2_ENC: &[u8] = &[0x50; 16];
/// Keyset-2 MAC key bytes.
pub const KS2_MAC: &[u8] = &[0x51; 16];
/// Keyset-2 DEK key bytes.
pub const KS2_DEK: &[u8] = &[0x52; 16];

// AES-256 variants of the demo keysets (same byte patterns, 32 bytes) for
// `isd-lifecycle`'s opt-in `SCLL_ISD_AES256=1` (SCP03 targets only, v0.9q).
/// Keyset-1 ENC key bytes, AES-256.
pub const KS1_ENC_256: &[u8] = &[0x40; 32];
/// Keyset-1 MAC key bytes, AES-256.
pub const KS1_MAC_256: &[u8] = &[0x41; 32];
/// Keyset-1 DEK key bytes, AES-256.
pub const KS1_DEK_256: &[u8] = &[0x42; 32];
/// Keyset-2 ENC key bytes, AES-256.
pub const KS2_ENC_256: &[u8] = &[0x50; 32];
/// Keyset-2 MAC key bytes, AES-256.
pub const KS2_MAC_256: &[u8] = &[0x51; 32];
/// Keyset-2 DEK key bytes, AES-256.
pub const KS2_DEK_256: &[u8] = &[0x52; 32];

// ─── Security levels ─────────────────────────────────────────────────────────

/// Which secure channel a demo is about to open; selects its security level
/// via [`security_level`]. The four roles exist because the two targets impose
/// different, empirically established ceilings (PDD §12) — the matrix:
///
/// | role         | jcsim  | PC/SC (JCOP 4 P71) |
/// |--------------|--------|--------------------|
/// | `Isd`        | `0x03` | `0x33`             |
/// | `IsdKeyOps`  | `0x03` | `0x03`             |
/// | `Ssd`        | `0x01` | `0x33`             |
/// | `SsdPutKey`  | `0x01` | `0x03`             |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// ISD management channel (status, inventory, load/install, object DELETE).
    Isd,
    /// ISD channel dedicated to PUT KEY / DELETE KEY (`isd-lifecycle`).
    IsdKeyOps,
    /// SSD-backed channels: SSD personalization and applet channels whose
    /// applet lives under the SSD (the cooperative applet delegates its SCP
    /// to its SD).
    Ssd,
    /// The direct SSD channel used specifically for PUT KEY.
    SsdPutKey,
}

/// Security level for `role` on `endpoint` — one function since patch #31
/// (formerly four near-identical helpers). Rationale per cell (evidence in
/// PDD §12; the library still caps any requested level to the card's `i`,
/// Amendment D §4.1 Table 4-2):
///
/// * **`Isd` on jcsim `0x03`** (C-MAC + C-DEC, no R-MAC/R-ENC): the sim does
///   not apply an R-MAC to the `63xx` GET STATUS "more data" warning (bare
///   `6310`), which a spec-correct client rejects — GET STATUS R-MAC is
///   mandatory for `9000`/`62xx`/`63xx` per Amendment D §6.2.5. Full `0x33`
///   on real hardware.
/// * **`Ssd` on jcsim `0x01`** (C-MAC only): the sim's SSD secure channel
///   mishandles C-DECRYPTION (PUT KEY with C-DEC tears down the inner card)
///   and applies no R-MAC/R-ENC despite advertising `i='70'`; its ISD path is
///   compliant. Matches gppro's SSD EXTERNAL AUTHENTICATE P1 = `0x01`. Full
///   `0x33` on real hardware.
/// * **`SsdPutKey` on PC/SC `0x03`** (R-MAC dropped): empirically isolated on
///   a live NXP JCOP 4 P71 SSD — PUT KEY over a direct SSD channel opened at
///   `0x13` returns `6982`; the byte-for-byte identical PUT KEY (confirmed
///   against a `GlobalPlatformPro -d` capture) succeeds at `0x03`. A
///   card-specific restriction, not a wire bug: GPCS v2.3.1 §10 Table 10-2
///   states only a *minimum* level per command
///   (<https://globalplatform.org/wp-content/uploads/2018/05/GPC_CardSpecification_v2.3.1_PublicRelease_CC.pdf>).
///   Scoped to the PUT KEY channel only — applet channels (`Ssd`) keep full
///   R-MAC on hardware. On jcsim it mirrors `Ssd` (`0x01`) rather than adding
///   a second sim code path.
/// * **`IsdKeyOps` `0x03` on both**: conservative mirror of the `SsdPutKey`
///   finding for ISD PUT/DELETE KEY (the `0x33` ISD variant is untested on
///   the P71); satisfies the §10 Table 10-2 minimum either way, and matches
///   the level the sim's ISD channel already uses.
///
/// Keyed off the transport the example itself selected, so it is
/// authoritative for "this run uses the jcsim bridge"; it would only
/// misclassify if that bridge were pointed at real hardware, which these
/// examples never do.
#[must_use]
pub fn security_level(endpoint: &Endpoint, role: ChannelRole) -> u8 {
    match (role, endpoint) {
        (ChannelRole::Isd, Endpoint::Jcsim(_)) => 0x03,
        (ChannelRole::Isd, Endpoint::Pcsc(_)) => 0x33,
        (ChannelRole::IsdKeyOps, _) => 0x03,
        (ChannelRole::Ssd, Endpoint::Jcsim(_)) => 0x01,
        (ChannelRole::Ssd, Endpoint::Pcsc(_)) => 0x33,
        (ChannelRole::SsdPutKey, Endpoint::Jcsim(_)) => 0x01,
        (ChannelRole::SsdPutKey, Endpoint::Pcsc(_)) => 0x03,
    }
}

// ─── Config (resolved up front; failures here are plain strings) ─────────────

/// Which transport + connection target was selected from the environment.
pub enum Endpoint {
    /// PC/SC reader selector (`SCLL_PCSC`).
    Pcsc(String),
    /// jcsim bridge address (`SCLL_JCSIM_ADDR`).
    Jcsim(String),
}

impl Endpoint {
    /// Human-readable "what we are connecting to" label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Endpoint::Pcsc(r) => format!("PC/SC reader {r:?}"),
            Endpoint::Jcsim(a) => format!("jcsim bridge {a}"),
        }
    }
    /// Env var prefix for this transport's ISD key roles.
    #[must_use]
    pub fn key_prefix(&self) -> &'static str {
        match self {
            Endpoint::Pcsc(_) => "SCLL_PCSC_KEY",
            Endpoint::Jcsim(_) => "SCLL_JCSIM_KEY",
        }
    }
}

/// Common configuration: transport endpoint + ISD management keys.
pub struct Config {
    /// Selected transport endpoint.
    pub endpoint: Endpoint,
    /// ISD static ENC key bytes.
    pub isd_enc: Vec<u8>,
    /// ISD static MAC key bytes.
    pub isd_mac: Vec<u8>,
    /// ISD static DEK key bytes.
    pub isd_dek: Vec<u8>,
    /// ISD keyset version used for the management channel (`SCLL_ISD_KVN`).
    pub isd_kvn: u8,
    /// `SCLL_KEEP=1` — skip teardown steps.
    pub keep: bool,
}

impl Config {
    /// Resolve the common configuration from the environment.
    ///
    /// # Errors
    /// A human-readable string when a required variable is missing or invalid.
    pub fn from_env() -> Result<Self, String> {
        let endpoint = select_endpoint()?;
        let prefix = endpoint.key_prefix();

        let isd_enc = from_hex(&env_req(&format!("{prefix}_ENC"))?)?;
        let isd_mac = from_hex(&env_req(&format!("{prefix}_MAC"))?)?;
        let isd_dek = from_hex(&env_req(&format!("{prefix}_DEK"))?)?;
        let len = isd_enc.len();
        if !(len == 16 || len == 24 || len == 32) {
            return Err(format!("ISD key length must be 16/24/32 bytes, got {len}"));
        }
        if isd_mac.len() != len || isd_dek.len() != len {
            return Err(format!("{prefix}_ENC/_MAC/_DEK must all be the same length"));
        }
        let isd_kvn = match env_opt("SCLL_ISD_KVN") {
            Some(s) => parse_u8(&s)?,
            None => 0x00,
        };
        let keep = env_opt("SCLL_KEEP").as_deref() == Some("1");

        Ok(Self {
            endpoint,
            isd_enc,
            isd_mac,
            isd_dek,
            isd_kvn,
            keep,
        })
    }

    /// Print the common configuration header.
    pub fn print(&self, title: &str) {
        println!("========================================");
        println!(" {title}");
        println!("========================================");
        println!("transport     : {}", self.endpoint.label());
        println!("ISD KVN       : 0x{:02X}", self.isd_kvn);
        println!("ISD key len   : {} bytes", self.isd_enc.len());
        println!(
            "teardown      : {}",
            if self.keep { "skipped (SCLL_KEEP=1)" } else { "yes" }
        );
    }
}

/// Applet-lifecycle configuration: the CAP file and the AIDs derived from it.
pub struct CapConfig {
    /// Raw CAP (zip) bytes read from `SCLL_CAP`.
    pub cap_bytes: Vec<u8>,
    /// ELF (package) AID, from the CAP.
    pub package_aid: Vec<u8>,
    /// Applet class (module) AID, from the CAP.
    pub module_aid: Vec<u8>,
    /// Applet instance AID: `SCLL_APPLET_AID` or the module AID.
    pub applet_aid: Vec<u8>,
}

impl CapConfig {
    /// Read `SCLL_CAP` (+ optional `SCLL_APPLET_AID`) and pull the package and
    /// module AIDs straight out of the CAP.
    ///
    /// # Errors
    /// A human-readable string when the CAP is missing or unparsable.
    pub fn from_env() -> Result<Self, String> {
        let cap_path = env_req("SCLL_CAP")?;
        let cap_bytes = std::fs::read(&cap_path)
            .map_err(|e| format!("cannot read SCLL_CAP ({cap_path}): {e}"))?;

        let mut infl = InflateCtx::new();
        let capf = cap::parse(&cap_bytes, &mut infl)
            .map_err(|e| format!("CAP parse failed ({cap_path}): {e:?}"))?;
        let package_aid = capf.package_aid.as_bytes().to_vec();
        let module_aid = capf
            .components
            .applets
            .first()
            .ok_or_else(|| "CAP has no applet (Applet.cap component is empty)".to_string())?
            .class_aid
            .as_bytes()
            .to_vec();

        let applet_aid = match env_opt("SCLL_APPLET_AID") {
            Some(s) => from_hex(&s)?,
            None => module_aid.clone(),
        };

        Ok(Self {
            cap_bytes,
            package_aid,
            module_aid,
            applet_aid,
        })
    }

    /// Print the CAP-derived configuration lines.
    pub fn print(&self) {
        println!("CAP size      : {} bytes", self.cap_bytes.len());
        println!("package (ELF) : {}", to_hex(&self.package_aid));
        println!("module (class): {}", to_hex(&self.module_aid));
        println!("applet inst.  : {}", to_hex(&self.applet_aid));
    }
}

/// Pick the transport: explicit `SCLL_TRANSPORT`, else infer from whichever
/// connection variable is set. Ambiguity (both set, no override) is an error.
///
/// # Errors
/// A human-readable string on a missing/ambiguous/unknown selection.
pub fn select_endpoint() -> Result<Endpoint, String> {
    let pcsc = env_opt("SCLL_PCSC");
    let jcsim = env_opt("SCLL_JCSIM_ADDR");
    match env_opt("SCLL_TRANSPORT").as_deref() {
        Some("pcsc") => pcsc
            .map(Endpoint::Pcsc)
            .ok_or_else(|| "SCLL_TRANSPORT=pcsc but SCLL_PCSC is not set".into()),
        Some("jcsim") => jcsim
            .map(Endpoint::Jcsim)
            .ok_or_else(|| "SCLL_TRANSPORT=jcsim but SCLL_JCSIM_ADDR is not set".into()),
        Some(other) => Err(format!("SCLL_TRANSPORT must be pcsc or jcsim, got {other:?}")),
        None => match (pcsc, jcsim) {
            (Some(r), None) => Ok(Endpoint::Pcsc(r)),
            (None, Some(a)) => Ok(Endpoint::Jcsim(a)),
            (Some(_), Some(_)) => {
                Err("both SCLL_PCSC and SCLL_JCSIM_ADDR are set — set SCLL_TRANSPORT to choose".into())
            }
            (None, None) => Err("set SCLL_PCSC (PC/SC) or SCLL_JCSIM_ADDR (jcsim)".into()),
        },
    }
}

// ─── APDU tracing (debugging aid) ─────────────────────────────────────────────

/// [`Transport`] decorator that hex-dumps every C-APDU/R-APDU pair to stderr
/// when `SCLL_APDU_TRACE=1`; a no-op passthrough otherwise. Wraps BOTH
/// transports (see [`run_demo`]; jcsim added in v0.9m — before that the
/// bridge's own log was the only jcsim trace) — used to capture raw wire
/// bytes for comparison against `gp -l -d` traces of the same exchanges.
pub struct TracingTransport<T> {
    inner: T,
    enabled: bool,
    seq: u32,
}

impl<T> TracingTransport<T> {
    /// Wrap `inner`, enabling the dump iff `SCLL_APDU_TRACE=1`.
    pub fn new(inner: T) -> Self {
        let enabled = env_opt("SCLL_APDU_TRACE").as_deref() == Some("1");
        Self {
            inner,
            enabled,
            seq: 0,
        }
    }
}

impl<T: Transport> Transport for TracingTransport<T> {
    fn transmit(
        &mut self,
        capdu: &[u8],
    ) -> Result<heapless::Vec<u8, RAPDU_MAX>, TransportError> {
        self.seq += 1;
        if self.enabled {
            eprintln!("[apdu #{:03}] C-APDU: {}", self.seq, hex_dump(capdu));
        }
        let result = self.inner.transmit(capdu);
        if self.enabled {
            match &result {
                Ok(r) => eprintln!("[apdu #{:03}] R-APDU: {}", self.seq, hex_dump(r)),
                Err(e) => eprintln!("[apdu #{:03}] transport error: {:?}", self.seq, e),
            }
        }
        result
    }

    fn capabilities(&self) -> TransportCaps {
        self.inner.capabilities()
    }

    fn reset(&mut self) -> Result<AtrAts, TransportError> {
        self.inner.reset()
    }

    fn protocol(&self) -> TransportProtocol {
        self.inner.protocol()
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

/// Upper-case hex, no separators — matches the style used elsewhere in these
/// examples (`dump`/`from_hex`) and in gppro's `-d` trace lines.
#[must_use]
pub fn hex_dump(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

// ─── Runner ──────────────────────────────────────────────────────────────────

/// One example lifecycle, generic over the transport. Implemented by each
/// binary; [`run_demo`] connects the transport selected in [`Config`] and
/// hands over a ready [`CardManager`].
pub trait Demo {
    /// Run the lifecycle against an open card manager.
    ///
    /// # Errors
    /// Any [`ScllError`] from the underlying `CardManager` calls.
    fn run<T: Transport>(&self, mgr: &mut CardManager<T, Be>) -> Result<(), ScllError>;
}

/// Connect the configured transport, build the `CardManager` (RustCrypto
/// backend + OS CSPRNG) and run `demo` on it.
///
/// # Errors
/// A human-readable string on connect failure or any lifecycle error.
pub fn run_demo<D: Demo>(endpoint: &Endpoint, demo: &D) -> Result<(), String> {
    match endpoint {
        Endpoint::Pcsc(reader) => {
            let transport = PcscTransport::connect_selector(reader)
                .map_err(|e| format!("PC/SC connect failed for {reader:?}: {e:?}"))?;
            // Hex-dump C-APDU/R-APDU pairs to stderr when SCLL_APDU_TRACE=1
            // (debugging aid, both transports — see TracingTransport).
            let transport = TracingTransport::new(transport);
            let mut mgr = CardManager::new(transport, RustCryptoBackend::new(OsRng));
            demo.run(&mut mgr).map_err(|e| format!("{e}"))
        }
        Endpoint::Jcsim(addr) => {
            let transport = JcSimTransport::connect(addr)
                .map_err(|e| format!("jcsim connect failed for {addr}: {e:?}"))?;
            // Same SCLL_APDU_TRACE wiring as the PC/SC path (v0.9m) so the
            // two targets produce comparable traces.
            let transport = TracingTransport::new(transport);
            let mut mgr = CardManager::new(transport, RustCryptoBackend::new(OsRng));
            demo.run(&mut mgr).map_err(|e| format!("{e}"))
        }
    }
}

/// Print the run summary and map the result to a process exit code.
#[must_use]
pub fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => {
            println!("\n========================================");
            println!(" RUN SUMMARY");
            println!("========================================");
            println!("All steps completed successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\n========================================");
            eprintln!(" RUN SUMMARY");
            eprintln!("========================================");
            eprintln!("Run FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── Channel + key helpers ───────────────────────────────────────────────────

/// Three SCP key handles (ENC/MAC/DEK) — reusable across channel re-opens.
#[derive(Clone, Copy)]
pub struct Triple {
    /// ENC key handle.
    pub enc: KeyHandle,
    /// MAC key handle.
    pub mac: KeyHandle,
    /// DEK key handle.
    pub dek: KeyHandle,
}

impl Triple {
    /// As `open_scp` channel keys.
    #[must_use]
    pub fn keys(self) -> SdKeys {
        SdKeys {
            enc: self.enc,
            mac: self.mac,
            dek: self.dek,
        }
    }
    /// As a PUT KEY payload. The examples provision 16-byte AES keys
    /// throughout (SCP03).
    #[must_use]
    pub fn new_keyset(self) -> NewKeyset {
        self.new_keyset_of(KeyKind::Aes128)
    }
    /// As a PUT KEY payload with an explicit key kind — used when restoring
    /// the card's original ISD keyset, whose length (16/24/32) comes from the
    /// environment rather than the fixed 16-byte demo constants.
    #[must_use]
    pub fn new_keyset_of(self, kind: KeyKind) -> NewKeyset {
        NewKeyset {
            enc: self.enc,
            mac: self.mac,
            dek: self.dek,
            kind,
        }
    }
}

/// Open a secure channel, dump the negotiated parameters and return them —
/// callers that must know the **effective** KVN (a `kvn` of 0x00 lets the
/// card pick its default keyset at INITIALIZE UPDATE) inspect
/// `OpenScpParams::kvn_effective`.
///
/// # Errors
/// Any [`ScllError`] from `open_scp`.
#[allow(clippy::too_many_arguments)]
pub fn open<T: Transport>(
    mgr: &mut CardManager<T, Be>,
    label: &str,
    target_aid: &[u8],
    kind: ScpTargetKind,
    keys: SdKeys,
    advertised: &[ScpVariant],
    scp: ScpVariant,
    kvn: u8,
    level: u8,
) -> Result<OpenScpParams, ScllError> {
    let p = mgr.open_scp(&OpenScpArgs {
        target_aid,
        target_kind: kind,
        sd_keys: keys,
        advertised,
        force_scp: Some(scp),
        kvn,
        requested_level: level,
    })?;
    println!("\n[channel opened: {label}]");
    dump(&p);
    Ok(p)
}

/// Open a channel **with the card's ORIGINAL ISD keys** — to the ISD
/// itself, or to a freshly created SSD that inherited them — trying
/// several key-version selectors in order: the known original KVN (if any),
/// the configured `SCLL_ISD_KVN`, every version the Key Information Template
/// reported at discovery except the demo versions
/// ([`ISD_KVN_1`]/[`ISD_KVN_2`]), and finally the explicit
/// [`JCSIM_FACTORY_KVN`].
///
/// Rationale: jcsim's INITIALIZE UPDATE with P1 = 0x00 answers `6A88` once
/// its internal default-KVN pointer dangles (the keyset it referenced was
/// deleted — e.g. by the `isd-lifecycle` teardown), even though the original
/// keyset exists and authenticates fine when addressed explicitly (PDD
/// §10.7). The JCOP-mocking bridge shows the same `6A88` for P1 = 0x00
/// against a freshly created SSD's inherited keyset. Every binary that opens
/// an original-keys channel uses this helper so that neither artifact can
/// strand it.
///
/// # Errors
/// The last candidate's [`ScllError`] when none authenticates.
#[allow(clippy::too_many_arguments)]
pub fn open_isd_original<T: Transport>(
    mgr: &mut CardManager<T, Be>,
    label: &str,
    isd_aid: &[u8],
    isd: Triple,
    advertised: &[ScpVariant],
    scp: ScpVariant,
    cfg_kvn: u8,
    reported_kvns: &[u8],
    known_original_kvn: Option<u8>,
    level: u8,
) -> Result<OpenScpParams, ScllError> {
    let mut candidates: Vec<u8> = Vec::new();
    if let Some(k) = known_original_kvn {
        candidates.push(k);
    }
    if !candidates.contains(&cfg_kvn) {
        candidates.push(cfg_kvn);
    }
    for &k in reported_kvns {
        if k != ISD_KVN_1 && k != ISD_KVN_2 && !candidates.contains(&k) {
            candidates.push(k);
        }
    }
    if cfg_kvn == 0x00 && !candidates.contains(&JCSIM_FACTORY_KVN) {
        candidates.push(JCSIM_FACTORY_KVN);
    }
    // INITIALIZE UPDATE P1 can only address key versions 0x01-0x7F (0x00 =
    // "first available"; GPCS v2.3.1 §11.8.2.3 Table 11-67 reserves the
    // range above). An initial keyset at 0xFF — reported in the KIT and the
    // IU response on real JCOP — is NOT selectable explicitly: the P71
    // answers 6A86 to P1=0xFF. Drop non-addressable candidates and make
    // sure P1=0x00 is tried.
    candidates.retain(|&k| k <= 0x7F);
    if !candidates.contains(&0x00) {
        candidates.push(0x00);
    }
    let mut last: Option<ScllError> = None;
    for kvn in candidates {
        match open(
            mgr,
            label,
            isd_aid,
            ScpTargetKind::SecurityDomainAid,
            isd.keys(),
            advertised,
            scp,
            kvn,
            level,
        ) {
            Ok(p) => return Ok(p),
            Err(e) => {
                println!(
                    "[original ISD keys with key version selector 0x{kvn:02X} did not open ({e})]"
                );
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or(ScllError::KeyNotFound))
}

/// Prefer SCP03 (AES) when advertised, else fall back to the card's SCP02.
///
/// # Errors
/// [`ScllError::ScpProtocolUnsupported`] if the card advertises no SCP.
pub fn pick_scp(info: &scll::model::CardInfo) -> Result<ScpVariant, ScllError> {
    info.scp_supported
        .iter()
        .copied()
        .find(|v| matches!(v, ScpVariant::Scp03 { .. }))
        .or_else(|| info.scp_supported.first().copied())
        .ok_or(ScllError::ScpProtocolUnsupported)
}

/// Map negotiated SCP + key length to a backend `KeyKind` (mirrors the smoke
/// tests): SCP03 ⇒ AES-128/192/256 by length; SCP02 ⇒ 16-byte 3DES-2key.
///
/// # Panics
/// On a key length the negotiated SCP cannot use (the length was validated at
/// config time, so this indicates a programming error in the example).
#[must_use]
pub fn key_kind_for(scp: ScpVariant, len: usize) -> KeyKind {
    match scp {
        ScpVariant::Scp03 { .. } => match len {
            16 => KeyKind::Aes128,
            24 => KeyKind::Aes192,
            32 => KeyKind::Aes256,
            other => panic!("SCP03 key must be 16/24/32 bytes, got {other}"),
        },
        ScpVariant::Scp02 { .. } => {
            assert!(len == 16, "SCP02 requires a 16-byte 3DES key, got {len}");
            KeyKind::TripleDesDouble
        }
    }
}

// ─── Printing helpers ────────────────────────────────────────────────────────

/// Print an applet-transmit report: data (hex + ASCII when printable) and SW.
pub fn print_transmit(r: &scll::report::AppletTransmitReport) {
    println!("R-APDU data : {}", to_hex(&r.rapdu));
    if let Ok(s) = core::str::from_utf8(&r.rapdu) {
        if s.chars().all(|c| !c.is_control()) {
            println!("R-APDU ascii: {s:?}");
        }
    }
    println!("SW          : 0x{:04X}", r.sw);
    dump(r);
}

/// Explicitly surface a report's non-fatal warnings (PDD §7/§8) instead of
/// relying on the `{:#?}` dump alone: the examples treat warnings as
/// first-class output so that e.g. `WarningKind::InventoryTruncated` (the
/// inventory is a valid prefix, not the full card content — §5.12a) or
/// `LifecycleNoOp` is never silently scrolled past.
pub fn report_warnings(context: &str, warnings: &[Warning]) {
    if warnings.is_empty() {
        println!("[{context}: no warnings]");
    } else {
        println!("[{context}: {} warning(s)]", warnings.len());
        for w in warnings {
            if w.detail.is_empty() {
                println!("  - {:?}", w.kind);
            } else {
                println!("  - {:?}: {}", w.kind, w.detail);
            }
        }
    }
}

/// Step banner.
pub fn banner(step: u32, title: &str) {
    println!("\n========================================");
    println!(" STEP {step}: {title}");
    println!("========================================");
}

/// `{:#?}`-dump any report.
pub fn dump<T: std::fmt::Debug>(v: &T) {
    println!("{v:#?}");
}

// ─── Env / hex utilities ─────────────────────────────────────────────────────

/// Required environment variable (non-empty).
///
/// # Errors
/// A human-readable string when the variable is unset or empty.
pub fn env_req(name: &str) -> Result<String, String> {
    env_opt(name).ok_or_else(|| format!("required environment variable {name} is not set"))
}

/// Optional environment variable (`None` when unset or empty).
#[must_use]
pub fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Parse a hex `u8` with optional `0x` prefix.
///
/// # Errors
/// A human-readable string on a malformed value.
pub fn parse_u8(s: &str) -> Result<u8, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u8::from_str_radix(s, 16).map_err(|_| format!("invalid u8 hex value: {s:?}"))
}

/// Upper-case hex encoding.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Hex decoding, whitespace-tolerant.
///
/// # Errors
/// A human-readable string on odd length or non-hex characters.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex: {s:?}")))
        .collect()
}
