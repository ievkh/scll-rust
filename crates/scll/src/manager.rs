//! [`CardManager`] — the assembled default manager (PDD §3.6).
//!
//! Owns a [`Transport`] and a backend implementing the three default-manager
//! traits (`KeyBackend + Scp02Backend + Scp03Backend`, PDD §3.6), and retains
//! the open [`ScpSession`] once a channel is established. Every method is a
//! thin, ergonomic wrapper over the matching free function in
//! [`scll_core::workflow`]: the manager only removes the per-call threading of
//! `&mut dyn Transport`, `&backend`, and `&mut ScpSession`, and the production
//! code path is *exactly* the workflow functions exercised by the S6 replay
//! tests (no logic is duplicated here).
//!
//! Pre-auth steps ([`probe`](CardManager::probe), [`discover`](CardManager::discover))
//! need no session; in-session steps return [`ScllError::NoOpenChannel`] when
//! called before [`open_scp`](CardManager::open_scp).
//!
//! An `Scp03Only` manager that drops the `Scp02Backend` bound (PDD §3.6) is
//! intentionally **not** provided yet — constrained targets that need it keep
//! calling the free functions directly. This keeps the S7 surface minimal.

use scll_core::backend::{KeyBackend, Scp02Backend, Scp03Backend};
use scll_core::cap::InflateCtx;
use scll_core::command::install::PrivLen;
use scll_core::error::ScllError;
use scll_core::model::CardInfo;
use scll_core::report::{
    AppletTransmitReport, CreateSsdReport, DeleteCascade, DeleteKeyReport, DeleteObjectReport,
    GetCardInventoryReport, GetCardStatusReport, InstallAppletReport, LoadPackageReport,
    OpenScpParams, ProbeReport, PutKeysReport, SetCardStatusReport, TransportName,
};
use scll_core::scp::ScpSession;
use scll_core::transport::Transport;
use scll_core::workflow::{
    self, CreateSsdArgs, DeleteAppletArgs, InstallAppletArgs, LoadPackageArgs, OpenScpArgs,
    PutSdKeysArgs, SetCardStatusArgs,
};

/// The assembled `GlobalPlatform` card manager: an owned transport, a crypto
/// backend, and — after [`open_scp`](CardManager::open_scp) — a retained secure
/// channel.
///
/// `B` must satisfy the default-manager bound `KeyBackend + Scp02Backend +
/// Scp03Backend` (PDD §3.6); the shipped [`scll_backend_rustcrypto`] backend
/// does. `T` is any [`Transport`] (e.g. `scll-transport-pcsc` /
/// `scll-transport-jcsim`, or a user transport).
///
/// # Examples
///
/// Assemble a manager and probe transport availability (no card needed):
///
/// ```
/// use scll::CardManager;
/// use scll::report::TransportName;
/// use scll::backend_rustcrypto::RustCryptoBackend;
/// # use scll::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};
/// # use scll::limits::RAPDU_MAX;
/// # use heapless::Vec;
/// # // A transport with no card present — enough to show assembly.
/// # struct Offline;
/// # impl Transport for Offline {
/// #     fn transmit(&mut self, _c: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> {
/// #         Err(TransportError::CardRemoved)
/// #     }
/// #     fn capabilities(&self) -> TransportCaps {
/// #         TransportCaps { handles_t0_get_response: false, protocol: TransportProtocol::T1, contactless: false }
/// #     }
/// #     fn reset(&mut self) -> Result<AtrAts, TransportError> { Err(TransportError::CardRemoved) }
/// #     fn protocol(&self) -> TransportProtocol { TransportProtocol::T1 }
/// #     fn is_connected(&self) -> bool { false }
/// # }
/// # // Deterministic, NOT secure — doctest only. A real caller injects an OS/board CSPRNG.
/// # struct DocRng(u64);
/// # impl rand_core::RngCore for DocRng {
/// #     fn next_u32(&mut self) -> u32 { self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15); (self.0 >> 32) as u32 }
/// #     fn next_u64(&mut self) -> u64 { (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32()) }
/// #     fn fill_bytes(&mut self, d: &mut [u8]) { for c in d.chunks_mut(4) { let b = self.next_u32().to_le_bytes(); c.copy_from_slice(&b[..c.len()]); } }
/// #     fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.fill_bytes(d); Ok(()) }
/// # }
/// # impl rand_core::CryptoRng for DocRng {}
/// let backend = RustCryptoBackend::new(DocRng(1));
/// let mut mgr = CardManager::new(Offline, backend);
///
/// assert!(!mgr.is_channel_open());
/// // No card present, so probing reports the transport as unavailable.
/// assert!(mgr.probe(TransportName::User).is_err());
/// ```
#[allow(clippy::module_name_repetitions)] // `CardManager`: headline type, re-exported at crate root; matches PDD §3.6
pub struct CardManager<T, B>
where
    T: Transport,
    B: KeyBackend + Scp02Backend + Scp03Backend,
{
    transport: T,
    backend: B,
    session: Option<ScpSession>,
    priv_len: PrivLen,
}

impl<T, B> CardManager<T, B>
where
    T: Transport,
    B: KeyBackend + Scp02Backend + Scp03Backend,
{
    /// Assemble a manager from an owned transport and backend. No I/O occurs
    /// until a workflow method is called.
    #[must_use]
    pub fn new(transport: T, backend: B) -> Self {
        Self {
            transport,
            backend,
            session: None,
            priv_len: PrivLen::Canonical,
        }
    }

    // --- accessors ---

    /// Borrow the underlying transport.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the underlying transport (e.g. to reconnect a host link).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Borrow the backend.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The retained secure channel, if one is open.
    #[must_use]
    pub fn session(&self) -> Option<&ScpSession> {
        self.session.as_ref()
    }

    /// `true` once a secure channel has been opened and not closed.
    #[must_use]
    pub fn is_channel_open(&self) -> bool {
        self.session.is_some()
    }

    /// Forget the retained channel on this side and release the backend's
    /// session slot (zeroizing its session keys). No card-side close APDU is
    /// sent; the session handle simply becomes unusable here. Releasing the
    /// slot keeps a long-lived manager from exhausting the backend's fixed
    /// session table across many open/close cycles (PDD §3.6).
    pub fn close_channel(&mut self) {
        if let Some(session) = self.session.as_ref() {
            match session {
                ScpSession::Scp03(s) => self.backend.scp03_close_session(s.session()),
                ScpSession::Scp02(s) => self.backend.scp02_close_session(s.session()),
            }
        }
        self.session = None;
    }

    /// Decompose the manager back into its transport and backend, releasing any
    /// retained session slot first (same zeroizing cleanup as `close_channel`),
    /// so the returned backend starts with a free session table.
    #[must_use]
    pub fn into_parts(mut self) -> (T, B) {
        self.close_channel();
        (self.transport, self.backend)
    }

    // --- pre-auth (PDD §5.1–§5.2) ---

    /// Step 1 — probe transport availability and capabilities (PDD §5.1).
    ///
    /// # Errors
    /// [`ScllError::TransportUnavailable`] if the transport is not connected.
    pub fn probe(&mut self, name: TransportName) -> Result<ProbeReport, ScllError> {
        workflow::probe(&mut self.transport, name)
    }

    /// Step 2 — discover card capabilities without authentication (PDD §5.2).
    ///
    /// # Errors
    /// Propagates [`ScllError`] from the discovery workflow (transport failure,
    /// rejected ISD `SELECT`, or no resolvable ISD AID). Missing *optional*
    /// data is surfaced as a warning inside [`CardInfo`], never an error.
    pub fn discover(&mut self, expected_isd_aid: Option<&[u8]>) -> Result<CardInfo, ScllError> {
        let info = workflow::discover_card(&mut self.transport, expected_isd_aid)?;
        self.priv_len = info.privilege_encoding;
        Ok(info)
    }

    // --- open channel (PDD §5.9) ---

    /// Step 9 — open an SCP02/SCP03 secure channel and retain it (PDD §5.9).
    /// On success the channel is stored and every later in-session method uses
    /// it; the returned [`OpenScpParams`] reports the effective (capped)
    /// protocol, `i`, KVN, and security level.
    ///
    /// # Errors
    /// [`ScllError::ScpProtocolUnsupported`] if no supported variant is on
    /// offer, [`ScllError::CardCryptogramFail`] / [`ScllError::ExternalAuthFail`]
    /// on a failed handshake, or a transport / backend / [`ScllError::Card`]
    /// error (see [`scll_core::workflow::open_scp`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use scll::CardManager;
    /// # use scll::backend::{KeyBackend, KeyKind};
    /// # use scll::backend_rustcrypto::RustCryptoBackend;
    /// # use scll::report::ScpTargetKind;
    /// # use scll::workflow::{OpenScpArgs, SdKeys};
    /// # use scll::transport::{AtrAts, Transport, TransportCaps, TransportError, TransportProtocol};
    /// # use scll::limits::RAPDU_MAX;
    /// # use heapless::Vec;
    /// # struct Offline;
    /// # impl Transport for Offline {
    /// #     fn transmit(&mut self, _c: &[u8]) -> Result<Vec<u8, RAPDU_MAX>, TransportError> { Err(TransportError::CardRemoved) }
    /// #     fn capabilities(&self) -> TransportCaps { TransportCaps { handles_t0_get_response: false, protocol: TransportProtocol::T1, contactless: false } }
    /// #     fn reset(&mut self) -> Result<AtrAts, TransportError> { Err(TransportError::CardRemoved) }
    /// #     fn protocol(&self) -> TransportProtocol { TransportProtocol::T1 }
    /// #     fn is_connected(&self) -> bool { false }
    /// # }
    /// # struct DocRng(u64);
    /// # impl rand_core::RngCore for DocRng {
    /// #     fn next_u32(&mut self) -> u32 { self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15); (self.0 >> 32) as u32 }
    /// #     fn next_u64(&mut self) -> u64 { (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32()) }
    /// #     fn fill_bytes(&mut self, d: &mut [u8]) { for c in d.chunks_mut(4) { let b = self.next_u32().to_le_bytes(); c.copy_from_slice(&b[..c.len()]); } }
    /// #     fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.fill_bytes(d); Ok(()) }
    /// # }
    /// # impl rand_core::CryptoRng for DocRng {}
    /// # fn run() -> Result<(), scll::error::ScllError> {
    /// let backend = RustCryptoBackend::new(DocRng(1));
    /// // GP default static test keys (same 16-byte value for ENC/MAC/DEK here).
    /// const K: [u8; 16] = [
    ///     0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ///     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    /// ];
    /// let h = backend.import_key(KeyKind::Aes128, &K)?;
    ///
    /// let mut mgr = CardManager::new(Offline, backend);
    /// let info = mgr.discover(None)?;
    /// let args = OpenScpArgs {
    ///     target_aid: info.isd_aid.as_bytes(),
    ///     target_kind: ScpTargetKind::SecurityDomainAid,
    ///     sd_keys: SdKeys { enc: h, mac: h, dek: h },
    ///     advertised: info.scp_supported.as_slice(),
    ///     force_scp: None,
    ///     kvn: 0x00,
    ///     requested_level: 0x03,
    /// };
    /// let _effective = mgr.open_scp(&args)?;
    /// assert!(mgr.is_channel_open());
    ///
    /// // In-session calls now use the retained channel.
    /// let _status = mgr.get_card_status(info.isd_aid.as_bytes())?;
    /// mgr.close_channel();
    /// # Ok(())
    /// # }
    /// ```
    pub fn open_scp(&mut self, args: &OpenScpArgs<'_>) -> Result<OpenScpParams, ScllError> {
        let report = workflow::open_scp(&mut self.transport, &self.backend, args)?;
        self.session = Some(report.session);
        Ok(report.effective)
    }

    // --- in-session (PDD §5.3–§5.12) ---

    /// Step 10 — exchange one application-level APDU over the open channel
    /// (PDD §5.10). The returned SW is *not* itself an error — inspect
    /// `report.sw`.
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a
    /// wrap/unwrap [`ScllError::Backend`], a mapped transport error, or
    /// [`ScllError::Card`].
    pub fn transmit(&mut self, plaintext_capdu: &[u8]) -> Result<AppletTransmitReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::transmit(&mut self.transport, &self.backend, session, plaintext_capdu)
    }

    /// Steps 3/6 — PUT KEY (Add) on a Security Domain over the open channel
    /// (PDD §5.3/§5.6). `args.target_sd_aid` selects the SD (ISD or SSD); the
    /// open channel must target that SD with its current keys.
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::KeyCheckValueMismatch`], [`ScllError::Card`]).
    pub fn put_sd_keys(&mut self, args: &PutSdKeysArgs<'_>) -> Result<PutKeysReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::put_sd_keys(&mut self.transport, &self.backend, session, args)
    }

    /// Delete an entire key **version** (all keys at `kvn`) from a Security
    /// Domain with one KVN-only DELETE. GP cards (e.g. JCOP) address a PUT KEY
    /// key set as a unit by its version, and deleting individual key
    /// identifiers can return `6A88` (PDD §5.3.3/§5.6; GPCS v2.3.1
    /// §11.2.2.3.2). Never target the keyset the current session authenticated
    /// with, nor the card's only ISD keyset.
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open, [`ScllError::KeyNotFound`]
    /// if the version is absent, or a transport / backend / card error.
    pub fn delete_sd_keyset(
        &mut self,
        kvn: u8,
        target_sd_aid: &[u8],
    ) -> Result<DeleteKeyReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::delete_sd_keyset(
            &mut self.transport,
            &self.backend,
            session,
            kvn,
            target_sd_aid,
        )
    }

    /// Step 4 — create an SSD via `INSTALL [for install & make selectable]`
    /// (PDD §5.4).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::AidAlreadyExists`], [`ScllError::ResidentSdNotFound`]).
    pub fn create_ssd(&mut self, args: &CreateSsdArgs<'_>) -> Result<CreateSsdReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::create_ssd(
            &mut self.transport,
            &self.backend,
            session,
            args,
            self.priv_len,
        )
    }

    /// Step 4a — `INSTALL [for load]` then stream the CAP Load File Data Block
    /// (PDD §5.4a). `infl` is the caller-lent 32 KiB inflate working set
    /// ([`InflateCtx`]); place it in a `static` or generous stack.
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::LoadTooLarge`], [`ScllError::PackageAidExists`]).
    pub fn load_package(
        &mut self,
        args: &LoadPackageArgs<'_>,
        infl: &mut InflateCtx,
    ) -> Result<LoadPackageReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::load_package(&mut self.transport, &self.backend, session, args, infl)
    }

    /// Step 5 — delete an SSD via `DELETE` (PDD §5.5).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::SsdHasApplets`], [`ScllError::TargetNoLongerExists`]).
    pub fn delete_ssd(
        &mut self,
        ssd_aid: &[u8],
        cascade: DeleteCascade,
    ) -> Result<DeleteObjectReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::delete_ssd(
            &mut self.transport,
            &self.backend,
            session,
            ssd_aid,
            cascade,
        )
    }

    /// Step 7 — install an applet via `INSTALL [for install & make selectable]`
    /// (PDD §5.7).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::PackageNotFound`], [`ScllError::AidAlreadyExists`]).
    pub fn install_applet(
        &mut self,
        args: &InstallAppletArgs<'_>,
    ) -> Result<InstallAppletReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::install_applet(
            &mut self.transport,
            &self.backend,
            session,
            args,
            self.priv_len,
        )
    }

    /// Step 8 — delete an applet instance (and optionally cascade its ELF)
    /// (PDD §5.8).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::ElfHasOtherInstances`]).
    pub fn delete_applet(
        &mut self,
        args: &DeleteAppletArgs<'_>,
    ) -> Result<DeleteObjectReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::delete_applet(&mut self.transport, &self.backend, session, args)
    }

    /// Step 12 — read the ISD card life-cycle state (PDD §5.12).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow error.
    pub fn get_card_status(&mut self, isd_aid: &[u8]) -> Result<GetCardStatusReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::get_card_status(&mut self.transport, &self.backend, session, isd_aid)
    }

    /// Step 12a — enumerate the card's object inventory: Security Domains,
    /// Application instances, and Executable Load Files with their modules — the
    /// `gp --list` equivalent (PDD §5.12a). Read-only; safe to call repeatedly.
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error. A populated card exceeding the `CardInventory` capacity bounds is
    /// **not** an error: it returns a valid prefix with
    /// [`scll_core::error::WarningKind::InventoryTruncated`] on the report.
    pub fn get_card_inventory(
        &mut self,
        isd_aid: &[u8],
    ) -> Result<GetCardInventoryReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::get_card_inventory(&mut self.transport, &self.backend, session, isd_aid)
    }

    /// Step 11 — set the ISD card life-cycle state via `SET STATUS` (PDD §5.11).
    ///
    /// # Errors
    /// [`ScllError::NoOpenChannel`] if no channel is open; otherwise a workflow
    /// error (e.g. [`ScllError::IllegalLifecycleTransition`]).
    pub fn set_card_status(
        &mut self,
        args: &SetCardStatusArgs<'_>,
    ) -> Result<SetCardStatusReport, ScllError> {
        let session = self.session.as_mut().ok_or(ScllError::NoOpenChannel)?;
        workflow::set_card_status(&mut self.transport, &self.backend, session, args)
    }
}
