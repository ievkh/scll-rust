//! Steps 11, 12 & 12a — `set_card_status` / `get_card_status` /
//! `get_card_inventory` (PDD §5.11/§5.12/§5.12a).
//!
//! `set_card_status`: SET STATUS (INS F0, P1 `0x80`) over an ISD session;
//! forward provisioning + reversible lock/unlock; `TERMINATED` refused (§2.2);
//! same-state no-op detected before any APDU (via `lifecycle::check_transition`,
//! GPCS v2.3.1 §5.1.1 / Table 11-6). `get_card_status`: GET STATUS (INS F2,
//! P1 `0x80`, P2 `0x02`, Data `4F00`) → decode `'9F70'` to [`CardLifeCycle`].
//! `get_card_inventory`: GET STATUS across the three registry scopes
//! (P1 `0x80`/`0x40`/`0x10`, GPCS v2.3.1 §11.4) with `63 10` paging, into a
//! [`CardInventory`] — the `gp --list` equivalent.
//!
//! ISD-ness of the session is the caller's contract (the session was opened
//! against the ISD); a registry-backed `SessionNotIsd` check needs the
//! inventory snapshot that fast discovery skips, so it is not raised here.

use heapless::{String, Vec};

use crate::aid::Aid;
use crate::backend::{Scp02Backend, Scp03Backend};
use crate::command::get_status::{get_status_p2, P2_FIRST_TLV, P2_NEXT_TLV};
use crate::command::set_status::set_card_status as set_card_status_cmd;
use crate::error::{ScllError, Warning, WarningKind};
use crate::lifecycle::{check_transition, TransitionPlan};
use crate::limits::{
    MAX_APPLETS, MAX_ELFS, MAX_MODULES_PER_ELF, MAX_SDS, MAX_STATUS_PAGES, MAX_STATUS_SCOPE_BYTES,
    MAX_WARNINGS,
};
use crate::model::{ApplicationEntry, CardInventory, ExecutableLoadFileEntry, SecurityDomainEntry};
use crate::report::{
    CardLifeCycle, GetCardInventoryParams, GetCardInventoryReport, GetCardStatusParams,
    GetCardStatusReport, SetCardStatusParams, SetCardStatusReport,
};
use crate::response::{parse_status_e3, parse_status_registry, RegistryEntry};
use crate::scp::ScpSession;
use crate::tlv;
use crate::transport::Transport;
use crate::workflow::session::{self, SW_CONDITIONS, SW_MORE_DATA, SW_OK, SW_REF_NOT_FOUND};

/// ISD / card scope P1 for GET STATUS and SET STATUS (GPCS v2.3.1 Table 11-33/86).
const P1_ISD_SCOPE: u8 = 0x80;
/// GET STATUS scope: Applications and Supplementary Security Domains
/// (GPCS v2.3.1 Table 11-33, P1 `0x40`).
const P1_APP_SD_SCOPE: u8 = 0x40;
/// GET STATUS scope: Executable Load Files **and** their Executable Modules
/// (GPCS v2.3.1 Table 11-33, P1 `0x10`; supersets the `0x20` ELF-only scope).
const P1_ELF_MODULE_SCOPE: u8 = 0x10;
/// Security Domain privilege — privileges byte 1, bit b8 (GPCS v2.3.1
/// Table 11-7). Distinguishes a Supplementary Security Domain from a plain
/// Application in the `0x40` scope, exactly as `gp --list` does.
const PRIV_SECURITY_DOMAIN: u8 = 0x80;

/// §5.12 — read the card (ISD) life-cycle state (read-only, idempotent).
///
/// # Errors
/// Returns a transport / backend / [`ScllError::Card`] error if the GET STATUS
/// exchange fails. A response with no parseable `'E3'`/`'9F70'` is **not** an
/// error: it yields [`CardLifeCycle::Unknown`] plus a
/// [`WarningKind::GetStatusParseFailed`].
pub fn get_card_status<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    isd_aid: &[u8],
) -> Result<GetCardStatusReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    // See `read_status_scope`: GET STATUS response chaining (§11.4, Table
    // 11-38) splits at the byte level, not on entry boundaries, so the scope
    // is accumulated across any `63 10` pages before parsing — the single-page
    // `get_status()` call this replaced would mis-parse a split response the
    // same way `get_card_inventory` did (confirmed live against a JCOP 4 P71;
    // in practice the ISD-only entry is small and rarely splits, but nothing
    // in the spec guarantees that).
    let (data, scope_truncated) = read_status_scope(t, backend, session, P1_ISD_SCOPE)?;
    let mut warnings: Vec<Warning, MAX_WARNINGS> = Vec::new();
    let decoded = if let Some(s) = parse_status_e3(&data)? {
        s
    } else {
        let _ = warnings.push(Warning {
            kind: WarningKind::GetStatusParseFailed,
            detail: String::new(),
        });
        CardLifeCycle::Unknown(0)
    };
    if scope_truncated {
        let _ = warnings.push(Warning {
            kind: WarningKind::GetStatusParseFailed,
            detail: String::new(),
        });
    }
    let isd = Aid::new(isd_aid)?;
    Ok(GetCardStatusReport {
        state: decoded,
        effective: GetCardStatusParams {
            raw_state_byte: raw_byte(decoded),
            decoded_state: decoded,
            isd_aid: isd,
        },
        warnings,
    })
}

/// §5.12a — enumerate the card's object inventory (the `gp --list` equivalent):
/// Security Domains, Application instances, and Executable Load Files with their
/// modules. Read-only and idempotent; modifies no card state.
///
/// Runs GET STATUS over the three registry scopes (GPCS v2.3.1 Table 11-33),
/// each with `63 10` "more data" paging (Table 11-38):
///   * P1 `0x80` — the Issuer Security Domain (recorded once, with no parent);
///   * P1 `0x40` — Applications + Supplementary Security Domains, split by the
///     Security Domain privilege bit (Table 11-7), with the ISD de-duplicated;
///   * P1 `0x10` — Executable Load Files and their Executable Modules (`'84'`).
///
/// Capacity is bounded by the `CardInventory` limits (`MAX_SDS` / `MAX_APPLETS`
/// / `MAX_ELFS`) and the per-scope page cap (`MAX_STATUS_PAGES`); hitting either
/// yields a valid prefix plus [`WarningKind::InventoryTruncated`], never an
/// error. Malformed individual AIDs are skipped; a structurally broken GET
/// STATUS page is an [`ScllError::MalformedResponse`].
///
/// # Errors
/// Returns [`ScllError::SecurityStatusNotSatisfied`] (`6982`, channel not open /
/// insufficient level), a mapped [`ScllError`] for any other non-`9000`/`6310`/
/// `6A88` SW, or a transport / backend error. An empty scope (`6A88`) is not an
/// error — it contributes no entries.
pub fn get_card_inventory<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    isd_aid: &[u8],
) -> Result<GetCardInventoryReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let isd = Aid::new(isd_aid)?;
    let mut security_domains: Vec<SecurityDomainEntry, MAX_SDS> = Vec::new();
    let mut applets: Vec<ApplicationEntry, MAX_APPLETS> = Vec::new();
    let mut elfs: Vec<ExecutableLoadFileEntry, MAX_ELFS> = Vec::new();
    let mut truncated = false;

    // 1) ISD scope (P1=0x80): exactly the Issuer Security Domain, shown once,
    //    with no parent SD. Its AID is taken from the '4F' echo when valid.
    truncated |= collect_scope(t, backend, session, P1_ISD_SCOPE, |e| {
        let aid = Aid::new(e.aid).unwrap_or_else(|_| isd.clone());
        security_domains
            .push(SecurityDomainEntry {
                aid,
                life_cycle_state: e.life_cycle,
                privileges: e.privileges,
                associated_sd_aid: None,
            })
            .is_ok()
    })?;

    // 2) Applications + Supplementary SDs (P1=0x40). Classify by the Security
    //    Domain privilege bit; de-duplicate the ISD (it is an SD, already held).
    truncated |= collect_scope(t, backend, session, P1_APP_SD_SCOPE, |e| {
        if e.aid == isd.as_bytes() {
            return true; // ISD shown once — intentional skip, not truncation
        }
        let Ok(aid) = Aid::new(e.aid) else {
            return true; // malformed AID — skip, not truncation
        };
        if e.privileges[0] & PRIV_SECURITY_DOMAIN != 0 {
            let parent = e.associated_sd_aid.and_then(|s| Aid::new(s).ok());
            security_domains
                .push(SecurityDomainEntry {
                    aid,
                    life_cycle_state: e.life_cycle,
                    privileges: e.privileges,
                    associated_sd_aid: parent,
                })
                .is_ok()
        } else {
            let parent = e
                .associated_sd_aid
                .and_then(|s| Aid::new(s).ok())
                .unwrap_or_else(|| isd.clone());
            let elf = e.elf_aid.and_then(|s| Aid::new(s).ok());
            applets
                .push(ApplicationEntry {
                    aid,
                    life_cycle_state: e.life_cycle,
                    privileges: e.privileges,
                    associated_sd_aid: parent,
                    associated_elf_aid: elf,
                })
                .is_ok()
        }
    })?;

    // 3) Executable Load Files + Modules (P1=0x10).
    truncated |= collect_scope(t, backend, session, P1_ELF_MODULE_SCOPE, |e| {
        let Ok(aid) = Aid::new(e.aid) else {
            return true;
        };
        let parent = e
            .associated_sd_aid
            .and_then(|s| Aid::new(s).ok())
            .unwrap_or_else(|| isd.clone());
        let mut modules: Vec<Aid, MAX_MODULES_PER_ELF> = Vec::new();
        for m in &e.modules {
            if let Ok(a) = Aid::new(m) {
                let _ = modules.push(a);
            }
        }
        elfs.push(ExecutableLoadFileEntry {
            aid,
            life_cycle_state: e.life_cycle,
            associated_sd_aid: parent,
            modules,
        })
        .is_ok()
    })?;

    let mut warnings: Vec<Warning, MAX_WARNINGS> = Vec::new();
    if truncated {
        let _ = warnings.push(Warning {
            kind: WarningKind::InventoryTruncated,
            detail: String::new(),
        });
    }

    let (sd_count, app_count, elf_count) = (security_domains.len(), applets.len(), elfs.len());
    Ok(GetCardInventoryReport {
        inventory: CardInventory {
            security_domains,
            applets,
            elfs,
        },
        effective: GetCardInventoryParams {
            isd_aid: isd,
            security_domain_count: sd_count,
            application_count: app_count,
            elf_count,
            truncated,
        },
        warnings,
    })
}

/// Drive a paged GET STATUS over one P1 scope, handing every decoded
/// [`RegistryEntry`] to `store`. `store` returns `false` when it could not keep
/// the entry (a `CardInventory` capacity bound); that — or a scope the
/// underlying accumulation had to cut short — sets the returned `truncated`
/// flag. A `6A88` empty scope ends the scan cleanly with whatever was stored.
///
/// Delegates the `63 10` (Table 11-38) paging to [`read_status_scope`], which
/// accumulates raw bytes across pages before this function parses the scope
/// exactly once — see that function's docs for why per-page parsing is unsound.
fn collect_scope<B, F>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    p1: u8,
    mut store: F,
) -> Result<bool, ScllError>
where
    B: Scp02Backend + Scp03Backend,
    F: FnMut(&RegistryEntry) -> bool,
{
    let (data, mut truncated) = read_status_scope(t, backend, session, p1)?;
    if data.is_empty() && !truncated {
        return Ok(false); // 6A88 empty scope, or a genuinely empty page
    }
    for entry in &parse_status_registry(&data)? {
        if !store(entry) {
            truncated = true;
        }
    }
    Ok(truncated)
}

/// Drive one GET STATUS scope (`p1`) through its `63 10` "more data"
/// continuations (Table 11-38), accumulating the **raw** response bytes into
/// one buffer before any TLV parsing. GPCS v2.3.1 §11.4 chains the response at
/// the **byte** level — a `'E3'` entry, or even a single value nested inside
/// one (e.g. a module AID), can be split exactly at the page boundary — so
/// parsing each page independently is unsound; only the fully-accumulated
/// buffer, once the card signals `9000`, is guaranteed to be a complete,
/// well-formed BER-TLV sequence. Confirmed against a live JCOP 4 P71
/// (SCP02 i=0x55): a module AID's value was split exactly at the page
/// boundary, and `gp -l -d`'s own trace shows the continuation resuming
/// mid-value, matching `GlobalPlatformPro`'s `GPRegistry`, which buffers
/// across pages the same way before parsing.
///
/// If accumulation cannot finish cleanly — the card keeps returning `63 10`
/// past [`MAX_STATUS_PAGES`], the total exceeds [`MAX_STATUS_SCOPE_BYTES`], or
/// the final `9000` buffer holds more top-level TLVs than [`crate::tlv::parse`]
/// can hold — the return is the **last prefix of the buffer known to be a
/// complete, parseable TLV sequence** (re-checked with `tlv::parse` after every
/// page), plus `truncated = true`. This preserves the "valid prefix, never an
/// error" contract the other inventory capacity limits already have; a
/// genuinely malformed response (not a capacity issue) is still a hard
/// [`crate::tlv::TlvError`] (surfaced by the caller's own `parse_status_e3` /
/// `parse_status_registry` call on the returned prefix).
///
/// # Errors
/// Returns a transport / backend error, or a mapped [`ScllError`] for any
/// GET STATUS SW other than `9000` / `63 10` / `6A88`.
fn read_status_scope<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    p1: u8,
) -> Result<(Vec<u8, MAX_STATUS_SCOPE_BYTES>, bool), ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let mut buf: Vec<u8, MAX_STATUS_SCOPE_BYTES> = Vec::new();
    let mut good_len = 0usize;
    let mut p2 = P2_FIRST_TLV;
    let mut truncated = false;
    let mut done = false;
    for _ in 0..MAX_STATUS_PAGES {
        let capdu = get_status_p2(p1, p2, &[])?;
        let (data, sw) = session::transmit_in_session(t, backend, session, &capdu)?;
        match sw {
            SW_OK | SW_MORE_DATA => {
                if buf.extend_from_slice(&data).is_err() {
                    // MAX_STATUS_SCOPE_BYTES exceeded — stop with the last
                    // known-good prefix rather than a partial, unparseable tail.
                    truncated = true;
                    break;
                }
                if tlv::parse(&buf).is_ok() {
                    // Buffer so far is a complete top-level TLV sequence —
                    // checkpoint it. True after most pages in practice (an
                    // entry rarely straddles *every* boundary), and always
                    // true once the card actually finishes.
                    good_len = buf.len();
                } else if sw == SW_OK {
                    // Card says complete, but we can't parse it as one TLV
                    // sequence (e.g. more top-level entries than tlv::parse
                    // holds) — fall back to the last checkpoint instead of
                    // erroring; a capacity limit truncates, it never fails.
                    truncated = true;
                }
                if sw == SW_OK {
                    done = true;
                    break;
                }
                p2 = P2_NEXT_TLV;
            }
            SW_REF_NOT_FOUND => return Ok((Vec::new(), false)), // 6A88 — empty scope
            other => return Err(ScllError::from_general_sw(other)),
        }
    }
    if !done {
        truncated = true; // MAX_STATUS_PAGES exhausted without a 9000
    }
    buf.truncate(good_len);
    Ok((buf, truncated))
}

/// Inputs to [`set_card_status`]. `current_state = None` triggers a GET STATUS
/// read first. `force` permits the spec-legal skip-ahead to `SECURED`
/// (§5.1.2); it never bypasses the `TERMINATED` or backward-transition refusal.
pub struct SetCardStatusArgs<'a> {
    pub target_state: CardLifeCycle,
    pub current_state: Option<CardLifeCycle>,
    pub force: bool,
    pub isd_aid: &'a [u8],
}

/// §5.11 — write the card (ISD) life-cycle state.
///
/// # Errors
/// Returns [`ScllError::TerminateOutOfScope`] if `target_state` is `TERMINATED`,
/// [`ScllError::IllegalLifecycleTransition`] for an illegal transition (or a
/// card `6985`), or a transport / backend / [`ScllError::Card`] error.
pub fn set_card_status<B>(
    t: &mut dyn Transport,
    backend: &B,
    session: &mut ScpSession,
    args: &SetCardStatusArgs<'_>,
) -> Result<SetCardStatusReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let current = match args.current_state {
        Some(s) => s,
        None => get_card_status(t, backend, session, args.isd_aid)?.state,
    };
    let plan = check_transition(current, args.target_state, args.force)?;
    let mut warnings: Vec<Warning, MAX_WARNINGS> = Vec::new();
    let (was_no_op, p2_state_byte) = match plan {
        TransitionPlan::NoOp => {
            let _ = warnings.push(Warning {
                kind: WarningKind::LifecycleNoOp,
                detail: String::new(),
            });
            (true, raw_byte(args.target_state))
        }
        TransitionPlan::Apply { p2 } => {
            let capdu = set_card_status_cmd(p2, args.isd_aid)?;
            let (_d, sw) = session::transmit_in_session(t, backend, session, &capdu)?;
            match sw {
                SW_OK => {}
                // 6985 means IllegalLifecycleTransition for SET STATUS (Table 11-87).
                SW_CONDITIONS => return Err(ScllError::IllegalLifecycleTransition),
                other => return Err(ScllError::from_general_sw(other)),
            }
            (false, p2)
        }
    };
    let irreversible = matches!(
        args.target_state,
        CardLifeCycle::Initialized | CardLifeCycle::Secured
    ) && current != CardLifeCycle::CardLocked;

    Ok(SetCardStatusReport {
        effective: SetCardStatusParams {
            state_before: current,
            target_state: args.target_state,
            p1_status_type: P1_ISD_SCOPE,
            p2_state_byte,
            was_no_op,
            force_used: args.force,
            irreversible,
        },
        warnings,
    })
}

/// Raw GP life-cycle byte for a [`CardLifeCycle`] (GPCS v2.3.1 Table 11-6).
fn raw_byte(s: CardLifeCycle) -> u8 {
    match s {
        CardLifeCycle::OpReady => 0x01,
        CardLifeCycle::Initialized => 0x07,
        CardLifeCycle::Secured => 0x0F,
        CardLifeCycle::CardLocked => 0x7F,
        CardLifeCycle::Terminated => 0xFF,
        CardLifeCycle::Unknown(b) => b,
    }
}
