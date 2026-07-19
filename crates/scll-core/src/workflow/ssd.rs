//! Steps 4 / 4a / 5 — SSD create, package load, SSD delete (PDD §5.4/§5.4a/§5.5).
//!
//! `create_ssd`: INSTALL [for Install and Make Selectable] (P1 `0x0C`) on a
//! resident SD module; refuses DAP / Mandated-DAP / Delegated-Management
//! privileges (GPCS v2.3.1 Table 6-2). `load_package`: library-internal CAP
//! parse → INSTALL [for Load] + chunked LOAD (240 B, ≤256 blocks), streaming the
//! Load File Data Block through `cap::LoadFileDataBlock::next_block` — the whole
//! LFDB is never materialised. `delete_ssd`: DELETE with explicit
//! non-cascading vs cascading scope.
//!
//! `no_std` / crypto-free: the LFDB hash is **not** computed here (hashing is a
//! crypto concern); the caller supplies `lfdb_hash` (empty ⇒ `Lh = 00`, accepted
//! under Authorized Management). The 32 KiB inflate window is lent via
//! [`InflateCtx`]; the per-block scratch is one stack-resident `LOAD_BLOCK_DATA`
//! buffer. `ParentLacksAm` and the specific non-empty-SSD sub-error need the
//! inventory snapshot that fast discovery skips; the card's SW is authoritative.

use heapless::Vec;

use crate::aid::Aid;
use crate::backend::{Scp02Backend, Scp03Backend};
use crate::cap::{parse as cap_parse, InflateCtx};
use crate::command::delete::delete_object;
use crate::command::install::{install_for_install_make_selectable, install_for_load, PrivLen};
use crate::command::load::load_block;
use crate::error::ScllError;
use crate::limits::{HASH_MAX, INSTALL_PARAMS_MAX, LOAD_BLOCK_DATA};
use crate::report::{
    CreateSsdParams, CreateSsdReport, DeleteCascade, DeleteObjectParams, DeleteObjectReport,
    DeleteTargetKind, LoadPackageParams, LoadPackageReport,
};
use crate::scp::ScpSession;
use crate::transport::Transport;
use crate::workflow::session::{self, SW_CONDITIONS, SW_OK, SW_REF_NOT_FOUND, SW_WRONG_DATA};

/// Privileges an SSD created here must NOT carry (GPCS v2.3.1 Table 6-2,
/// privilege byte 1): DAP Verification (`0x40`), Delegated Management (`0x20`),
/// Mandated DAP Verification (`0x01`).
const PRIV_REFUSED_MASK: u8 = 0x40 | 0x20 | 0x01;
/// Short-APDU LOAD budget: ≤256 blocks of `LOAD_BLOCK_DATA` (PDD §5.4a).
const MAX_LOAD_BYTES: usize = 256 * LOAD_BLOCK_DATA;

/// Inputs to [`create_ssd`].
pub struct CreateSsdArgs<'a> {
    pub parent_sd_aid: &'a [u8],
    pub ssd_aid: &'a [u8],
    pub elf_aid: &'a [u8],
    pub module_aid: &'a [u8],
    pub privileges: [u8; 3],
    /// Complete Install-Params field value (must already contain the mandatory
    /// `'C9'` TLV, e.g. `C9 00`).
    pub install_params: &'a [u8],
}

/// §5.4 — create a Supplementary Security Domain under a parent SD.
///
/// # Errors
/// [`ScllError::UnsupportedPrivilege`] for a refused privilege,
/// [`ScllError::ResidentSdNotFound`] (`6A88`), [`ScllError::AidAlreadyExists`]
/// (`6A80`), or a transport / backend / [`ScllError::Card`] error.
pub fn create_ssd<B>(
    t: &mut dyn Transport,
    backend: &B,
    parent_session: &mut ScpSession,
    args: &CreateSsdArgs<'_>,
    priv_len: PrivLen,
) -> Result<CreateSsdReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    if args.privileges[0] & PRIV_REFUSED_MASK != 0 {
        return Err(ScllError::UnsupportedPrivilege);
    }
    let capdu = install_for_install_make_selectable(
        args.elf_aid,
        args.module_aid,
        args.ssd_aid,
        args.privileges,
        priv_len,
        args.install_params,
    )?;
    let (_d, sw) = session::transmit_in_session(t, backend, parent_session, &capdu)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::ResidentSdNotFound),
        SW_WRONG_DATA => return Err(ScllError::AidAlreadyExists),
        other => return Err(ScllError::from_general_sw(other)),
    }
    Ok(CreateSsdReport {
        effective: CreateSsdParams {
            ssd_aid_effective: Aid::new(args.ssd_aid)?,
            aid_was_generated: false,
            parent_sd_aid: Aid::new(args.parent_sd_aid)?,
            privileges_used: args.privileges,
            elf_aid_used: Aid::new(args.elf_aid)?,
            module_aid_used: Aid::new(args.module_aid)?,
            install_params_used: copy_bounded::<INSTALL_PARAMS_MAX>(args.install_params)?,
        },
        warnings: Vec::new(),
    })
}

/// Inputs to [`load_package`]. `cap_zip` is the borrowed CAP (a ZIP; STORED or
/// DEFLATE). `lfdb_hash` may be empty (`Lh = 00`).
pub struct LoadPackageArgs<'a> {
    pub target_sd_aid: &'a [u8],
    pub cap_zip: &'a [u8],
    pub lfdb_hash: &'a [u8],
}

/// §5.4a — load a CAP file under a target SD. `infl` lends the 32 KiB DEFLATE
/// window (allocate once; large).
///
/// # Errors
/// [`ScllError::Cap`] if the CAP cannot be parsed, [`ScllError::LoadTooLarge`]
/// if it exceeds the short-APDU LOAD budget, [`ScllError::ResidentSdNotFound`]
/// (`6A88`), [`ScllError::PackageAidExists`] (`6A80`), or a transport / backend /
/// [`ScllError::Card`] error.
pub fn load_package<B>(
    t: &mut dyn Transport,
    backend: &B,
    parent_session: &mut ScpSession,
    args: &LoadPackageArgs<'_>,
    infl: &mut InflateCtx,
) -> Result<LoadPackageReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let cap = cap_parse(args.cap_zip, infl)?;
    let package_aid = cap.package_aid.clone();
    let total = cap.lfdb().len();
    if total > MAX_LOAD_BYTES {
        return Err(ScllError::LoadTooLarge);
    }

    // INSTALL [for Load].
    let install = install_for_load(package_aid.as_bytes(), args.target_sd_aid, args.lfdb_hash)?;
    let (_d, sw) = session::transmit_in_session(t, backend, parent_session, &install)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::ResidentSdNotFound),
        SW_WRONG_DATA => return Err(ScllError::PackageAidExists),
        other => return Err(ScllError::from_general_sw(other)),
    }

    // Stream the LFDB through chunked LOAD.
    infl.reset();
    let mut lfdb = cap.lfdb();
    let mut out = [0u8; LOAD_BLOCK_DATA];
    let mut sent = 0usize;
    let mut block_no = 0u8;
    let mut blocks_sent = 0u16;
    loop {
        let n = lfdb.next_block(infl, &mut out)?;
        if n == 0 {
            break;
        }
        sent += n;
        let last = sent >= total;
        let capdu = load_block(block_no, last, &out[..n])?;
        let (_ld, lsw) = session::transmit_in_session(t, backend, parent_session, &capdu)?;
        if lsw != SW_OK {
            return Err(ScllError::from_general_sw(lsw));
        }
        block_no = block_no.wrapping_add(1);
        blocks_sent += 1;
        if last {
            break;
        }
    }

    Ok(LoadPackageReport {
        effective: LoadPackageParams {
            package_aid,
            load_file_size: u32::try_from(total).unwrap_or(u32::MAX),
            hash_value: copy_bounded::<HASH_MAX>(args.lfdb_hash)?,
            block_count: blocks_sent,
            target_sd_aid: Aid::new(args.target_sd_aid)?,
        },
        warnings: Vec::new(),
    })
}

/// §5.5 — delete an SSD (optionally cascading its contents).
///
/// # Errors
/// [`ScllError::SsdHasApplets`] if a non-cascading delete hits a non-empty SSD
/// (`6985`; the precise sub-error needs the inventory), [`ScllError::TargetNoLongerExists`]
/// (`6A88`), or a transport / backend / [`ScllError::Card`] error.
pub fn delete_ssd<B>(
    t: &mut dyn Transport,
    backend: &B,
    parent_session: &mut ScpSession,
    ssd_aid: &[u8],
    cascade: DeleteCascade,
) -> Result<DeleteObjectReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    let cascade_flag = matches!(cascade, DeleteCascade::Cascade | DeleteCascade::Always);
    let capdu = delete_object(ssd_aid, cascade_flag)?;
    let (_d, sw) = session::transmit_in_session(t, backend, parent_session, &capdu)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::TargetNoLongerExists),
        SW_CONDITIONS if !cascade_flag => return Err(ScllError::SsdHasApplets),
        other => return Err(ScllError::from_general_sw(other)),
    }
    Ok(DeleteObjectReport {
        effective: DeleteObjectParams {
            target_aid: Aid::new(ssd_aid)?,
            target_kind: DeleteTargetKind::Ssd,
            cascade_requested: cascade,
            cascade_used: cascade_flag,
            instances_removed: Vec::new(),
            elfs_removed: Vec::new(),
        },
        warnings: Vec::new(),
    })
}

/// Copy a slice into a fresh bounded buffer; [`ScllError::Build`] overflow if too long.
fn copy_bounded<const N: usize>(src: &[u8]) -> Result<Vec<u8, N>, ScllError> {
    let mut v = Vec::new();
    v.extend_from_slice(src)
        .map_err(|()| ScllError::Build(crate::command::BuildError::Overflow))?;
    Ok(v)
}
