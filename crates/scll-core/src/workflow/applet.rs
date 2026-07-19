//! Steps 7 / 8 — `install_applet`, `delete_applet` (PDD §5.7/§5.8).
//!
//! `install_applet`: INSTALL [for Install and Make Selectable] (P1 `0x0C`) from
//! a LOADED ELF; refuses DAP / Mandated-DAP / Delegated-Management / Security-
//! Domain privileges (GPCS v2.3.1 Table 6-2). The Install-Params field is
//! assembled here: mandatory `'C9'` application params, optionally followed by
//! an `'EF'` system-params TLV. `delete_applet`: DELETE [object] for the
//! instance, with a library-side ELF cascade (`Never` / `IfLastInstance` /
//! `Always`) — distinct from §5.5's card-side cascade. `IfLastInstance` cannot
//! be pre-checked without the inventory, so a blocked ELF delete surfaces as the
//! card's `6985` → [`ScllError::ElfHasOtherInstances`].

use heapless::Vec;

use crate::aid::Aid;
use crate::backend::{Scp02Backend, Scp03Backend};
use crate::command::delete::delete_object;
use crate::command::install::{install_for_install_make_selectable, PrivLen};
use crate::error::ScllError;
use crate::limits::{INSTALL_PARAMS_MAX, MAX_REMOVED_OBJECTS};
use crate::report::{
    DeleteCascade, DeleteObjectParams, DeleteObjectReport, DeleteTargetKind, InstallAppletParams,
    InstallAppletReport,
};
use crate::scp::ScpSession;
use crate::transport::Transport;
use crate::workflow::session::{self, SW_CONDITIONS, SW_OK, SW_REF_NOT_FOUND, SW_WRONG_DATA};

/// Application-specific install-params TLV tag (GPCS v2.3.1 §11.5.2.3.7).
const TAG_C9_APP_PARAMS: u8 = 0xC9;
/// System install-params TLV tag (`'EF'`).
const TAG_EF_SYS_PARAMS: u8 = 0xEF;
/// Privileges an applet instance must NOT carry (GPCS Table 6-2, byte 1):
/// Security Domain (`0x80`), DAP (`0x40`), Delegated Mgmt (`0x20`),
/// Mandated DAP (`0x01`).
const PRIV_REFUSED_MASK: u8 = 0x80 | 0x40 | 0x20 | 0x01;

/// Inputs to [`install_applet`].
pub struct InstallAppletArgs<'a> {
    pub parent_sd_aid: &'a [u8],
    pub package_aid: &'a [u8],
    pub module_aid: &'a [u8],
    pub instance_aid: &'a [u8],
    pub privileges: [u8; 3],
    pub system_install_params: &'a [u8],
    pub applet_install_params: &'a [u8],
}

/// §5.7 — instantiate an applet from a loaded ELF into an SSD.
///
/// # Errors
/// [`ScllError::UnsupportedPrivilege`] for a refused privilege,
/// [`ScllError::PackageNotFound`] (`6A88`), [`ScllError::AidAlreadyExists`]
/// (`6A80`), or a transport / backend / [`ScllError::Card`] error.
pub fn install_applet<B>(
    t: &mut dyn Transport,
    backend: &B,
    parent_session: &mut ScpSession,
    args: &InstallAppletArgs<'_>,
    priv_len: PrivLen,
) -> Result<InstallAppletReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    if args.privileges[0] & PRIV_REFUSED_MASK != 0 {
        return Err(ScllError::UnsupportedPrivilege);
    }
    let params = build_install_params(args.applet_install_params, args.system_install_params)?;
    let capdu = install_for_install_make_selectable(
        args.package_aid,
        args.module_aid,
        args.instance_aid,
        args.privileges,
        priv_len,
        &params,
    )?;
    let (_d, sw) = session::transmit_in_session(t, backend, parent_session, &capdu)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::PackageNotFound),
        SW_WRONG_DATA => return Err(ScllError::AidAlreadyExists),
        other => return Err(ScllError::from_general_sw(other)),
    }
    Ok(InstallAppletReport {
        effective: InstallAppletParams {
            instance_aid: Aid::new(args.instance_aid)?,
            package_aid_used: Aid::new(args.package_aid)?,
            module_aid_used: Aid::new(args.module_aid)?,
            privileges_used: args.privileges,
            system_install_params: copy_bounded::<INSTALL_PARAMS_MAX>(args.system_install_params)?,
            applet_install_params: copy_bounded::<INSTALL_PARAMS_MAX>(args.applet_install_params)?,
            parent_sd_aid: Aid::new(args.parent_sd_aid)?,
        },
        warnings: Vec::new(),
    })
}

/// Inputs to [`delete_applet`]. `elf_aid` is required to cascade the ELF;
/// `cascade_elf` selects whether (and conceptually when) the ELF is removed.
pub struct DeleteAppletArgs<'a> {
    pub instance_aid: &'a [u8],
    pub elf_aid: Option<&'a [u8]>,
    pub cascade_elf: DeleteCascade,
}

/// §5.8 — delete an applet instance, optionally cascading its ELF.
///
/// # Errors
/// [`ScllError::ElfHasOtherInstances`] if an ELF cascade is blocked (`6985`),
/// [`ScllError::TargetNoLongerExists`] (`6A88`), or a transport / backend /
/// [`ScllError::Card`] error.
pub fn delete_applet<B>(
    t: &mut dyn Transport,
    backend: &B,
    parent_session: &mut ScpSession,
    args: &DeleteAppletArgs<'_>,
) -> Result<DeleteObjectReport, ScllError>
where
    B: Scp02Backend + Scp03Backend,
{
    // Delete the instance (object only).
    let capdu = delete_object(args.instance_aid, false)?;
    let (_d, sw) = session::transmit_in_session(t, backend, parent_session, &capdu)?;
    match sw {
        SW_OK => {}
        SW_REF_NOT_FOUND => return Err(ScllError::TargetNoLongerExists),
        other => return Err(ScllError::from_general_sw(other)),
    }
    let mut instances_removed: Vec<Aid, MAX_REMOVED_OBJECTS> = Vec::new();
    let _ = instances_removed.push(Aid::new(args.instance_aid)?);

    // Optional ELF cascade.
    let mut elfs_removed: Vec<Aid, MAX_REMOVED_OBJECTS> = Vec::new();
    let want_cascade = matches!(
        args.cascade_elf,
        DeleteCascade::Always | DeleteCascade::IfLastInstance
    );
    let mut cascade_used = false;
    if want_cascade {
        if let Some(elf) = args.elf_aid {
            let ecapdu = delete_object(elf, false)?;
            let (_ed, esw) = session::transmit_in_session(t, backend, parent_session, &ecapdu)?;
            match esw {
                SW_OK => {
                    let _ = elfs_removed.push(Aid::new(elf)?);
                    cascade_used = true;
                }
                // Other instances still depend on the ELF (Table 11-26).
                SW_CONDITIONS => return Err(ScllError::ElfHasOtherInstances),
                SW_REF_NOT_FOUND => return Err(ScllError::TargetNoLongerExists),
                other => return Err(ScllError::from_general_sw(other)),
            }
        }
    }

    Ok(DeleteObjectReport {
        effective: DeleteObjectParams {
            target_aid: Aid::new(args.instance_aid)?,
            target_kind: DeleteTargetKind::AppletInstance,
            cascade_requested: args.cascade_elf,
            cascade_used,
            instances_removed,
            elfs_removed,
        },
        warnings: Vec::new(),
    })
}

/// Assemble the Install-Params field: `'C9' La app_params [ 'EF' Ls sys_params ]`.
fn build_install_params(
    app_params: &[u8],
    sys_params: &[u8],
) -> Result<Vec<u8, INSTALL_PARAMS_MAX>, ScllError> {
    let mut out: Vec<u8, INSTALL_PARAMS_MAX> = Vec::new();
    push_tlv(&mut out, TAG_C9_APP_PARAMS, app_params)?;
    if !sys_params.is_empty() {
        push_tlv(&mut out, TAG_EF_SYS_PARAMS, sys_params)?;
    }
    Ok(out)
}

/// Short-hand for the only build error these helpers can raise.
fn overflow() -> ScllError {
    ScllError::Build(crate::command::BuildError::Overflow)
}

/// Push a 1-byte-length BER-TLV (`tag len value`); overflow ⇒ [`ScllError::Build`].
fn push_tlv<const N: usize>(out: &mut Vec<u8, N>, tag: u8, value: &[u8]) -> Result<(), ScllError> {
    let len = u8::try_from(value.len()).map_err(|_| overflow())?;
    out.push(tag).map_err(|_| overflow())?;
    out.push(len).map_err(|_| overflow())?;
    out.extend_from_slice(value).map_err(|()| overflow())
}

/// Copy a slice into a fresh bounded buffer; [`ScllError::Build`] overflow if too long.
fn copy_bounded<const N: usize>(src: &[u8]) -> Result<Vec<u8, N>, ScllError> {
    let mut v: Vec<u8, N> = Vec::new();
    v.extend_from_slice(src).map_err(|()| overflow())?;
    Ok(v)
}
