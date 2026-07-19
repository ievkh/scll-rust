//! High-level workflow — PDD §5 (steps 1–12).
//!
//! Each function borrows `&mut dyn Transport` and (for channel steps) a backend
//! and an open [`crate::scp::ScpSession`], performs the pre-flight checks of its
//! §5 subsection, drives the §command builders through the §scp session, and
//! returns `Result<XReport, ScllError>` (§7/§8). No success payload is reachable
//! on the error path.
//!
//! Channel steps are generic over `B: KeyBackend + Scp02Backend + Scp03Backend`
//! (Fork F-A): the open session may be either variant, so wrap/unwrap needs both
//! backend traits. Pre-auth steps (`probe`, `discover_card`) take no backend.
//! All per-step inputs are borrowed `*Args` structs (Fork F-C/D); the shared
//! transport/SCP plumbing lives in [`session`] (Fork F-B).

pub mod applet; // §5.7 install_applet, §5.8 delete_applet
pub mod card_status; // §5.11 set_card_status, §5.12 get_card_status, §5.12a get_card_inventory
pub mod discover; // §5.2  discover_card
pub mod keys; // §5.3/§5.6  put/delete key core + ISD/SSD wrappers
pub mod open_scp; // §5.9  open_scp
pub mod probe; // §5.1  transport probe
pub mod session; // shared SELECT + in-session transmit plumbing
pub mod ssd; // §5.4 create_ssd, §5.4a load_package, §5.5 delete_ssd
pub mod transmit; // §5.10 applet APDU exchange

// --- Flat re-export of the public workflow surface (PDD §5) ---
pub use applet::{delete_applet, install_applet, DeleteAppletArgs, InstallAppletArgs};
pub use card_status::{get_card_inventory, get_card_status, set_card_status, SetCardStatusArgs};
pub use discover::discover_card;
pub use keys::{delete_sd_keyset, put_sd_keys, NewKeyset, PutSdKeysArgs};
pub use open_scp::{open_scp, OpenScpArgs, SdKeys};
pub use probe::probe;
pub use ssd::{create_ssd, delete_ssd, load_package, CreateSsdArgs, LoadPackageArgs};
pub use transmit::transmit;
