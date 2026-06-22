//! The KACS security vocabulary shared by every interface: SIDs, access masks,
//! privileges, ACLs/ACEs, and security descriptors.
//!
//! These are the currency of tokens, files, access checks, and registry-key
//! security. SIDs ([`Sid`]/[`SidRef`]) are owned-or-borrowed identifiers; ACLs
//! and security descriptors are assembled with sticky-error builders
//! ([`AclBuilder`], [`SdBuilder`]) and read back with zero-copy views
//! ([`SdView`], [`AclView`], …).

mod acl;
mod mask;
mod sd;
pub mod sddl;
mod sid;

pub use acl::{Ace, AceFlags, AceType, AceView, Acl, AclBuilder, AclView, LabelPolicy, SidAndAttributes, SidArrayView};
pub use mask::{AccessMask, GenericMapping, Privileges};
pub use sd::{Control, SdBuilder, SdView, SecurityDescriptor};
pub use sid::{IntegrityLevel, Sid, SidRef, WellKnown};
// SD inheritance reads naturally at the security root; the SDDL text codec
// stays namespaced under `security::sddl`.
pub use sddl::{reinherit, strip_inherited};

// Internal helpers other modules reach for.
pub(crate) use sid::raw as sid_raw;
