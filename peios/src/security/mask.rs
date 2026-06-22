//! Access masks, privileges, and generic-right mapping.
//!
//! A KACS access mask is 32 bits: the low half is object-specific (the
//! per-class right sets live in their own modules — [`FileAccess`] in
//! [`crate::file`], [`KeyAccess`] in [`crate::registry`]), and the high half is
//! the standard and generic rights shared by every object, modelled here by
//! [`AccessMask`]. The four generic bits are folded into object-specific rights
//! by a per-class [`GenericMapping`].
//!
//! [`FileAccess`]: crate::file::FileAccess
//! [`KeyAccess`]: crate::registry::KeyAccess

use bitflags::bitflags;
use peios_sys as sys;

bitflags! {
    /// The standard and generic rights common to every securable object.
    ///
    /// Object-specific rights (file, key, token, …) are separate types that
    /// `Into<u32>`-combine with these in the final desired-access mask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AccessMask: u32 {
        /// Delete the object.
        const DELETE = sys::KACS_ACCESS_DELETE;
        /// Read the security descriptor (owner, group, DACL).
        const READ_CONTROL = sys::KACS_ACCESS_READ_CONTROL;
        /// Write the DACL.
        const WRITE_DAC = sys::KACS_ACCESS_WRITE_DAC;
        /// Change the owner.
        const WRITE_OWNER = sys::KACS_ACCESS_WRITE_OWNER;
        /// Synchronize (wait) on the object.
        const SYNCHRONIZE = sys::KACS_ACCESS_SYNCHRONIZE;
        /// Access the SACL (audit). Needs the privilege.
        const ACCESS_SYSTEM_SECURITY = sys::KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
        /// Resolve to the maximum the caller is allowed at open time.
        const MAXIMUM_ALLOWED = sys::KACS_ACCESS_MAXIMUM_ALLOWED;
        /// Generic "all" — mapped to object-specific rights at the boundary.
        const GENERIC_ALL = sys::KACS_ACCESS_GENERIC_ALL;
        /// Generic "execute".
        const GENERIC_EXECUTE = sys::KACS_ACCESS_GENERIC_EXECUTE;
        /// Generic "write".
        const GENERIC_WRITE = sys::KACS_ACCESS_GENERIC_WRITE;
        /// Generic "read".
        const GENERIC_READ = sys::KACS_ACCESS_GENERIC_READ;
    }
}

impl AccessMask {
    /// Fold this mask's generic bits into object-specific rights using `mapping`,
    /// clearing the generic bits. The result is the concrete mask the kernel sees.
    pub fn resolve_generic(self, mapping: &GenericMapping) -> AccessMask {
        // SAFETY: `mapping.0` is a plain POD struct passed by const pointer.
        let bits = unsafe { sys::peios_access_map_generic(self.bits(), &mapping.0) };
        AccessMask::from_bits_retain(bits)
    }
}

bitflags! {
    /// A set of KACS privileges (`SeCreateTokenPrivilege`, `SeTcbPrivilege`, …),
    /// the 64-bit privilege bitmask carried by a token.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Privileges: u64 {
        /// `SeCreateTokenPrivilege`.
        const CREATE_TOKEN = sys::KACS_SE_CREATE_TOKEN_PRIVILEGE as u64;
        /// `SeAssignPrimaryTokenPrivilege`.
        const ASSIGN_PRIMARY_TOKEN = sys::KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE as u64;
        /// `SeLockMemoryPrivilege`.
        const LOCK_MEMORY = sys::KACS_SE_LOCK_MEMORY_PRIVILEGE as u64;
        /// `SeIncreaseQuotaPrivilege`.
        const INCREASE_QUOTA = sys::KACS_SE_INCREASE_QUOTA_PRIVILEGE as u64;
        /// `SeTcbPrivilege` — act as part of the trusted computing base.
        const TCB = sys::KACS_SE_TCB_PRIVILEGE as u64;
        /// `SeSecurityPrivilege` — manage auditing and the security log.
        const SECURITY = sys::KACS_SE_SECURITY_PRIVILEGE as u64;
        /// `SeLoadDriverPrivilege`.
        const LOAD_DRIVER = sys::KACS_SE_LOAD_DRIVER_PRIVILEGE as u64;
        /// `SeSystemtimePrivilege`.
        const SYSTEMTIME = sys::KACS_SE_SYSTEMTIME_PRIVILEGE as u64;
        /// `SeProfileSingleProcessPrivilege`.
        const PROFILE_SINGLE_PROCESS = sys::KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE as u64;
        /// `SeIncreaseBasePriorityPrivilege`.
        const INCREASE_BASE_PRIORITY = sys::KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE as u64;
        /// `SeBackupPrivilege`.
        const BACKUP = sys::KACS_SE_BACKUP_PRIVILEGE as u64;
        /// `SeRestorePrivilege`.
        const RESTORE = sys::KACS_SE_RESTORE_PRIVILEGE as u64;
        /// `SeShutdownPrivilege`.
        const SHUTDOWN = sys::KACS_SE_SHUTDOWN_PRIVILEGE as u64;
        /// `SeDebugPrivilege`.
        const DEBUG = sys::KACS_SE_DEBUG_PRIVILEGE as u64;
        /// `SeAuditPrivilege` — emit KMES events.
        const AUDIT = sys::KACS_SE_AUDIT_PRIVILEGE as u64;
        /// `SeChangeNotifyPrivilege`.
        const CHANGE_NOTIFY = sys::KACS_SE_CHANGE_NOTIFY_PRIVILEGE as u64;
        /// `SeRemoteShutdownPrivilege`.
        const REMOTE_SHUTDOWN = sys::KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE as u64;
        /// `SeImpersonatePrivilege`.
        const IMPERSONATE = sys::KACS_SE_IMPERSONATE_PRIVILEGE as u64;
        /// `SeCreateSymbolicLinkPrivilege`.
        const CREATE_SYMBOLIC_LINK = sys::KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE;
    }
}

/// The mapping from the four generic rights to object-specific rights for one
/// object class. The canonical per-class mappings are [`crate::file::File`]'s and
/// [`crate::token::Token`]'s; custom mappings can be built with [`GenericMapping::new`].
#[derive(Debug, Clone, Copy)]
pub struct GenericMapping(pub(crate) sys::kacs_generic_mapping);

impl GenericMapping {
    /// Build a mapping from the masks the four generic rights expand to.
    pub fn new(read: u32, write: u32, execute: u32, all: u32) -> Self {
        GenericMapping(sys::kacs_generic_mapping { read, write, execute, all })
    }

    pub(crate) fn from_raw(raw: sys::kacs_generic_mapping) -> Self {
        GenericMapping(raw)
    }
}
