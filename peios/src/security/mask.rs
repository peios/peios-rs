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
        /// `SeManageVolumePrivilege` — mount, unmount, and reshape the mount
        /// tree.
        ///
        /// Highly sensitive despite being an administrative rather than a TCB
        /// privilege: its holder may mount a filesystem whose synthesised
        /// security descriptors it chooses, and may mount over an existing
        /// path. Together that is enough to author policy on a subtree and to
        /// shadow a system path. Grant it nearer to `LOAD_DRIVER` than to
        /// `CHANGE_NOTIFY`.
        const MANAGE_VOLUME = sys::KACS_SE_MANAGE_VOLUME_PRIVILEGE as u64;
        /// `SeImpersonatePrivilege`.
        const IMPERSONATE = sys::KACS_SE_IMPERSONATE_PRIVILEGE as u64;
        /// `SeCreateSymbolicLinkPrivilege`.
        const CREATE_SYMBOLIC_LINK = sys::KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE;
        /// `SeBindPrivilegedPortPrivilege` — bind below the reserved port floor.
        ///
        /// The cast is load-bearing: this is the only privilege at bit 63, and
        /// `1ULL << 63` exceeds `i64::MAX`, so bindgen types it `i64` where the
        /// rest come through unsigned. `as u64` reinterprets the bit pattern,
        /// which is the value the header wrote — asserted in the tests below.
        const BIND_PRIVILEGED_PORT = sys::KACS_SE_BIND_PRIVILEGED_PORT_PRIVILEGE as u64;
    }
}

/// The canonical name of every privilege, paired with the bit it names.
///
/// **The bits come from the constants above, never from a literal.** That is the
/// whole point of this table living here: a name↔bit mapping written out by hand
/// drifts from the ABI silently, and has — `peinit` carried its own copy with
/// `SeCreateTokenPrivilege` recorded as bit 0 where the header says bit 2, along
/// with the same off-by-two for the three privileges after it. Nothing caught it
/// because a wrong bit still *is* a bit.
///
/// Order is by bit, matching `pkm/uapi/pkm/token.h`, so the two can be read side
/// by side.
const NAMES: &[(&str, Privileges)] = &[
    ("SeCreateTokenPrivilege", Privileges::CREATE_TOKEN),
    ("SeAssignPrimaryTokenPrivilege", Privileges::ASSIGN_PRIMARY_TOKEN),
    ("SeLockMemoryPrivilege", Privileges::LOCK_MEMORY),
    ("SeIncreaseQuotaPrivilege", Privileges::INCREASE_QUOTA),
    ("SeTcbPrivilege", Privileges::TCB),
    ("SeSecurityPrivilege", Privileges::SECURITY),
    ("SeLoadDriverPrivilege", Privileges::LOAD_DRIVER),
    ("SeSystemtimePrivilege", Privileges::SYSTEMTIME),
    (
        "SeProfileSingleProcessPrivilege",
        Privileges::PROFILE_SINGLE_PROCESS,
    ),
    (
        "SeIncreaseBasePriorityPrivilege",
        Privileges::INCREASE_BASE_PRIORITY,
    ),
    ("SeBackupPrivilege", Privileges::BACKUP),
    ("SeRestorePrivilege", Privileges::RESTORE),
    ("SeShutdownPrivilege", Privileges::SHUTDOWN),
    ("SeDebugPrivilege", Privileges::DEBUG),
    ("SeAuditPrivilege", Privileges::AUDIT),
    ("SeChangeNotifyPrivilege", Privileges::CHANGE_NOTIFY),
    ("SeRemoteShutdownPrivilege", Privileges::REMOTE_SHUTDOWN),
    ("SeManageVolumePrivilege", Privileges::MANAGE_VOLUME),
    ("SeImpersonatePrivilege", Privileges::IMPERSONATE),
    ("SeCreateSymbolicLinkPrivilege", Privileges::CREATE_SYMBOLIC_LINK),
    ("SeBindPrivilegedPortPrivilege", Privileges::BIND_PRIVILEGED_PORT),
];

impl Privileges {
    /// Look a privilege up by its canonical name.
    ///
    /// Names are matched **case-sensitively**. `SeTcbPrivilege` is an identifier
    /// from the ABI rather than a word an operator composes, every source that
    /// writes one is copying it from documentation, and accepting `setcbprivilege`
    /// would mean this function decides that two spellings name one privilege —
    /// a judgement that belongs to whatever is parsing, not to the table.
    ///
    /// Returns `None` for an unknown name, including one naming a privilege the
    /// kernel enforces but the ABI has not published: `SeTakeOwnershipPrivilege`
    /// and `SeRelabelPrivilege` are honoured by AccessCheck and named in audit
    /// output, yet absent from the headers this crate is built against, so they
    /// cannot be named here without hand-writing a bit. See PEI-186.
    pub fn parse_name(name: &str) -> Option<Privileges> {
        NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, privilege)| *privilege)
    }

    /// The canonical name of a single privilege.
    ///
    /// `None` when `self` is empty or holds more than one bit — a name describes
    /// one privilege, and a set of them has no single name. Use [`canonical_names`] for a
    /// mask.
    ///
    /// [`canonical_names`]: Privileges::canonical_names
    pub fn canonical_name(self) -> Option<&'static str> {
        if self.bits().count_ones() != 1 {
            return None;
        }
        NAMES
            .iter()
            .find(|(_, privilege)| *privilege == self)
            .map(|(name, _)| *name)
    }

    /// The canonical name of every named privilege in this mask, in bit order.
    ///
    /// Bits this crate has no name for are **skipped silently**, which is the
    /// right behaviour for what this is used for — rendering a token's privileges
    /// for a human. A token minted by something built against a newer ABI can
    /// legitimately carry a bit unknown here, and refusing to describe the rest
    /// of it would be worse than describing what is known.
    pub fn canonical_names(self) -> impl Iterator<Item = &'static str> {
        NAMES
            .iter()
            .filter(move |(_, privilege)| self.contains(*privilege))
            .map(|(name, _)| *name)
    }

    /// Every privilege this crate can name, in bit order.
    pub fn all_named() -> impl Iterator<Item = (&'static str, Privileges)> {
        NAMES.iter().copied()
    }
}

/// The mapping from the four generic rights to object-specific rights for one
/// object class. The canonical per-class mappings are [`crate::file::File`]'s and
/// [`crate::token::Token`]'s; custom mappings can be built with [`GenericMapping::new`].
#[derive(Debug, Clone, Copy)]
pub struct GenericMapping(pub(crate) sys::kacs_generic_mapping);

impl PartialEq for GenericMapping {
    fn eq(&self, other: &Self) -> bool {
        self.0.read == other.0.read
            && self.0.write == other.0.write
            && self.0.execute == other.0.execute
            && self.0.all == other.0.all
    }
}

impl Eq for GenericMapping {}

impl GenericMapping {
    /// Build a mapping from the masks the four generic rights expand to.
    pub fn new(read: u32, write: u32, execute: u32, all: u32) -> Self {
        GenericMapping(sys::kacs_generic_mapping {
            read,
            write,
            execute,
            all,
        })
    }

    pub(crate) fn from_raw(raw: sys::kacs_generic_mapping) -> Self {
        GenericMapping(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant the whole table exists to hold: it names every privilege
    /// this crate defines, and nothing else. A privilege added to the bitflags
    /// without a name here fails this rather than becoming quietly unnameable —
    /// which is exactly how `SeBindPrivilegedPortPrivilege` sat in the ABI
    /// unexposed.
    #[test]
    fn every_privilege_is_named_exactly_once() {
        let mut covered = Privileges::empty();
        for (name, privilege) in Privileges::all_named() {
            assert_eq!(
                privilege.bits().count_ones(),
                1,
                "{name} must name exactly one bit"
            );
            assert!(
                !covered.contains(privilege),
                "{name} names a bit already named"
            );
            covered |= privilege;
        }
        assert_eq!(
            covered,
            Privileges::all(),
            "the table and the bitflags disagree about which privileges exist"
        );
    }

    #[test]
    fn no_two_privileges_share_a_name() {
        let mut seen: Vec<&str> = Vec::new();
        for (name, _) in Privileges::all_named() {
            assert!(!seen.contains(&name), "{name} appears twice");
            seen.push(name);
        }
    }

    #[test]
    fn a_name_round_trips_through_its_bit() {
        for (name, privilege) in Privileges::all_named() {
            assert_eq!(Privileges::parse_name(name), Some(privilege));
            assert_eq!(privilege.canonical_name(), Some(name));
        }
    }

    /// The bits are the ABI's, not the table's. Spot-check the four `peinit`
    /// recorded wrongly — it had these as bits 0, 1, 2 and 3.
    #[test]
    fn the_low_privileges_carry_the_bits_the_abi_assigns() {
        assert_eq!(Privileges::CREATE_TOKEN.bits(), 1 << 2);
        assert_eq!(Privileges::ASSIGN_PRIMARY_TOKEN.bits(), 1 << 3);
        assert_eq!(Privileges::LOCK_MEMORY.bits(), 1 << 4);
        assert_eq!(Privileges::INCREASE_QUOTA.bits(), 1 << 5);
    }

    /// The one privilege whose constant crosses the signed boundary, so the
    /// `as u64` cast on it is checked rather than assumed.
    #[test]
    fn the_top_bit_privilege_survives_the_signed_crossing() {
        assert_eq!(Privileges::BIND_PRIVILEGED_PORT.bits(), 1u64 << 63);
        assert_eq!(
            Privileges::parse_name("SeBindPrivilegedPortPrivilege"),
            Some(Privileges::BIND_PRIVILEGED_PORT)
        );
    }

    #[test]
    fn an_unknown_name_is_none() {
        assert_eq!(Privileges::parse_name("SeNotAPrivilege"), None);
        assert_eq!(Privileges::parse_name(""), None);
        // Case-sensitive: an identifier from the ABI, not a word to compose.
        assert_eq!(Privileges::parse_name("setcbprivilege"), None);
        assert_eq!(Privileges::parse_name("SeTCBPrivilege"), None);
    }

    /// Privileges the kernel enforces but the ABI has not published. If either
    /// of these ever starts resolving, PEI-186 has landed and they should be in
    /// the table — with their bit taken from `sys::`, never written out here.
    #[test]
    fn the_unpublished_privileges_are_not_nameable() {
        assert_eq!(Privileges::parse_name("SeTakeOwnershipPrivilege"), None);
        assert_eq!(Privileges::parse_name("SeRelabelPrivilege"), None);
    }

    /// Mounting is gated on this privilege rather than on `TCB`, so it has to
    /// be nameable: the authd policy seed grants it to Administrators by name.
    #[test]
    fn manage_volume_round_trips_by_name() {
        assert_eq!(
            Privileges::parse_name("SeManageVolumePrivilege"),
            Some(Privileges::MANAGE_VOLUME),
        );
        assert_eq!(
            Privileges::MANAGE_VOLUME.canonical_name(),
            Some("SeManageVolumePrivilege"),
        );
        // Bit 28, following the Windows LUID numbering the catalog uses
        // throughout -- and distinct from TCB, which is the whole point.
        assert_eq!(Privileges::MANAGE_VOLUME.bits(), 1u64 << 28);
        assert!(!Privileges::MANAGE_VOLUME.intersects(Privileges::TCB));
    }

    #[test]
    fn a_set_of_privileges_has_no_single_name() {
        assert_eq!(Privileges::empty().canonical_name(), None);
        assert_eq!((Privileges::TCB | Privileges::BACKUP).canonical_name(), None);
    }

    #[test]
    fn names_lists_every_set_bit_and_nothing_else() {
        let mask = Privileges::TCB | Privileges::BACKUP | Privileges::CHANGE_NOTIFY;
        let named: Vec<_> = mask.canonical_names().collect();
        assert_eq!(
            named,
            ["SeTcbPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege"],
            "names must come back in bit order"
        );
        assert!(Privileges::empty().canonical_names().next().is_none());
    }

    /// A bit with no name must not stop the named ones being described — a
    /// token from a newer ABI is a thing that can legitimately exist.
    #[test]
    fn an_unnamed_bit_is_skipped_rather_than_breaking_the_rest() {
        let unnamed = Privileges::from_bits_retain(1 << 40);
        let mask = Privileges::TCB | unnamed;
        assert_eq!(mask.canonical_names().collect::<Vec<_>>(), ["SeTcbPrivilege"]);
    }
}
