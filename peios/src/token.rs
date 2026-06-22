//! KACS access tokens, the token-spec builder, and logon sessions.
//!
//! A [`Token`] is an fd-backed handle (so it `impl`s [`AsFd`] and drops cleanly).
//! Tokens are opened from the running thread/process/peer, or minted from a spec
//! assembled by [`TokenBuilder`]. Queries read a token's contents by information
//! class; the adjust/transform calls duplicate, restrict, impersonate, and
//! install tokens. [`Session`] covers the logon-session bookkeeping a token
//! references.

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::{
    GenericMapping, IntegrityLevel, Privileges, Sid, SidArrayView, SidRef,
};
use crate::util::{check, check_fd, check_len, probe};

bitflags! {
    /// Token handle-right mask: the token-object rights plus the standard rights.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TokenAccess: u32 {
        /// Assign as a process primary token.
        const ASSIGN_PRIMARY = sys::KACS_TOKEN_ASSIGN_PRIMARY;
        /// Duplicate the token.
        const DUPLICATE = sys::KACS_TOKEN_DUPLICATE;
        /// Impersonate with the token.
        const IMPERSONATE = sys::KACS_TOKEN_IMPERSONATE;
        /// Query token information classes.
        const QUERY = sys::KACS_TOKEN_QUERY;
        /// Query the token source.
        const QUERY_SOURCE = sys::KACS_TOKEN_QUERY_SOURCE;
        /// Adjust privileges.
        const ADJUST_PRIVS = sys::KACS_TOKEN_ADJUST_PRIVS;
        /// Adjust groups.
        const ADJUST_GROUPS = sys::KACS_TOKEN_ADJUST_GROUPS;
        /// Adjust the default DACL / owner / group.
        const ADJUST_DEFAULT = sys::KACS_TOKEN_ADJUST_DEFAULT;
        /// Adjust the session id.
        const ADJUST_SESSIONID = sys::KACS_TOKEN_ADJUST_SESSIONID;
        /// All token rights.
        const ALL_ACCESS = sys::KACS_TOKEN_ALL_ACCESS;
        /// Standard: delete.
        const DELETE = sys::KACS_ACCESS_DELETE;
        /// Standard: read the security descriptor.
        const READ_CONTROL = sys::KACS_ACCESS_READ_CONTROL;
        /// Standard: write the DACL.
        const WRITE_DAC = sys::KACS_ACCESS_WRITE_DAC;
        /// Standard: change the owner.
        const WRITE_OWNER = sys::KACS_ACCESS_WRITE_OWNER;
    }
}

bitflags! {
    /// A token's mandatory-integrity policy bits (the spec `mandatory_policy`
    /// field / `KACS_TOKEN_CLASS_MANDATORY_POLICY`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MandatoryPolicy: u32 {
        /// Forbid write-up across the integrity boundary.
        const NO_WRITE_UP = sys::KACS_TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
        /// New processes start at the minimum of the creator and the executable.
        const NEW_PROCESS_MIN = sys::KACS_TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
    }
}

bitflags! {
    /// Per-token audit-policy bits: which access-check outcomes the token audits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AuditPolicy: u32 {
        /// Audit successful object-access checks.
        const OBJECT_ACCESS_SUCCESS = sys::KACS_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS;
        /// Audit failed object-access checks.
        const OBJECT_ACCESS_FAILURE = sys::KACS_AUDIT_POLICY_OBJECT_ACCESS_FAILURE;
        /// Audit successful privilege use.
        const PRIVILEGE_USE_SUCCESS = sys::KACS_AUDIT_POLICY_PRIVILEGE_USE_SUCCESS;
        /// Audit failed privilege use.
        const PRIVILEGE_USE_FAILURE = sys::KACS_AUDIT_POLICY_PRIVILEGE_USE_FAILURE;
    }
}

bitflags! {
    /// Claim attribute bits (`KACS_CLAIM_ATTR_*`) for a [`Claim`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ClaimAttr: u32 {
        /// String comparisons against this claim are case-sensitive.
        const CASE_SENSITIVE = sys::KACS_CLAIM_ATTR_CASE_SENSITIVE;
        /// The claim is usable only to deny access, never to grant it.
        const USE_FOR_DENY_ONLY = sys::KACS_CLAIM_ATTR_USE_FOR_DENY_ONLY;
        /// The claim is present but disabled.
        const DISABLED = sys::KACS_CLAIM_ATTR_DISABLED;
    }
}

bitflags! {
    /// Flags for [`Token::restrict`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RestrictFlags: u32 {
        /// Mark the resulting token write-restricted: restricting SIDs must also
        /// grant access on writes, not just reads.
        const WRITE_RESTRICTED = sys::KACS_TOKEN_RESTRICT_WRITE_RESTRICTED;
    }
}

/// The kind of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// A primary token (assignable to a process).
    Primary,
    /// An impersonation token.
    Impersonation,
}

impl TokenType {
    fn to_raw(self) -> u8 {
        match self {
            TokenType::Primary => sys::KACS_TOKEN_TYPE_PRIMARY as u8,
            TokenType::Impersonation => sys::KACS_TOKEN_TYPE_IMPERSONATION as u8,
        }
    }
    fn from_raw(v: u32) -> Option<TokenType> {
        match v {
            sys::KACS_TOKEN_TYPE_PRIMARY => Some(TokenType::Primary),
            sys::KACS_TOKEN_TYPE_IMPERSONATION => Some(TokenType::Impersonation),
            _ => None,
        }
    }
}

/// The impersonation level of an impersonation token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImpersonationLevel {
    /// Anonymous — the server cannot identify the client.
    Anonymous,
    /// Identification — identify but not act as the client.
    Identification,
    /// Impersonation — act as the client on the local system.
    Impersonation,
    /// Delegation — act as the client on remote systems.
    Delegation,
}

impl ImpersonationLevel {
    fn to_raw(self) -> u8 {
        match self {
            ImpersonationLevel::Anonymous => sys::KACS_IMLEVEL_ANONYMOUS as u8,
            ImpersonationLevel::Identification => sys::KACS_IMLEVEL_IDENTIFICATION as u8,
            ImpersonationLevel::Impersonation => sys::KACS_IMLEVEL_IMPERSONATION as u8,
            ImpersonationLevel::Delegation => sys::KACS_IMLEVEL_DELEGATION as u8,
        }
    }
}

/// A token information class, for the generic [`Token::query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenClass(pub u32);

impl TokenClass {
    /// The user SID class.
    pub const USER: Self = Self(sys::KACS_TOKEN_CLASS_USER);
    /// The groups (SID-and-attributes array) class.
    pub const GROUPS: Self = Self(sys::KACS_TOKEN_CLASS_GROUPS);
    /// The privileges class.
    pub const PRIVILEGES: Self = Self(sys::KACS_TOKEN_CLASS_PRIVILEGES);
    /// The restricted-SIDs array class.
    pub const RESTRICTED_SIDS: Self = Self(sys::KACS_TOKEN_CLASS_RESTRICTED_SIDS);
    /// The device-groups array class.
    pub const DEVICE_GROUPS: Self = Self(sys::KACS_TOKEN_CLASS_DEVICE_GROUPS);
    /// The capabilities array class.
    pub const CAPABILITIES: Self = Self(sys::KACS_TOKEN_CLASS_CAPABILITIES);
    /// The default-DACL class.
    pub const DEFAULT_DACL: Self = Self(sys::KACS_TOKEN_CLASS_DEFAULT_DACL);
}

/// A token's four privilege words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeSet {
    /// Privileges present on the token.
    pub present: Privileges,
    /// Privileges currently enabled.
    pub enabled: Privileges,
    /// Privileges enabled by default.
    pub enabled_by_default: Privileges,
    /// Privileges used since the last reset.
    pub used: Privileges,
}

/// A logon session id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// An access token: an fd-backed KACS handle.
#[derive(Debug)]
pub struct Token(OwnedFd);

impl Token {
    /// The calling thread's token. With `real`, the process primary token even
    /// while impersonating.
    pub fn open_self(real: bool, access: TokenAccess) -> Result<Token> {
        let flags = if real { sys::KACS_TOKEN_OPEN_REAL } else { 0 };
        // SAFETY: a plain syscall returning a token fd or -1/errno.
        check_fd(unsafe { sys::peios_token_open_self(flags, access.bits()) }).map(Token)
    }

    /// The primary token of the process referred to by `pidfd`.
    pub fn open_process(pidfd: BorrowedFd<'_>, access: TokenAccess) -> Result<Token> {
        // SAFETY: `pidfd` is a live borrowed fd for the duration of the call.
        check_fd(unsafe { sys::peios_token_open_process(pidfd.as_raw_fd(), access.bits()) }).map(Token)
    }

    /// Thread `tid`'s impersonation token (or the process primary token if it is
    /// not impersonating).
    pub fn open_thread(pidfd: BorrowedFd<'_>, tid: i32, access: TokenAccess) -> Result<Token> {
        // SAFETY: `pidfd` is live for the call.
        check_fd(unsafe { sys::peios_token_open_thread(pidfd.as_raw_fd(), tid, access.bits()) })
            .map(Token)
    }

    /// The peer-identity token captured at `connect()` on a connected Unix
    /// stream/seqpacket socket.
    pub fn open_peer(conn: BorrowedFd<'_>) -> Result<Token> {
        // SAFETY: `conn` is live for the call.
        check_fd(unsafe { sys::peios_token_open_peer(conn.as_raw_fd()) }).map(Token)
    }

    /// Mint a token from a pre-built token-spec buffer (prefer [`TokenBuilder`]).
    /// Requires `SeCreateTokenPrivilege`.
    pub fn from_spec(spec: &[u8]) -> Result<Token> {
        // SAFETY: (ptr, len) from a live slice.
        check_fd(unsafe { sys::peios_token_create_raw(spec.as_ptr().cast(), spec.len()) }).map(Token)
    }

    /// The canonical KACS generic mapping for the token object class.
    pub fn generic_mapping() -> GenericMapping {
        // SAFETY: reading a libpeios-exported POD static.
        GenericMapping::from_raw(unsafe { sys::peios_token_generic_mapping })
    }

    fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    // ---- queries ----------------------------------------------------------

    /// Read an information class as raw bytes (getxattr-style probe).
    pub fn query(&self, class: TokenClass) -> Result<Vec<u8>> {
        probe(|buf, cap| {
            // SAFETY: live token fd; (buf, cap) is the output window.
            unsafe { sys::peios_token_query(self.raw(), class.0, buf, cap) }
        })
    }

    /// The user SID.
    pub fn user(&self) -> Result<Sid> {
        let mut buf = [0u8; Sid::MAX_LEN];
        // SAFETY: live fd; `buf` is a MAX_LEN output buffer (holds any SID).
        let n = unsafe { sys::peios_token_user(self.raw(), buf.as_mut_ptr().cast(), buf.len()) };
        let len = check_len(n)?;
        // SAFETY: libpeios wrote a valid SID of `len` bytes.
        SidRef::from_bytes(&buf[..len])
            .map(SidRef::to_sid)
            .ok_or_else(|| Error::from_raw_os_error(EINVAL))
    }

    /// The token type.
    pub fn token_type(&self) -> Result<TokenType> {
        let mut out = 0u32;
        // SAFETY: live fd; `out` writable.
        check(unsafe { sys::peios_token_type(self.raw(), &mut out) })?;
        TokenType::from_raw(out).ok_or_else(|| Error::from_raw_os_error(EINVAL))
    }

    /// The session id.
    pub fn session_id(&self) -> Result<SessionId> {
        let mut out = 0u32;
        // SAFETY: live fd; `out` writable.
        check(unsafe { sys::peios_token_session_id(self.raw(), &mut out) })?;
        Ok(SessionId(out as u64))
    }

    /// The integrity level (the label SID's RID).
    pub fn integrity(&self) -> Result<IntegrityLevel> {
        let mut rid = 0u32;
        // SAFETY: live fd; `rid` writable.
        check(unsafe { sys::peios_token_integrity(self.raw(), &mut rid) })?;
        Ok(IntegrityLevel(rid))
    }

    /// The four privilege words.
    pub fn privileges(&self) -> Result<PrivilegeSet> {
        let mut p = sys::peios_privilege_set { present: 0, enabled: 0, enabled_by_default: 0, used: 0 };
        // SAFETY: live fd; `p` writable.
        check(unsafe { sys::peios_token_privileges(self.raw(), &mut p) })?;
        Ok(PrivilegeSet {
            present: Privileges::from_bits_retain(p.present),
            enabled: Privileges::from_bits_retain(p.enabled),
            enabled_by_default: Privileges::from_bits_retain(p.enabled_by_default),
            used: Privileges::from_bits_retain(p.used),
        })
    }

    /// The groups (SID-and-attributes), copied into an owned vector.
    pub fn groups(&self) -> Result<Vec<(Sid, u32)>> {
        self.sid_array(TokenClass::GROUPS)
    }

    /// The restricted SIDs, copied into an owned vector.
    pub fn restricted_sids(&self) -> Result<Vec<(Sid, u32)>> {
        self.sid_array(TokenClass::RESTRICTED_SIDS)
    }

    fn sid_array(&self, class: TokenClass) -> Result<Vec<(Sid, u32)>> {
        let blob = self.query(class)?;
        let view = SidArrayView::parse(&blob)?;
        Ok(view.iter().map(|e| (e.sid.to_sid(), e.attributes)).collect())
    }

    // ---- adjust / transform ----------------------------------------------

    /// Adjust privileges; returns the previous enabled mask. `entries` map to the
    /// kernel's privilege adjustment entries (a LUID plus attribute bits).
    pub fn adjust_privileges(&self, entries: &[PrivilegeAdjustment]) -> Result<Privileges> {
        let raw: Vec<sys::kacs_priv_entry> = entries
            .iter()
            .map(|e| sys::kacs_priv_entry { luid: e.luid, attributes: e.attributes })
            .collect();
        let mut prev = 0u64;
        // SAFETY: live fd; `raw` lives for the call; `prev` writable.
        check(unsafe {
            sys::peios_token_adjust_privileges(
                self.raw(),
                raw.as_ptr(),
                raw.len() as core::ffi::c_uint,
                &mut prev,
            )
        })?;
        Ok(Privileges::from_bits_retain(prev))
    }

    /// Restore enabled privileges to the enabled-by-default set.
    pub fn reset_privileges(&self) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_token_reset_privileges(self.raw()) })
    }

    /// Reset adjusted groups to their default state.
    pub fn reset_groups(&self) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_token_reset_groups(self.raw()) })
    }

    /// Duplicate this token into a new one.
    pub fn duplicate(
        &self,
        access: TokenAccess,
        ty: TokenType,
        imp_level: ImpersonationLevel,
    ) -> Result<Token> {
        // SAFETY: live fd.
        check_fd(unsafe {
            sys::peios_token_duplicate(self.raw(), access.bits(), ty.to_raw(), imp_level.to_raw())
        })
        .map(Token)
    }

    /// Install this primary token as the calling process's primary token.
    pub fn install(&self) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_token_install(self.raw()) })
    }

    /// Impersonate this impersonation token on the calling thread.
    ///
    /// The thread keeps the adopted identity until [`Token::revert`] (or process
    /// exit). For a scope-bound version that reverts automatically, use
    /// [`impersonate_scoped`](Self::impersonate_scoped).
    pub fn impersonate(&self) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_token_impersonate(self.raw()) })
    }

    /// Impersonate this token until the returned [`Impersonation`] guard is
    /// dropped, which reverts the thread to its real identity.
    ///
    /// ```no_run
    /// # fn f(client: &peios::token::Token) -> peios::Result<()> {
    /// let _guard = client.impersonate_scoped()?;
    /// // ... access checks here run as the client ...
    /// # Ok(())
    /// } // `_guard` drops here → the thread reverts to its real identity.
    /// ```
    pub fn impersonate_scoped(&self) -> Result<Impersonation> {
        self.impersonate()?;
        Ok(Impersonation { active: true })
    }

    /// Revert the calling thread to its own identity, undoing any active
    /// impersonation — the inverse of [`impersonate`](Self::impersonate). A no-op
    /// (reported as success) if the thread is not impersonating.
    ///
    /// Takes no token because it clears the thread's impersonation state rather
    /// than acting on a specific token.
    pub fn revert() -> Result<()> {
        // SAFETY: a plain thread-local syscall with no arguments.
        check(unsafe { sys::peios_token_revert() })
    }

    /// Open this token's linked token.
    pub fn linked(&self) -> Result<Token> {
        // SAFETY: live fd.
        check_fd(unsafe { sys::peios_token_get_linked(self.raw()) }).map(Token)
    }

    /// Set the token's session id (`SeTcbPrivilege`).
    pub fn set_session_id(&self, session: SessionId) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_token_set_session_id(self.raw(), session.0 as u32) })
    }

    /// Create a restricted (filtered) token: a copy with privileges deleted,
    /// groups demoted to deny-only, and restricting SIDs added. Returns the new
    /// token.
    pub fn restrict(&self, spec: &RestrictSpec) -> Result<Token> {
        // Pointers below borrow `spec`'s buffers (and these temporaries), which
        // all outlive the synchronous call.
        let sid_ptrs: Vec<*const c_void> =
            spec.restrict_sids.iter().map(|s| s.as_bytes().as_ptr().cast()).collect();
        let sid_lens: Vec<usize> = spec.restrict_sids.iter().map(|s| s.as_bytes().len()).collect();
        let raw = sys::peios_token_restrict {
            privs_to_delete: spec.privs_to_delete.bits(),
            deny_group_indices: spec.deny_group_indices.as_ptr(),
            deny_count: spec.deny_group_indices.len() as core::ffi::c_uint,
            restrict_sids: sid_ptrs.as_ptr(),
            restrict_sid_lens: sid_lens.as_ptr(),
            restrict_count: spec.restrict_sids.len() as core::ffi::c_uint,
            flags: spec.flags.bits(),
        };
        // SAFETY: live fd; `raw` and every buffer it points into outlive the call.
        check_fd(unsafe { sys::peios_token_restrict(self.raw(), &raw) }).map(Token)
    }

    /// Link an elevated and a filtered primary token together under `session`,
    /// so each can later open the other via [`linked`](Self::linked) (`[adv]`,
    /// `SeTcbPrivilege`).
    pub fn link(elevated: &Token, filtered: &Token, session: SessionId) -> Result<()> {
        // SAFETY: both fds are live for the call.
        check(unsafe { sys::peios_token_link(elevated.raw(), filtered.raw(), session.0) })
    }

    /// Enable or disable groups by index, returning the previous enabled-state
    /// mask. Index 0 is the user SID and 1..N the Nth added group.
    pub fn adjust_groups(&self, entries: &[GroupAdjustment]) -> Result<GroupMask> {
        let raw: Vec<sys::kacs_group_entry> = entries
            .iter()
            .map(|e| sys::kacs_group_entry { index: e.index, enable: e.enable as u32 })
            .collect();
        let mut prev = [0u64; GROUP_MASK_WORDS];
        // SAFETY: live fd; `raw` lives for the call; `prev` is the full
        // GROUP_MASK_WORDS-word window libpeios writes back into.
        check(unsafe {
            sys::peios_token_adjust_groups(
                self.raw(),
                raw.as_ptr(),
                raw.len() as core::ffi::c_uint,
                prev.as_mut_ptr(),
            )
        })?;
        Ok(GroupMask(prev))
    }

    /// Replace the token's default DACL and/or its owner / primary-group indices
    /// (`[adv]`). `dacl` of `None` leaves the DACL unchanged, `Some(empty)`
    /// clears it; an index of `None` leaves that index unchanged.
    pub fn adjust_default(
        &self,
        dacl: Option<&crate::security::Acl>,
        owner_index: Option<u16>,
        group_index: Option<u16>,
    ) -> Result<()> {
        let (ptr, len) = match dacl {
            Some(acl) => {
                let b = acl.as_bytes();
                (b.as_ptr().cast::<c_void>(), b.len())
            }
            None => (core::ptr::null(), 0),
        };
        // 0xFFFF is the libpeios sentinel for "leave this index unchanged".
        let oi = owner_index.unwrap_or(0xFFFF);
        let gi = group_index.unwrap_or(0xFFFF);
        // SAFETY: live fd; `ptr`/`len` describe the DACL bytes (or null) for the call.
        check(unsafe { sys::peios_token_adjust_default(self.raw(), ptr, len, oi, gi) })
    }
}

/// The number of `u64` words in a [`GroupMask`] — libpeios' fixed group-mask
/// width (`KACS_TOKEN_GROUP_MASK_WORDS`).
pub const GROUP_MASK_WORDS: usize = sys::KACS_TOKEN_GROUP_MASK_WORDS as usize;

/// One group enable/disable for [`Token::adjust_groups`].
#[derive(Debug, Clone, Copy)]
pub struct GroupAdjustment {
    /// The group index (0 = user SID, 1..N = the Nth added group).
    pub index: u32,
    /// Whether to enable (`true`) or disable (`false`) the group.
    pub enable: bool,
}

/// A token group enabled-state bitmask: one bit per group index, returned by
/// [`Token::adjust_groups`] as the state *before* the adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMask(pub [u64; GROUP_MASK_WORDS]);

impl GroupMask {
    /// Whether the group at `index` was enabled.
    pub fn is_enabled(&self, index: usize) -> bool {
        let (word, bit) = (index / 64, index % 64);
        self.0.get(word).is_some_and(|w| w & (1u64 << bit) != 0)
    }
}

/// The spec for [`Token::restrict`]: the privileges to drop, the groups to
/// demote to deny-only (by index), and the restricting SIDs to add.
#[derive(Debug, Clone)]
pub struct RestrictSpec {
    /// Privileges to delete from the restricted token.
    pub privs_to_delete: Privileges,
    /// Indices of groups to demote to deny-only (0 = user, 1..N = Nth group).
    pub deny_group_indices: Vec<u32>,
    /// Restricting SIDs to add to the restricted token.
    pub restrict_sids: Vec<Sid>,
    /// Restriction flags.
    pub flags: RestrictFlags,
}

impl Default for RestrictSpec {
    fn default() -> Self {
        RestrictSpec {
            privs_to_delete: Privileges::empty(),
            deny_group_indices: Vec::new(),
            restrict_sids: Vec::new(),
            flags: RestrictFlags::empty(),
        }
    }
}

/// The typed values a [`Claim`] carries. Every value in a claim shares one type;
/// the variant fixes the claim's wire value-type (`KACS_CLAIM_TYPE_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValues {
    /// Signed 64-bit integers.
    Int64(Vec<i64>),
    /// Unsigned 64-bit integers.
    Uint64(Vec<u64>),
    /// Booleans.
    Boolean(Vec<bool>),
    /// UTF-8 strings (transcoded to UTF-16LE on the wire).
    String(Vec<String>),
    /// Binary SIDs.
    Sid(Vec<Sid>),
    /// Opaque octet blobs.
    Octet(Vec<Vec<u8>>),
}

impl ClaimValues {
    fn value_type(&self) -> u16 {
        let t = match self {
            ClaimValues::Int64(_) => sys::KACS_CLAIM_TYPE_INT64,
            ClaimValues::Uint64(_) => sys::KACS_CLAIM_TYPE_UINT64,
            ClaimValues::Boolean(_) => sys::KACS_CLAIM_TYPE_BOOLEAN,
            ClaimValues::String(_) => sys::KACS_CLAIM_TYPE_STRING,
            ClaimValues::Sid(_) => sys::KACS_CLAIM_TYPE_SID,
            ClaimValues::Octet(_) => sys::KACS_CLAIM_TYPE_OCTET,
        };
        t as u16
    }

    /// Build the FFI value array. Scalar variants store the value inline;
    /// bytes-backed variants point into `self`, which outlives the call.
    fn to_ffi(&self) -> Vec<sys::peios_token_claim_value> {
        fn scalar(s: u64) -> sys::peios_token_claim_value {
            sys::peios_token_claim_value { scalar: s, bytes: core::ptr::null(), len: 0 }
        }
        fn bytes(b: &[u8]) -> sys::peios_token_claim_value {
            sys::peios_token_claim_value { scalar: 0, bytes: b.as_ptr().cast(), len: b.len() }
        }
        match self {
            ClaimValues::Int64(v) => v.iter().map(|&x| scalar(x as u64)).collect(),
            ClaimValues::Uint64(v) => v.iter().map(|&x| scalar(x)).collect(),
            ClaimValues::Boolean(v) => v.iter().map(|&x| scalar(x as u64)).collect(),
            ClaimValues::String(v) => v.iter().map(|s| bytes(s.as_bytes())).collect(),
            ClaimValues::Sid(v) => v.iter().map(|s| bytes(s.as_bytes())).collect(),
            ClaimValues::Octet(v) => v.iter().map(|b| bytes(b)).collect(),
        }
    }
}

/// A claim attribute: a named, typed, multi-valued security attribute attached
/// to a token via [`TokenBuilder::add_user_claim`] / [`add_device_claim`].
///
/// [`add_device_claim`]: TokenBuilder::add_device_claim
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The claim name (UTF-8; transcoded to UTF-16LE on the wire). Must not
    /// contain an interior NUL.
    pub name: String,
    /// Claim attribute bits.
    pub flags: ClaimAttr,
    /// The claim's typed values.
    pub values: ClaimValues,
}

/// The LCS registry-credentials extension: the layer scope GUIDs a token may
/// resolve plus the private layer names it owns. Set on a [`TokenBuilder`] via
/// [`lcs_credentials`](TokenBuilder::lcs_credentials).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LcsCredentials {
    /// Layer scope GUIDs (each 16 bytes, non-nil and unique).
    pub scope_guids: Vec<[u8; 16]>,
    /// Private layer names the token owns (UTF-8, 1..=255 bytes, no `/` or `\`,
    /// unique, no interior NUL).
    pub private_layers: Vec<String>,
}

/// One privilege adjustment for [`Token::adjust_privileges`] — a LUID and its new
/// attribute bits, mirroring the kernel's `kacs_priv_entry`.
#[derive(Debug, Clone, Copy)]
pub struct PrivilegeAdjustment {
    /// The privilege LUID.
    pub luid: u32,
    /// The new attribute bits.
    pub attributes: u32,
}

impl AsFd for Token {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl AsRawFd for Token {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl From<Token> for OwnedFd {
    fn from(t: Token) -> OwnedFd {
        t.0
    }
}
impl From<OwnedFd> for Token {
    fn from(fd: OwnedFd) -> Token {
        Token(fd)
    }
}
impl IntoRawFd for Token {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

/// An active impersonation that reverts the calling thread to its real identity
/// when dropped. Returned by [`Token::impersonate_scoped`].
///
/// The kernel's revert clears impersonation entirely rather than restoring a
/// previously-impersonated identity, so dropping this guard returns the thread to
/// its *real* token — impersonations do not nest. Prefer
/// [`revert`](Self::revert) when you must observe the result; [`Drop`] is a
/// best-effort backstop that cannot report a failure.
#[must_use = "the impersonation reverts the instant this guard is dropped; bind it to a variable to keep it active"]
pub struct Impersonation {
    active: bool,
}

impl Impersonation {
    /// Revert now, observing the result, instead of waiting for the drop.
    pub fn revert(mut self) -> Result<()> {
        self.active = false;
        Token::revert()
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        if self.active {
            // Best-effort: a `Drop` cannot surface an error, and clearing the
            // thread's impersonation state effectively never fails. Callers who
            // must observe the outcome use `Impersonation::revert`.
            let _ = Token::revert();
        }
    }
}

/// The four token-spec boolean flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenFlags {
    /// The token is write-restricted.
    pub write_restricted: bool,
    /// The user SID is deny-only.
    pub user_deny_only: bool,
    /// The token marks an isolation boundary.
    pub isolation_boundary: bool,
    /// The token is exempt from confinement.
    pub confinement_exempt: bool,
}

/// A sticky-error builder for a token spec.
///
/// Infallible chained setters assemble the wire format; the first error latches
/// and surfaces at [`create`](Self::create) / [`to_bytes`](Self::to_bytes).
/// Index conventions follow the wire format: owner / primary-group / restrict
/// indices are 0 for the user SID and 1..N for the Nth added group.
pub struct TokenBuilder {
    raw: *mut sys::peios_token_builder,
    /// A Rust-side validation error (e.g. a claim/layer name with an interior
    /// NUL that can't cross the C ABI), latched so it surfaces at
    /// [`error`](Self::error) / [`to_bytes`](Self::to_bytes) /
    /// [`create`](Self::create) exactly like the C builder's own sticky error.
    /// First error wins; `0` means none.
    pending: i32,
}

impl TokenBuilder {
    /// Create an empty token-spec builder.
    pub fn new() -> TokenBuilder {
        // SAFETY: _new returns an owned builder or null on OOM.
        let raw = unsafe { sys::peios_token_builder_new() };
        assert!(!raw.is_null(), "peios_token_builder_new: out of memory");
        TokenBuilder { raw, pending: 0 }
    }

    /// Latch a Rust-side validation error (first one wins).
    fn latch(&mut self, errno: i32) {
        if self.pending == 0 {
            self.pending = errno;
        }
    }

    /// Reset to empty, reusing the builder.
    pub fn reset(&mut self) -> &mut Self {
        self.pending = 0;
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_reset(self.raw) };
        self
    }

    /// Set the user SID (index 0).
    pub fn user(&mut self, sid: &SidRef) -> &mut Self {
        let (p, n) = crate::security::sid_raw(sid);
        // SAFETY: live builder; valid SID for the call.
        unsafe { sys::peios_token_builder_user(self.raw, p, n) };
        self
    }

    /// Append a group SID with attribute bits (`KACS_SID_GROUP_*`).
    pub fn add_group(&mut self, sid: &SidRef, attrs: u32) -> &mut Self {
        let (p, n) = crate::security::sid_raw(sid);
        // SAFETY: live builder; valid SID for the call.
        unsafe { sys::peios_token_builder_add_group(self.raw, p, n, attrs) };
        self
    }

    /// Set the present and enabled privilege masks.
    pub fn privileges(&mut self, present: Privileges, enabled: Privileges) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_privileges(self.raw, present.bits(), enabled.bits()) };
        self
    }

    /// Set the token type and impersonation level.
    pub fn token_type(&mut self, ty: TokenType, imp_level: ImpersonationLevel) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_type(self.raw, ty.to_raw(), imp_level.to_raw()) };
        self
    }

    /// Set the integrity level.
    pub fn integrity(&mut self, level: IntegrityLevel) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_integrity(self.raw, level.rid()) };
        self
    }

    /// Set the logon-session id.
    pub fn session(&mut self, session: SessionId) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_session(self.raw, session.0) };
        self
    }

    /// Set the owner index (0 = user, 1..N = the Nth group).
    pub fn owner_index(&mut self, index: u32) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_owner_index(self.raw, index) };
        self
    }

    /// Set the primary-group index.
    pub fn primary_group_index(&mut self, index: u32) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_primary_group_index(self.raw, index) };
        self
    }

    /// Set the default DACL.
    pub fn default_dacl(&mut self, acl: &crate::security::Acl) -> &mut Self {
        let b = acl.as_bytes();
        // SAFETY: live builder; `b` lives for the call.
        unsafe { sys::peios_token_builder_default_dacl(self.raw, b.as_ptr().cast(), b.len()) };
        self
    }

    /// Set the four token-spec boolean flags.
    pub fn flags(&mut self, flags: TokenFlags) -> &mut Self {
        let f = sys::peios_token_flags {
            write_restricted: flags.write_restricted,
            user_deny_only: flags.user_deny_only,
            isolation_boundary: flags.isolation_boundary,
            confinement_exempt: flags.confinement_exempt,
        };
        // SAFETY: live builder; `f` lives for the call.
        unsafe { sys::peios_token_builder_flags(self.raw, &f) };
        self
    }

    /// Set the projected POSIX uid/gid.
    pub fn projected_ids(&mut self, uid: u32, gid: u32) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_projected_ids(self.raw, uid, gid) };
        self
    }

    /// Set the supplementary projected GIDs.
    pub fn supplementary_gids(&mut self, gids: &[u32]) -> &mut Self {
        // SAFETY: live builder; `gids` lives for the call.
        unsafe {
            sys::peios_token_builder_supp_gids(self.raw, gids.as_ptr(), gids.len() as core::ffi::c_uint)
        };
        self
    }

    /// Set the integrity mandatory policy.
    pub fn mandatory_policy(&mut self, policy: MandatoryPolicy) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_mandatory_policy(self.raw, policy.bits()) };
        self
    }

    /// Set the per-token audit policy.
    pub fn audit_policy(&mut self, policy: AuditPolicy) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_audit_policy(self.raw, policy.bits()) };
        self
    }

    /// Set the token's expiry timestamp (`0` = never expires).
    pub fn expiration(&mut self, when: u64) -> &mut Self {
        // SAFETY: live builder.
        unsafe { sys::peios_token_builder_expiration(self.raw, when) };
        self
    }

    /// Set the token source: an up-to-8-byte name and a source id. Names longer
    /// than 8 bytes latch `EINVAL`.
    pub fn source(&mut self, name: &str, source_id: u64) -> &mut Self {
        let bytes = name.as_bytes();
        if bytes.len() > SOURCE_NAME_LEN {
            self.latch(EINVAL);
            return self;
        }
        // A fixed zero-padded field; libpeios reads up to SOURCE_NAME_LEN bytes,
        // stopping at the first NUL. `buf` outlives the call.
        let mut buf = [0 as c_char; SOURCE_NAME_LEN];
        for (d, &s) in buf.iter_mut().zip(bytes) {
            *d = s as c_char;
        }
        // SAFETY: live builder; `buf` is a valid SOURCE_NAME_LEN-byte buffer.
        unsafe { sys::peios_token_builder_source(self.raw, buf.as_ptr(), source_id) };
        self
    }

    /// Append a restricting SID with attribute bits. Restricting SIDs filter the
    /// token: access requires a grant to both the normal and the restricted set.
    pub fn add_restricted_sid(&mut self, sid: &SidRef, attrs: u32) -> &mut Self {
        let (p, n) = crate::security::sid_raw(sid);
        // SAFETY: live builder; valid SID for the call.
        unsafe { sys::peios_token_builder_add_restricted_sid(self.raw, p, n, attrs) };
        self
    }

    /// Append a device-group SID with attribute bits.
    pub fn add_device_group(&mut self, sid: &SidRef, attrs: u32) -> &mut Self {
        let (p, n) = crate::security::sid_raw(sid);
        // SAFETY: live builder; valid SID for the call.
        unsafe { sys::peios_token_builder_add_device_group(self.raw, p, n, attrs) };
        self
    }

    /// Set the confinement SID, sandboxing the token to a confinement domain.
    pub fn confinement(&mut self, sid: &SidRef) -> &mut Self {
        let (p, n) = crate::security::sid_raw(sid);
        // SAFETY: live builder; valid SID for the call.
        unsafe { sys::peios_token_builder_confinement(self.raw, p, n) };
        self
    }

    /// Append a user claim. A malformed claim latches `EINVAL` (a name with an
    /// interior NUL here, or the kernel's own claim-parser rejection at create).
    pub fn add_user_claim(&mut self, claim: &Claim) -> &mut Self {
        self.with_claim(claim, |raw, c| {
            // SAFETY: live builder; `c` and its buffers live for the call.
            unsafe { sys::peios_token_builder_add_user_claim(raw, c) }
        });
        self
    }

    /// Append a device claim. See [`add_user_claim`](Self::add_user_claim) for
    /// error handling.
    pub fn add_device_claim(&mut self, claim: &Claim) -> &mut Self {
        self.with_claim(claim, |raw, c| {
            // SAFETY: live builder; `c` and its buffers live for the call.
            unsafe { sys::peios_token_builder_add_device_claim(raw, c) }
        });
        self
    }

    /// Marshal a [`Claim`] into its FFI form and hand it to `f`. The name
    /// `CString` and value array live across the call; bytes-backed values
    /// borrow `claim`. A name with an interior NUL latches `EINVAL` and skips `f`.
    fn with_claim(
        &mut self,
        claim: &Claim,
        f: impl FnOnce(*mut sys::peios_token_builder, *const sys::peios_token_claim),
    ) {
        let name = match CString::new(claim.name.as_str()) {
            Ok(n) => n,
            Err(_) => {
                self.latch(EINVAL);
                return;
            }
        };
        let values = claim.values.to_ffi();
        let c = sys::peios_token_claim {
            name: name.as_ptr(),
            value_type: claim.values.value_type(),
            flags: claim.flags.bits(),
            values: values.as_ptr(),
            value_count: values.len() as core::ffi::c_uint,
        };
        f(self.raw, &c);
    }

    /// Set the LCS registry credentials (replaces any prior set). A private-layer
    /// name with an interior NUL latches `EINVAL`.
    pub fn lcs_credentials(&mut self, creds: &LcsCredentials) -> &mut Self {
        let layers: core::result::Result<Vec<CString>, _> =
            creds.private_layers.iter().map(|s| CString::new(s.as_str())).collect();
        let layers = match layers {
            Ok(v) => v,
            Err(_) => {
                self.latch(EINVAL);
                return self;
            }
        };
        let layer_ptrs: Vec<*const c_char> = layers.iter().map(|c| c.as_ptr()).collect();
        let c = sys::peios_token_lcs_credentials {
            scope_guids: creds.scope_guids.as_ptr(),
            scope_count: creds.scope_guids.len() as core::ffi::c_uint,
            private_layers: layer_ptrs.as_ptr(),
            private_layer_count: creds.private_layers.len() as core::ffi::c_uint,
        };
        // SAFETY: live builder; `c` and the GUID/name buffers live for the call.
        unsafe { sys::peios_token_builder_lcs_credentials(self.raw, &c) };
        self
    }

    /// The latched error, if any (Rust-side validation or the C builder's own).
    pub fn error(&self) -> Result<()> {
        if self.pending != 0 {
            return Err(Error::from_raw_os_error(self.pending));
        }
        // SAFETY: live builder.
        let e = unsafe { sys::peios_token_builder_error(self.raw) };
        if e == 0 {
            Ok(())
        } else {
            Err(Error::from_raw_os_error(e))
        }
    }

    /// Serialize the assembled spec into owned bytes, or surface the latched error.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.error()?;
        let mut out: *const c_void = core::ptr::null();
        // SAFETY: live builder; `out` writable. The returned pointer borrows the
        // builder, so we copy immediately.
        let n = unsafe { sys::peios_token_builder_bytes(self.raw, &mut out) };
        let len = check_len(n)?;
        if out.is_null() {
            return Err(Error::from_raw_os_error(EINVAL));
        }
        // SAFETY: libpeios returned `len` valid bytes at `out`, valid until the
        // next builder mutation — we copy them out now.
        Ok(unsafe { core::slice::from_raw_parts(out.cast::<u8>(), len) }.to_vec())
    }

    /// Mint the token in one step (requires `SeCreateTokenPrivilege`).
    pub fn create(&self) -> Result<Token> {
        self.error()?;
        // SAFETY: live builder.
        check_fd(unsafe { sys::peios_token_builder_create(self.raw) }).map(Token)
    }
}

impl Default for TokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TokenBuilder {
    fn drop(&mut self) {
        // SAFETY: `raw` came from _new and is dropped exactly once.
        unsafe { sys::peios_token_builder_free(self.raw) };
    }
}

/// The kind of a logon session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogonType {
    /// Interactive logon.
    Interactive,
    /// Network logon.
    Network,
    /// Batch logon.
    Batch,
    /// Service logon.
    Service,
    /// Cleartext network logon.
    NetworkCleartext,
    /// New-credentials logon.
    NewCredentials,
}

impl LogonType {
    fn to_raw(self) -> u8 {
        match self {
            LogonType::Interactive => sys::KACS_LOGON_TYPE_INTERACTIVE as u8,
            LogonType::Network => sys::KACS_LOGON_TYPE_NETWORK as u8,
            LogonType::Batch => sys::KACS_LOGON_TYPE_BATCH as u8,
            LogonType::Service => sys::KACS_LOGON_TYPE_SERVICE as u8,
            LogonType::NetworkCleartext => sys::KACS_LOGON_TYPE_NETWORK_CLEARTEXT as u8,
            LogonType::NewCredentials => sys::KACS_LOGON_TYPE_NEW_CREDENTIALS as u8,
        }
    }
}

/// A logon session — the lightweight kernel bookkeeping a token references.
#[derive(Debug, Clone, Copy)]
pub struct Session;

impl Session {
    /// Create a logon session (`SeTcbPrivilege`), returning its id.
    pub fn create(
        logon_type: LogonType,
        auth_package: &str,
        user_sid: &SidRef,
    ) -> Result<SessionId> {
        let pkg = CString::new(auth_package).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let (sid_p, sid_n) = crate::security::sid_raw(user_sid);
        let spec = sys::peios_session_spec {
            logon_type: logon_type.to_raw(),
            auth_package: pkg.as_ptr() as *const c_char,
            user_sid: sid_p,
            user_sid_len: sid_n,
        };
        let mut id = 0u64;
        // SAFETY: `spec` borrows live buffers for the call; `id` writable.
        check(unsafe { sys::peios_session_create(&spec, &mut id) })?;
        Ok(SessionId(id))
    }

    /// Destroy a session with no live tokens (`SeTcbPrivilege`).
    pub fn destroy_empty(session: SessionId) -> Result<()> {
        // SAFETY: a plain syscall.
        check(unsafe { sys::peios_session_destroy_empty(session.0) })
    }
}

const EINVAL: i32 = 22;

/// The fixed width of a token source name (`KACS_TOKEN_SPEC_SOURCE_NAME_BYTES`).
const SOURCE_NAME_LEN: usize = sys::KACS_TOKEN_SPEC_SOURCE_NAME_BYTES as usize;
