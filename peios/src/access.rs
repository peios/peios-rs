//! KACS access checks: the [`AccessCheck`] builder and its [`AccessDecision`].
//!
//! [`AccessCheck`] runs the full KACS AccessCheck pipeline for a token against a
//! security descriptor and a desired access mask. These checks are *advisory* —
//! they evaluate, they do not enforce; enforcement always uses the subject's own
//! process security block.
//!
//! Denial is not an error here: a check that completes always yields an
//! [`AccessDecision`] reporting whether access was `allowed` and the `granted`
//! mask (filled even on denial). Only a genuine failure (a bad descriptor, a
//! missing token, …) surfaces as an [`Err`].
//!
//! A daemon that guards objects of its own names the object it checked with an
//! [`AuditContext`], so the kernel's audit record of the decision says what
//! was decided on (PGSS §6.7).

use std::ffi::CString;
use std::os::fd::BorrowedFd;

use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::{AccessMask, GenericMapping, SecurityDescriptor, SidRef};
use crate::util::{check, check_len, opt_fd};

/// `EACCES` without pulling in the `libc` crate (stable on Linux): the errno
/// libpeios reports for an access *denial*, which is a decision, not an error.
const EACCES: i32 = 13;

/// `EINVAL`, for a name holding a NUL byte, which no C string can carry.
const EINVAL: i32 = 22;

/// One identifying field's value in an [`AuditContext`]: a scalar in one of
/// the PGSS §6.5 wire forms.
///
/// There is no nil: a field with no value is left out (PGSS §6.5). Convert from
/// the plain Rust types with [`From`]: `&str`, `u64`/`u32`, `i64`/`i32`,
/// `bool`, `&[u8]`, and a [`SidRef`] (written in its binary form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditValue<'v> {
    /// A UTF-8 string.
    Str(&'v str),
    /// An unsigned integer.
    Uint(u64),
    /// A signed integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// Binary: a SID, a GUID, a digest.
    Bin(&'v [u8]),
}

impl<'v> From<&'v str> for AuditValue<'v> {
    fn from(v: &'v str) -> Self {
        AuditValue::Str(v)
    }
}

impl<'v> From<&'v String> for AuditValue<'v> {
    fn from(v: &'v String) -> Self {
        AuditValue::Str(v)
    }
}

impl From<u64> for AuditValue<'_> {
    fn from(v: u64) -> Self {
        AuditValue::Uint(v)
    }
}

impl From<u32> for AuditValue<'_> {
    fn from(v: u32) -> Self {
        AuditValue::Uint(v.into())
    }
}

impl From<i64> for AuditValue<'_> {
    fn from(v: i64) -> Self {
        AuditValue::Int(v)
    }
}

impl From<i32> for AuditValue<'_> {
    fn from(v: i32) -> Self {
        AuditValue::Int(v.into())
    }
}

impl From<bool> for AuditValue<'_> {
    fn from(v: bool) -> Self {
        AuditValue::Bool(v)
    }
}

impl<'v> From<&'v [u8]> for AuditValue<'v> {
    fn from(v: &'v [u8]) -> Self {
        AuditValue::Bin(v)
    }
}

impl<'v> From<&'v SidRef> for AuditValue<'v> {
    fn from(v: &'v SidRef) -> Self {
        AuditValue::Bin(v.as_bytes())
    }
}

/// The identity of an object a daemon guards, for the audit record of an
/// access check: the PGSS §6.7 map `{kind: "<kind>", "<kind>": {<key>: <value>,
/// ...}}`.
///
/// The kernel copies it into `kacs.audit.access.checked` as `object.kind` and
/// `object.<kind>.<key>`, and marks the record `fields.attestation.userspace`,
/// because the values are the daemon's claim. Pass it to a check with
/// [`AccessCheck::audit_context`].
///
/// ```no_run
/// use peios::access::{AccessCheck, AuditContext};
/// # fn f(sd: &peios::security::SecurityDescriptor,
/// #      mapping: peios::security::GenericMapping) -> peios::Result<()> {
/// let ctx = AuditContext::new("service", &[("name", "jellyfin".into())])?;
/// let decision = AccessCheck::new(sd, peios::security::AccessMask::GENERIC_READ, mapping)
///     .audit_context(&ctx)
///     .check()?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditContext(Vec<u8>);

impl AuditContext {
    /// Name an object of kind `kind` by `fields`.
    ///
    /// `kind` and every key are one kebab-case event-name segment,
    /// `[a-z][a-z0-9]*(-[a-z0-9]+)*`, and each key appears once; with no
    /// fields the context is `{kind: <kind>}`. Fails with `EINVAL` for a bad
    /// kind or key, a repeated key, or a context longer than the kernel's
    /// `KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN`.
    pub fn new(kind: &str, fields: &[(&str, AuditValue<'_>)]) -> Result<AuditContext> {
        let kind = CString::new(kind).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let keys = fields
            .iter()
            .map(|(key, _)| CString::new(*key).map_err(|_| Error::from_raw_os_error(EINVAL)))
            .collect::<Result<Vec<_>>>()?;
        let raw: Vec<sys::peios_audit_field> = fields
            .iter()
            .zip(&keys)
            .map(|((_, value), key)| raw_field(key, value))
            .collect();
        let encode = |buf: *mut core::ffi::c_void, cap: usize| {
            // SAFETY: `kind`, every key, and every value buffer outlive the call;
            // `raw` holds `raw.len()` entries; `buf` is NULL (cap 0) or valid for `cap`.
            unsafe {
                sys::peios_audit_context_encode(kind.as_ptr(), raw.as_ptr(), raw.len(), buf, cap)
            }
        };
        let need = check_len(encode(core::ptr::null_mut(), 0))?;
        let mut bytes = vec![0u8; need];
        let written = check_len(encode(bytes.as_mut_ptr().cast(), bytes.len()))?;
        bytes.truncate(written);
        Ok(AuditContext(bytes))
    }

    /// Adopt an encoded context built some other way, checking it against the
    /// kernel's rules first. Fails with `EINVAL` if the kernel would refuse it.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<AuditContext> {
        // SAFETY: (ptr, len) from a live Vec.
        check(unsafe { sys::peios_audit_context_validate(bytes.as_ptr().cast(), bytes.len()) })?;
        Ok(AuditContext(bytes))
    }

    /// The encoded MessagePack map.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The C view of one field, borrowing `key` and the value's bytes.
fn raw_field(key: &CString, value: &AuditValue<'_>) -> sys::peios_audit_field {
    let (value_type, scalar, bytes): (_, u64, &[u8]) = match *value {
        AuditValue::Str(s) => (sys::peios_audit_value_type_PEIOS_AUDIT_STR, 0, s.as_bytes()),
        AuditValue::Uint(v) => (sys::peios_audit_value_type_PEIOS_AUDIT_UINT, v, &[]),
        AuditValue::Int(v) => (sys::peios_audit_value_type_PEIOS_AUDIT_INT, v as u64, &[]),
        AuditValue::Bool(v) => (sys::peios_audit_value_type_PEIOS_AUDIT_BOOL, v.into(), &[]),
        AuditValue::Bin(b) => (sys::peios_audit_value_type_PEIOS_AUDIT_BIN, 0, b),
    };
    sys::peios_audit_field {
        key: key.as_ptr(),
        value_type,
        scalar,
        bytes: bytes.as_ptr().cast(),
        len: bytes.len(),
    }
}

/// The outcome of an [`AccessCheck`]: whether access was granted, and the mask
/// of rights actually granted.
///
/// `granted` is filled whether or not access was `allowed` — on denial it is the
/// (partial) set of desired rights that *would* have been granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessDecision {
    /// `true` if every desired right was granted.
    pub allowed: bool,
    /// The mask of rights actually granted (object-specific, generics resolved).
    pub granted: AccessMask,
}

/// A builder for a KACS access check against one security descriptor.
///
/// Set the mandatory inputs at construction ([`new`](Self::new)); the remaining
/// setters cover the optional, advanced inputs and may be skipped. Terminate
/// with [`check`](Self::check) for an ordinary check, or
/// [`check_list`](Self::check_list) for the object-type-list variant.
pub struct AccessCheck<'a> {
    token: Option<BorrowedFd<'a>>,
    sd: &'a SecurityDescriptor,
    desired: AccessMask,
    mapping: GenericMapping,
    self_sid: Option<&'a SidRef>,
    privilege_intent: u32,
    audit_context: Option<&'a AuditContext>,
}

impl<'a> AccessCheck<'a> {
    /// Begin a check of `desired` against `sd`, folding generic rights through
    /// `mapping` (the object class's generic mapping, e.g.
    /// [`Token::generic_mapping`](crate::token::Token::generic_mapping)).
    ///
    /// By default the check uses the caller's effective token; override it with
    /// [`token`](Self::token).
    pub fn new(
        sd: &'a SecurityDescriptor,
        desired: AccessMask,
        mapping: GenericMapping,
    ) -> AccessCheck<'a> {
        AccessCheck {
            token: None,
            sd,
            desired,
            mapping,
            self_sid: None,
            privilege_intent: 0,
            audit_context: None,
        }
    }

    /// Check against a specific token rather than the caller's effective token.
    pub fn token(&mut self, token: BorrowedFd<'a>) -> &mut Self {
        self.token = Some(token);
        self
    }

    /// Substitute `sid` for the `PRINCIPAL_SELF` well-known SID in the DACL.
    pub fn self_sid(&mut self, sid: &'a SidRef) -> &mut Self {
        self.self_sid = Some(sid);
        self
    }

    /// Set the backup/restore privilege-intent bits.
    pub fn privilege_intent(&mut self, intent: u32) -> &mut Self {
        self.privilege_intent = intent;
        self
    }

    /// Name the object being checked, for the kernel's audit record of the
    /// decision (PGSS §6.7). A daemon checking access to an object it guards
    /// passes one; without it the record cannot say what was checked.
    pub fn audit_context(&mut self, context: &'a AuditContext) -> &mut Self {
        self.audit_context = Some(context);
        self
    }

    /// Build the FFI request shared by both terminal calls.
    ///
    /// `object_tree`/`object_tree_count` are filled by the caller (NULL/0 for an
    /// ordinary check). The other advanced list pointers are left absent; the
    /// audit context is the one set, if any. libpeios owns the versioned kernel-args
    /// struct (`caller_size`, reserved fields) — this is only the request it
    /// reads from.
    fn build_request(
        &self,
        object_tree: *const sys::kacs_object_type_entry,
        object_tree_count: u32,
    ) -> sys::peios_access_request {
        let (sid_ptr, sid_len) = match self.self_sid {
            Some(sid) => crate::security::sid_raw(sid),
            None => (core::ptr::null(), 0),
        };
        let (context_ptr, context_len) = match self.audit_context {
            Some(context) => (context.as_bytes().as_ptr().cast(), context.as_bytes().len()),
            None => (core::ptr::null(), 0),
        };
        sys::peios_access_request {
            token_fd: opt_fd(self.token),
            sd: self.sd.as_bytes().as_ptr().cast(),
            sd_len: self.sd.as_bytes().len(),
            desired: self.desired.bits(),
            mapping: self.mapping.0,
            self_sid: sid_ptr,
            self_sid_len: sid_len,
            privilege_intent: self.privilege_intent,
            object_tree,
            object_tree_count,
            local_claims: core::ptr::null(),
            local_claims_len: 0,
            pip_type: 0,
            pip_trust: 0,
            audit_context: context_ptr,
            audit_context_len: context_len,
        }
    }

    /// Run the check, returning the [`AccessDecision`].
    ///
    /// A completed check — granted or denied — is `Ok`; only a real failure is
    /// `Err`. The granted mask is read whether or not access was allowed.
    pub fn check(&self) -> Result<AccessDecision> {
        let req = self.build_request(core::ptr::null(), 0);
        let mut granted = 0u32;
        // SAFETY: `req` borrows live buffers (SD bytes, optional SID) for the
        // duration of the call; `granted` is a writable out-param; audit is NULL.
        let r = unsafe { sys::peios_access_check(&req, &mut granted, core::ptr::null_mut()) };
        if r == 0 {
            return Ok(AccessDecision {
                allowed: true,
                granted: AccessMask::from_bits_retain(granted),
            });
        }
        // A denial (EACCES) is a decision, not an error: `granted` is filled.
        let err = Error::last_os_error();
        if err.raw_os_error() == Some(EACCES) {
            Ok(AccessDecision {
                allowed: false,
                granted: AccessMask::from_bits_retain(granted),
            })
        } else {
            Err(err)
        }
    }

    /// Run the object-type-list variant (`AccessCheckByTypeResultList`).
    ///
    /// `object_tree` is the object-type tree (an entry per node, in preorder);
    /// the returned vector holds one [`sys::kacs_node_result`] per node, in the
    /// same order. Both the tree and the result types are the raw pkm UAPI
    /// structs from [`peios_sys`] — modelling the object-type tree and per-node
    /// results as bespoke Rust types would buy little over the plain
    /// `repr(C)` structs, so they are passed and returned directly.
    ///
    /// Unlike [`check`](Self::check), this reports the full per-node result set
    /// rather than a single allowed/denied decision: each entry's `status` and
    /// `granted` carry that node's outcome. A `-1`/errno return surfaces as `Err`.
    pub fn check_list(
        &self,
        object_tree: &[sys::kacs_object_type_entry],
    ) -> Result<Vec<sys::kacs_node_result>> {
        let count = object_tree.len() as u32;
        let req = self.build_request(object_tree.as_ptr(), count);
        let mut results = vec![
            sys::kacs_node_result {
                granted: 0,
                status: 0
            };
            object_tree.len()
        ];
        // SAFETY: `req` borrows live buffers (SD bytes, optional SID, and the
        // `object_tree` slice of `count` entries) for the call; `results` is a
        // writable buffer of exactly `count` entries, matching `req.object_tree_count`.
        let r = unsafe { sys::peios_access_check_list(&req, results.as_mut_ptr(), count) };
        crate::util::check(r)?;
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgpack::{Reader, Writer};
    use crate::security::{Sid, WellKnown};

    fn einval<T: core::fmt::Debug>(r: Result<T>) -> bool {
        r.unwrap_err().raw_os_error() == Some(EINVAL)
    }

    // PGSS §6.7: `kind`, then the object's fields under the kind's own name.
    #[test]
    fn audit_context_names_the_object_by_kind() {
        let ctx = AuditContext::new("service", &[("name", "jellyfin".into())]).unwrap();
        let mut r = Reader::new(ctx.as_bytes());
        assert_eq!(r.read_map().unwrap(), 2);
        assert_eq!(r.read_str().unwrap(), "kind");
        assert_eq!(r.read_str().unwrap(), "service");
        assert_eq!(r.read_str().unwrap(), "service");
        assert_eq!(r.read_map().unwrap(), 1);
        assert_eq!(r.read_str().unwrap(), "name");
        assert_eq!(r.read_str().unwrap(), "jellyfin");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn audit_context_without_fields_is_kind_alone() {
        let ctx = AuditContext::new("system", &[]).unwrap();
        let mut r = Reader::new(ctx.as_bytes());
        assert_eq!(r.read_map().unwrap(), 1);
        assert_eq!(r.read_str().unwrap(), "kind");
        assert_eq!(r.read_str().unwrap(), "system");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn audit_context_carries_every_scalar_type() {
        let system = Sid::well_known(WellKnown::System);
        let digest: &[u8] = &[0xde, 0xad];
        let ctx = AuditContext::new(
            "job",
            &[
                ("id", 42u64.into()),
                ("delta", (-7i64).into()),
                ("enabled", true.into()),
                ("owner", AuditValue::from(&*system)),
                ("digest", digest.into()),
            ],
        )
        .unwrap();
        let mut r = Reader::new(ctx.as_bytes());
        assert_eq!(r.read_map().unwrap(), 2);
        assert_eq!(r.read_str().unwrap(), "kind");
        assert_eq!(r.read_str().unwrap(), "job");
        assert_eq!(r.read_str().unwrap(), "job");
        assert_eq!(r.read_map().unwrap(), 5);
        assert_eq!(r.read_str().unwrap(), "id");
        assert_eq!(r.read_uint().unwrap(), 42);
        assert_eq!(r.read_str().unwrap(), "delta");
        assert_eq!(r.read_int().unwrap(), -7);
        assert_eq!(r.read_str().unwrap(), "enabled");
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_str().unwrap(), "owner");
        assert_eq!(r.read_bin().unwrap(), system.as_bytes());
        assert_eq!(r.read_str().unwrap(), "digest");
        assert_eq!(r.read_bin().unwrap(), digest);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn audit_context_refuses_what_the_kernel_would() {
        let name = [("name", AuditValue::from("x"))];
        for kind in ["", "Service", "a--b", "a.b", "a\0b"] {
            assert!(einval(AuditContext::new(kind, &name)), "{kind:?}");
        }
        for key in ["", "Name", "a.b", "a\0b"] {
            assert!(
                einval(AuditContext::new("service", &[(key, "x".into())])),
                "{key:?}"
            );
        }
        // A key given twice would make object.<kind>.<key> ambiguous.
        let twice = [("name", "a".into()), ("name", "b".into())];
        assert!(einval(AuditContext::new("service", &twice)));
        // The kernel takes at most KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN bytes.
        let big = "x".repeat(4096);
        assert!(einval(AuditContext::new(
            "service",
            &[("name", big.as_str().into())]
        )));
    }

    #[test]
    fn from_bytes_checks_the_kernel_rules() {
        let ctx = AuditContext::new("service", &[("name", "jellyfin".into())]).unwrap();
        assert_eq!(
            AuditContext::from_bytes(ctx.as_bytes().to_vec()).unwrap(),
            ctx
        );

        // The free-form string eventd once passed is not a context.
        let mut w = Writer::new();
        w.write_str("events:kacs.*");
        assert!(einval(AuditContext::from_bytes(w.to_bytes().unwrap())));
        // Nor is a map with a key outside the kind's own.
        let mut w = Writer::new();
        w.write_map(2)
            .write_str("kind")
            .write_str("service")
            .write_str("subject")
            .write_map(1)
            .write_str("name")
            .write_str("x");
        assert!(einval(AuditContext::from_bytes(w.to_bytes().unwrap())));
        assert!(einval(AuditContext::from_bytes(Vec::new())));
    }

    #[test]
    fn the_builder_passes_the_context_to_libpeios() {
        let sd = SecurityDescriptor::from_bytes(vec![1, 0, 0, 0x80]);
        let mapping = GenericMapping::new(1, 2, 4, 7);
        let ctx = AuditContext::new("service", &[("name", "jellyfin".into())]).unwrap();
        let mut check = AccessCheck::new(&sd, AccessMask::from_bits_retain(1), mapping);
        let req = check.build_request(core::ptr::null(), 0);
        assert!(req.audit_context.is_null());
        assert_eq!(req.audit_context_len, 0);

        check.audit_context(&ctx);
        let req = check.build_request(core::ptr::null(), 0);
        assert_eq!(req.audit_context.cast::<u8>(), ctx.as_bytes().as_ptr());
        assert_eq!(req.audit_context_len, ctx.as_bytes().len());
    }
}
