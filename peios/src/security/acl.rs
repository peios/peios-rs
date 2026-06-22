//! Access-control lists: the [`AclBuilder`] (a wrapper over libpeios' sticky-error
//! C builder), an owned [`Acl`], and zero-copy [`AclView`]/[`AceView`] readers.

use core::ffi::c_void;
use core::marker::PhantomData;

use bitflags::bitflags;
use peios_sys as sys;

use super::sid::{self, SidRef};
use crate::error::{Error, Result};
use crate::util::probe;

/// The type discriminant of an ACE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AceType {
    /// Grant the rights in the mask.
    AccessAllowed,
    /// Deny the rights in the mask.
    AccessDenied,
    /// Audit on access.
    SystemAudit,
    /// A mandatory-integrity label.
    SystemMandatoryLabel,
    /// A resource-attribute ACE (carries application data).
    SystemResourceAttribute,
    /// Any other ACE type, by raw discriminant (object/callback families, …).
    Other(u8),
}

impl AceType {
    fn to_raw(self) -> u8 {
        match self {
            AceType::AccessAllowed => sys::KACS_ACE_TYPE_ACCESS_ALLOWED as u8,
            AceType::AccessDenied => sys::KACS_ACE_TYPE_ACCESS_DENIED as u8,
            AceType::SystemAudit => sys::KACS_ACE_TYPE_SYSTEM_AUDIT as u8,
            AceType::SystemMandatoryLabel => sys::KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL as u8,
            AceType::SystemResourceAttribute => sys::KACS_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE as u8,
            AceType::Other(v) => v,
        }
    }

    fn from_raw(v: u8) -> AceType {
        match v as u32 {
            sys::KACS_ACE_TYPE_ACCESS_ALLOWED => AceType::AccessAllowed,
            sys::KACS_ACE_TYPE_ACCESS_DENIED => AceType::AccessDenied,
            sys::KACS_ACE_TYPE_SYSTEM_AUDIT => AceType::SystemAudit,
            sys::KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL => AceType::SystemMandatoryLabel,
            sys::KACS_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE => AceType::SystemResourceAttribute,
            _ => AceType::Other(v),
        }
    }
}

bitflags! {
    /// ACE inheritance and audit flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AceFlags: u8 {
        /// Inherited by child objects.
        const OBJECT_INHERIT = sys::KACS_ACE_FLAG_OBJECT_INHERIT as u8;
        /// Inherited by child containers.
        const CONTAINER_INHERIT = sys::KACS_ACE_FLAG_CONTAINER_INHERIT as u8;
        /// Inheritance does not propagate past direct children.
        const NO_PROPAGATE_INHERIT = sys::KACS_ACE_FLAG_NO_PROPAGATE_INHERIT as u8;
        /// Applies to children only, not the object itself.
        const INHERIT_ONLY = sys::KACS_ACE_FLAG_INHERIT_ONLY as u8;
        /// This ACE was itself inherited.
        const INHERITED = sys::KACS_ACE_FLAG_INHERITED as u8;
        /// Audit successful access (audit ACEs).
        const SUCCESSFUL_ACCESS = sys::KACS_ACE_FLAG_SUCCESSFUL_ACCESS as u8;
        /// Audit failed access (audit ACEs).
        const FAILED_ACCESS = sys::KACS_ACE_FLAG_FAILED_ACCESS as u8;
    }
}

bitflags! {
    /// The "no-up" policy bits of a mandatory-integrity label.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LabelPolicy: u32 {
        /// Lower-integrity subjects cannot read up.
        const NO_READ_UP = sys::KACS_SYSTEM_MANDATORY_LABEL_NO_READ_UP;
        /// Lower-integrity subjects cannot write up.
        const NO_WRITE_UP = sys::KACS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
        /// Lower-integrity subjects cannot execute up.
        const NO_EXECUTE_UP = sys::KACS_SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
    }
}

/// A general ACE description for [`AclBuilder::add`], covering the object,
/// callback, and resource-attribute families. Fields not used by `ace_type` are
/// left at their defaults.
#[derive(Debug, Clone, Copy)]
pub struct Ace<'a> {
    /// The ACE type discriminant.
    pub ace_type: AceType,
    /// Inheritance / audit flags.
    pub flags: AceFlags,
    /// The access mask.
    pub mask: u32,
    /// The trustee SID.
    pub sid: &'a SidRef,
    /// Object-ACE object-type GUID (16 bytes), if any.
    pub object_type: Option<&'a [u8; 16]>,
    /// Object-ACE inherited-object-type GUID (16 bytes), if any.
    pub inherited_object_type: Option<&'a [u8; 16]>,
    /// Trailing application data (callback / resource-attribute ACEs).
    pub app_data: Option<&'a [u8]>,
}

/// A sticky-error builder for an [`Acl`].
///
/// The adders cannot fail individually (mirroring the C contract); the first
/// error latches and surfaces at [`build`](Self::build).
pub struct AclBuilder {
    raw: *mut sys::peios_acl_builder,
}

impl AclBuilder {
    /// Create an empty ACL builder.
    pub fn new() -> AclBuilder {
        // SAFETY: _new returns an owned builder or null on allocation failure.
        let raw = unsafe { sys::peios_acl_builder_new() };
        assert!(!raw.is_null(), "peios_acl_builder_new: out of memory");
        AclBuilder { raw }
    }

    /// Drop all accumulated ACEs and clear the latched error, reusing the builder.
    pub fn reset(&mut self) -> &mut Self {
        // SAFETY: `raw` is a live builder.
        unsafe { sys::peios_acl_builder_reset(self.raw) };
        self
    }

    /// Append an access-allowed ACE.
    pub fn allow(&mut self, sid: &SidRef, mask: u32, flags: AceFlags) -> &mut Self {
        let (p, n) = sid::raw(sid);
        // SAFETY: `raw` is live; `sid` is a valid SID of `n` bytes.
        unsafe { sys::peios_acl_builder_allow(self.raw, p, n, mask, flags.bits()) };
        self
    }

    /// Append an access-denied ACE.
    pub fn deny(&mut self, sid: &SidRef, mask: u32, flags: AceFlags) -> &mut Self {
        let (p, n) = sid::raw(sid);
        // SAFETY: `raw` is live; `sid` is a valid SID of `n` bytes.
        unsafe { sys::peios_acl_builder_deny(self.raw, p, n, mask, flags.bits()) };
        self
    }

    /// Append a system-audit ACE.
    pub fn audit(&mut self, sid: &SidRef, mask: u32, flags: AceFlags) -> &mut Self {
        let (p, n) = sid::raw(sid);
        // SAFETY: `raw` is live; `sid` is a valid SID of `n` bytes.
        unsafe { sys::peios_acl_builder_audit(self.raw, p, n, mask, flags.bits()) };
        self
    }

    /// Append a mandatory-integrity label ACE for integrity level `integrity_rid`.
    pub fn label(&mut self, integrity_rid: u32, policy: LabelPolicy) -> &mut Self {
        // SAFETY: `raw` is live.
        unsafe { sys::peios_acl_builder_label(self.raw, integrity_rid, policy.bits()) };
        self
    }

    /// Append an arbitrary ACE (object / callback / resource-attribute families).
    pub fn add(&mut self, ace: &Ace<'_>) -> &mut Self {
        let (sid_p, sid_n) = sid::raw(ace.sid);
        let (app_p, app_n) = match ace.app_data {
            Some(d) => (d.as_ptr().cast::<c_void>(), d.len()),
            None => (core::ptr::null(), 0),
        };
        let spec = sys::peios_ace_spec {
            type_: ace.ace_type.to_raw(),
            flags: ace.flags.bits(),
            mask: ace.mask,
            sid: sid_p,
            sid_len: sid_n,
            object_type: ace.object_type.map_or(core::ptr::null(), |g| g.as_ptr()),
            inherited_object_type: ace.inherited_object_type.map_or(core::ptr::null(), |g| g.as_ptr()),
            app_data: app_p,
            app_data_len: app_n,
        };
        // SAFETY: `raw` is live; `spec` borrows live buffers for the duration of the call.
        unsafe { sys::peios_acl_builder_add(self.raw, &spec) };
        self
    }

    /// Serialize the accumulated ACEs into an owned [`Acl`], or return the latched
    /// error.
    pub fn build(&self) -> Result<Acl> {
        // SAFETY: `raw` is live; _error reads the latched errno.
        let err = unsafe { sys::peios_acl_builder_error(self.raw) };
        if err != 0 {
            return Err(Error::from_raw_os_error(err));
        }
        let bytes = probe(|buf, cap| {
            // SAFETY: `raw` is live; (buf, cap) is the getxattr-style output window.
            unsafe { sys::peios_acl_builder_finish(self.raw, buf, cap) }
        })?;
        Ok(Acl(bytes))
    }
}

impl Default for AclBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AclBuilder {
    fn drop(&mut self) {
        // SAFETY: `raw` came from _new and is dropped exactly once.
        unsafe { sys::peios_acl_builder_free(self.raw) };
    }
}

/// An owned, serialized ACL in KACS wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl(pub(crate) Vec<u8>);

impl Acl {
    /// Borrow the raw ACL bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parse this ACL into a borrowing [`AclView`].
    pub fn view(&self) -> Result<AclView<'_>> {
        AclView::parse(&self.0)
    }
}

/// A zero-copy reader over a serialized ACL. Borrows the bytes it parses.
#[derive(Clone, Copy)]
pub struct AclView<'a> {
    raw: sys::peios_acl_view,
    _buf: PhantomData<&'a [u8]>,
}

impl<'a> AclView<'a> {
    /// Parse a bare ACL buffer.
    pub fn parse(acl: &'a [u8]) -> Result<AclView<'a>> {
        let mut raw = sys::peios_acl_view { _opaque: [0; 4] };
        // SAFETY: (ptr, len) from a live slice; `raw` is a writable out-view.
        let r = unsafe { sys::peios_acl_parse(acl.as_ptr().cast(), acl.len(), &mut raw) };
        crate::util::check(r)?;
        Ok(AclView { raw, _buf: PhantomData })
    }

    pub(crate) fn from_raw(raw: sys::peios_acl_view) -> AclView<'a> {
        AclView { raw, _buf: PhantomData }
    }

    /// The number of ACEs.
    pub fn len(&self) -> usize {
        // SAFETY: `raw` is a populated view.
        (unsafe { sys::peios_acl_view_count(&self.raw) }) as usize
    }

    /// Whether the ACL has no ACEs (a present-but-empty DACL).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ACE at index `i`, in stored order.
    pub fn ace(&self, i: usize) -> Option<AceView<'a>> {
        let mut raw = sys::peios_ace_view { _opaque: [0; 4] };
        // SAFETY: `self.raw` is populated; `raw` is a writable out-view.
        let r = unsafe { sys::peios_acl_view_ace(&self.raw, i as core::ffi::c_uint, &mut raw) };
        (r == 0).then_some(AceView { raw, _buf: PhantomData })
    }

    /// Iterate over the ACEs in stored order.
    pub fn iter(&self) -> impl Iterator<Item = AceView<'a>> + '_ {
        (0..self.len()).map_while(|i| self.ace(i))
    }
}

/// A zero-copy reader over a single ACE. Borrows the underlying ACL buffer.
#[derive(Clone, Copy)]
pub struct AceView<'a> {
    raw: sys::peios_ace_view,
    _buf: PhantomData<&'a [u8]>,
}

impl<'a> AceView<'a> {
    /// The ACE type.
    pub fn ace_type(&self) -> AceType {
        // SAFETY: `raw` is a populated ACE view.
        AceType::from_raw(unsafe { sys::peios_ace_view_type(&self.raw) })
    }

    /// The inheritance / audit flags.
    pub fn flags(&self) -> AceFlags {
        // SAFETY: `raw` is a populated ACE view.
        AceFlags::from_bits_retain(unsafe { sys::peios_ace_view_flags(&self.raw) })
    }

    /// The access mask.
    pub fn mask(&self) -> u32 {
        // SAFETY: `raw` is a populated ACE view.
        unsafe { sys::peios_ace_view_mask(&self.raw) }
    }

    /// The trustee SID, borrowing the ACL buffer.
    pub fn sid(&self) -> Option<&'a SidRef> {
        let mut p: *const c_void = core::ptr::null();
        let mut len = 0usize;
        // SAFETY: `raw` is populated; out-params are writable.
        let r = unsafe { sys::peios_ace_view_sid(&self.raw, &mut p, &mut len) };
        if r != 0 || p.is_null() {
            return None;
        }
        // SAFETY: libpeios returned a pointer to a valid SID of `len` bytes inside
        // the buffer this view borrows ('a).
        let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) };
        // SAFETY: the SID came from a parsed, validated ACL.
        Some(unsafe { SidRef::from_bytes_unchecked(bytes) })
    }

    /// The object-type GUID of an object ACE, if present.
    pub fn object_type(&self) -> Option<&'a [u8; 16]> {
        let mut p: *const u8 = core::ptr::null();
        // SAFETY: `raw` is populated; out-param is writable.
        let r = unsafe { sys::peios_ace_view_object_type(&self.raw, &mut p) };
        if r != 0 || p.is_null() {
            return None;
        }
        // SAFETY: a 16-byte GUID inside the borrowed buffer.
        Some(unsafe { &*(p as *const [u8; 16]) })
    }

    /// The inherited-object-type GUID of an object ACE, if present. This GUID
    /// limits which child object class the ACE propagates to on inheritance.
    pub fn inherited_object_type(&self) -> Option<&'a [u8; 16]> {
        let mut p: *const u8 = core::ptr::null();
        // SAFETY: `raw` is populated; out-param is writable.
        let r = unsafe { sys::peios_ace_view_inherited_object_type(&self.raw, &mut p) };
        if r != 0 || p.is_null() {
            return None;
        }
        // SAFETY: a 16-byte GUID inside the borrowed buffer.
        Some(unsafe { &*(p as *const [u8; 16]) })
    }

    /// The trailing application data of a callback / resource-attribute ACE.
    pub fn app_data(&self) -> Option<&'a [u8]> {
        let mut p: *const c_void = core::ptr::null();
        let mut len = 0usize;
        // SAFETY: `raw` is populated; out-params are writable.
        let r = unsafe { sys::peios_ace_view_app_data(&self.raw, &mut p, &mut len) };
        if r != 0 || p.is_null() {
            return None;
        }
        // SAFETY: `len` bytes inside the borrowed buffer.
        Some(unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) })
    }
}

/// A zero-copy reader over a SID-and-attributes array — the blob returned by the
/// token GROUPS / RESTRICTED_SIDS / DEVICE_GROUPS / CAPABILITIES classes.
#[derive(Clone, Copy)]
pub struct SidArrayView<'a> {
    raw: sys::peios_sid_array_view,
    _buf: PhantomData<&'a [u8]>,
}

/// One entry of a [`SidArrayView`]: a SID and its attribute bits.
#[derive(Clone, Copy)]
pub struct SidAndAttributes<'a> {
    /// The SID, borrowing the array buffer.
    pub sid: &'a SidRef,
    /// The attribute bits (`KACS_SID_GROUP_*`).
    pub attributes: u32,
}

impl<'a> SidArrayView<'a> {
    /// Parse a SID-and-attributes blob.
    pub fn parse(blob: &'a [u8]) -> Result<SidArrayView<'a>> {
        let mut raw = sys::peios_sid_array_view { _opaque: [0; 4] };
        // SAFETY: (ptr, len) from a live slice; `raw` is a writable out-view.
        let r = unsafe { sys::peios_sid_array_parse(blob.as_ptr().cast(), blob.len(), &mut raw) };
        crate::util::check(r)?;
        Ok(SidArrayView { raw, _buf: PhantomData })
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        // SAFETY: `raw` is a populated view.
        (unsafe { sys::peios_sid_array_count(&self.raw) }) as usize
    }

    /// Whether the array is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The entry at index `i`.
    pub fn get(&self, i: usize) -> Option<SidAndAttributes<'a>> {
        let mut p: *const c_void = core::ptr::null();
        let mut len = 0usize;
        let mut attrs = 0u32;
        // SAFETY: `raw` is populated; out-params are writable.
        let r = unsafe {
            sys::peios_sid_array_get(&self.raw, i as core::ffi::c_uint, &mut p, &mut len, &mut attrs)
        };
        if r != 0 || p.is_null() {
            return None;
        }
        // SAFETY: a valid SID of `len` bytes inside the borrowed buffer.
        let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) };
        Some(SidAndAttributes {
            sid: unsafe { SidRef::from_bytes_unchecked(bytes) },
            attributes: attrs,
        })
    }

    /// Iterate over the entries.
    pub fn iter(&self) -> impl Iterator<Item = SidAndAttributes<'a>> + '_ {
        (0..self.len()).map_while(|i| self.get(i))
    }
}
