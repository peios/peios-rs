//! Security descriptors: the [`SdBuilder`], an owned [`SecurityDescriptor`], and
//! a zero-copy [`SdView`].

use core::ffi::c_void;
use core::marker::PhantomData;

use bitflags::bitflags;
use peios_sys as sys;

use super::acl::{Acl, AclView};
use super::sid::SidRef;
use crate::error::{Error, Result};
use crate::util::probe;

bitflags! {
    /// Security-descriptor control bits. `SELF_RELATIVE` and the component
    /// `*_PRESENT` bits are managed by the builder and need not be set by hand.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Control: u16 {
        /// The DACL is present.
        const DACL_PRESENT = sys::KACS_SD_DACL_PRESENT as u16;
        /// The SACL is present.
        const SACL_PRESENT = sys::KACS_SD_SACL_PRESENT as u16;
        /// The DACL is protected from inheritance.
        const DACL_PROTECTED = sys::KACS_SD_DACL_PROTECTED as u16;
        /// The SACL is protected from inheritance.
        const SACL_PROTECTED = sys::KACS_SD_SACL_PROTECTED as u16;
        /// The DACL was auto-inherited.
        const DACL_AUTO_INHERITED = sys::KACS_SD_DACL_AUTO_INHERITED as u16;
        /// The SACL was auto-inherited.
        const SACL_AUTO_INHERITED = sys::KACS_SD_SACL_AUTO_INHERITED as u16;
        /// The descriptor is in self-relative form.
        const SELF_RELATIVE = sys::KACS_SD_SELF_RELATIVE as u16;
    }
}

/// A sticky-error builder for a [`SecurityDescriptor`].
///
/// Omit a component's setter to leave it absent — useful for building a partial
/// SD that sets only some components (e.g. for a by-component update). The first
/// error latches and surfaces at [`build`](Self::build).
pub struct SdBuilder {
    raw: *mut sys::peios_sd_builder,
}

impl SdBuilder {
    /// Create an empty SD builder.
    pub fn new() -> SdBuilder {
        // SAFETY: _new returns an owned builder or null on allocation failure.
        let raw = unsafe { sys::peios_sd_builder_new() };
        assert!(!raw.is_null(), "peios_sd_builder_new: out of memory");
        SdBuilder { raw }
    }

    /// Clear all components and the latched error, reusing the builder.
    pub fn reset(&mut self) -> &mut Self {
        // SAFETY: `raw` is live.
        unsafe { sys::peios_sd_builder_reset(self.raw) };
        self
    }

    /// Set the owner SID.
    pub fn owner(&mut self, sid: &SidRef) -> &mut Self {
        let (p, n) = super::sid::raw(sid);
        // SAFETY: `raw` is live; `sid` is valid for `n` bytes.
        unsafe { sys::peios_sd_builder_owner(self.raw, p, n) };
        self
    }

    /// Set the group SID.
    pub fn group(&mut self, sid: &SidRef) -> &mut Self {
        let (p, n) = super::sid::raw(sid);
        // SAFETY: `raw` is live; `sid` is valid for `n` bytes.
        unsafe { sys::peios_sd_builder_group(self.raw, p, n) };
        self
    }

    /// Set and/or clear control bits.
    pub fn control(&mut self, set: Control, clear: Control) -> &mut Self {
        // SAFETY: `raw` is live.
        unsafe { sys::peios_sd_builder_control(self.raw, set.bits(), clear.bits()) };
        self
    }

    /// Set the DACL. An ACL with zero ACEs is a present-but-empty DACL.
    pub fn dacl(&mut self, acl: &Acl) -> &mut Self {
        // SAFETY: `raw` is live; `acl` bytes live for the call.
        unsafe {
            sys::peios_sd_builder_dacl(
                self.raw,
                acl.as_bytes().as_ptr().cast(),
                acl.as_bytes().len(),
            )
        };
        self
    }

    /// Request an *absent* DACL (KACS' "grant everyone" — there is no NULL-DACL
    /// encoding), clearing any DACL set earlier.
    pub fn dacl_grant_all(&mut self) -> &mut Self {
        // SAFETY: `raw` is live.
        unsafe { sys::peios_sd_builder_dacl_null(self.raw) };
        self
    }

    /// Set the SACL.
    pub fn sacl(&mut self, acl: &Acl) -> &mut Self {
        // SAFETY: `raw` is live; `acl` bytes live for the call.
        unsafe {
            sys::peios_sd_builder_sacl(
                self.raw,
                acl.as_bytes().as_ptr().cast(),
                acl.as_bytes().len(),
            )
        };
        self
    }

    /// Serialize into an owned [`SecurityDescriptor`], or return the latched error.
    pub fn build(&self) -> Result<SecurityDescriptor> {
        // SAFETY: `raw` is live.
        let err = unsafe { sys::peios_sd_builder_error(self.raw) };
        if err != 0 {
            return Err(Error::from_raw_os_error(err));
        }
        let bytes = probe(|buf, cap| {
            // SAFETY: `raw` is live; (buf, cap) is the getxattr-style output window.
            unsafe { sys::peios_sd_builder_finish(self.raw, buf, cap) }
        })?;
        Ok(SecurityDescriptor(bytes))
    }
}

impl Default for SdBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SdBuilder {
    fn drop(&mut self) {
        // SAFETY: `raw` came from _new and is dropped exactly once.
        unsafe { sys::peios_sd_builder_free(self.raw) };
    }
}

/// An owned, self-relative security descriptor in KACS wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor(pub(crate) Vec<u8>);

impl SecurityDescriptor {
    /// Wrap raw self-relative SD bytes without validation (e.g. bytes read back
    /// from a `get_sd` call).
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        SecurityDescriptor(bytes)
    }

    /// Validate raw self-relative security-descriptor bytes and wrap them in an
    /// owned descriptor.
    pub fn from_validated_bytes(bytes: Vec<u8>) -> Result<Self> {
        SdView::parse(&bytes)?;
        Ok(SecurityDescriptor(bytes))
    }

    /// Borrow the raw SD bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parse into a borrowing [`SdView`].
    pub fn view(&self) -> Result<SdView<'_>> {
        SdView::parse(&self.0)
    }
}

/// A zero-copy reader over a serialized security descriptor. Borrows its buffer.
#[derive(Clone, Copy)]
pub struct SdView<'a> {
    raw: sys::peios_sd_view,
    _buf: PhantomData<&'a [u8]>,
}

impl<'a> SdView<'a> {
    /// Validate and parse a self-relative SD.
    pub fn parse(sd: &'a [u8]) -> Result<SdView<'a>> {
        let mut raw = sys::peios_sd_view { _opaque: [0; 8] };
        // SAFETY: (ptr, len) from a live slice; `raw` is a writable out-view.
        let r = unsafe { sys::peios_sd_parse(sd.as_ptr().cast(), sd.len(), &mut raw) };
        crate::util::check(r)?;
        Ok(SdView {
            raw,
            _buf: PhantomData,
        })
    }

    /// The control bits.
    pub fn control(&self) -> Control {
        // SAFETY: `raw` is populated.
        Control::from_bits_retain(unsafe { sys::peios_sd_view_control(&self.raw) })
    }

    /// The owner SID, if present.
    pub fn owner(&self) -> Option<&'a SidRef> {
        // SAFETY: out-params writable; `raw` populated.
        sid_component(|p, l| unsafe { sys::peios_sd_view_owner(&self.raw, p, l) })
    }

    /// The group SID, if present.
    pub fn group(&self) -> Option<&'a SidRef> {
        // SAFETY: out-params writable; `raw` populated.
        sid_component(|p, l| unsafe { sys::peios_sd_view_group(&self.raw, p, l) })
    }

    /// The DACL, if present (absent = grant-all).
    pub fn dacl(&self) -> Option<AclView<'a>> {
        let mut acl = sys::peios_acl_view { _opaque: [0; 4] };
        // SAFETY: `raw` populated; `acl` writable.
        let r = unsafe { sys::peios_sd_view_dacl(&self.raw, &mut acl) };
        (r == 0).then(|| AclView::from_raw(acl))
    }

    /// The SACL, if present.
    pub fn sacl(&self) -> Option<AclView<'a>> {
        let mut acl = sys::peios_acl_view { _opaque: [0; 4] };
        // SAFETY: `raw` populated; `acl` writable.
        let r = unsafe { sys::peios_sd_view_sacl(&self.raw, &mut acl) };
        (r == 0).then(|| AclView::from_raw(acl))
    }
}

/// Shared helper for the SID-component accessors (owner / group).
fn sid_component<'a, F>(call: F) -> Option<&'a SidRef>
where
    F: FnOnce(*mut *const c_void, *mut usize) -> core::ffi::c_int,
{
    let mut p: *const c_void = core::ptr::null();
    let mut len = 0usize;
    if call(&mut p, &mut len) != 0 || p.is_null() {
        return None;
    }
    // SAFETY: libpeios returned a valid SID of `len` bytes inside the borrowed
    // buffer ('a).
    let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) };
    Some(unsafe { SidRef::from_bytes_unchecked(bytes) })
}
