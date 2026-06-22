//! Security identifiers (SIDs).
//!
//! A SID is a short, bounded (≤ [`Sid::MAX_LEN`] bytes), self-contained binary
//! identifier compared by exact byte equality. [`Sid`] is the owned form — an
//! inline buffer, so it is `Copy` and never allocates — and [`SidRef`] is the
//! borrowed form ([`Sid`] is to [`SidRef`] as [`PathBuf`](std::path::PathBuf) is
//! to [`Path`](std::path::Path)). SIDs parsed *out of* a token or security
//! descriptor are handed back as `&SidRef` borrowing that buffer.

use core::ffi::{c_char, c_void};
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use peios_sys as sys;

use crate::error::{Error, Result};

/// A well-known SID, selected by [`Sid::well_known`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WellKnown {
    /// `S-1-0-0` — Nobody.
    Null,
    /// `S-1-1-0` — World / Everyone.
    Everyone,
    /// `S-1-2-0` — Local.
    Local,
    /// `S-1-3-0` — Creator Owner.
    CreatorOwner,
    /// `S-1-3-1` — Creator Group.
    CreatorGroup,
    /// `S-1-3-4` — Owner Rights (suppresses the owner's implicit `WRITE_DAC`).
    OwnerRights,
    /// `S-1-5-7` — Anonymous.
    Anonymous,
    /// `S-1-5-10` — `PRINCIPAL_SELF`.
    PrincipalSelf,
    /// `S-1-5-11` — Authenticated Users.
    AuthenticatedUsers,
    /// `S-1-5-18` — Local System.
    System,
    /// `S-1-5-19` — Local Service.
    LocalService,
    /// `S-1-5-20` — Network Service.
    NetworkService,
    /// `S-1-5-32-544` — Administrators.
    Administrators,
}

impl WellKnown {
    fn raw(self) -> sys::peios_wks {
        use WellKnown::*;
        (match self {
            Null => sys::peios_wks_PEIOS_WKS_NULL,
            Everyone => sys::peios_wks_PEIOS_WKS_EVERYONE,
            Local => sys::peios_wks_PEIOS_WKS_LOCAL,
            CreatorOwner => sys::peios_wks_PEIOS_WKS_CREATOR_OWNER,
            CreatorGroup => sys::peios_wks_PEIOS_WKS_CREATOR_GROUP,
            OwnerRights => sys::peios_wks_PEIOS_WKS_OWNER_RIGHTS,
            Anonymous => sys::peios_wks_PEIOS_WKS_ANONYMOUS,
            PrincipalSelf => sys::peios_wks_PEIOS_WKS_SELF,
            AuthenticatedUsers => sys::peios_wks_PEIOS_WKS_AUTHENTICATED_USERS,
            System => sys::peios_wks_PEIOS_WKS_SYSTEM,
            LocalService => sys::peios_wks_PEIOS_WKS_LOCAL_SERVICE,
            NetworkService => sys::peios_wks_PEIOS_WKS_NETWORK_SERVICE,
            Administrators => sys::peios_wks_PEIOS_WKS_ADMINISTRATORS,
        }) as sys::peios_wks
    }
}

/// A mandatory-integrity level — the RID of an `S-1-16-x` label SID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntegrityLevel(pub u32);

impl IntegrityLevel {
    /// Untrusted (RID 0).
    pub const UNTRUSTED: Self = Self(0);
    /// Low integrity (RID 4096).
    pub const LOW: Self = Self(4096);
    /// Medium integrity (RID 8192) — the default for ordinary users.
    pub const MEDIUM: Self = Self(8192);
    /// High integrity (RID 12288) — elevated.
    pub const HIGH: Self = Self(12288);
    /// System integrity (RID 16384).
    pub const SYSTEM: Self = Self(16384);

    /// The integrity RID.
    #[inline]
    pub const fn rid(self) -> u32 {
        self.0
    }
}

/// An owned SID: an inline, `Copy` buffer (never allocates).
#[derive(Clone, Copy)]
pub struct Sid {
    buf: [u8; Self::MAX_LEN],
    len: u8,
}

impl Sid {
    /// The largest possible encoded SID, in bytes. A buffer this size holds any
    /// valid SID, so SID construction never needs a two-call size probe.
    pub const MAX_LEN: usize = sys::PEIOS_SID_MAX_BYTES as usize;

    /// Build a SID from its identifier authority and sub-authorities.
    ///
    /// `sub_auths` may hold up to 15 entries; more fails with `EINVAL`.
    pub fn build(id_authority: u64, sub_auths: &[u32]) -> Result<Sid> {
        let mut buf = [0u8; Self::MAX_LEN];
        // SAFETY: `buf` is MAX_LEN, which holds any SID; `count` matches the slice.
        let n = unsafe {
            sys::peios_sid_build(
                buf.as_mut_ptr().cast(),
                buf.len(),
                id_authority,
                sub_auths.as_ptr(),
                sub_auths.len() as core::ffi::c_uint,
            )
        };
        Self::from_encoded(buf, crate::util::check_len(n)?)
    }

    /// Construct a well-known SID. Infallible: every variant fits in [`MAX_LEN`](Self::MAX_LEN).
    pub fn well_known(which: WellKnown) -> Sid {
        let mut buf = [0u8; Self::MAX_LEN];
        // SAFETY: output buffer sized for any SID; `which` is a valid enumerator.
        let n = unsafe { sys::peios_sid_well_known(buf.as_mut_ptr().cast(), buf.len(), which.raw()) };
        Self::from_encoded(buf, n as usize).expect("well-known SID always encodes")
    }

    /// Construct the integrity-label SID `S-1-16-<rid>`.
    pub fn integrity(level: IntegrityLevel) -> Sid {
        let mut buf = [0u8; Self::MAX_LEN];
        // SAFETY: output buffer sized for any SID.
        let n = unsafe { sys::peios_sid_integrity(buf.as_mut_ptr().cast(), buf.len(), level.rid()) };
        Self::from_encoded(buf, n as usize).expect("integrity SID always encodes")
    }

    /// Construct the logon SID `S-1-5-5-<hi>-<lo>` for a session id.
    pub fn logon(session_id: u64) -> Sid {
        let mut buf = [0u8; Self::MAX_LEN];
        // SAFETY: output buffer sized for any SID.
        let n = unsafe { sys::peios_sid_logon(buf.as_mut_ptr().cast(), buf.len(), session_id) };
        Self::from_encoded(buf, n as usize).expect("logon SID always encodes")
    }

    /// Copy a borrowed SID into an owned one.
    pub fn from_ref(sid: &SidRef) -> Sid {
        let mut buf = [0u8; Self::MAX_LEN];
        let bytes = sid.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        Sid { buf, len: bytes.len() as u8 }
    }

    fn from_encoded(buf: [u8; Self::MAX_LEN], len: usize) -> Result<Sid> {
        debug_assert!(len <= Self::MAX_LEN);
        Ok(Sid { buf, len: len as u8 })
    }
}

impl Deref for Sid {
    type Target = SidRef;
    #[inline]
    fn deref(&self) -> &SidRef {
        // SAFETY: `buf[..len]` is the SID we encoded — already valid.
        unsafe { SidRef::from_bytes_unchecked(&self.buf[..self.len as usize]) }
    }
}

impl Borrow<SidRef> for Sid {
    #[inline]
    fn borrow(&self) -> &SidRef {
        self
    }
}

impl AsRef<SidRef> for Sid {
    #[inline]
    fn as_ref(&self) -> &SidRef {
        self
    }
}

impl FromStr for Sid {
    type Err = Error;
    /// Parse the SDDL string form, e.g. `"S-1-5-21-…"`.
    fn from_str(s: &str) -> Result<Sid> {
        let c = std::ffi::CString::new(s).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let mut buf = [0u8; Self::MAX_LEN];
        // SAFETY: output buffer sized for any SID; `c` is a valid C string.
        let n = unsafe { sys::peios_sid_parse_string(buf.as_mut_ptr().cast(), buf.len(), c.as_ptr()) };
        Self::from_encoded(buf, crate::util::check_len(n)?)
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl PartialEq for Sid {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for Sid {}

impl std::hash::Hash for Sid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialEq<SidRef> for Sid {
    #[inline]
    fn eq(&self, other: &SidRef) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

/// A borrowed SID — a validated, self-relative byte buffer. Unsized; always held
/// behind a reference (`&SidRef`), exactly like [`Path`](std::path::Path).
#[repr(transparent)]
pub struct SidRef([u8]);

impl SidRef {
    /// Borrow a byte buffer as a SID, validating its structure first. Returns
    /// `None` if the bytes are not a structurally valid SID of exactly this length.
    pub fn from_bytes(bytes: &[u8]) -> Option<&SidRef> {
        // SAFETY: pointer/len from a live slice.
        let valid = unsafe { sys::peios_sid_valid(bytes.as_ptr().cast(), bytes.len()) };
        // SAFETY: just validated.
        valid.then(|| unsafe { SidRef::from_bytes_unchecked(bytes) })
    }

    /// Borrow bytes as a SID without validating.
    ///
    /// # Safety
    /// `bytes` must be a structurally valid SID of exactly `bytes.len()` bytes.
    #[inline]
    pub(crate) unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &SidRef {
        // SAFETY: SidRef is repr(transparent) over [u8]; caller guarantees validity.
        unsafe { &*(bytes as *const [u8] as *const SidRef) }
    }

    /// The raw self-relative SID bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The RID — the last sub-authority — or `0` if the SID has none.
    pub fn rid(&self) -> u32 {
        // SAFETY: `self` is a validated SID of `self.0.len()` bytes.
        unsafe { sys::peios_sid_rid(self.0.as_ptr().cast(), self.0.len()) }
    }

    /// Copy into an owned [`Sid`].
    pub fn to_sid(&self) -> Sid {
        Sid::from_ref(self)
    }
}

impl ToOwned for SidRef {
    type Owned = Sid;
    #[inline]
    fn to_owned(&self) -> Sid {
        Sid::from_ref(self)
    }
}

impl PartialEq for SidRef {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SidRef {}

impl std::hash::Hash for SidRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for SidRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

impl fmt::Display for SidRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 256 bytes holds the SDDL form of any SID (≤ 15 sub-authorities).
        let mut text = [0u8; 256];
        // SAFETY: `self` is a validated SID; `text` is a writable output buffer.
        let n = unsafe {
            sys::peios_sid_format(
                self.0.as_ptr().cast(),
                self.0.len(),
                text.as_mut_ptr() as *mut c_char,
                text.len(),
            )
        };
        if n < 0 {
            return f.write_str("S-?");
        }
        let s = core::str::from_utf8(&text[..n as usize]).map_err(|_| fmt::Error)?;
        f.write_str(s)
    }
}

const EINVAL: i32 = 22;

/// Raw `(ptr, len)` for passing a borrowed SID to an FFI call expecting
/// `(const void *, size_t)`.
#[inline]
pub(crate) fn raw(sid: &SidRef) -> (*const c_void, usize) {
    (sid.as_bytes().as_ptr().cast(), sid.as_bytes().len())
}
