//! KACS native file objects: the `NtCreateFile`-shaped open, by-path and by-fd
//! security-descriptor I/O, and mount-policy control.
//!
//! [`File`] is an fd-backed handle (so it `impl`s [`AsFd`] and drops cleanly) —
//! an ordinary Linux file fd whose granted access mask is fixed for the fd's
//! lifetime, so it can be delegated by `dup` / `SCM_RIGHTS` / `exec`. It is
//! opened through [`OpenOptions`], a builder over [`struct peios_open_params`]
//! carrying a desired-access mask ([`FileAccess`]), a create [`Disposition`],
//! [`CreateOptions`], [`OpenFlags`], and an optional creator
//! [`SecurityDescriptor`]. The create disposition (opened / created / …) is a
//! success output ([`OpenStatus`]) returned alongside the handle, never an error.
//!
//! [`get_sd`] / [`set_sd`] read and write a file's security descriptor by path;
//! [`File::fd_get_sd`] / [`File::fd_set_sd`] do so by fd. The mount-policy calls
//! ([`File::mount_get_policy`] / [`File::mount_set_policy`]) govern how a
//! superblock without native SD storage is treated.

use core::ffi::c_void;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::{GenericMapping, SecurityDescriptor};
use crate::util::{check, check_fd, opt_fd, probe};

bitflags! {
    /// A file/directory desired-access mask: the file-object rights plus the
    /// standard and generic rights. The directory aliases (`LIST_DIRECTORY`,
    /// `TRAVERSE`, `ADD_FILE`, `ADD_SUBDIRECTORY`) share bits with the
    /// file-data rights and name the same operation on a directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileAccess: u32 {
        /// Read file data.
        const READ_DATA = sys::KACS_FILE_READ_DATA;
        /// List a directory's entries (alias of `READ_DATA`).
        const LIST_DIRECTORY = sys::KACS_FILE_LIST_DIRECTORY;
        /// Write file data.
        const WRITE_DATA = sys::KACS_FILE_WRITE_DATA;
        /// Create a file in a directory (alias of `WRITE_DATA`).
        const ADD_FILE = sys::KACS_FILE_ADD_FILE;
        /// Append file data.
        const APPEND_DATA = sys::KACS_FILE_APPEND_DATA;
        /// Create a subdirectory (alias of `APPEND_DATA`).
        const ADD_SUBDIRECTORY = sys::KACS_FILE_ADD_SUBDIRECTORY;
        /// Read extended attributes.
        const READ_EA = sys::KACS_FILE_READ_EA;
        /// Write extended attributes.
        const WRITE_EA = sys::KACS_FILE_WRITE_EA;
        /// Execute the file.
        const EXECUTE = sys::KACS_FILE_EXECUTE;
        /// Traverse a directory (alias of `EXECUTE`).
        const TRAVERSE = sys::KACS_FILE_TRAVERSE;
        /// Delete a child of a directory.
        const DELETE_CHILD = sys::KACS_FILE_DELETE_CHILD;
        /// Read attributes.
        const READ_ATTRIBUTES = sys::KACS_FILE_READ_ATTRIBUTES;
        /// Write attributes.
        const WRITE_ATTRIBUTES = sys::KACS_FILE_WRITE_ATTRIBUTES;
        /// Standard: delete.
        const DELETE = sys::KACS_ACCESS_DELETE;
        /// Standard: read the security descriptor.
        const READ_CONTROL = sys::KACS_ACCESS_READ_CONTROL;
        /// Standard: write the DACL.
        const WRITE_DAC = sys::KACS_ACCESS_WRITE_DAC;
        /// Standard: change the owner.
        const WRITE_OWNER = sys::KACS_ACCESS_WRITE_OWNER;
        /// Standard: synchronize (wait) on the object.
        const SYNCHRONIZE = sys::KACS_ACCESS_SYNCHRONIZE;
        /// Generic "all" — mapped to file rights at the open boundary.
        const GENERIC_ALL = sys::KACS_ACCESS_GENERIC_ALL;
        /// Generic "execute".
        const GENERIC_EXECUTE = sys::KACS_ACCESS_GENERIC_EXECUTE;
        /// Generic "write".
        const GENERIC_WRITE = sys::KACS_ACCESS_GENERIC_WRITE;
        /// Generic "read".
        const GENERIC_READ = sys::KACS_ACCESS_GENERIC_READ;
    }
}

bitflags! {
    /// Create options for [`OpenOptions`] (`KACS_CREATE_OPT_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CreateOptions: u32 {
        /// The object must be (or be created as) a directory.
        const DIRECTORY = sys::KACS_CREATE_OPT_DIRECTORY;
        /// Delete the object when the last handle to it closes.
        const DELETE_ON_CLOSE = sys::KACS_CREATE_OPT_DELETE_ON_CLOSE;
    }
}

bitflags! {
    /// Open flags for [`OpenOptions`]: the path-resolution and intent bits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct OpenFlags: u32 {
        /// Do not follow a trailing symlink (`AT_SYMLINK_NOFOLLOW`).
        const SYMLINK_NOFOLLOW = AT_SYMLINK_NOFOLLOW;
        /// Open with backup intent (bypass traversal checks with the privilege).
        const BACKUP_INTENT = sys::KACS_BACKUP_INTENT;
        /// Open with restore intent (bypass traversal checks with the privilege).
        const RESTORE_INTENT = sys::KACS_RESTORE_INTENT;
    }
}

bitflags! {
    /// Security-information selector (`KACS_SECINFO_*`): which components of a
    /// security descriptor a get/set call reads or writes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SecInfo: u32 {
        /// The owner SID.
        const OWNER = sys::KACS_SECINFO_OWNER;
        /// The group SID.
        const GROUP = sys::KACS_SECINFO_GROUP;
        /// The DACL.
        const DACL = sys::KACS_SECINFO_DACL;
        /// The SACL.
        const SACL = sys::KACS_SECINFO_SACL;
        /// The mandatory-integrity label.
        const LABEL = sys::KACS_SECINFO_LABEL;
    }
}

/// The create disposition for an open (`KACS_DISPOSITION_*`): what to do when
/// the target does and does not already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Disposition {
    /// Replace an existing file (delete + create), or create if absent.
    Supersede,
    /// Open an existing file; fail if it does not exist.
    #[default]
    Open,
    /// Create a new file; fail if it already exists.
    Create,
    /// Open if it exists, else create.
    OpenIf,
    /// Open and overwrite an existing file; fail if it does not exist.
    Overwrite,
    /// Overwrite if it exists, else create.
    OverwriteIf,
}

impl Disposition {
    fn to_raw(self) -> u32 {
        match self {
            Disposition::Supersede => sys::KACS_DISPOSITION_SUPERSEDE,
            Disposition::Open => sys::KACS_DISPOSITION_OPEN,
            Disposition::Create => sys::KACS_DISPOSITION_CREATE,
            Disposition::OpenIf => sys::KACS_DISPOSITION_OPEN_IF,
            Disposition::Overwrite => sys::KACS_DISPOSITION_OVERWRITE,
            Disposition::OverwriteIf => sys::KACS_DISPOSITION_OVERWRITE_IF,
        }
    }
}

/// The outcome of an open (`KACS_STATUS_*`), returned alongside the handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenStatus {
    /// An existing object was opened.
    Opened,
    /// A new object was created.
    Created,
    /// An existing object was opened and overwritten.
    Overwritten,
    /// An existing object was superseded (replaced).
    Superseded,
}

impl OpenStatus {
    fn from_raw(v: u32) -> Option<OpenStatus> {
        match v {
            sys::KACS_STATUS_OPENED => Some(OpenStatus::Opened),
            sys::KACS_STATUS_CREATED => Some(OpenStatus::Created),
            sys::KACS_STATUS_OVERWRITTEN => Some(OpenStatus::Overwritten),
            sys::KACS_STATUS_SUPERSEDED => Some(OpenStatus::Superseded),
            _ => None,
        }
    }
}

/// An `NtCreateFile`-shaped open builder over [`struct peios_open_params`].
///
/// Set the desired access, disposition, options, flags, and (on create) the
/// creator security descriptor, then call [`open`](Self::open) or
/// [`create`](Self::create). Unlike `std::fs::OpenOptions`, the disposition is
/// an explicit [`Disposition`] rather than read/write/create booleans.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions<'a> {
    desired_access: FileAccess,
    disposition: Disposition,
    options: CreateOptions,
    flags: OpenFlags,
    sd: Option<&'a SecurityDescriptor>,
}

impl Default for FileAccess {
    fn default() -> Self {
        FileAccess::empty()
    }
}

impl<'a> OpenOptions<'a> {
    /// A fresh builder: no access, [`Disposition::Open`], no options or flags,
    /// no creator SD.
    pub fn new() -> OpenOptions<'a> {
        OpenOptions::default()
    }

    /// Set the desired-access mask granted on the returned fd.
    pub fn desired_access(&mut self, access: FileAccess) -> &mut Self {
        self.desired_access = access;
        self
    }

    /// Set the create disposition.
    pub fn disposition(&mut self, disposition: Disposition) -> &mut Self {
        self.disposition = disposition;
        self
    }

    /// Set the create options.
    pub fn options(&mut self, options: CreateOptions) -> &mut Self {
        self.options = options;
        self
    }

    /// Set the open flags.
    pub fn flags(&mut self, flags: OpenFlags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Set the creator security descriptor, applied when the open creates a new
    /// object (ignored on a pure open).
    pub fn creator_sd(&mut self, sd: &'a SecurityDescriptor) -> &mut Self {
        self.sd = Some(sd);
        self
    }

    /// Open `path` relative to `dirfd` (`None` => the process cwd), returning
    /// the file handle and the [`OpenStatus`] of the open.
    pub fn create(
        &self,
        dirfd: Option<BorrowedFd<'_>>,
        path: &Path,
    ) -> Result<(File, OpenStatus)> {
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let (sd_ptr, sd_len) = match self.sd {
            Some(sd) => (sd.as_bytes().as_ptr().cast::<c_void>(), sd.as_bytes().len()),
            None => (core::ptr::null(), 0),
        };
        let params = sys::peios_open_params {
            desired_access: self.desired_access.bits(),
            disposition: self.disposition.to_raw(),
            options: self.options.bits(),
            flags: self.flags.bits(),
            sd: sd_ptr,
            sd_len,
        };
        let mut status = 0u32;
        // SAFETY: `cpath` is a live NUL-terminated path; `params` borrows the
        // creator-SD bytes (kept alive by `self`) for the call; `status`
        // writable. Returns an owned file fd or -1/errno.
        let fd = check_fd(unsafe {
            sys::peios_file_open(opt_fd(dirfd), cpath.as_ptr(), &params, &mut status)
        })?;
        let status = OpenStatus::from_raw(status).ok_or_else(|| Error::from_raw_os_error(EINVAL))?;
        Ok((File(fd), status))
    }

    /// Open `path` relative to `dirfd`, discarding the [`OpenStatus`].
    pub fn open(&self, dirfd: Option<BorrowedFd<'_>>, path: &Path) -> Result<File> {
        self.create(dirfd, path).map(|(file, _)| file)
    }
}

/// A KACS native file object: an fd-backed handle.
#[derive(Debug)]
pub struct File(OwnedFd);

impl File {
    /// The canonical KACS generic mapping for the file object class.
    pub fn generic_mapping() -> GenericMapping {
        // SAFETY: reading a libpeios-exported POD static.
        GenericMapping::from_raw(unsafe { sys::peios_file_generic_mapping })
    }

    fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// Read this fd's security descriptor (getxattr-style probe). The effective
    /// access check depends on the fd type — the cached granted mask for a
    /// normal file fd, a live check for an `O_PATH` / pidfd / token fd.
    pub fn fd_get_sd(&self, secinfo: SecInfo) -> Result<SecurityDescriptor> {
        let bytes = probe(|buf, cap| {
            // SAFETY: live fd; (buf, cap) is the getxattr-style output window.
            unsafe { sys::peios_fd_get_sd(self.raw(), secinfo.bits(), buf, cap) }
        })?;
        Ok(SecurityDescriptor::from_bytes(bytes))
    }

    /// Write the `secinfo` components of `sd` onto this fd, preserving the rest.
    pub fn fd_set_sd(&self, secinfo: SecInfo, sd: &SecurityDescriptor) -> Result<()> {
        let bytes = sd.as_bytes();
        // SAFETY: live fd; `bytes` (ptr, len) from a live slice.
        check(unsafe {
            sys::peios_fd_set_sd(self.raw(), secinfo.bits(), bytes.as_ptr().cast(), bytes.len())
        })
    }

    /// Read the mount policy of the superblock this fd lives on
    /// (`SeTcbPrivilege`). The template SD is fetched with a size probe.
    pub fn mount_get_policy(&self) -> Result<MountPolicy> {
        // First, learn the policy and the required template buffer size with a
        // NULL template buffer.
        let mut out = sys::peios_mount_policy {
            policy: 0,
            flags: 0,
            generation: 0,
            template_sd: core::ptr::null(),
            template_sd_len: 0,
        };
        // SAFETY: live fd; `out` writable; NULL/0 template buffer just probes.
        check(unsafe {
            sys::peios_mount_get_policy(self.raw(), &mut out, core::ptr::null_mut(), 0)
        })?;

        let template = if out.template_sd_len == 0 {
            None
        } else {
            // Re-read with a buffer large enough for the reported template,
            // growing on ERANGE in case it changed between calls.
            let mut cap = out.template_sd_len;
            let mut got = None;
            for _ in 0..4 {
                let mut buf = vec![0u8; cap];
                let mut o = sys::peios_mount_policy {
                    policy: 0,
                    flags: 0,
                    generation: 0,
                    template_sd: core::ptr::null(),
                    template_sd_len: 0,
                };
                // SAFETY: live fd; `o` writable; `buf` is a writable template
                // window of `cap` bytes that outlives the call.
                let r = unsafe {
                    sys::peios_mount_get_policy(
                        self.raw(),
                        &mut o,
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                };
                if r == 0 {
                    if o.template_sd.is_null() || o.template_sd_len == 0 {
                        break;
                    }
                    buf.truncate(o.template_sd_len);
                    out = o;
                    got = Some(SecurityDescriptor::from_bytes(buf));
                    break;
                }
                match Error::last_os_error().raw_os_error() {
                    Some(e) if e == ERANGE => cap = o.template_sd_len.max(cap + 1),
                    _ => return Err(Error::last_os_error()),
                }
            }
            got
        };

        Ok(MountPolicy {
            kind: MountPolicyKind(out.policy),
            flags: out.flags,
            generation: out.generation,
            template_sd: template,
        })
    }

    /// Set the mount policy of the superblock this fd lives on
    /// (`SeTcbPrivilege`).
    pub fn mount_set_policy(&self, policy: &MountPolicy) -> Result<()> {
        let (sd_ptr, sd_len) = match &policy.template_sd {
            Some(sd) => (sd.as_bytes().as_ptr().cast::<c_void>(), sd.as_bytes().len()),
            None => (core::ptr::null(), 0),
        };
        let p = sys::peios_mount_policy {
            policy: policy.kind.0,
            flags: policy.flags,
            generation: policy.generation,
            template_sd: sd_ptr,
            template_sd_len: sd_len,
        };
        // SAFETY: live fd; `p` borrows the template-SD bytes (kept alive by
        // `policy`) for the call.
        check(unsafe { sys::peios_mount_set_policy(self.raw(), &p) })
    }
}

/// Read a file's security descriptor by path (getxattr-style probe).
///
/// A free function rather than a [`File`] method: it operates on a path
/// relative to `dirfd` (`None` => the process cwd) and never opens a handle.
/// `secinfo` selects the components; `at_flags` accepts `AT_SYMLINK_NOFOLLOW`.
pub fn get_sd(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    secinfo: SecInfo,
    at_flags: i32,
) -> Result<SecurityDescriptor> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let bytes = probe(|buf, cap| {
        // SAFETY: live NUL-terminated path; (buf, cap) is the output window.
        unsafe {
            sys::peios_file_get_sd(
                opt_fd(dirfd),
                cpath.as_ptr(),
                secinfo.bits(),
                buf,
                cap,
                at_flags as u32,
            )
        }
    })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

/// Write the `secinfo` components of `sd` onto a file by path, preserving the
/// rest. A free function for the same reason as [`get_sd`].
pub fn set_sd(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    secinfo: SecInfo,
    sd: &SecurityDescriptor,
    at_flags: i32,
) -> Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let bytes = sd.as_bytes();
    // SAFETY: live NUL-terminated path; `bytes` (ptr, len) from a live slice.
    check(unsafe {
        sys::peios_file_set_sd(
            opt_fd(dirfd),
            cpath.as_ptr(),
            secinfo.bits(),
            bytes.as_ptr().cast(),
            bytes.len(),
            at_flags as u32,
        )
    })
}

/// A mount-policy kind (`KACS_MOUNT_POLICY_*`): how a superblock without native
/// SD storage is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MountPolicyKind(pub u32);

impl MountPolicyKind {
    /// The superblock is unmanaged — KACS does not enforce on it.
    pub const UNMANAGED: Self = Self(sys::KACS_MOUNT_POLICY_UNMANAGED);
    /// Deny access to objects with no stored SD.
    pub const DENY_MISSING: Self = Self(sys::KACS_MOUNT_POLICY_DENY_MISSING);
    /// Synthesize an ephemeral SD (not persisted) for objects with none.
    pub const SYNTHESIZE_EPHEMERAL: Self = Self(sys::KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
    /// Synthesize and persist an SD for objects with none.
    pub const SYNTHESIZE_PERSISTENT: Self = Self(sys::KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT);
}

/// A mount policy mirroring [`struct peios_mount_policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPolicy {
    /// The policy kind.
    pub kind: MountPolicyKind,
    /// Policy flags.
    pub flags: u32,
    /// The policy generation counter.
    pub generation: u32,
    /// The template SD applied to objects with none, if any.
    pub template_sd: Option<SecurityDescriptor>,
}

impl AsFd for File {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl AsRawFd for File {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl From<File> for OwnedFd {
    fn from(f: File) -> OwnedFd {
        f.0
    }
}
impl From<OwnedFd> for File {
    fn from(fd: OwnedFd) -> File {
        File(fd)
    }
}
impl IntoRawFd for File {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

/// `AT_SYMLINK_NOFOLLOW`, without pulling in the `libc` crate.
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `ERANGE`, without pulling in the `libc` crate (stable on Linux).
const ERANGE: i32 = 34;
/// `EINVAL`, without pulling in the `libc` crate.
const EINVAL: i32 = 22;
