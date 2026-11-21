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
//! A [`File`] also works through its open handle: [`File::query`] reads back
//! what it was granted, [`File::set_delete_disposition`] deletes its file when
//! the last open closes (or at once), [`File::rename`] renames the link it
//! names, [`File::lock`] takes NT byte-range locks, and [`File::request_lease`]
//! holds a lease under a [`LeaseManager`]. Every file also carries
//! [`SpecialAttributes`] — read-only and Created At.
//!
//! [`get_sd`] / [`set_sd`] read and write a file's security descriptor by path;
//! [`File::fd_get_sd`] / [`File::fd_set_sd`] do so by fd, [`fd_get_sd`] /
//! [`fd_set_sd`] do the same for a *borrowed* fd the caller keeps, and
//! [`sysv_get_sd`] / [`sysv_set_sd`] by System V IPC kind and id. The mount-policy calls
//! ([`File::mount_get_policy`] / [`File::mount_set_policy`]) govern how a
//! superblock without native SD storage is treated.

use core::ffi::c_void;
use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::{GenericMapping, SecurityDescriptor};
use crate::util::{check, check_fd, check_len, opt_dirfd, probe};

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
        /// Pin the directories above the file while the open lasts: nobody can
        /// rename or remove them. Needs `SeLockParentagePrivilege`.
        const PIN_ANCESTORS = sys::KACS_OPEN_PIN_ANCESTORS;
    }
}

bitflags! {
    /// The access other opens may have while an open lasts
    /// (`KACS_FILE_SHARE_*`). An open that shares nothing is exclusive.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ShareAccess: u32 {
        /// Others may read or execute the file.
        const READ = sys::KACS_FILE_SHARE_READ;
        /// Others may write or append to the file.
        const WRITE = sys::KACS_FILE_SHARE_WRITE;
        /// Others may delete or rename the file.
        const DELETE = sys::KACS_FILE_SHARE_DELETE;
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

/// Why a native open failed, where its `errno` alone cannot say
/// (`KACS_STATUS_*`). Read it with [`Error::open_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenFailure {
    /// Another open's sharing conflicts with this one (`EBUSY`).
    SharingViolation,
    /// The file is marked to be deleted when its last open closes (`EBUSY`).
    DeletePending,
    /// Delete-on-close was asked of a read-only file (`EPERM`).
    CannotDelete,
}

impl OpenFailure {
    fn from_raw(v: u32) -> Option<OpenFailure> {
        match v {
            sys::KACS_STATUS_SHARING_VIOLATION => Some(OpenFailure::SharingViolation),
            sys::KACS_STATUS_DELETE_PENDING => Some(OpenFailure::DeletePending),
            sys::KACS_STATUS_CANNOT_DELETE => Some(OpenFailure::CannotDelete),
            _ => None,
        }
    }
}

impl fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpenFailure::SharingViolation => "sharing violation",
            OpenFailure::DeletePending => "delete pending",
            OpenFailure::CannotDelete => "cannot delete",
        })
    }
}

/// An `NtCreateFile`-shaped open builder over [`struct peios_open_params`].
///
/// Set the desired access, disposition, options, flags, sharing, and (on
/// create) the creator security descriptor, then call [`open`](Self::open) or
/// [`create`](Self::create). Unlike `std::fs::OpenOptions`, the disposition is
/// an explicit [`Disposition`] rather than read/write/create booleans.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions<'a> {
    desired_access: FileAccess,
    disposition: Disposition,
    options: CreateOptions,
    flags: OpenFlags,
    sd: Option<&'a SecurityDescriptor>,
    share: Option<ShareAccess>,
    lease: Option<(BorrowedFd<'a>, LeaseKey)>,
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

    /// Set the access other opens may have while this one lasts. Without it
    /// the open shares read, write and delete, as a plain `open(2)` does.
    pub fn share_access(&mut self, share: ShareAccess) -> &mut Self {
        self.share = Some(share);
        self
    }

    /// Open under `manager` and `key`: the open does not break leases held
    /// under the same manager and key.
    pub fn lease_key(&mut self, manager: &'a LeaseManager, key: LeaseKey) -> &mut Self {
        self.lease = Some((manager.as_fd(), key));
        self
    }

    /// Open `path` relative to `dirfd` (`None` => the process cwd), returning
    /// the file handle and the [`OpenStatus`] of the open.
    pub fn create(&self, dirfd: Option<BorrowedFd<'_>>, path: &Path) -> Result<(File, OpenStatus)> {
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let (sd_ptr, sd_len) = match self.sd {
            Some(sd) => (sd.as_bytes().as_ptr().cast::<c_void>(), sd.as_bytes().len()),
            None => (core::ptr::null(), 0),
        };
        let mut flags = self.flags.bits();
        if self.share.is_some() {
            flags |= sys::KACS_OPEN_SHARE_ACCESS;
        }
        let (lease_fd, lease_key) = match self.lease {
            Some((fd, key)) => {
                flags |= sys::KACS_OPEN_LEASE_KEY;
                (fd.as_raw_fd(), key.0)
            }
            None => (0, [0; 16]),
        };
        let params = sys::peios_open_params {
            desired_access: self.desired_access.bits(),
            disposition: self.disposition.to_raw(),
            options: self.options.bits(),
            flags,
            sd: sd_ptr,
            sd_len,
            share_access: self.share.map_or(0, |share| share.bits()),
            lease_fd,
            lease_key,
        };
        let mut status = 0u32;
        // SAFETY: `cpath` is a live NUL-terminated path; `params` borrows the
        // creator-SD bytes (kept alive by `self`) for the call; `status`
        // writable. Returns an owned file fd or -1/errno.
        let fd = check_fd(unsafe {
            sys::peios_file_open(opt_dirfd(dirfd), cpath.as_ptr(), &params, &mut status)
        })
        .map_err(|e| e.with_open_failure(OpenFailure::from_raw(status)))?;
        let status =
            OpenStatus::from_raw(status).ok_or_else(|| Error::from_raw_os_error(EINVAL))?;
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
            sys::peios_fd_set_sd(
                self.raw(),
                secinfo.bits(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
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
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let bytes = probe(|buf, cap| {
        // SAFETY: live NUL-terminated path; (buf, cap) is the output window.
        unsafe {
            sys::peios_file_get_sd(
                opt_dirfd(dirfd),
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
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let bytes = sd.as_bytes();
    // SAFETY: live NUL-terminated path; `bytes` (ptr, len) from a live slice.
    check(unsafe {
        sys::peios_file_set_sd(
            opt_dirfd(dirfd),
            cpath.as_ptr(),
            secinfo.bits(),
            bytes.as_ptr().cast(),
            bytes.len(),
            at_flags as u32,
        )
    })
}

/// Read a security descriptor by fd, borrowing rather than owning it.
///
/// [`File::fd_get_sd`] answers the same question, but a [`File`] *owns* its
/// descriptor: reaching that method from a live `UnixListener` or
/// `UnixDatagram` would mean surrendering the socket, and dropping the `File`
/// would close it. A caller stamping a socket it intends to keep serving on
/// wants this form.
pub fn fd_get_sd(fd: BorrowedFd<'_>, secinfo: SecInfo) -> Result<SecurityDescriptor> {
    let bytes = probe(|buf, cap| {
        // SAFETY: live borrowed fd; (buf, cap) is the getxattr-style output window.
        unsafe { sys::peios_fd_get_sd(fd.as_raw_fd(), secinfo.bits(), buf, cap) }
    })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

/// Write the `secinfo` components of `sd` onto an fd, preserving the rest,
/// borrowing rather than owning it. A free function for the same reason as
/// [`fd_get_sd`].
///
/// # Not usable on a socket
///
/// This is the path syscall with the target as `dirfd`, an empty path and
/// `AT_EMPTY_PATH` (see the module docs), and the kernel answers `EOPNOTSUPP`
/// for a socket fd. A pathname socket must be stamped through [`set_sd`]
/// instead, after `bind` has published it. Tried on peinit's notification
/// socket, and it took PID 1 into recovery.
///
/// What this is for is an fd that names a file or directory and that the caller
/// intends to keep — where [`File::fd_set_sd`] would work but owning the
/// descriptor is not acceptable.
pub fn fd_set_sd(fd: BorrowedFd<'_>, secinfo: SecInfo, sd: &SecurityDescriptor) -> Result<()> {
    let bytes = sd.as_bytes();
    // SAFETY: live borrowed fd; `bytes` (ptr, len) from a live slice.
    check(unsafe {
        sys::peios_fd_set_sd(
            fd.as_raw_fd(),
            secinfo.bits(),
            bytes.as_ptr().cast(),
            bytes.len(),
        )
    })
}

/// Which kind of System V IPC object a [`sysv_get_sd`] / [`sysv_set_sd`] call
/// addresses. SysV objects have no fd and no path: they are named by kind and
/// the id that `shmget` / `msgget` / `semget` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SysvKind {
    /// A shared memory segment (`shmget`).
    SharedMemory = sys::KACS_SD_AT_SYSV_SHM,
    /// A message queue (`msgget`).
    MessageQueue = sys::KACS_SD_AT_SYSV_MSG,
    /// A semaphore array (`semget`).
    SemaphoreArray = sys::KACS_SD_AT_SYSV_SEM,
}

/// Read the security descriptor of a System V IPC object by kind and id. The
/// object is looked up in the caller's IPC namespace (`EINVAL` unknown, `EIDRM`
/// removed) and the requested components need `READ_CONTROL` /
/// `ACCESS_SYSTEM_SECURITY` on its descriptor.
pub fn sysv_get_sd(kind: SysvKind, id: i32, secinfo: SecInfo) -> Result<SecurityDescriptor> {
    let bytes = probe(|buf, cap| {
        // SAFETY: (buf, cap) is the getxattr-style output window.
        unsafe { sys::peios_sysv_get_sd(kind as u32, id, secinfo.bits(), buf, cap) }
    })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

/// Write the `secinfo` components of `sd` onto a System V IPC object,
/// preserving the rest (`WRITE_DAC` / `WRITE_OWNER` on its descriptor).
pub fn sysv_set_sd(
    kind: SysvKind,
    id: i32,
    secinfo: SecInfo,
    sd: &SecurityDescriptor,
) -> Result<()> {
    let bytes = sd.as_bytes();
    // SAFETY: `bytes` (ptr, len) from a live slice.
    check(unsafe {
        sys::peios_sysv_set_sd(
            kind as u32,
            id,
            secinfo.bits(),
            bytes.as_ptr().cast(),
            bytes.len(),
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

/// A lease key: 16 bytes that name a lease holder to its [`LeaseManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LeaseKey(pub [u8; 16]);

/// What an open was granted, read back with [`File::query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenInfo {
    /// The access the handle carries; after a `MAXIMUM_ALLOWED` open, what it
    /// received.
    pub granted_access: FileAccess,
    /// The access the open lets others have.
    pub share_access: ShareAccess,
    /// The file is marked to be deleted when its last open closes.
    pub delete_pending: bool,
    /// This open marks its file delete-pending when it closes.
    pub delete_on_close: bool,
    /// The open pins the directories above its file.
    pub ancestors_pinned: bool,
}

bitflags! {
    /// A delete disposition (`KACS_DISPOSITION_*`, as NT's
    /// `FILE_DISPOSITION_INFORMATION_EX`), set with
    /// [`File::set_delete_disposition`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DeleteDisposition: u32 {
        /// Delete the file when its last open closes. Without it, the call
        /// clears the mark.
        const DELETE = sys::KACS_DISPOSITION_DELETE;
        /// With `DELETE`: remove the name now, as `unlink(2)` does.
        const POSIX_SEMANTICS = sys::KACS_DISPOSITION_POSIX_SEMANTICS;
        /// Set or clear this open's delete-on-close instead of the file's mark.
        const ON_CLOSE = sys::KACS_DISPOSITION_ON_CLOSE;
        /// Delete a read-only file. Needs `FILE_WRITE_ATTRIBUTES` too.
        const IGNORE_READONLY = sys::KACS_DISPOSITION_IGNORE_READONLY;
    }
}

bitflags! {
    /// Rename flags (`KACS_RENAME_*`, as NT's `FILE_RENAME_INFORMATION_EX`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RenameFlags: u32 {
        /// Replace an existing file at the new name.
        const REPLACE_IF_EXISTS = sys::KACS_RENAME_REPLACE_IF_EXISTS;
        /// Replace a file that is open, if all its opens share delete.
        const POSIX_SEMANTICS = sys::KACS_RENAME_POSIX_SEMANTICS;
        /// Replace a read-only file.
        const IGNORE_READONLY = sys::KACS_RENAME_IGNORE_READONLY;
    }
}

/// The kind of an NT byte-range lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockKind {
    /// Keep everyone, this open included, from writing the range.
    Shared,
    /// Keep every other open from reading or writing the range.
    Exclusive,
}

bitflags! {
    /// A lease's caching state (`KACS_LEASE_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct LeaseState: u32 {
        /// Cache reads.
        const READ = sys::KACS_LEASE_READ;
        /// Cache the open handle.
        const HANDLE = sys::KACS_LEASE_HANDLE;
        /// Cache writes.
        const WRITE = sys::KACS_LEASE_WRITE;
    }
}

/// What broke a lease (`KACS_LEASE_BREAK_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseBreakReason {
    /// Another open of the file.
    Open,
    /// Another open whose sharing conflicts with the holder's.
    Sharing,
    /// A write.
    Write,
    /// A size change.
    Size,
    /// A byte-range lock.
    Lock,
    /// A rename or link of the file or a directory above it.
    Namespace,
    /// A deletion.
    Delete,
    /// A change of security descriptor.
    Security,
    /// A change of attributes.
    Attributes,
    /// A change to a leased directory's entries.
    Child,
    /// The break timed out and the kernel completed it.
    Timeout,
    /// A reason this crate does not know.
    Other(u32),
}

impl LeaseBreakReason {
    fn from_raw(v: u32) -> LeaseBreakReason {
        match v {
            sys::KACS_LEASE_BREAK_OPEN => LeaseBreakReason::Open,
            sys::KACS_LEASE_BREAK_SHARING => LeaseBreakReason::Sharing,
            sys::KACS_LEASE_BREAK_WRITE => LeaseBreakReason::Write,
            sys::KACS_LEASE_BREAK_SIZE => LeaseBreakReason::Size,
            sys::KACS_LEASE_BREAK_LOCK => LeaseBreakReason::Lock,
            sys::KACS_LEASE_BREAK_NAMESPACE => LeaseBreakReason::Namespace,
            sys::KACS_LEASE_BREAK_DELETE => LeaseBreakReason::Delete,
            sys::KACS_LEASE_BREAK_SECURITY => LeaseBreakReason::Security,
            sys::KACS_LEASE_BREAK_ATTRIBUTES => LeaseBreakReason::Attributes,
            sys::KACS_LEASE_BREAK_CHILD => LeaseBreakReason::Child,
            sys::KACS_LEASE_BREAK_TIMEOUT => LeaseBreakReason::Timeout,
            other => LeaseBreakReason::Other(other),
        }
    }
}

/// A break notice read from a [`LeaseManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseBreak {
    /// The key the lease is held under.
    pub key: LeaseKey,
    /// The leased file's device number.
    pub dev: u64,
    /// The leased file's inode number.
    pub ino: u64,
    /// The lease's state before the break.
    pub current: LeaseState,
    /// The state it is being broken to.
    pub new: LeaseState,
    /// What broke it.
    pub reason: LeaseBreakReason,
    /// Counts the lease's breaks, so a stale acknowledgement can be told apart.
    pub epoch: u32,
}

/// A lease manager: the descriptor that receives the break notices for the
/// leases held under it. It is pollable.
#[derive(Debug)]
pub struct LeaseManager(OwnedFd);

impl LeaseManager {
    /// A new manager. `break_timeout` bounds how long a break waits for
    /// acknowledgement before the kernel completes it (`None` for the default
    /// of 35 seconds); `nonblocking` makes [`read_breaks`](Self::read_breaks)
    /// fail with `WouldBlock` rather than wait.
    pub fn new(break_timeout: Option<Duration>, nonblocking: bool) -> Result<LeaseManager> {
        let mut flags = sys::KACS_LEASE_MANAGER_CLOEXEC;
        if nonblocking {
            flags |= sys::KACS_LEASE_MANAGER_NONBLOCK;
        }
        let timeout_ms =
            break_timeout.map_or(0, |t| u32::try_from(t.as_millis()).unwrap_or(u32::MAX));
        // SAFETY: plain values; returns an owned fd or -1/errno.
        let fd = check_fd(unsafe { sys::peios_lease_manager_create(flags, timeout_ms) })?;
        Ok(LeaseManager(fd))
    }

    /// Read up to `max` pending break notices.
    pub fn read_breaks(&self, max: usize) -> Result<Vec<LeaseBreak>> {
        let max = max.max(1);
        let mut raw: Vec<sys::kacs_lease_break> = Vec::with_capacity(max);
        // SAFETY: live fd; the buffer has room for `max` notices, and the
        // call writes only the whole notices it returns.
        let n = check_len(unsafe {
            sys::peios_lease_manager_read(self.0.as_raw_fd(), raw.as_mut_ptr(), max)
        })?;
        // SAFETY: the kernel initialised the first `n` notices.
        unsafe { raw.set_len(n) };
        Ok(raw
            .iter()
            .map(|b| LeaseBreak {
                key: LeaseKey(b.lease_key),
                dev: b.dev,
                ino: b.ino,
                current: LeaseState::from_bits_retain(b.current_state),
                new: LeaseState::from_bits_retain(b.new_state),
                reason: LeaseBreakReason::from_raw(b.reason),
                epoch: b.epoch,
            })
            .collect())
    }
}

impl AsFd for LeaseManager {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for LeaseManager {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// A file's special attributes: read-only and Created At.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpecialAttributes {
    /// A read-only file cannot be opened for writing or deleted, by anyone.
    pub read_only: bool,
    /// The settable creation date, if set. See [`File::creation_time`] for a
    /// file's creation date whether or not it is.
    pub created_at: Option<SystemTime>,
}

impl SpecialAttributes {
    fn from_raw(raw: &sys::kacs_sattr) -> SpecialAttributes {
        SpecialAttributes {
            read_only: raw.attributes & sys::KACS_SATTR_READONLY != 0,
            created_at: (raw.flags & sys::KACS_SATTR_CREATED_AT_SET != 0)
                .then(|| time_from_raw(raw.created_at_sec, raw.created_at_nsec)),
        }
    }
}

/// A `kacs_sattr` that writes the fields `valid` names from `attrs`, in the
/// SDK's form: Created At is set exactly when `KACS_SATTR_CREATED_AT_SET` is.
fn sattr_write(attrs: &SpecialAttributes, valid: u32) -> sys::kacs_sattr {
    let (sec, nsec) = attrs.created_at.map_or((0, 0), time_to_raw);
    sys::kacs_sattr {
        version: sys::KACS_SATTR_VERSION,
        valid,
        attributes: if attrs.read_only {
            sys::KACS_SATTR_READONLY
        } else {
            0
        },
        flags: if attrs.created_at.is_some() {
            sys::KACS_SATTR_CREATED_AT_SET
        } else {
            0
        },
        created_at_sec: sec,
        created_at_nsec: nsec,
        __pad: 0,
    }
}

/// A zeroed `kacs_sattr` for a read to fill. bindgen's structs derive no
/// `Default` unless the `uapi` feature supplies them.
fn empty_sattr() -> sys::kacs_sattr {
    sys::kacs_sattr {
        version: 0,
        valid: 0,
        attributes: 0,
        flags: 0,
        created_at_sec: 0,
        created_at_nsec: 0,
        __pad: 0,
    }
}

const VALID_ALL: u32 = sys::KACS_SATTR_VALID_ATTRIBUTES | sys::KACS_SATTR_VALID_CREATED_AT;

fn time_from_raw(sec: i64, nsec: u32) -> SystemTime {
    let nanos = Duration::from_nanos(u64::from(nsec));
    if sec >= 0 {
        UNIX_EPOCH + Duration::from_secs(sec as u64) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(sec.unsigned_abs()) + nanos
    }
}

fn time_to_raw(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                (-(d.as_secs() as i64), 0)
            } else {
                (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

impl File {
    /// What this open was granted: its access, its sharing, and its file's
    /// delete state.
    pub fn query(&self) -> Result<OpenInfo> {
        let mut raw = sys::kacs_open_info {
            granted_access: 0,
            share_access: 0,
            flags: 0,
            __pad: 0,
        };
        // SAFETY: live fd; `raw` writable.
        check(unsafe { sys::peios_file_query_open(self.raw(), &mut raw) })?;
        Ok(OpenInfo {
            granted_access: FileAccess::from_bits_retain(raw.granted_access),
            share_access: ShareAccess::from_bits_retain(raw.share_access),
            delete_pending: raw.flags & sys::KACS_OPEN_INFO_DELETE_PENDING != 0,
            delete_on_close: raw.flags & sys::KACS_OPEN_INFO_DELETE_ON_CLOSE != 0,
            ancestors_pinned: raw.flags & sys::KACS_OPEN_INFO_ANCESTORS_PINNED != 0,
        })
    }

    /// Set or clear the file's delete disposition. The open needs `DELETE`.
    /// With [`DeleteDisposition::DELETE`] the file is removed when its last
    /// open closes, from whichever process; with `POSIX_SEMANTICS` too, at
    /// once.
    pub fn set_delete_disposition(&self, disposition: DeleteDisposition) -> Result<()> {
        // SAFETY: live fd; plain flags.
        check(unsafe { sys::peios_file_set_disposition(self.raw(), disposition.bits()) })
    }

    /// Move the link this open names to `path`, relative to `dirfd` (`None` =>
    /// the process cwd). The open needs `DELETE`.
    pub fn rename(
        &self,
        dirfd: Option<BorrowedFd<'_>>,
        path: &Path,
        flags: RenameFlags,
    ) -> Result<()> {
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::from_raw_os_error(EINVAL))?;
        // SAFETY: live fd; live NUL-terminated path.
        check(unsafe {
            sys::peios_file_rename(self.raw(), opt_dirfd(dirfd), cpath.as_ptr(), flags.bits())
        })
    }

    /// Take an NT byte-range lock over `length` bytes from `offset`. A
    /// conflicting lock waits unless `fail_immediately`, when it fails with
    /// `WouldBlock`; give a waiting lock a `cookie` so that another thread can
    /// [`cancel_lock`](Self::cancel_lock) it.
    pub fn lock(
        &self,
        kind: LockKind,
        offset: u64,
        length: u64,
        fail_immediately: bool,
        cookie: u64,
    ) -> Result<()> {
        let op = match kind {
            LockKind::Shared => sys::KACS_LOCK_SHARED,
            LockKind::Exclusive => sys::KACS_LOCK_EXCLUSIVE,
        };
        let flags = if fail_immediately {
            sys::KACS_LOCK_FAIL_IMMEDIATELY
        } else {
            0
        };
        // SAFETY: live fd; plain values.
        check(unsafe { sys::peios_file_lock(self.raw(), op, offset, length, flags, cookie) })
    }

    /// Release the lock this open holds over exactly `length` bytes from
    /// `offset`.
    pub fn unlock(&self, offset: u64, length: u64) -> Result<()> {
        // SAFETY: live fd; plain values.
        check(unsafe {
            sys::peios_file_lock(self.raw(), sys::KACS_LOCK_UNLOCK, offset, length, 0, 0)
        })
    }

    /// Cancel this open's waiting lock request named by `cookie`.
    pub fn cancel_lock(&self, cookie: u64) -> Result<()> {
        // SAFETY: live fd; plain values.
        check(unsafe { sys::peios_file_lock(self.raw(), sys::KACS_LOCK_CANCEL, 0, 0, 0, cookie) })
    }

    /// Request a lease on this open's file under `manager` and `key`, returning
    /// the state granted, which may be less than `state`.
    pub fn request_lease(
        &self,
        manager: &LeaseManager,
        key: LeaseKey,
        state: LeaseState,
    ) -> Result<LeaseState> {
        self.lease_call(manager, key, state, 0)
    }

    /// Acknowledge a break of the lease held under `manager` and `key`,
    /// settling on `state`, which may be no more than the break's new state.
    pub fn acknowledge_lease_break(
        &self,
        manager: &LeaseManager,
        key: LeaseKey,
        state: LeaseState,
    ) -> Result<LeaseState> {
        self.lease_call(manager, key, state, sys::KACS_LEASE_ACKNOWLEDGE)
    }

    fn lease_call(
        &self,
        manager: &LeaseManager,
        key: LeaseKey,
        state: LeaseState,
        flags: u32,
    ) -> Result<LeaseState> {
        let mut raw = state.bits();
        // SAFETY: live fds; `key.0` is 16 bytes; `raw` writable.
        check(unsafe {
            sys::peios_file_lease(
                self.raw(),
                manager.as_raw_fd(),
                key.0.as_ptr(),
                &mut raw,
                flags,
            )
        })?;
        Ok(LeaseState::from_bits_retain(raw))
    }

    /// This file's special attributes.
    pub fn special_attributes(&self) -> Result<SpecialAttributes> {
        let mut raw = empty_sattr();
        // SAFETY: live fd; `raw` writable.
        check(unsafe { sys::peios_fd_get_sattr(self.raw(), &mut raw) })?;
        Ok(SpecialAttributes::from_raw(&raw))
    }

    /// Set both special attributes, as when copying them from another file.
    pub fn set_special_attributes(&self, attrs: &SpecialAttributes) -> Result<()> {
        self.set_sattr(&sattr_write(attrs, VALID_ALL))
    }

    /// Make the file read-only, or not, leaving Created At alone.
    pub fn set_read_only(&self, read_only: bool) -> Result<()> {
        let attrs = SpecialAttributes {
            read_only,
            created_at: None,
        };
        self.set_sattr(&sattr_write(&attrs, sys::KACS_SATTR_VALID_ATTRIBUTES))
    }

    /// Set Created At, or unset it with `None`, leaving read-only alone.
    pub fn set_created_at(&self, created_at: Option<SystemTime>) -> Result<()> {
        let attrs = SpecialAttributes {
            read_only: false,
            created_at,
        };
        self.set_sattr(&sattr_write(&attrs, sys::KACS_SATTR_VALID_CREATED_AT))
    }

    fn set_sattr(&self, raw: &sys::kacs_sattr) -> Result<()> {
        // SAFETY: live fd; `raw` readable.
        check(unsafe { sys::peios_fd_set_sattr(self.raw(), raw) })
    }

    /// The file's creation date: its Created At if set, else its birth time.
    /// Fails with `ENODATA` if it has neither.
    pub fn creation_time(&self) -> Result<SystemTime> {
        let (mut sec, mut nsec) = (0i64, 0u32);
        // SAFETY: live fd; outputs writable.
        check(unsafe { sys::peios_fd_creation_time(self.raw(), &mut sec, &mut nsec) })?;
        Ok(time_from_raw(sec, nsec))
    }
}

/// A file's special attributes by path. `at_flags` accepts
/// `AT_SYMLINK_NOFOLLOW`.
pub fn special_attributes(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    at_flags: i32,
) -> Result<SpecialAttributes> {
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let mut raw = empty_sattr();
    // SAFETY: live NUL-terminated path; `raw` writable.
    check(unsafe {
        sys::peios_file_get_sattr(opt_dirfd(dirfd), cpath.as_ptr(), &mut raw, at_flags as u32)
    })?;
    Ok(SpecialAttributes::from_raw(&raw))
}

/// Set both special attributes of a file by path.
pub fn set_special_attributes(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    attrs: &SpecialAttributes,
    at_flags: i32,
) -> Result<()> {
    set_sattr_at(dirfd, path, &sattr_write(attrs, VALID_ALL), at_flags)
}

/// Make a file read-only, or not, by path, leaving Created At alone.
pub fn set_read_only(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    read_only: bool,
    at_flags: i32,
) -> Result<()> {
    let attrs = SpecialAttributes {
        read_only,
        created_at: None,
    };
    set_sattr_at(
        dirfd,
        path,
        &sattr_write(&attrs, sys::KACS_SATTR_VALID_ATTRIBUTES),
        at_flags,
    )
}

/// Set a file's Created At by path, or unset it with `None`, leaving read-only
/// alone.
pub fn set_created_at(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    created_at: Option<SystemTime>,
    at_flags: i32,
) -> Result<()> {
    let attrs = SpecialAttributes {
        read_only: false,
        created_at,
    };
    set_sattr_at(
        dirfd,
        path,
        &sattr_write(&attrs, sys::KACS_SATTR_VALID_CREATED_AT),
        at_flags,
    )
}

fn set_sattr_at(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    raw: &sys::kacs_sattr,
    at_flags: i32,
) -> Result<()> {
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    // SAFETY: live NUL-terminated path; `raw` readable.
    check(unsafe {
        sys::peios_file_set_sattr(opt_dirfd(dirfd), cpath.as_ptr(), raw, at_flags as u32)
    })
}

/// A file's creation date by path: its Created At if set, else its birth time.
/// Fails with `ENODATA` if it has neither.
pub fn creation_time(
    dirfd: Option<BorrowedFd<'_>>,
    path: &Path,
    at_flags: i32,
) -> Result<SystemTime> {
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let (mut sec, mut nsec) = (0i64, 0u32);
    // SAFETY: live NUL-terminated path; outputs writable.
    check(unsafe {
        sys::peios_file_creation_time(
            opt_dirfd(dirfd),
            cpath.as_ptr(),
            &mut sec,
            &mut nsec,
            at_flags as u32,
        )
    })?;
    Ok(time_from_raw(sec, nsec))
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

/// `AT_SYMLINK_NOFOLLOW`, using the platform definition.
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `ERANGE`, using the platform definition.
const ERANGE: i32 = libc::ERANGE;
/// `EINVAL`, using the platform definition.
const EINVAL: i32 = libc::EINVAL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_round_trip_across_the_epoch() {
        for (sec, nsec) in [
            (0, 0),
            (1_000_000_000, 5),
            (-1, 0),
            (-1, 999_999_999),
            (-86_400, 250),
        ] {
            assert_eq!(time_to_raw(time_from_raw(sec, nsec)), (sec, nsec));
        }
        assert_eq!(
            time_from_raw(-1, 500_000_000),
            UNIX_EPOCH - Duration::from_millis(500)
        );
    }

    #[test]
    fn special_attributes_write_in_the_read_form() {
        let at = time_from_raw(1_000_000_000, 5);
        let both = sattr_write(
            &SpecialAttributes {
                read_only: true,
                created_at: Some(at),
            },
            VALID_ALL,
        );
        assert_eq!(both.attributes, sys::KACS_SATTR_READONLY);
        assert_eq!(both.flags, sys::KACS_SATTR_CREATED_AT_SET);
        assert_eq!(
            (both.created_at_sec, both.created_at_nsec),
            (1_000_000_000, 5)
        );
        assert_eq!(
            SpecialAttributes::from_raw(&both),
            SpecialAttributes {
                read_only: true,
                created_at: Some(at)
            }
        );

        // Unset Created At is written without the flag, which the SDK reads as
        // "unset", never as the epoch.
        let unset = sattr_write(
            &SpecialAttributes::default(),
            sys::KACS_SATTR_VALID_CREATED_AT,
        );
        assert_eq!(unset.flags, 0);
        assert_eq!(unset.valid, sys::KACS_SATTR_VALID_CREATED_AT);
        assert_eq!(SpecialAttributes::from_raw(&unset).created_at, None);
    }

    #[test]
    fn failure_statuses_map() {
        assert_eq!(
            OpenFailure::from_raw(sys::KACS_STATUS_SHARING_VIOLATION),
            Some(OpenFailure::SharingViolation)
        );
        assert_eq!(
            OpenFailure::from_raw(sys::KACS_STATUS_DELETE_PENDING),
            Some(OpenFailure::DeletePending)
        );
        assert_eq!(
            OpenFailure::from_raw(sys::KACS_STATUS_CANNOT_DELETE),
            Some(OpenFailure::CannotDelete)
        );
        // Success statuses and an unwritten status are not failures.
        assert_eq!(OpenFailure::from_raw(0), None);
        assert_eq!(OpenFailure::from_raw(sys::KACS_STATUS_OPENED), None);
        let e = Error::from_raw_os_error(libc::EBUSY)
            .with_open_failure(Some(OpenFailure::DeletePending));
        assert_eq!(e.open_failure(), Some(OpenFailure::DeletePending));
        assert_eq!(e.raw_os_error(), Some(libc::EBUSY));
    }

    #[test]
    fn break_reasons_map() {
        assert_eq!(
            LeaseBreakReason::from_raw(sys::KACS_LEASE_BREAK_OPEN),
            LeaseBreakReason::Open
        );
        assert_eq!(
            LeaseBreakReason::from_raw(sys::KACS_LEASE_BREAK_TIMEOUT),
            LeaseBreakReason::Timeout
        );
        assert_eq!(
            LeaseBreakReason::from_raw(999),
            LeaseBreakReason::Other(999)
        );
    }
}
