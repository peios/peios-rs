//! LCS, the layered configuration registry.
//!
//! LCS is Peios's kernel-mediated configuration store, modelled on the Windows
//! registry: a hierarchy of [`Key`]s (each secured by a KACS security
//! descriptor) holding typed values, with every write tagged by a
//! precedence-ordered *layer* so the effective view resolves to the
//! highest-precedence entry. This module is the registry *client* surface: open
//! keys, read/write values, enumerate, watch, and run transactions.
//!
//! A [`Key`] and a [`Transaction`] are both fd-backed handles (so they `impl`
//! [`AsFd`] and drop cleanly). The mutating and reading operations are
//! *key-centric*: they hang off [`Key`] and take an optional `&Transaction` to
//! enlist in — the transaction is never the receiver. Dropping a
//! [`Transaction`] without committing aborts it (closing the fd aborts).
//!
//! The buffer-returning reads follow the getxattr/`ERANGE` convention: a
//! zero-capacity (NULL-buffer) probe reports the required size, which we then
//! allocate and re-read.

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};

use bitflags::bitflags;
use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::SecurityDescriptor;
use crate::util::{check, check_fd, opt_fd};

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const ERANGE: i32 = 34;

bitflags! {
    /// Key access-right mask: the key-object rights plus the standard rights.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeyAccess: u32 {
        /// Read a value of the key.
        const QUERY_VALUE = sys::KEY_QUERY_VALUE;
        /// Write a value of the key.
        const SET_VALUE = sys::KEY_SET_VALUE;
        /// Create a subkey.
        const CREATE_SUB_KEY = sys::KEY_CREATE_SUB_KEY;
        /// Enumerate subkeys.
        const ENUMERATE_SUB_KEYS = sys::KEY_ENUMERATE_SUB_KEYS;
        /// Arm change watches.
        const NOTIFY = sys::KEY_NOTIFY;
        /// Create a symlink subkey.
        const CREATE_LINK = sys::KEY_CREATE_LINK;
        /// Composite read access (query/enumerate/notify + read-control).
        const READ = sys::KEY_READ;
        /// Composite write access (set-value/create-subkey + read-control).
        const WRITE = sys::KEY_WRITE;
        /// All key rights.
        const ALL_ACCESS = sys::KEY_ALL_ACCESS;
        /// Standard: delete.
        const DELETE = sys::KACS_ACCESS_DELETE;
        /// Standard: read the security descriptor.
        const READ_CONTROL = sys::KACS_ACCESS_READ_CONTROL;
        /// Standard: write the DACL.
        const WRITE_DAC = sys::KACS_ACCESS_WRITE_DAC;
        /// Standard: change the owner.
        const WRITE_OWNER = sys::KACS_ACCESS_WRITE_OWNER;
        /// Standard: access the SACL.
        const ACCESS_SYSTEM_SECURITY = sys::KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
    }
}

bitflags! {
    /// Flags for [`Key::open`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct OpenFlags: u32 {
        /// Open a symlink key itself rather than following it.
        const OPEN_LINK = sys::REG_OPEN_LINK;
    }
}

bitflags! {
    /// Flags for [`Key::create`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CreateFlags: u32 {
        /// Create a volatile (non-persisted) key.
        const VOLATILE = sys::REG_OPTION_VOLATILE;
        /// Create a symlink key (privileged).
        const CREATE_LINK = sys::REG_OPTION_CREATE_LINK;
    }
}

bitflags! {
    /// Change-watch filter for [`Key::notify`]. An empty filter disarms.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct NotifyFilter: u32 {
        /// Watch value changes.
        const VALUE = sys::REG_NOTIFY_VALUE;
        /// Watch subkey changes.
        const SUBKEY = sys::REG_NOTIFY_SUBKEY;
        /// Watch security-descriptor changes.
        const SD = sys::REG_NOTIFY_SD;
        /// Watch all change classes.
        const ALL = sys::REG_NOTIFY_ALL;
    }
}

bitflags! {
    /// Security-information component bits for [`Key::get_security`] /
    /// [`Key::set_security`].
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
        /// The integrity label.
        const LABEL = sys::KACS_SECINFO_LABEL;
    }
}

/// A registry value type (`REG_SZ`, `REG_DWORD`, …), or [`TOMBSTONE`] for a
/// per-value tombstone.
///
/// [`TOMBSTONE`]: ValueType::TOMBSTONE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueType(pub u32);

impl ValueType {
    /// No defined value type (an untyped/empty value).
    pub const NONE: Self = Self(sys::REG_NONE);
    /// A NUL-terminated string.
    pub const SZ: Self = Self(sys::REG_SZ);
    /// A string with unexpanded environment references.
    pub const EXPAND_SZ: Self = Self(sys::REG_EXPAND_SZ);
    /// Free-form binary data.
    pub const BINARY: Self = Self(sys::REG_BINARY);
    /// A 32-bit little-endian integer.
    pub const DWORD: Self = Self(sys::REG_DWORD);
    /// A 32-bit big-endian integer.
    pub const DWORD_BIG_ENDIAN: Self = Self(sys::REG_DWORD_BIG_ENDIAN);
    /// A symbolic-link target string.
    pub const LINK: Self = Self(sys::REG_LINK);
    /// A sequence of NUL-terminated strings, double-NUL terminated.
    pub const MULTI_SZ: Self = Self(sys::REG_MULTI_SZ);
    /// A resource list.
    pub const RESOURCE_LIST: Self = Self(sys::REG_RESOURCE_LIST);
    /// A full resource descriptor.
    pub const FULL_RESOURCE_DESCRIPTOR: Self = Self(sys::REG_FULL_RESOURCE_DESCRIPTOR);
    /// A resource-requirements list.
    pub const RESOURCE_REQUIREMENTS_LIST: Self = Self(sys::REG_RESOURCE_REQUIREMENTS_LIST);
    /// A 64-bit little-endian integer.
    pub const QWORD: Self = Self(sys::REG_QWORD);
    /// A per-value tombstone (masks lower-precedence entries).
    pub const TOMBSTONE: Self = Self(sys::REG_TOMBSTONE);

    /// Wrap a raw `REG_*` value-type code.
    #[inline]
    pub fn from_raw(v: u32) -> Self {
        Self(v)
    }
}

/// Whether [`Key::create`] opened an existing key or created a new one. This is
/// a **success** output returned alongside the key, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// A new key was created.
    CreatedNew,
    /// An existing key was opened.
    OpenedExisting,
}

impl Disposition {
    fn from_raw(v: u32) -> Disposition {
        if v == sys::REG_OPENED_EXISTING {
            Disposition::OpenedExisting
        } else {
            Disposition::CreatedNew
        }
    }
}

/// The state of a [`Transaction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxnState {
    /// Active but not yet bound to a source.
    ActiveUnbound,
    /// Active and bound to a source.
    ActiveBound,
    /// Committed (terminal).
    Committed,
    /// Aborted (terminal).
    Aborted,
    /// Timed out (terminal).
    TimedOut,
    /// The bound source went down (terminal).
    SourceDown,
}

impl TxnState {
    fn from_raw(v: u32) -> Option<TxnState> {
        match v {
            sys::REG_TXN_ACTIVE_UNBOUND => Some(TxnState::ActiveUnbound),
            sys::REG_TXN_ACTIVE_BOUND => Some(TxnState::ActiveBound),
            sys::REG_TXN_COMMITTED => Some(TxnState::Committed),
            sys::REG_TXN_ABORTED => Some(TxnState::Aborted),
            sys::REG_TXN_TIMED_OUT => Some(TxnState::TimedOut),
            sys::REG_TXN_SOURCE_DOWN => Some(TxnState::SourceDown),
            _ => None,
        }
    }
}

/// The status of a [`Transaction`]: its [`state`](TxnStatus::state) plus the
/// errno that ended it (`0` while active or after a clean commit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxnStatus {
    /// The transaction state.
    pub state: TxnState,
    /// The errno that terminated the transaction, or `0`.
    pub terminal_errno: i32,
}

/// An owned registry value read by [`Key::query_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    /// The effective entry's sequence number.
    pub sequence: u64,
    /// The value type.
    pub ty: ValueType,
    /// The value data.
    pub data: Vec<u8>,
    /// The name of the layer the effective entry came from.
    pub layer: Vec<u8>,
}

/// One record from [`Key::query_values_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueRecord {
    /// The value name (empty = the key's default value).
    pub name: Vec<u8>,
    /// The value type.
    pub ty: ValueType,
    /// The value data.
    pub data: Vec<u8>,
}

/// One entry from [`Key::enum_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumValue {
    /// The value name.
    pub name: Vec<u8>,
    /// The value type.
    pub ty: ValueType,
    /// The value data.
    pub data: Vec<u8>,
}

/// One child-key entry from [`Key::enum_subkey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subkey {
    /// The child key's leaf name.
    pub name: Vec<u8>,
    /// The child's last-write time (ns since the Unix epoch).
    pub last_write_time: u64,
    /// The child's subkey count.
    pub subkey_count: u32,
    /// The child's value count.
    pub value_count: u32,
}

/// A key's name and metadata, from [`Key::info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The key's leaf name.
    pub name: Vec<u8>,
    /// Last-write time (ns since the Unix epoch).
    pub last_write_time: u64,
    /// Per-hive change epoch.
    pub hive_generation: u64,
    /// Number of subkeys.
    pub subkey_count: u32,
    /// Number of values.
    pub value_count: u32,
    /// Longest subkey name length.
    pub max_subkey_name_len: u32,
    /// Longest value name length.
    pub max_value_name_len: u32,
    /// Largest value data size.
    pub max_value_data_size: u32,
    /// Security-descriptor size.
    pub sd_size: u32,
    /// Whether the key is volatile.
    pub volatile: bool,
    /// Whether the key is a symlink.
    pub symlink: bool,
}

/// A registry transaction: an fd-backed handle that mutating value/key
/// operations enlist in via their `txn` argument.
///
/// Dropping a `Transaction` that has not been committed aborts it — closing the
/// fd aborts the transaction automatically (handled by `OwnedFd`'s `Drop`).
#[derive(Debug)]
pub struct Transaction(OwnedFd);

impl Transaction {
    /// Start a new registry transaction (initially unbound; it binds to a
    /// source on first use).
    pub fn begin() -> Result<Transaction> {
        // SAFETY: a plain syscall returning a transaction fd or -1/errno.
        check_fd(unsafe { sys::peios_reg_begin_transaction() }).map(Transaction)
    }

    fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// Atomically commit everything enlisted in this transaction, consuming it.
    ///
    /// On success the transaction is terminal and the fd is closed by the move.
    /// Note the EBUSY/EIO caveat: those errors mean the *transaction stays
    /// active and is retryable*, but because `commit` consumes `self`, the fd is
    /// closed (aborting the transaction) when the error is returned. A caller
    /// who wants to retry must therefore [`begin`](Transaction::begin) a fresh
    /// transaction and replay the enlisted operations.
    pub fn commit(self) -> Result<()> {
        // SAFETY: live transaction fd.
        check(unsafe { sys::peios_reg_commit(self.raw()) })
    }

    /// Read this transaction's [`state`](TxnStatus::state) and terminal errno.
    pub fn status(&self) -> Result<TxnStatus> {
        let mut state = 0u32;
        let mut terminal_errno = 0i32;
        // SAFETY: live fd; both out-params writable.
        check(unsafe { sys::peios_reg_txn_status(self.raw(), &mut state, &mut terminal_errno) })?;
        let state = TxnState::from_raw(state).ok_or_else(|| Error::from_raw_os_error(EINVAL))?;
        Ok(TxnStatus { state, terminal_errno })
    }
}

impl AsFd for Transaction {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl AsRawFd for Transaction {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl From<Transaction> for OwnedFd {
    fn from(t: Transaction) -> OwnedFd {
        t.0
    }
}
impl From<OwnedFd> for Transaction {
    fn from(fd: OwnedFd) -> Transaction {
        Transaction(fd)
    }
}
impl IntoRawFd for Transaction {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

/// A registry key: an fd-backed LCS handle whose granted access mask is fixed
/// for its lifetime.
#[derive(Debug)]
pub struct Key(OwnedFd);

impl Key {
    /// Open an existing key. `parent` is a key to resolve `path` against, or
    /// `None` for an absolute path.
    pub fn open(
        parent: Option<&Key>,
        path: &str,
        access: KeyAccess,
        flags: OpenFlags,
    ) -> Result<Key> {
        let cpath = CString::new(path).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let parent_fd = parent.map_or(-1, Key::raw);
        // SAFETY: `cpath` is a live NUL-terminated string for the call; `parent`
        // (if any) is a live borrowed fd.
        check_fd(unsafe {
            sys::peios_reg_open_key(parent_fd, cpath.as_ptr(), access.bits(), flags.bits())
        })
        .map(Key)
    }

    /// Open an existing key or create a new one, returning the key and its
    /// [`Disposition`]. `parent` is `None` for an absolute path; `layer` is the
    /// target layer name (`None` = the base layer); `txn` enlists the create.
    pub fn create(
        parent: Option<&Key>,
        path: &str,
        access: KeyAccess,
        flags: CreateFlags,
        layer: Option<&str>,
        txn: Option<&Transaction>,
    ) -> Result<(Key, Disposition)> {
        let cpath = CString::new(path).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let clayer = match layer {
            Some(l) => Some(CString::new(l).map_err(|_| Error::from_raw_os_error(EINVAL))?),
            None => None,
        };
        let layer_ptr = clayer.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
        let parent_fd = parent.map_or(-1, Key::raw);
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let mut disp = 0u32;
        // SAFETY: `cpath`/`clayer` are live for the call; `disp` is writable;
        // `parent`/`txn` (if any) are live borrowed fds.
        let key = check_fd(unsafe {
            sys::peios_reg_create_key(
                parent_fd,
                cpath.as_ptr(),
                access.bits(),
                flags.bits(),
                layer_ptr,
                txn_fd,
                &mut disp,
            )
        })
        .map(Key)?;
        Ok((key, Disposition::from_raw(disp)))
    }

    fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    // ---- values -----------------------------------------------------------

    /// Begin a value write. `name` is the length-counted value name (empty =
    /// the key's default value); `ty` is the value type (or
    /// [`ValueType::TOMBSTONE`] for a per-value tombstone); `data` is the value
    /// data. Finish with [`SetValue::call`].
    pub fn set_value<'a>(&'a self, name: &'a [u8], ty: ValueType, data: &'a [u8]) -> SetValue<'a> {
        SetValue {
            key: self,
            name,
            ty,
            data,
            layer: None,
            expected_seq: 0,
            txn: None,
        }
    }

    /// Read the effective value `name` (empty = the default value), optionally
    /// within `txn`.
    ///
    /// Errors with `ENOENT` if there is no effective value (or it is a
    /// tombstone).
    pub fn query_value(&self, name: &[u8], txn: Option<&Transaction>) -> Result<RegValue> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let (name_ptr, name_len) = bytes_u32(name);

        // Two-call descriptor probe: NULL buffers / 0 caps learn data_len &
        // layer_len, then allocate and re-read, retrying once if it grows.
        let mut data = Vec::new();
        let mut layer = Vec::new();
        for _ in 0..4 {
            let mut v = sys::peios_reg_value {
                sequence: 0,
                data: buf_ptr(&mut data),
                layer: buf_ptr(&mut layer),
                type_: 0,
                data_cap: data.len() as u32,
                data_len: 0,
                layer_cap: layer.len() as u32,
                layer_len: 0,
            };
            // SAFETY: live fd; `name` is valid for `name_len` bytes; `v`
            // describes the two output windows (`data`/`layer` live here).
            let ret = unsafe {
                sys::peios_reg_query_value(self.raw(), name_ptr, name_len, txn_fd, &mut v)
            };
            if ret == 0 {
                data.truncate(v.data_len as usize);
                layer.truncate(v.layer_len as usize);
                return Ok(RegValue {
                    sequence: v.sequence,
                    ty: ValueType(v.type_),
                    data,
                    layer,
                });
            }
            match Error::last_os_error().raw_os_error() {
                Some(e) if e == ERANGE => {
                    data = vec![0u8; v.data_len as usize];
                    layer = vec![0u8; v.layer_len as usize];
                }
                _ => return Err(Error::last_os_error()),
            }
        }
        Err(Error::from_raw_os_error(ERANGE))
    }

    /// Remove a layer's entry for the value `name` (`layer` `None` = base).
    /// Idempotent; lower-precedence layers re-emerge.
    pub fn delete_value(
        &self,
        name: &[u8],
        layer: Option<&str>,
        txn: Option<&Transaction>,
    ) -> Result<()> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let (name_ptr, name_len) = bytes_u32(name);
        let (layer_ptr, layer_len) = opt_layer(layer);
        // SAFETY: live fd; `name`/`layer` valid for their lengths for the call.
        check(unsafe {
            sys::peios_reg_delete_value(
                self.raw(),
                name_ptr,
                name_len,
                layer_ptr,
                layer_len,
                txn_fd,
            )
        })
    }

    /// Set (`set == true`) or clear a blanket tombstone on `layer` (`None` =
    /// base), masking all lower-precedence values of this key on that layer.
    pub fn blanket_tombstone(
        &self,
        layer: Option<&str>,
        set: bool,
        txn: Option<&Transaction>,
    ) -> Result<()> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let (layer_ptr, layer_len) = opt_layer(layer);
        // SAFETY: live fd; `layer` valid for `layer_len` for the call.
        check(unsafe {
            sys::peios_reg_blanket_tombstone(
                self.raw(),
                layer_ptr,
                layer_len,
                set as core::ffi::c_int,
                txn_fd,
            )
        })
    }

    /// Read every effective value of this key, optionally within `txn`.
    pub fn query_values_batch(&self, txn: Option<&Transaction>) -> Result<Vec<ValueRecord>> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        // Probe for the packed-record buffer size, then read it.
        let mut cap = 0u32;
        let mut count = 0u32;
        {
            // SAFETY: live fd; NULL buffer with 0 cap probes for the size in `cap`.
            let ret = unsafe {
                sys::peios_reg_query_values_batch(
                    self.raw(),
                    txn_fd,
                    core::ptr::null_mut(),
                    0,
                    &mut cap,
                    &mut count,
                )
            };
            if ret != 0 {
                match Error::last_os_error().raw_os_error() {
                    Some(e) if e == ERANGE => {}
                    _ => return Err(Error::last_os_error()),
                }
            }
        }
        let mut buf = vec![0u8; cap as usize];
        let mut len = 0u32;
        // SAFETY: live fd; (buf, cap) is the output window; out-params writable.
        check(unsafe {
            sys::peios_reg_query_values_batch(
                self.raw(),
                txn_fd,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
                &mut count,
            )
        })?;
        buf.truncate(len as usize);
        parse_value_records(&buf, count as usize)
    }

    /// Read the effective value at dense position `index` (walk from `0` until
    /// `Ok(None)`), optionally within `txn`.
    pub fn enum_value(&self, index: u32, txn: Option<&Transaction>) -> Result<Option<EnumValue>> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let mut name = Vec::new();
        let mut data = Vec::new();
        for _ in 0..4 {
            let mut v = sys::peios_reg_enum_value {
                name: buf_ptr(&mut name),
                data: buf_ptr(&mut data),
                type_: 0,
                name_cap: name.len() as u32,
                name_len: 0,
                data_cap: data.len() as u32,
                data_len: 0,
            };
            // SAFETY: live fd; `v` describes the two output windows
            // (`name`/`data` live here).
            let ret =
                unsafe { sys::peios_reg_enum_value(self.raw(), index, txn_fd, &mut v) };
            if ret == 0 {
                name.truncate(v.name_len as usize);
                data.truncate(v.data_len as usize);
                return Ok(Some(EnumValue { name, ty: ValueType(v.type_), data }));
            }
            match Error::last_os_error().raw_os_error() {
                Some(e) if e == ENOENT => return Ok(None),
                Some(e) if e == ERANGE => {
                    name = vec![0u8; v.name_len as usize];
                    data = vec![0u8; v.data_len as usize];
                }
                _ => return Err(Error::last_os_error()),
            }
        }
        Err(Error::from_raw_os_error(ERANGE))
    }

    /// An iterator over this key's effective values (walks [`enum_value`] from
    /// index 0). Each item is a `Result<EnumValue>`; iteration stops at the
    /// first `None` or error.
    ///
    /// [`enum_value`]: Key::enum_value
    pub fn values<'a>(&'a self, txn: Option<&'a Transaction>) -> Values<'a> {
        Values { key: self, txn, index: 0, done: false }
    }

    // ---- subkeys / metadata / watches -------------------------------------

    /// Read the child key at dense position `index` (walk from `0` until
    /// `Ok(None)`), optionally within `txn`.
    pub fn enum_subkey(&self, index: u32, txn: Option<&Transaction>) -> Result<Option<Subkey>> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let mut name = Vec::new();
        for _ in 0..4 {
            let mut v = sys::peios_reg_subkey {
                name: buf_ptr(&mut name),
                last_write_time: 0,
                name_cap: name.len() as u32,
                name_len: 0,
                subkey_count: 0,
                value_count: 0,
            };
            // SAFETY: live fd; `v` describes the name output window (`name`
            // lives here).
            let ret =
                unsafe { sys::peios_reg_enum_subkey(self.raw(), index, txn_fd, &mut v) };
            if ret == 0 {
                name.truncate(v.name_len as usize);
                return Ok(Some(Subkey {
                    name,
                    last_write_time: v.last_write_time,
                    subkey_count: v.subkey_count,
                    value_count: v.value_count,
                }));
            }
            match Error::last_os_error().raw_os_error() {
                Some(e) if e == ENOENT => return Ok(None),
                Some(e) if e == ERANGE => name = vec![0u8; v.name_len as usize],
                _ => return Err(Error::last_os_error()),
            }
        }
        Err(Error::from_raw_os_error(ERANGE))
    }

    /// An iterator over this key's child keys (walks [`enum_subkey`] from index
    /// 0). Iteration stops at the first `None` or error.
    ///
    /// [`enum_subkey`]: Key::enum_subkey
    pub fn subkeys<'a>(&'a self, txn: Option<&'a Transaction>) -> Subkeys<'a> {
        Subkeys { key: self, txn, index: 0, done: false }
    }

    /// Read this key's name and metadata (requires `READ_CONTROL`).
    pub fn info(&self) -> Result<KeyInfo> {
        let mut name = Vec::new();
        for _ in 0..4 {
            let mut v = sys::peios_reg_key_info {
                name: buf_ptr(&mut name),
                last_write_time: 0,
                hive_generation: 0,
                name_cap: name.len() as u32,
                name_len: 0,
                subkey_count: 0,
                value_count: 0,
                max_subkey_name_len: 0,
                max_value_name_len: 0,
                max_value_data_size: 0,
                sd_size: 0,
                volatile_key: 0,
                symlink: 0,
            };
            // SAFETY: live fd; `v` describes the name output window (`name`
            // lives here) and receives the metadata once the name fits.
            let ret = unsafe { sys::peios_reg_query_key_info(self.raw(), &mut v) };
            if ret == 0 {
                name.truncate(v.name_len as usize);
                return Ok(KeyInfo {
                    name,
                    last_write_time: v.last_write_time,
                    hive_generation: v.hive_generation,
                    subkey_count: v.subkey_count,
                    value_count: v.value_count,
                    max_subkey_name_len: v.max_subkey_name_len,
                    max_value_name_len: v.max_value_name_len,
                    max_value_data_size: v.max_value_data_size,
                    sd_size: v.sd_size,
                    volatile: v.volatile_key != 0,
                    symlink: v.symlink != 0,
                });
            }
            match Error::last_os_error().raw_os_error() {
                Some(e) if e == ERANGE => name = vec![0u8; v.name_len as usize],
                _ => return Err(Error::last_os_error()),
            }
        }
        Err(Error::from_raw_os_error(ERANGE))
    }

    /// Remove this key's path entry in a layer (`None` = base; lower entries
    /// re-emerge). Requires `DELETE`; fails `ENOTEMPTY` with visible children.
    pub fn delete_key(&self, layer: Option<&str>, txn: Option<&Transaction>) -> Result<()> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let (layer_ptr, layer_len) = opt_layer(layer);
        // SAFETY: live fd; `layer` valid for `layer_len` for the call.
        check(unsafe { sys::peios_reg_delete_key(self.raw(), layer_ptr, layer_len, txn_fd) })
    }

    /// Create a hidden path entry masking this key in a layer (`None` = base);
    /// removing the layer makes the key reappear. Requires `DELETE`.
    pub fn hide_key(&self, layer: Option<&str>, txn: Option<&Transaction>) -> Result<()> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let (layer_ptr, layer_len) = opt_layer(layer);
        // SAFETY: live fd; `layer` valid for `layer_len` for the call.
        check(unsafe { sys::peios_reg_hide_key(self.raw(), layer_ptr, layer_len, txn_fd) })
    }

    /// Arm (or, with an empty `filter`, disarm) change watches on this key
    /// (requires `KEY_NOTIFY`). `subtree` extends the watch to descendants. Once
    /// armed the key fd is pollable (`EPOLLIN` = events pending) and `read()`
    /// returns the records.
    pub fn notify(&self, filter: NotifyFilter, subtree: bool) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe {
            sys::peios_reg_notify(self.raw(), filter.bits(), subtree as core::ffi::c_int)
        })
    }

    /// Force the source to persist this key's hive's pending writes (requires
    /// `KEY_SET_VALUE`); returns once persistence is confirmed.
    pub fn flush(&self) -> Result<()> {
        // SAFETY: live fd.
        check(unsafe { sys::peios_reg_flush(self.raw()) })
    }

    // ---- security descriptors ---------------------------------------------

    /// Read the `secinfo` components of this key's security descriptor (KACS
    /// binary format). Owner/group/DACL need `READ_CONTROL`; the SACL needs
    /// `ACCESS_SYSTEM_SECURITY`.
    pub fn get_security(&self, secinfo: SecInfo) -> Result<SecurityDescriptor> {
        // Probe for the SD size (zero cap), then read it, retrying once if it
        // grows between calls.
        let mut cap = 0u32;
        {
            // SAFETY: live fd; NULL buffer with 0 cap probes the size into `cap`.
            let ret = unsafe {
                sys::peios_reg_get_security(
                    self.raw(),
                    secinfo.bits(),
                    core::ptr::null_mut(),
                    0,
                    &mut cap,
                )
            };
            if ret != 0 {
                match Error::last_os_error().raw_os_error() {
                    Some(e) if e == ERANGE => {}
                    _ => return Err(Error::last_os_error()),
                }
            }
        }
        for _ in 0..4 {
            let mut buf = vec![0u8; cap as usize];
            let mut len = 0u32;
            // SAFETY: live fd; (buf, cap) is the output window; `len` writable.
            let ret = unsafe {
                sys::peios_reg_get_security(
                    self.raw(),
                    secinfo.bits(),
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut len,
                )
            };
            if ret == 0 {
                buf.truncate(len as usize);
                return Ok(SecurityDescriptor::from_bytes(buf));
            }
            match Error::last_os_error().raw_os_error() {
                Some(e) if e == ERANGE => cap = len,
                _ => return Err(Error::last_os_error()),
            }
        }
        Err(Error::from_raw_os_error(ERANGE))
    }

    /// Apply the `secinfo` components of `sd` to this key's security descriptor,
    /// merging with the rest. `txn` gives atomicity (not layer qualification).
    /// SD changes affect only future opens.
    pub fn set_security(
        &self,
        secinfo: SecInfo,
        sd: &SecurityDescriptor,
        txn: Option<&Transaction>,
    ) -> Result<()> {
        let txn_fd = opt_fd(txn.map(Transaction::as_fd_borrow));
        let bytes = sd.as_bytes();
        // SAFETY: live fd; `bytes` live for the call.
        check(unsafe {
            sys::peios_reg_set_security(
                self.raw(),
                secinfo.bits(),
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                txn_fd,
            )
        })
    }

    // ---- backup / restore -------------------------------------------------

    /// Export this key and its entire subtree to `output` (requires
    /// `SeBackupPrivilege`). Takes a read-only snapshot.
    pub fn backup(&self, output: BorrowedFd<'_>) -> Result<()> {
        // SAFETY: live key fd; `output` is a live borrowed fd for the call.
        check(unsafe { sys::peios_reg_backup(self.raw(), output.as_raw_fd()) })
    }

    /// Replace this key and its entire subtree from `input` (requires
    /// `SeRestorePrivilege`), applied in one transaction.
    pub fn restore(&self, input: BorrowedFd<'_>) -> Result<()> {
        // SAFETY: live key fd; `input` is a live borrowed fd for the call.
        check(unsafe { sys::peios_reg_restore(self.raw(), input.as_raw_fd()) })
    }
}

impl AsFd for Key {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl AsRawFd for Key {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl From<Key> for OwnedFd {
    fn from(k: Key) -> OwnedFd {
        k.0
    }
}
impl From<OwnedFd> for Key {
    fn from(fd: OwnedFd) -> Key {
        Key(fd)
    }
}
impl IntoRawFd for Key {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

/// A terminal builder for [`Key::set_value`].
///
/// Chained setters refine the write; [`call`](SetValue::call) performs it.
#[derive(Debug)]
pub struct SetValue<'a> {
    key: &'a Key,
    name: &'a [u8],
    ty: ValueType,
    data: &'a [u8],
    layer: Option<&'a str>,
    expected_seq: u64,
    txn: Option<&'a Transaction>,
}

impl<'a> SetValue<'a> {
    /// Target a specific layer by name (default: the base layer).
    pub fn layer(&mut self, layer: &'a str) -> &mut Self {
        self.layer = Some(layer);
        self
    }

    /// Compare-and-swap guard: apply only if the current sequence matches
    /// `seq`, else `EAGAIN`. `0` (the default) disables the CAS.
    pub fn expect_seq(&mut self, seq: u64) -> &mut Self {
        self.expected_seq = seq;
        self
    }

    /// Enlist the write in `txn` (default: auto-commit).
    pub fn in_txn(&mut self, txn: &'a Transaction) -> &mut Self {
        self.txn = Some(txn);
        self
    }

    /// Perform the value write.
    pub fn call(&self) -> Result<()> {
        let txn_fd = opt_fd(self.txn.map(Transaction::as_fd_borrow));
        let (name_ptr, name_len) = bytes_u32(self.name);
        let (data_ptr, data_len) = bytes_u32(self.data);
        let clayer = match self.layer {
            Some(l) => Some(CString::new(l).map_err(|_| Error::from_raw_os_error(EINVAL))?),
            None => None,
        };
        let (layer_ptr, layer_len): (*const c_void, u32) = match clayer.as_ref() {
            Some(c) => (c.as_ptr().cast(), c.as_bytes().len() as u32),
            None => (core::ptr::null(), 0),
        };
        // SAFETY: live key fd; `name`/`data`/`layer` are valid for their lengths
        // for the call.
        check(unsafe {
            sys::peios_reg_set_value(
                self.key.raw(),
                name_ptr,
                name_len,
                self.ty.0,
                data_ptr,
                data_len,
                layer_ptr,
                layer_len,
                txn_fd,
                self.expected_seq,
            )
        })
    }
}

/// The iterator returned by [`Key::values`].
#[derive(Debug)]
pub struct Values<'a> {
    key: &'a Key,
    txn: Option<&'a Transaction>,
    index: u32,
    done: bool,
}

impl Iterator for Values<'_> {
    type Item = Result<EnumValue>;

    fn next(&mut self) -> Option<Result<EnumValue>> {
        if self.done {
            return None;
        }
        match self.key.enum_value(self.index, self.txn) {
            Ok(Some(v)) => {
                self.index += 1;
                Some(Ok(v))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// The iterator returned by [`Key::subkeys`].
#[derive(Debug)]
pub struct Subkeys<'a> {
    key: &'a Key,
    txn: Option<&'a Transaction>,
    index: u32,
    done: bool,
}

impl Iterator for Subkeys<'_> {
    type Item = Result<Subkey>;

    fn next(&mut self) -> Option<Result<Subkey>> {
        if self.done {
            return None;
        }
        match self.key.enum_subkey(self.index, self.txn) {
            Ok(Some(s)) => {
                self.index += 1;
                Some(Ok(s))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl Transaction {
    /// Borrow this transaction's fd (private helper for the `opt_fd` sites).
    #[inline]
    fn as_fd_borrow(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// `(ptr, u32 len)` for a byte slice, casting the pointer to `c_void`.
#[inline]
fn bytes_u32(b: &[u8]) -> (*const c_void, u32) {
    (b.as_ptr().cast(), b.len() as u32)
}

/// A mutable `c_void` buffer pointer that is genuinely NULL when the buffer is
/// empty, so a zero-capacity descriptor field truly probes (the libpeios
/// convention is a NULL buffer with zero capacity).
#[inline]
fn buf_ptr(b: &mut [u8]) -> *mut c_void {
    if b.is_empty() {
        core::ptr::null_mut()
    } else {
        b.as_mut_ptr().cast()
    }
}

/// `(ptr, u32 len)` for an optional layer name — `(NULL, 0)` for the base layer.
/// A `c_char` pointer is fine here: libpeios reads `layer_len` bytes regardless.
#[inline]
fn opt_layer(layer: Option<&str>) -> (*const c_void, u32) {
    match layer {
        Some(l) => (l.as_ptr() as *const c_char as *const c_void, l.len() as u32),
        None => (core::ptr::null(), 0),
    }
}

/// Parse `count` packed `[name_len u32][name][type u32][data_len u32][data]`
/// records (little-endian) from `buf` into owned [`ValueRecord`]s.
fn parse_value_records(buf: &[u8], count: usize) -> Result<Vec<ValueRecord>> {
    let mut out = Vec::with_capacity(count);
    let mut pos = 0usize;
    let read_u32 = |buf: &[u8], pos: usize| -> Result<u32> {
        let end = pos.checked_add(4).filter(|&e| e <= buf.len());
        match end {
            Some(e) => Ok(u32::from_le_bytes(buf[pos..e].try_into().unwrap())),
            None => Err(Error::from_raw_os_error(EINVAL)),
        }
    };
    for _ in 0..count {
        let name_len = read_u32(buf, pos)? as usize;
        pos += 4;
        let name_end = pos.checked_add(name_len).filter(|&e| e <= buf.len());
        let name_end = name_end.ok_or_else(|| Error::from_raw_os_error(EINVAL))?;
        let name = buf[pos..name_end].to_vec();
        pos = name_end;

        let ty = ValueType(read_u32(buf, pos)?);
        pos += 4;

        let data_len = read_u32(buf, pos)? as usize;
        pos += 4;
        let data_end = pos.checked_add(data_len).filter(|&e| e <= buf.len());
        let data_end = data_end.ok_or_else(|| Error::from_raw_os_error(EINVAL))?;
        let data = buf[pos..data_end].to_vec();
        pos = data_end;

        out.push(ValueRecord { name, ty, data });
    }
    Ok(out)
}
