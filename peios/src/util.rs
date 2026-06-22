//! Internal FFI glue shared by every module: return-value checking, fd
//! conversion, and the getxattr-style probe→alloc→fill helper.
//!
//! Nothing here is public. These are the handful of patterns that turn a raw
//! libpeios call (`-1`/errno, a `NULL` handle, a sentinel `-1` fd, a two-call
//! size probe) into the safe idioms the rest of the crate is written in terms of.

use core::ffi::c_void;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::error::{Error, Result};

/// `0`/`-1`-returning calls: `Ok(())` on `0`, `errno` otherwise.
#[inline]
pub(crate) fn check(ret: core::ffi::c_int) -> Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

/// fd-returning calls: take ownership of the returned fd, or `errno` on `-1`.
#[inline]
pub(crate) fn check_fd(ret: core::ffi::c_int) -> Result<OwnedFd> {
    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        // SAFETY: libpeios returned a freshly-opened, owned fd (>= 0). We are the
        // sole owner from here, so wrapping it in OwnedFd is sound.
        Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
    }
}

/// `ssize_t`-returning calls that yield a non-negative length: the length as
/// `usize`, or `errno` on a negative return.
#[inline]
pub(crate) fn check_len(ret: isize) -> Result<usize> {
    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// The raw fd of an optional borrowed handle, using libpeios' `-1` sentinel for
/// "none" (the convention for `dirfd`, `txn_fd`, `token_fd`, `pidfd`, …).
#[inline]
pub(crate) fn opt_fd(fd: Option<BorrowedFd<'_>>) -> RawFd {
    fd.map_or(-1, |f| f.as_raw_fd())
}

use std::os::fd::AsRawFd;

/// Drive a getxattr-style size probe to completion, returning an owned buffer.
///
/// `f(buf, cap)` must follow the libpeios convention: a non-negative return is
/// the number of bytes written; `cap == 0` (with a `NULL` buffer) probes for the
/// required size without writing; a too-small non-zero buffer fails with
/// `ERANGE` and writes nothing. We probe for the size, allocate, and fill — with
/// a bounded retry in case the size grows between the two calls.
pub(crate) fn probe<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(*mut c_void, usize) -> isize,
{
    let mut cap = check_len(f(core::ptr::null_mut(), 0))?;
    for _ in 0..4 {
        let mut buf = vec![0u8; cap];
        let ret = f(buf.as_mut_ptr().cast(), buf.len());
        if ret >= 0 {
            buf.truncate(ret as usize);
            return Ok(buf);
        }
        // ERANGE means the object grew since the probe; re-read the size and retry.
        match Error::last_os_error().raw_os_error() {
            Some(libc_erange) if libc_erange == ERANGE => {
                cap = check_len(f(core::ptr::null_mut(), 0))?;
            }
            _ => return Err(Error::last_os_error()),
        }
    }
    Err(Error::from_raw_os_error(ERANGE))
}

/// `ERANGE` without pulling in the `libc` crate (stable on Linux).
const ERANGE: i32 = 34;
