//! The crate-wide error type.
//!
//! Every libpeios call reports failure the classic Linux way — a `-1` (or a
//! `NULL` handle / negative `ssize_t`) with the thread's `errno` set. So a
//! [`peios::Error`](Error) is exactly an OS error, captured from `errno` at the
//! point of failure; it is a thin newtype over [`std::io::Error`] so it slots
//! into any `std` I/O context while still naming the crate it came from.
//!
//! The KACS *status* values (`opened`/`created`) and the registry *disposition*
//! (`created-new`/`opened-existing`) are **not** errors — they are success
//! outputs and are returned alongside the handle (see [`crate::file::OpenStatus`]
//! and [`crate::registry::Disposition`]), never surfaced here.

use std::fmt;

/// An error from a libpeios call: an OS error captured from `errno`.
pub struct Error(std::io::Error);

impl Error {
    /// Capture the calling thread's current `errno` as an [`Error`].
    ///
    /// Call this immediately after a libpeios function reports failure, before
    /// any other libc call can overwrite `errno`.
    #[inline]
    pub fn last_os_error() -> Self {
        Error(std::io::Error::last_os_error())
    }

    /// Construct from a specific `errno` value.
    #[inline]
    pub fn from_raw_os_error(errno: i32) -> Self {
        Error(std::io::Error::from_raw_os_error(errno))
    }

    /// The underlying `errno`, if this is an OS error (it always is).
    #[inline]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.0.raw_os_error()
    }

    /// The portable [`std::io::ErrorKind`] classification.
    #[inline]
    pub fn kind(&self) -> std::io::ErrorKind {
        self.0.kind()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Self {
        Error(e)
    }
}

impl From<Error> for std::io::Error {
    #[inline]
    fn from(e: Error) -> Self {
        e.0
    }
}

/// The crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
