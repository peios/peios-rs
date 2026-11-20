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
//! and [`crate::registry::Disposition`]), never surfaced here. A failed native
//! open can also name the NT condition one `errno` cannot tell apart — a
//! sharing violation or a delete-pending file both fail with `EBUSY` — and
//! [`Error::open_failure`] carries it.

use std::fmt;

use crate::file::OpenFailure;

/// An error from a libpeios call: an OS error captured from `errno`.
pub struct Error {
    io: std::io::Error,
    open_failure: Option<OpenFailure>,
}

impl Error {
    /// Capture the calling thread's current `errno` as an [`Error`].
    ///
    /// Call this immediately after a libpeios function reports failure, before
    /// any other libc call can overwrite `errno`.
    #[inline]
    pub fn last_os_error() -> Self {
        std::io::Error::last_os_error().into()
    }

    /// Construct from a specific `errno` value.
    #[inline]
    pub fn from_raw_os_error(errno: i32) -> Self {
        std::io::Error::from_raw_os_error(errno).into()
    }

    /// Attach the NT condition a failed open reported.
    pub(crate) fn with_open_failure(mut self, failure: Option<OpenFailure>) -> Self {
        self.open_failure = failure;
        self
    }

    /// The underlying `errno`, if this is an OS error (it always is).
    #[inline]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.io.raw_os_error()
    }

    /// The portable [`std::io::ErrorKind`] classification.
    #[inline]
    pub fn kind(&self) -> std::io::ErrorKind {
        self.io.kind()
    }

    /// For a failed native open, the NT condition behind its `errno`: a
    /// sharing violation, a delete-pending file, or delete-on-close of a
    /// read-only file. `None` for every other error.
    #[inline]
    pub fn open_failure(&self) -> Option<OpenFailure> {
        self.open_failure
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.open_failure {
            Some(failure) => write!(f, "{:?} ({failure:?})", self.io),
            None => fmt::Debug::fmt(&self.io, f),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.open_failure {
            Some(failure) => write!(f, "{} ({failure})", self.io),
            None => fmt::Display::fmt(&self.io, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.io)
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Self {
        Error {
            io: e,
            open_failure: None,
        }
    }
}

impl From<Error> for std::io::Error {
    #[inline]
    fn from(e: Error) -> Self {
        e.io
    }
}

/// The crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
