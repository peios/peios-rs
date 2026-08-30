//! Per-message identity and descriptors on a Unix socket.
//!
//! A message can carry, as ancillary data, a token the kernel attests the
//! sender could act as (`KACS_SCM_TOKEN`) and a set of descriptors
//! (`SCM_RIGHTS`). [`send_message`] attaches them; [`recv_message`] hands
//! back what arrived, owning every descriptor so nothing leaks; and
//! [`peer_pidfd`] is the kernel's handle on the process at the other end —
//! what [`Token::open_process`] takes when a server wants the peer's primary
//! token rather than what it conveyed.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use peios_sys as sys;

use crate::token::Token;
use crate::util::{check_fd, check_len};
use crate::Result;

/// What one received message carried.
#[derive(Debug)]
pub struct ReceivedMessage {
    /// Bytes written into the caller's buffer. Zero means end of stream.
    pub len: usize,
    /// The token the kernel attached, when the sender conveyed an identity
    /// distinct from the register's: `TOKEN_QUERY | TOKEN_IMPERSONATE |
    /// TOKEN_DUPLICATE`.
    pub token: Option<Token>,
    /// Descriptors passed with `SCM_RIGHTS`, in order, each close-on-exec.
    pub fds: Vec<OwnedFd>,
    /// The data did not fit the buffer (`MSG_TRUNC`).
    pub truncated: bool,
    /// Ancillary data did not fit (`MSG_CTRUNC`): more descriptors than
    /// `max_fds`, or a token with no room. The kernel closed the excess.
    pub control_truncated: bool,
}

/// Send `buf` on `sock`, attaching `token` as a `KACS_SCM_TOKEN` and `fds` as
/// `SCM_RIGHTS`. `flags` are `sendmsg(2)` flags. Returns the bytes sent.
///
/// The kernel gates the token attach as if the sender were impersonating it
/// (`EACCES` without `TOKEN_IMPERSONATE`; `EPERM` if the attach would lower
/// the token's level). The caller keeps its descriptors.
pub fn send_message(
    sock: BorrowedFd<'_>,
    buf: &[u8],
    token: Option<BorrowedFd<'_>>,
    fds: &[BorrowedFd<'_>],
    flags: i32,
) -> Result<usize> {
    let raw_fds: Vec<i32> = fds.iter().map(|fd| fd.as_raw_fd()).collect();
    let fd_count =
        u32::try_from(raw_fds.len()).map_err(|_| crate::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: every fd is live for the call; (ptr, len) come from live slices.
    let n = unsafe {
        sys::peios_socket_send_message(
            sock.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            token.map_or(-1, |t| t.as_raw_fd()),
            raw_fds.as_ptr(),
            fd_count,
            flags,
        )
    };
    check_len(n)
}

/// Receive one message from `sock` into `buf`, accepting one attached token
/// and up to `max_fds` descriptors. `flags` are `recvmsg(2)` flags;
/// `MSG_CMSG_CLOEXEC` is always added. On error nothing was consumed.
pub fn recv_message(
    sock: BorrowedFd<'_>,
    buf: &mut [u8],
    max_fds: usize,
    flags: i32,
) -> Result<ReceivedMessage> {
    let mut raw_fds: Vec<i32> = vec![-1; max_fds];
    let fd_cap =
        u32::try_from(max_fds).map_err(|_| crate::Error::from_raw_os_error(libc::EINVAL))?;
    let mut msg = sys::peios_socket_message {
        token_fd: -1,
        fds: raw_fds.as_mut_ptr(),
        fd_cap,
        fd_count: 0,
        flags: 0,
    };
    // SAFETY: `sock` is live; `buf` and `raw_fds` are live output windows for
    // the duration of the call; `msg` is a valid, initialised out-struct.
    let n = unsafe {
        sys::peios_socket_recv_message(
            sock.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut msg,
            flags,
        )
    };
    let len = check_len(n)?;
    // From here every fd libpeios handed us is ours to own.
    let token = if msg.token_fd >= 0 {
        // SAFETY: a fresh O_CLOEXEC token fd delivered to this call alone.
        Some(Token::from(unsafe {
            OwnedFd::from_raw_fd(msg.token_fd as RawFd)
        }))
    } else {
        None
    };
    let fds = raw_fds
        .into_iter()
        .take(msg.fd_count as usize)
        // SAFETY: each is a fresh O_CLOEXEC fd delivered to this call alone.
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
        .collect();
    Ok(ReceivedMessage {
        len,
        token,
        fds,
        truncated: msg.flags & sys::PEIOS_SOCKET_MSG_TRUNCATED != 0,
        control_truncated: msg.flags & sys::PEIOS_SOCKET_MSG_CTRUNCATED != 0,
    })
}

/// A pidfd for the process on the other end of a connected Unix socket (the
/// `SO_PEERPIDFD` socket option). The kernel's handle on the peer — what a
/// server opens the peer's *primary* token through — never a PID the peer
/// names.
pub fn peer_pidfd(sock: BorrowedFd<'_>) -> Result<OwnedFd> {
    // SAFETY: `sock` is live for the call.
    check_fd(unsafe { sys::peios_socket_peer_pidfd(sock.as_raw_fd()) })
}
