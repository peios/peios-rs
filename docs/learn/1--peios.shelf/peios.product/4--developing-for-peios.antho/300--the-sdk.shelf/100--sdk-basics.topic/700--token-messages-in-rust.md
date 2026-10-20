---
title: Token Messages in Rust
type: concept
description: Handle identity and descriptor ownership for requests received through Unix sockets.
---

The Rust socket helpers send and receive per-message identity with file
descriptors. `ReceivedMessage` owns each received descriptor, including its
optional token, so rejecting a message can release those resources by dropping
it. The request bytes remain in the caller's receive buffer.

Use [Per-Message Identity](~peios/sdk-tokens/opening-and-creating-tokens)
for the shared interface contract. A conveyed token identifies the authority
the sender could convey; it does not authorize every requested operation.

## Send one identity with a request

For a connected socket and an existing user token, the sending call is:

```rust
use std::os::fd::AsFd;
use peios::socket;

let sent = socket::send_message(
    jobs.as_fd(), request, Some(user_token.as_fd()), &[], 0,
)?;
```

The caller retains its descriptors. Check the returned byte count according
to the transport's framing rules. On a stream, a partial write is not a
complete request. Do not blindly replay the whole request and its ancillary
data after a partial write.

## Receive and reject incomplete requests

This helper requires an attached identity and rejects truncation. The
application chooses an 8-descriptor bound; choose a bound appropriate to your
own protocol and validate the number and purpose of descriptors after receipt.

```rust
use std::error::Error;
use std::os::fd::{BorrowedFd, OwnedFd};

use peios::socket;
use peios::token::{ImpersonationLevel, Token};

fn receive_identity(
    connection: BorrowedFd<'_>,
    buffer: &mut [u8],
) -> Result<(usize, Token, Vec<OwnedFd>), Box<dyn Error>> {
    let message = socket::recv_message(connection, buffer, 8, 0)?;
    if message.truncated || message.control_truncated {
        return Err("incomplete request or ancillary data".into());
    }
    if message.len == 0 {
        return Err("empty request or closed stream".into());
    }
    let identity = match message.token {
        Some(token) => token,
        None => return Err("this protocol requires an attached identity".into()),
    };
    if identity.impersonation_level()? < ImpersonationLevel::Impersonation {
        return Err("identity cannot be used to act for this caller".into());
    }
    Ok((message.len, identity, message.fds))
}
```

This is an identity/ownership helper, not a stream message decoder. A stream
read can contain only part of the application's frame. Reassemble and validate
the frame before interpreting its contents. Do not use zero-length data as
an identity-only request with this helper.

Returning an error drops descriptors already received. Moving the token or
`OwnedFd` values out transfers their ownership to the caller; those handles
close when their new owners drop them. Do not close their raw descriptor
numbers separately. Received handles are close-on-exec.

The example requires at least the local impersonation level because its
server intends to act for the caller. An identification-only protocol needs
its own explicit contract. Checking the level does not enter impersonation
or perform an access check.

## Choose fallback identity explicitly

A protocol can instead specify that an absent attached token means the
connected peer's primary token. In that case, obtain the peer process handle
from the kernel and open the token through it:

```rust
use std::os::fd::AsFd;
use peios::socket;
use peios::token::{Token, TokenAccess};

let peer = socket::peer_pidfd(connection.as_fd())?;
let identity = Token::open_process(
    peer.as_fd(), TokenAccess::QUERY | TokenAccess::DUPLICATE,
)?;
```

This is the connected peer's primary identity, not necessarily the identity
of a client that peer represents. Do not substitute a process number named
in the payload. Do not use fallback after truncation, an invalid attached
token, or a failed token query; those are failures rather than absence.

Apply the protocol's level and authorization checks to a fallback token too.
Opening a primary token does not convert it into an impersonation token or
enter impersonation. If acting under it is required, use the token duplication
and scoped impersonation interfaces described by the SDK.

A scoped impersonation guard stays on its creating thread. It does not carry
identity safely across arbitrary async task migration. Explicitly revert when
you need to handle restoration failure; dropping the guard cannot report it.
