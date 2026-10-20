---
title: Audit Contexts in Rust
type: concept
description: Attach an owned object description to a Rust access check without confusing audit data with authority.
---

An audit context names the object behind an access check. The Rust
`AuditContext` type owns the encoded description and lends it to an
`AccessCheck`. The kernel can then include that description in an audit
record when the applicable audit policy calls for one.

The description is the daemon's claim, not independently observed identity.
It does not grant access or replace the security descriptor. See
[The Audit Context](~peios/sdk-access/the-audit-context) for the shared format
and [Access Decisions](~specifications/pgss/events/access-decisions) for the
rules governing audited objects.

## Build and use a context

This helper checks a service object using a supplied caller token, descriptor,
access mask, and object-specific generic mapping:

```rust
use std::os::fd::BorrowedFd;

use peios::access::{AccessCheck, AccessDecision, AuditContext};
use peios::security::{AccessMask, GenericMapping, SecurityDescriptor};

fn check_service(
    caller: BorrowedFd<'_>,
    descriptor: &SecurityDescriptor,
    desired: AccessMask,
    mapping: GenericMapping,
) -> peios::Result<AccessDecision> {
    let context = AuditContext::new("service", &[("name", "jellyfin".into())])?;
    AccessCheck::new(descriptor, desired, mapping)
        .token(caller)
        .audit_context(&context)
        .check()
}
```

The example names an illustrative service. Replace its name with the actual
object being checked, and define asserted object fields in the owning event
catalog fragment. Do not label an arbitrary request as another component's
object merely because its name is convenient.

A completed check returns an `AccessDecision`. Inspect `allowed`: denial is
an ordinary decision, not a Rust `Err`. An error means the check itself could
not complete. The check evaluates access; your daemon still enforces the
result before performing the operation.

## Values and ownership

Field values convert from `&str`, `u64`, `u32`, `i64`, `i32`, `bool`, `&[u8]`,
and `&SidRef`. A security identifier (SID) uses its binary representation.
Use the declared field type rather than converting every value to a string.
Leave absent fields out instead of supplying nil or a placeholder value.

The constructor copies the encoding into owned storage. Temporary field
slices need not outlive the returned context. `AccessCheck` borrows that
context for the check; `as_bytes` lends the encoded bytes without transferring
ownership.

Invalid kind or key names, repeated keys, and oversized encodings are rejected
with `EINVAL`. Names are single kebab-case segments, and the encoded context
is limited to 4096 bytes. Other construction failures remain errors to handle.

## Accept an existing encoding

`AuditContext::from_bytes` takes a `Vec<u8>`, validates the encoded context,
and adopts it on success. It applies the shared validator's structural rules,
which are broader than the scalar-only constructor. Passing validation does
not prove that fields are cataloged, truthful, or appropriate for this object.

Keep the caller token and descriptor associated with the same request while
constructing and checking the context. Neither a successfully encoded context
nor a successful audit write is an authorization decision by itself.
