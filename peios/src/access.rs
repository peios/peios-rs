//! KACS access checks: the [`AccessCheck`] builder and its [`AccessDecision`].
//!
//! [`AccessCheck`] runs the full KACS AccessCheck pipeline for a token against a
//! security descriptor and a desired access mask. These checks are *advisory* —
//! they evaluate, they do not enforce; enforcement always uses the subject's own
//! process security block.
//!
//! Denial is not an error here: a check that completes always yields an
//! [`AccessDecision`] reporting whether access was `allowed` and the `granted`
//! mask (filled even on denial). Only a genuine failure (a bad descriptor, a
//! missing token, …) surfaces as an [`Err`].

use std::os::fd::BorrowedFd;

use peios_sys as sys;

use crate::error::{Error, Result};
use crate::security::{AccessMask, GenericMapping, SecurityDescriptor, SidRef};
use crate::util::opt_fd;

/// `EACCES` without pulling in the `libc` crate (stable on Linux): the errno
/// libpeios reports for an access *denial*, which is a decision, not an error.
const EACCES: i32 = 13;

/// The outcome of an [`AccessCheck`]: whether access was granted, and the mask
/// of rights actually granted.
///
/// `granted` is filled whether or not access was `allowed` — on denial it is the
/// (partial) set of desired rights that *would* have been granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessDecision {
    /// `true` if every desired right was granted.
    pub allowed: bool,
    /// The mask of rights actually granted (object-specific, generics resolved).
    pub granted: AccessMask,
}

/// A builder for a KACS access check against one security descriptor.
///
/// Set the mandatory inputs at construction ([`new`](Self::new)); the remaining
/// setters cover the optional, advanced inputs and may be skipped. Terminate
/// with [`check`](Self::check) for an ordinary check, or
/// [`check_list`](Self::check_list) for the object-type-list variant.
pub struct AccessCheck<'a> {
    token: Option<BorrowedFd<'a>>,
    sd: &'a SecurityDescriptor,
    desired: AccessMask,
    mapping: GenericMapping,
    self_sid: Option<&'a SidRef>,
    privilege_intent: u32,
}

impl<'a> AccessCheck<'a> {
    /// Begin a check of `desired` against `sd`, folding generic rights through
    /// `mapping` (the object class's generic mapping, e.g.
    /// [`Token::generic_mapping`](crate::token::Token::generic_mapping)).
    ///
    /// By default the check uses the caller's effective token; override it with
    /// [`token`](Self::token).
    pub fn new(
        sd: &'a SecurityDescriptor,
        desired: AccessMask,
        mapping: GenericMapping,
    ) -> AccessCheck<'a> {
        AccessCheck {
            token: None,
            sd,
            desired,
            mapping,
            self_sid: None,
            privilege_intent: 0,
        }
    }

    /// Check against a specific token rather than the caller's effective token.
    pub fn token(&mut self, token: BorrowedFd<'a>) -> &mut Self {
        self.token = Some(token);
        self
    }

    /// Substitute `sid` for the `PRINCIPAL_SELF` well-known SID in the DACL.
    pub fn self_sid(&mut self, sid: &'a SidRef) -> &mut Self {
        self.self_sid = Some(sid);
        self
    }

    /// Set the backup/restore privilege-intent bits.
    pub fn privilege_intent(&mut self, intent: u32) -> &mut Self {
        self.privilege_intent = intent;
        self
    }

    /// Build the FFI request shared by both terminal calls.
    ///
    /// `object_tree`/`object_tree_count` are filled by the caller (NULL/0 for an
    /// ordinary check). All other advanced list pointers are left absent; the
    /// audit context is left absent. libpeios owns the versioned kernel-args
    /// struct (`caller_size`, reserved fields) — this is only the request it
    /// reads from.
    fn build_request(
        &self,
        object_tree: *const sys::kacs_object_type_entry,
        object_tree_count: u32,
    ) -> sys::peios_access_request {
        let (sid_ptr, sid_len) = match self.self_sid {
            Some(sid) => crate::security::sid_raw(sid),
            None => (core::ptr::null(), 0),
        };
        sys::peios_access_request {
            token_fd: opt_fd(self.token),
            sd: self.sd.as_bytes().as_ptr().cast(),
            sd_len: self.sd.as_bytes().len(),
            desired: self.desired.bits(),
            mapping: self.mapping.0,
            self_sid: sid_ptr,
            self_sid_len: sid_len,
            privilege_intent: self.privilege_intent,
            object_tree,
            object_tree_count,
            local_claims: core::ptr::null(),
            local_claims_len: 0,
            pip_type: 0,
            pip_trust: 0,
            audit_context: core::ptr::null(),
            audit_context_len: 0,
        }
    }

    /// Run the check, returning the [`AccessDecision`].
    ///
    /// A completed check — granted or denied — is `Ok`; only a real failure is
    /// `Err`. The granted mask is read whether or not access was allowed.
    pub fn check(&self) -> Result<AccessDecision> {
        let req = self.build_request(core::ptr::null(), 0);
        let mut granted = 0u32;
        // SAFETY: `req` borrows live buffers (SD bytes, optional SID) for the
        // duration of the call; `granted` is a writable out-param; audit is NULL.
        let r = unsafe { sys::peios_access_check(&req, &mut granted, core::ptr::null_mut()) };
        if r == 0 {
            return Ok(AccessDecision {
                allowed: true,
                granted: AccessMask::from_bits_retain(granted),
            });
        }
        // A denial (EACCES) is a decision, not an error: `granted` is filled.
        let err = Error::last_os_error();
        if err.raw_os_error() == Some(EACCES) {
            Ok(AccessDecision {
                allowed: false,
                granted: AccessMask::from_bits_retain(granted),
            })
        } else {
            Err(err)
        }
    }

    /// Run the object-type-list variant (`AccessCheckByTypeResultList`).
    ///
    /// `object_tree` is the object-type tree (an entry per node, in preorder);
    /// the returned vector holds one [`sys::kacs_node_result`] per node, in the
    /// same order. Both the tree and the result types are the raw pkm UAPI
    /// structs from [`peios_sys`] — modelling the object-type tree and per-node
    /// results as bespoke Rust types would buy little over the plain
    /// `repr(C)` structs, so they are passed and returned directly.
    ///
    /// Unlike [`check`](Self::check), this reports the full per-node result set
    /// rather than a single allowed/denied decision: each entry's `status` and
    /// `granted` carry that node's outcome. A `-1`/errno return surfaces as `Err`.
    pub fn check_list(
        &self,
        object_tree: &[sys::kacs_object_type_entry],
    ) -> Result<Vec<sys::kacs_node_result>> {
        let count = object_tree.len() as u32;
        let req = self.build_request(object_tree.as_ptr(), count);
        let mut results = vec![
            sys::kacs_node_result {
                granted: 0,
                status: 0
            };
            object_tree.len()
        ];
        // SAFETY: `req` borrows live buffers (SD bytes, optional SID, and the
        // `object_tree` slice of `count` entries) for the call; `results` is a
        // writable buffer of exactly `count` entries, matching `req.object_tree_count`.
        let r = unsafe { sys::peios_access_check_list(&req, results.as_mut_ptr(), count) };
        crate::util::check(r)?;
        Ok(results)
    }
}
