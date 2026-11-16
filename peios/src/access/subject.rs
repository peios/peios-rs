//! Supplied identity facts for advisory checks without an OS token.
use super::AccessCheck;
use crate::error::{Error, Result};
use crate::security::{AccessMask, SidRef};
use crate::token::Claim;
use peios_sys as sys;
use std::ffi::CString;

/// A group SID and its KACS_SID_GROUP_* flags, including enabled/deny-only state.
pub struct SubjectGroup<'a> {
    pub sid: &'a SidRef,
    pub attributes: u32,
}

/// Whether an omitted claim is absent or remains undisclosed/unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClaimCoverage {
    #[default]
    Partial,
    Complete,
}

/// Disclosed values and explicit known absences under KACS name equivalence
/// (Unicode lowercase). Partial results must not invent absences. An adapter
/// must reconcile a source's name rules before copying its absence assertions.
/// Updated PGSS Named results use this rule; their explicit absences provide
/// Partial knowledge. Filtered results never establish additional absences.
#[derive(Default)]
pub struct SuppliedClaims<'a> {
    pub values: &'a [Claim],
    pub absent: &'a [&'a str],
    pub coverage: ClaimCoverage,
}

/// Hypothetical identity data. None is unknown; Some(&[]) is known empty.
/// These facts convey no authority to impersonate, install or mint OS tokens.
#[derive(Default)]
pub struct SuppliedSubject<'a> {
    pub user: Option<&'a SidRef>,
    pub groups: Option<&'a [SubjectGroup<'a>]>,
    pub user_claims: Option<SuppliedClaims<'a>>,
    pub device_groups: Option<&'a [SubjectGroup<'a>]>,
    pub device_claims: Option<SuppliedClaims<'a>>,
    pub local_claims: Option<SuppliedClaims<'a>>,
}

bitflags::bitflags! {
    /// Missing input categories. Claim names and restricted values are not exposed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MissingSubjectContext: u32 {
        const USER = sys::PEIOS_SUBJECT_MISSING_USER;
        const GROUPS = sys::PEIOS_SUBJECT_MISSING_GROUPS;
        const USER_CLAIMS = sys::PEIOS_SUBJECT_MISSING_USER_CLAIMS;
        const DEVICE_GROUPS = sys::PEIOS_SUBJECT_MISSING_DEVICE_GROUPS;
        const DEVICE_CLAIMS = sys::PEIOS_SUBJECT_MISSING_DEVICE_CLAIMS;
        const LOCAL_CLAIMS = sys::PEIOS_SUBJECT_MISSING_LOCAL_CLAIMS;
        const SELF = sys::PEIOS_SUBJECT_MISSING_SELF;
        const OBJECT_TYPES = sys::PEIOS_SUBJECT_MISSING_OBJECT_TYPES;
        const EXECUTION_CONTEXT = sys::PEIOS_SUBJECT_MISSING_EXECUTION_CONTEXT;
        const AUDIT_CONTEXT = sys::PEIOS_SUBJECT_MISSING_AUDIT_CONTEXT;
    }
}

/// Only Granted is sufficient for service admission. MissingContext carries no
/// provisional grant; the caller can request more facts or deny access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectAccessDecision {
    Granted { granted: AccessMask },
    Denied { granted: AccessMask },
    MissingContext { missing: MissingSubjectContext },
}

struct ClaimsStorage {
    // Keep every allocation referenced by raw live through the FFI call.
    _names: Vec<CString>,
    _values: Vec<Vec<sys::peios_token_claim_value>>,
    _absent: Vec<CString>,
    _absent_ptrs: Vec<*const core::ffi::c_char>,
    _claims: Vec<sys::peios_token_claim>,
    raw: sys::peios_subject_claims,
}

fn invalid() -> Error {
    Error::from_raw_os_error(libc::EINVAL)
}

impl ClaimsStorage {
    fn new(input: Option<&SuppliedClaims<'_>>) -> Result<Option<Self>> {
        let Some(input) = input else {
            return Ok(None);
        };
        let names = input
            .values
            .iter()
            .map(|claim| CString::new(claim.name.as_str()).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        let values: Vec<_> = input
            .values
            .iter()
            .map(|claim| claim.values.to_ffi())
            .collect();
        let claims: Vec<_> = input
            .values
            .iter()
            .enumerate()
            .map(|(index, claim)| {
                Ok(sys::peios_token_claim {
                    name: names[index].as_ptr(),
                    value_type: claim.values.value_type(),
                    flags: claim.flags.bits(),
                    values: values[index].as_ptr(),
                    value_count: u32::try_from(values[index].len()).map_err(|_| invalid())?,
                })
            })
            .collect::<Result<_>>()?;
        let absent = input
            .absent
            .iter()
            .map(|name| CString::new(*name).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        let absent_ptrs: Vec<_> = absent.iter().map(|name| name.as_ptr()).collect();
        let raw = sys::peios_subject_claims {
            values: claims.as_ptr(),
            value_count: claims.len(),
            absent: absent_ptrs.as_ptr(),
            absent_count: absent_ptrs.len(),
            complete: u32::from(input.coverage == ClaimCoverage::Complete),
        };
        Ok(Some(Self {
            _names: names,
            _values: values,
            _absent: absent,
            _absent_ptrs: absent_ptrs,
            _claims: claims,
            raw,
        }))
    }
}

fn groups(input: Option<&[SubjectGroup<'_>]>) -> Option<Vec<sys::peios_subject_group>> {
    input.map(|groups| {
        groups
            .iter()
            .map(|group| {
                let (sid, sid_len) = crate::security::sid_raw(group.sid);
                sys::peios_subject_group {
                    sid,
                    sid_len,
                    attributes: group.attributes,
                }
            })
            .collect()
    })
}

impl AccessCheck<'_> {
    /// Check supplied identity facts at the SD root, without using any caller
    /// token. No kernel rebuild is required by the initial userspace backend.
    ///
    /// Explicit token, privilege-intent or kernel-audit settings are invalid for
    /// this mode. Execution-sensitive SDs return MissingContext; this does not
    /// simulate OS privileges/confinement or replace kernel enforcement.
    pub fn check_subject(&self, subject: &SuppliedSubject<'_>) -> Result<SubjectAccessDecision> {
        self.check_supplied(subject, &[], 0)
    }

    /// Check one node of an explicit object-type tree. GUID-scoped ACEs retain
    /// their scope; they are never silently treated as global grants.
    pub fn check_subject_by_type(
        &self,
        subject: &SuppliedSubject<'_>,
        tree: &[sys::kacs_object_type_entry],
        node: usize,
    ) -> Result<SubjectAccessDecision> {
        if tree.is_empty() {
            return Err(invalid());
        }
        self.check_supplied(subject, tree, node)
    }

    fn check_supplied(
        &self,
        subject: &SuppliedSubject<'_>,
        tree: &[sys::kacs_object_type_entry],
        node: usize,
    ) -> Result<SubjectAccessDecision> {
        let user_claims = ClaimsStorage::new(subject.user_claims.as_ref())?;
        let device_claims = ClaimsStorage::new(subject.device_claims.as_ref())?;
        let local_claims = ClaimsStorage::new(subject.local_claims.as_ref())?;
        let groups = groups(subject.groups);
        let device_groups = self::groups(subject.device_groups);
        let (user, user_len) = subject
            .user
            .map(crate::security::sid_raw)
            .unwrap_or((core::ptr::null(), 0));
        let raw = sys::peios_access_subject {
            size: core::mem::size_of::<sys::peios_access_subject>(),
            user,
            user_len,
            groups: groups
                .as_ref()
                .map_or(core::ptr::null(), |groups| groups.as_ptr()),
            group_count: groups.as_ref().map_or(0, Vec::len),
            user_claims: user_claims
                .as_ref()
                .map_or(core::ptr::null(), |claims| &claims.raw),
            device_groups: device_groups
                .as_ref()
                .map_or(core::ptr::null(), |groups| groups.as_ptr()),
            device_group_count: device_groups.as_ref().map_or(0, Vec::len),
            device_claims: device_claims
                .as_ref()
                .map_or(core::ptr::null(), |claims| &claims.raw),
            local_claims: local_claims
                .as_ref()
                .map_or(core::ptr::null(), |claims| &claims.raw),
        };
        let request = self.build_request(
            tree.as_ptr(),
            u32::try_from(tree.len()).map_err(|_| invalid())?,
        );
        let node = u32::try_from(node).map_err(|_| invalid())?;
        let mut out = sys::peios_subject_access_result {
            decision: 2,
            granted: 0,
            missing: 0,
        };
        // SAFETY: all spans borrow self/subject or the storage above for this
        // synchronous call; out is writable and disjoint from every input.
        let result = unsafe { sys::peios_access_check_subject(&request, &raw, node, &mut out) };
        crate::util::check(result)?;
        match out.decision {
            sys::PEIOS_SUBJECT_ACCESS_GRANTED => Ok(SubjectAccessDecision::Granted {
                granted: AccessMask::from_bits_retain(out.granted),
            }),
            sys::PEIOS_SUBJECT_ACCESS_DENIED => Ok(SubjectAccessDecision::Denied {
                granted: AccessMask::from_bits_retain(out.granted),
            }),
            sys::PEIOS_SUBJECT_ACCESS_MISSING_CONTEXT => {
                Ok(SubjectAccessDecision::MissingContext {
                    missing: MissingSubjectContext::from_bits_retain(out.missing),
                })
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{AccessCheck, ClaimCoverage, SubjectAccessDecision};
    use crate::security::{sddl, GenericMapping, Sid, WellKnown};
    use crate::token::{ClaimAttr, ClaimValues};

    #[test]
    fn supplied_identity_does_not_use_the_callers_token_or_invent_groups() {
        let sd = sddl::parse("O:SYG:SYD:(D;;0x1;;;BA)(A;;0x1;;;SY)").unwrap();
        let user = Sid::well_known(WellKnown::System);
        let blocked = Sid::well_known(WellKnown::Administrators);
        let check = AccessCheck::new(
            &sd,
            AccessMask::from_bits_retain(1),
            GenericMapping::new(1, 0, 1, 1),
        );
        let mut subject = SuppliedSubject {
            user: Some(user.as_ref()),
            ..Default::default()
        };
        assert_eq!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::MissingContext {
                missing: MissingSubjectContext::GROUPS
            }
        );
        subject.groups = Some(&[]);
        assert!(matches!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::Granted { .. }
        ));
        let groups = [SubjectGroup {
            sid: blocked.as_ref(),
            attributes: sys::KACS_SID_GROUP_ENABLED,
        }];
        subject.groups = Some(&groups);
        assert!(matches!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::Denied { .. }
        ));
    }

    #[test]
    fn claim_values_and_coverage_survive_the_safe_wrapper() {
        for (name, alias) in [("Department", "department"), ("Équipe", "équipe")] {
            check_claim_knowledge(name, alias);
        }
    }

    fn check_claim_knowledge(name: &str, alias: &str) {
        use crate::security::{Ace, AceFlags, AceType, AclBuilder, SdBuilder};
        let user = Sid::well_known(WellKnown::System);
        // Build the ARTX reference directly: the text codec currently accepts
        // ASCII attribute identifiers, while binary conditions support Unicode.
        let utf16: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut expression = b"artx".to_vec();
        expression.push(0xf9); // @User attribute reference
        expression.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        expression.extend_from_slice(&utf16);
        expression.push(0x8d); // Not_Exists
        while expression.len() % 4 != 0 {
            expression.push(0);
        }
        let acl = AclBuilder::new()
            .add(&Ace {
                ace_type: AceType::Other(0x09), // ACCESS_ALLOWED_CALLBACK_ACE
                flags: AceFlags::empty(),
                mask: 1,
                sid: user.as_ref(),
                object_type: None,
                inherited_object_type: None,
                app_data: Some(&expression),
            })
            .build()
            .unwrap();
        let sd = SdBuilder::new()
            .owner(user.as_ref())
            .dacl(&acl)
            .build()
            .unwrap();
        let check = AccessCheck::new(
            &sd,
            AccessMask::from_bits_retain(1),
            GenericMapping::new(1, 0, 1, 1),
        );
        let mut subject = SuppliedSubject {
            user: Some(user.as_ref()),
            groups: Some(&[]),
            user_claims: Some(SuppliedClaims::default()),
            ..Default::default()
        };
        assert_eq!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::MissingContext {
                missing: MissingSubjectContext::USER_CLAIMS
            }
        );
        let absent = [alias];
        subject.user_claims.as_mut().unwrap().absent = &absent;
        assert!(matches!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::Granted { .. }
        ));
        let claims = [Claim {
            name: alias.into(),
            flags: ClaimAttr::empty(),
            values: ClaimValues::String(vec!["Household".into()]),
        }];
        subject.user_claims = Some(SuppliedClaims {
            values: &claims,
            absent: &[],
            coverage: ClaimCoverage::Partial,
        });
        assert!(matches!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::Denied { .. }
        ));
        let conflicting_absence = [name];
        subject.user_claims.as_mut().unwrap().absent = &conflicting_absence;
        assert!(check.check_subject(&subject).is_err());
        subject.user_claims = Some(SuppliedClaims {
            values: &[],
            absent: &[],
            coverage: ClaimCoverage::Complete,
        });
        assert!(matches!(
            check.check_subject(&subject).unwrap(),
            SubjectAccessDecision::Granted { .. }
        ));
    }
}
