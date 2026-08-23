//! SDDL text codec + security-descriptor inheritance.
//!
//! Safe wrappers over libpeios' `peios_sddl_*` / `peios_sd_*` C ABI — the
//! userspace-only facilities the kernel binary ABI doesn't provide. SDDL is
//! the textual interchange form of a security descriptor (MS-DTYP §2.5.1);
//! [`reinherit`] / [`strip_inherited`] are the inheritance helpers used when
//! propagating an SD down a hierarchy.
//!
//! Parsing returns an owned [`SecurityDescriptor`]; the byte-oriented entries
//! ([`format`], [`reinherit`], [`strip_inherited`]) take raw self-relative SD
//! wire bytes (e.g. [`SecurityDescriptor::as_bytes`]).

use core::ffi::c_int;
use std::ffi::CString;

use peios_sys as sys;

use super::SecurityDescriptor;
use super::acl::Acl;
use crate::error::{Error, Result};
use crate::file::SecInfo;
use crate::util::{probe, probe_str};

/// `EINVAL`, for the interior-NUL rejection on a borrowed `&str`.
const EINVAL: i32 = 22;

/// Parse an SDDL string (e.g. `"O:SYG:BAD:(A;;FA;;;BA)"`) into a security
/// descriptor.
pub fn parse(sddl: &str) -> Result<SecurityDescriptor> {
    let c = CString::new(sddl).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let bytes = probe(|buf, cap| unsafe { sys::peios_sddl_parse_sd(buf, cap, c.as_ptr()) })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

/// Parse the DACL out of an SDDL string, as an owned ACL.
///
/// For the places that want an ACL rather than a whole descriptor — a token's
/// default DACL is the motivating one. `"D:(A;;GA;;;SY)(A;;GA;;;BA)"` is the
/// usual shape, but any SDDL carrying a `D:` section works, so a full
/// descriptor can be handed over and only its DACL taken.
///
/// A convenience over [`parse`] plus [`AclView::to_acl`], and worth having as
/// one call because the intermediate descriptor has to outlive the view taken
/// from it — a borrow the caller would otherwise have to arrange itself, and
/// get wrong once.
///
/// # Errors
///
/// `EINVAL` if the string does not parse, or if it carries no DACL at all.
/// **An absent DACL is refused rather than treated as empty**, because in a
/// security descriptor those mean opposite things: no DACL grants everyone
/// everything, an empty DACL grants nobody anything. Guessing which was meant
/// is not this function's to do.
pub fn parse_acl(sddl: &str) -> Result<Acl> {
    let sd = parse(sddl)?;
    let view = sd.view()?;
    view.dacl()
        .ok_or_else(|| Error::from_raw_os_error(EINVAL))?
        .to_acl()
}

/// Render a self-relative security descriptor's wire bytes as an SDDL string.
pub fn format(sd: &[u8]) -> Result<String> {
    probe_str(|buf, cap| unsafe {
        sys::peios_sddl_format_sd(buf, cap, sd.as_ptr().cast(), sd.len())
    })
}

/// Parse an SDDL conditional expression (e.g. `"@User.Title == \"PM\""`) into
/// its `"artx"` callback-ACE bytecode — the form embedded in a conditional
/// ACE's application data.
pub fn parse_condition(expr: &str) -> Result<Vec<u8>> {
    let c = CString::new(expr).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    probe(|buf, cap| unsafe { sys::peios_sddl_parse_condition(buf, cap, c.as_ptr()) })
}

/// Render `"artx"` callback-ACE bytecode back to canonical SDDL
/// conditional-expression text (no outer parens).
pub fn format_condition(artx: &[u8]) -> Result<String> {
    probe_str(|buf, cap| unsafe {
        sys::peios_sddl_format_condition(buf, cap, artx.as_ptr().cast(), artx.len())
    })
}

/// Recompute a child SD's inherited ACEs from a parent SD: strip the ACEs
/// carrying `ACE_FLAG_INHERITED` from the child DACL, re-derive them from the
/// parent DACL (MS-DTYP §2.5.3.4), and append them after the child's explicit
/// ACEs. Owner/group/SACL and the control bits pass through. Both inputs must
/// be self-relative; `is_container` marks a container child.
pub fn reinherit(parent: &[u8], child: &[u8], is_container: bool) -> Result<SecurityDescriptor> {
    let bytes = probe(|buf, cap| unsafe {
        sys::peios_sd_reinherit(
            buf,
            cap,
            parent.as_ptr().cast(),
            parent.len(),
            child.as_ptr().cast(),
            child.len(),
            is_container as c_int,
        )
    })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

/// Drop ACEs carrying `ACE_FLAG_INHERITED` from the ACLs selected by `info`
/// (the DACL and/or SACL; other components pass through). Selecting neither
/// returns the input unchanged.
pub fn strip_inherited(sd: &[u8], info: SecInfo) -> Result<SecurityDescriptor> {
    let bytes = probe(|buf, cap| unsafe {
        sys::peios_sd_strip_inherited(buf, cap, sd.as_ptr().cast(), sd.len(), info.bits())
    })?;
    Ok(SecurityDescriptor::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sd_text_round_trips() {
        let sd = parse("O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)").unwrap();
        let text = format(sd.as_bytes()).unwrap();
        assert!(text.starts_with("O:SYG:BA"), "got {text:?}");
        // Re-parsing the rendered text is a fixed point.
        assert_eq!(parse(&text).unwrap().as_bytes(), sd.as_bytes());
    }

    #[test]
    fn condition_text_round_trips() {
        let artx = parse_condition("@User.Title == \"PM\"").unwrap();
        assert!(artx.starts_with(b"artx"));
        assert!(format_condition(&artx).unwrap().contains("Title"));
    }

    #[test]
    fn reinherit_and_strip_produce_descriptors() {
        let sd = parse("O:SYG:BAD:(A;;FA;;;BA)").unwrap();
        assert!(!reinherit(sd.as_bytes(), sd.as_bytes(), true)
            .unwrap()
            .as_bytes()
            .is_empty());
        assert!(!strip_inherited(sd.as_bytes(), SecInfo::DACL)
            .unwrap()
            .as_bytes()
            .is_empty());
    }

    #[test]
    fn bad_sddl_is_an_error() {
        assert!(parse("not valid sddl").is_err());
    }

    #[test]
    fn a_dacl_only_string_parses_to_an_acl() {
        let acl = parse_acl("D:(A;;GA;;;SY)(A;;GA;;;BA)").expect("a DACL");
        assert_eq!(acl.view().expect("a parseable ACL").len(), 2);
    }

    /// A whole descriptor is accepted; only its DACL comes back.
    #[test]
    fn a_full_descriptor_yields_only_its_dacl() {
        let acl = parse_acl("O:SYG:SYD:(A;;GA;;;SY)").expect("a DACL");
        assert_eq!(acl.view().expect("a parseable ACL").len(), 1);
    }

    /// The case `to_acl` exists to get right. A conditional ACE keeps its
    /// expression in the ACE's application data, so a rebuild that dropped
    /// `app_data` would turn "Engineering may write" into "anyone may write" —
    /// silently, and in the direction that grants more.
    #[test]
    fn a_conditional_ace_keeps_its_condition_through_the_round_trip() {
        let sddl = "D:(XA;;GA;;;WD;(@USER.Department == \"Engineering\"))";
        let acl = parse_acl(sddl).expect("a conditional DACL");
        let view = acl.view().expect("a parseable ACL");
        let ace = view.ace(0).expect("one ACE");

        let condition = ace
            .app_data()
            .expect("the condition must survive the rebuild");
        assert!(
            condition.starts_with(b"artx"),
            "application data must still be the ARTX bytecode, got {condition:?}"
        );
        assert_eq!(
            super::format_condition(condition).expect("a formattable condition"),
            "@User.Department == \"Engineering\""
        );
    }

    /// Every field an ACE carries has to survive, not just the ones a simple
    /// allow-ACE uses.
    #[test]
    fn flags_and_masks_survive_the_round_trip() {
        let acl = parse_acl("D:(A;OICI;GA;;;BA)(D;;GR;;;WD)").expect("a DACL");
        let view = acl.view().expect("a parseable ACL");

        let allow = view.ace(0).expect("the allow ACE");
        assert_eq!(allow.mask(), crate::security::AccessMask::GENERIC_ALL.bits());
        assert!(allow.flags().contains(crate::security::AceFlags::OBJECT_INHERIT));
        assert!(allow.flags().contains(crate::security::AceFlags::CONTAINER_INHERIT));

        let deny = view.ace(1).expect("the deny ACE");
        assert_eq!(deny.mask(), crate::security::AccessMask::GENERIC_READ.bits());
    }

    /// No DACL and an empty DACL mean opposite things — grant everyone
    /// everything, versus grant nobody anything — so an absent one must not be
    /// quietly turned into an empty one.
    #[test]
    fn a_descriptor_with_no_dacl_is_refused_rather_than_read_as_empty() {
        assert!(parse_acl("O:SYG:SY").is_err());
    }

    #[test]
    fn an_empty_dacl_is_an_acl_with_no_entries() {
        let acl = parse_acl("D:").expect("an empty DACL is still a DACL");
        assert_eq!(acl.view().expect("a parseable ACL").len(), 0);
    }
}
