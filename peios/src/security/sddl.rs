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
}
