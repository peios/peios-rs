//! Link + call-convention smoke test for the raw bindings.
//!
//! `peios-sys`'s `layout_tests` already prove the generated structs are
//! ABI-identical to libpeios' at compile time. This test proves the other half:
//! that the bindings actually *resolve and call* the real `libpeios.{so,a}` with
//! the right calling convention, by round-tripping a few entry points that run
//! entirely in userspace (the SID/ACL vocabulary in kacs-core — no syscalls), so
//! the test needs no Peios kernel and runs anywhere libpeios links.
//!
//! It is an integration test (a std crate) on purpose: `peios-sys` itself is
//! `no_std` and carries no test harness.

use core::ffi::c_void;
use peios_sys as sys;

/// `peios_sid_well_known` → `peios_sid_valid` → `peios_sid_format` → `peios_sid_rid`
/// for Local System: build S-1-5-18, confirm it parses, formats, and yields RID 18.
#[test]
fn sid_well_known_round_trips() {
    let mut sid = [0u8; sys::PEIOS_SID_MAX_BYTES as usize];

    // SAFETY: `sid` is PEIOS_SID_MAX_BYTES, which holds any SID; `cap` matches it.
    let len = unsafe {
        sys::peios_sid_well_known(
            sid.as_mut_ptr() as *mut c_void,
            sid.len(),
            sys::peios_wks_PEIOS_WKS_SYSTEM,
        )
    };
    assert!(len > 0, "peios_sid_well_known failed: {len}");
    let len = len as usize;

    // SAFETY: `sid[..len]` is the SID just encoded.
    assert!(unsafe { sys::peios_sid_valid(sid.as_ptr() as *const c_void, len) });

    let mut text = [0i8; 64];
    // SAFETY: valid SID of `len` bytes; `text` is a 64-byte output buffer.
    let n = unsafe {
        sys::peios_sid_format(
            sid.as_ptr() as *const c_void,
            len,
            text.as_mut_ptr(),
            text.len(),
        )
    };
    assert!(n > 0, "peios_sid_format failed: {n}");
    let s = core::str::from_utf8(unsafe {
        core::slice::from_raw_parts(text.as_ptr() as *const u8, n as usize)
    })
    .unwrap();
    assert_eq!(s, "S-1-5-18");

    // SAFETY: valid SID of `len` bytes.
    assert_eq!(
        unsafe { sys::peios_sid_rid(sid.as_ptr() as *const c_void, len) },
        18
    );
}

/// Exercise an opaque-handle lifecycle (new → mutate → bytes → free): a one-ACE
/// allow ACL for Everyone serializes without latching the sticky error.
#[test]
fn acl_builder_lifecycle() {
    let mut everyone = [0u8; sys::PEIOS_SID_MAX_BYTES as usize];
    // SAFETY: output buffer sized for any SID.
    let sid_len = unsafe {
        sys::peios_sid_well_known(
            everyone.as_mut_ptr() as *mut c_void,
            everyone.len(),
            sys::peios_wks_PEIOS_WKS_EVERYONE,
        )
    };
    assert!(sid_len > 0);
    let sid_len = sid_len as usize;

    // SAFETY: _new returns an owned builder or null on OOM.
    let b = unsafe { sys::peios_acl_builder_new() };
    assert!(!b.is_null(), "peios_acl_builder_new returned null");

    // SAFETY: `b` is live; `everyone[..sid_len]` is a valid SID. mask = generic-all.
    unsafe {
        sys::peios_acl_builder_allow(
            b,
            everyone.as_ptr() as *const c_void,
            sid_len,
            sys::KACS_ACCESS_GENERIC_ALL,
            0,
        );
    }

    let mut out_len: usize = 0;
    // SAFETY: `b` is live; `out_len` is a valid out-param.
    let bytes = unsafe { sys::peios_acl_builder_bytes(b, &mut out_len) };
    // SAFETY: `b` is live.
    let err = unsafe { sys::peios_acl_builder_error(b) };
    assert_eq!(err, 0, "builder latched errno {err}");
    assert!(!bytes.is_null() && out_len > 0, "empty serialized ACL");

    // SAFETY: `b` was returned by _new and is not used again.
    unsafe { sys::peios_acl_builder_free(b) };
}
