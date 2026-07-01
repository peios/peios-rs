//! End-to-end smoke test for the safe `peios` surface.
//!
//! Exercises the userspace-only vocabulary (SIDs, ACL/SD builders, the MessagePack
//! codec) — no Peios kernel required — proving the safe wrappers resolve, call,
//! and round-trip the real `libpeios`.

use peios::msgpack::{self, Reader, Writer};
use peios::security::{
    AccessMask, Acl, AclBuilder, IntegrityLevel, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};

#[test]
fn sid_round_trips() {
    let system = Sid::well_known(WellKnown::System);
    assert_eq!(system.to_string(), "S-1-5-18");
    assert_eq!(system.rid(), 18);

    // Owned <-> borrowed and exact-byte equality.
    let parsed: Sid = "S-1-5-18".parse().expect("parse SDDL");
    assert_eq!(parsed, system);

    let il = Sid::integrity(IntegrityLevel::HIGH);
    assert_eq!(il.to_string(), "S-1-16-12288");
}

#[test]
fn acl_and_sd_builders_round_trip() {
    let everyone = Sid::well_known(WellKnown::Everyone);
    let admins = Sid::well_known(WellKnown::Administrators);

    let mut b = AclBuilder::new();
    let acl: Acl = b
        .allow(
            &everyone,
            AccessMask::GENERIC_READ.bits(),
            Default::default(),
        )
        .allow(&admins, AccessMask::GENERIC_ALL.bits(), Default::default())
        .build()
        .expect("serialize ACL");

    // The ACL parses back and yields both ACEs in order.
    let view = acl.view().expect("parse ACL");
    assert_eq!(view.len(), 2);
    let first = view.ace(0).expect("ace 0");
    assert_eq!(first.sid().expect("ace sid"), &*everyone);

    // Embed it in a security descriptor with an owner, then read it back.
    let mut sb = SdBuilder::new();
    let sd: SecurityDescriptor = sb
        .owner(&admins)
        .group(&everyone)
        .dacl(&acl)
        .build()
        .expect("serialize SD");

    let sv = sd.view().expect("parse SD");
    assert_eq!(sv.owner().expect("owner"), &*admins);
    assert_eq!(sv.dacl().expect("dacl").len(), 2);
}

#[test]
fn msgpack_writer_reader_round_trip() {
    let mut w = Writer::new();
    let bytes = w
        .write_array(3)
        .write_uint(42)
        .write_str("hello")
        .write_bool(true)
        .to_bytes()
        .expect("encode");

    // The validator agrees the payload is well-formed at the default depth.
    msgpack::validate(&bytes, msgpack::DEFAULT_MAX_DEPTH).expect("valid payload");

    let mut r = Reader::new(&bytes);
    assert_eq!(r.read_array().expect("array header"), 3);
    assert_eq!(r.read_uint().expect("uint"), 42);
    assert_eq!(r.read_str().expect("str"), "hello");
    assert!(r.read_bool().expect("bool"));
}
