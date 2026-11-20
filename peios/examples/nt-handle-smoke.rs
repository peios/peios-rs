//! Runtime smoke test of the NT handle API (PEI-1745): sharing and the open
//! failure, query, special attributes, locks, rename through a handle,
//! delete-pending and leases. Run it as SYSTEM on a Peios kernel, in a
//! directory on a managed mount; it prints PASS or FAIL per check and a
//! summary. For a static binary to copy into a VM:
//!
//! ```text
//! RUSTFLAGS="-C target-feature=+crt-static" cargo build -p peios --features static \
//!     --example nt-handle-smoke --target x86_64-unknown-linux-gnu
//! ```
//!
//! Usage: `nt-handle-smoke [DIRECTORY]` (default `/srv/rs`).
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use peios::file::{
    self, DeleteDisposition, Disposition, FileAccess, LeaseKey, LeaseManager, LeaseState, LockKind,
    OpenFailure, OpenOptions, RenameFlags, ShareAccess, SpecialAttributes,
};

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "/srv/rs".into()));
    let _ = std::fs::create_dir_all(&dir);
    let (a, b, c) = (dir.join("a"), dir.join("b"), dir.join("c"));
    let _ = std::fs::remove_file(&b);
    std::fs::write(&a, b"hello").unwrap();
    let (mut checks, mut failures) = (0, 0);
    let mut check = |ok: bool, what: &str| {
        checks += 1;
        if !ok {
            failures += 1;
        }
        println!("{} {what}", if ok { "PASS" } else { "FAIL" });
    };

    let f = OpenOptions::new()
        .desired_access(
            FileAccess::READ_DATA
                | FileAccess::DELETE
                | FileAccess::READ_ATTRIBUTES
                | FileAccess::WRITE_ATTRIBUTES,
        )
        .disposition(Disposition::Open)
        .share_access(ShareAccess::READ)
        .open(None, &a)
        .expect("open");
    let info = f.query().expect("query");
    check(
        info.share_access == ShareAccess::READ && info.granted_access.contains(FileAccess::DELETE),
        "query",
    );

    let e = OpenOptions::new()
        .desired_access(FileAccess::WRITE_DATA)
        .disposition(Disposition::Open)
        .open(None, &a)
        .unwrap_err();
    check(
        e.open_failure() == Some(OpenFailure::SharingViolation),
        &format!("sharing violation reported ({e})"),
    );

    check(
        f.special_attributes().unwrap() == SpecialAttributes::default(),
        "no special attributes",
    );
    let at = UNIX_EPOCH + Duration::new(1_000_000_000, 5);
    f.set_created_at(Some(at)).unwrap();
    file::set_read_only(None, &a, true, 0).unwrap();
    let sa = file::special_attributes(None, &a, 0).unwrap();
    check(
        sa == SpecialAttributes {
            read_only: true,
            created_at: Some(at),
        },
        "read-only and Created At",
    );
    check(
        f.creation_time().unwrap() == at,
        "creation time is Created At",
    );
    // Copy both to another file exactly, then clear.
    std::fs::write(&c, b"copy").unwrap();
    file::set_special_attributes(None, &c, &sa, 0).unwrap();
    check(
        file::special_attributes(None, &c, 0).unwrap() == sa,
        "copied special attributes",
    );
    file::set_special_attributes(None, &c, &SpecialAttributes::default(), 0).unwrap();
    check(
        file::special_attributes(None, &c, 0).unwrap() == SpecialAttributes::default(),
        "cleared on the copy",
    );
    f.set_read_only(false).unwrap();

    f.lock(LockKind::Exclusive, 0, 4, true, 0).unwrap();
    f.unlock(0, 4).unwrap();
    check(f.unlock(0, 4).is_err(), "unlock twice fails");

    f.rename(None, Path::new(&b), RenameFlags::empty()).unwrap();
    check(b.exists() && !a.exists(), "rename through the handle");
    f.set_delete_disposition(DeleteDisposition::DELETE).unwrap();
    check(f.query().unwrap().delete_pending, "delete-pending");
    drop(f);
    check(!b.exists(), "last close removes it");

    let mgr = LeaseManager::new(Some(Duration::from_secs(2)), true).unwrap();
    let key = LeaseKey([3; 16]);
    let g = OpenOptions::new()
        .desired_access(FileAccess::READ_DATA)
        .disposition(Disposition::Open)
        .lease_key(&mgr, key)
        .open(None, &c)
        .unwrap();
    let got = g
        .request_lease(&mgr, key, LeaseState::READ | LeaseState::HANDLE)
        .unwrap();
    check(
        got == LeaseState::READ | LeaseState::HANDLE,
        "lease granted",
    );
    check(mgr.read_breaks(4).is_err(), "no break pending");
    drop(g);
    let _ = std::fs::remove_file(&c);

    println!("RSSMOKE {}/{} passed", checks - failures, checks);
}
