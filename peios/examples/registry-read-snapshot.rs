//! Native qualification: run only in a disposable Peios guest as SYSTEM.
//! PEIOS_DISPOSABLE_REGISTRY_TEST=yes ./registry-read-snapshot
use peios::{
    registry::{
        layers, CreateFlags, Key, KeyAccess, OpenFlags, SecInfo, Transaction, TxnState, ValueType,
    },
    security::sddl,
};
use std::{sync::Arc, thread, time::Duration};

fn open(parent: Option<&Key>, name: &str, txn: Option<&Transaction>) -> peios::Result<Key> {
    Key::open_transacted(parent, name, KeyAccess::READ, OpenFlags::empty(), txn)
}
fn create(parent: &Key, name: &str) -> peios::Result<Key> {
    Key::create(
        Some(parent),
        name,
        KeyAccess::ALL_ACCESS,
        CreateFlags::empty(),
        None,
        None,
    )
    .map(|(key, _)| key)
}
fn set(key: &Key, name: &[u8], n: u32, txn: Option<&Transaction>) -> peios::Result<()> {
    let bytes = n.to_le_bytes();
    let mut write = key.set_value(name, ValueType::DWORD, &bytes);
    if let Some(txn) = txn {
        write.in_txn(txn);
    }
    write.call()
}
fn get(key: &Key, name: &[u8], txn: Option<&Transaction>) -> peios::Result<u32> {
    let value = key.query_value(name, txn)?;
    assert_eq!(value.ty, ValueType::DWORD);
    Ok(u32::from_le_bytes(value.data.try_into().unwrap()))
}
fn snapshot(root: &Key) -> peios::Result<(Transaction, Key)> {
    for _ in 0..1000 {
        let txn = Transaction::begin_read_only()?;
        match open(Some(root), "Child", Some(&txn)) {
            Ok(key) => return Ok((txn, key)),
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    panic!("could not capture an idle publication interval")
}
fn run() -> peios::Result<()> {
    let machine = Key::open(None, "Machine", KeyAccess::ALL_ACCESS, OpenFlags::empty())?;
    let software = create(&machine, "Software")?;
    let name = format!("ReadSnapshotTest-{}", std::process::id());
    let root = create(&software, &name)?;
    let child = Arc::new(create(&root, "Child")?);
    let replace = create(&root, "Replace")?;
    let volatile = Key::create(
        Some(&root),
        "Volatile",
        KeyAccess::ALL_ACCESS,
        CreateFlags::VOLATILE,
        None,
        None,
    )?
    .0;
    set(&volatile, b"A", 1, None)?;
    set(&child, b"A", 1, None)?;
    set(&child, b"B", 1, None)?;
    let txn = Transaction::begin_read_only()?;
    assert_eq!(txn.status()?.state, TxnState::ActiveUnbound);
    set(&child, b"A", 2, None)?;
    let saved = open(Some(&root), "Child", Some(&txn))?;
    assert_eq!(txn.status()?.state, TxnState::ActiveBound);
    assert_eq!(get(&saved, b"A", Some(&txn))?, 2); // first read, not begin
    let before = saved.info_transacted(Some(&txn))?;
    let sd = saved.get_security_transacted(SecInfo::OWNER | SecInfo::DACL, Some(&txn))?;
    set(&child, b"A", 3, None)?;
    set(&child, b"Extra", 9, None)?;
    set(&volatile, b"A", 2, None)?;
    let _new = create(&root, "NewChild")?;
    assert_eq!(get(&saved, b"A", Some(&txn))?, 2);
    assert_eq!(get(&child, b"A", None)?, 3);
    let after = saved.info_transacted(Some(&txn))?;
    assert_eq!(before.value_count, after.value_count);
    assert_eq!(before.hive_generation, after.hive_generation);
    assert_eq!(
        saved
            .values(Some(&txn))
            .collect::<peios::Result<Vec<_>>>()?
            .len(),
        2
    );
    assert_eq!(saved.query_values_batch(Some(&txn))?.len(), 2);
    assert_eq!(get(&volatile, b"A", Some(&txn))?, 1);
    assert_eq!(get(&volatile, b"A", None)?, 2);
    let names = root
        .subkeys(Some(&txn))
        .collect::<peios::Result<Vec<_>>>()?;
    assert!(!names.iter().any(|n| n.name == b"NewChild"));
    assert_eq!(
        set(&child, b"A", 99, Some(&txn))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    assert_eq!(
        Key::open_transacted(
            None,
            "Users",
            KeyAccess::READ,
            OpenFlags::empty(),
            Some(&txn)
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::EXDEV)
    );
    replace.delete_key(None, None)?;
    let replacement = create(&root, "Replace")?;
    assert_eq!(
        open(Some(&root), "Replace", Some(&txn))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    drop(replacement);
    // Descriptor bytes are historical; new-open authority is current.
    let deny = sddl::parse("O:SYG:SYD:(D;;0x1;;;WD)(A;;GA;;;SY)")?;
    child.set_security(SecInfo::DACL, &deny, None)?;
    assert_eq!(
        saved
            .get_security_transacted(SecInfo::OWNER | SecInfo::DACL, Some(&txn))?
            .as_bytes(),
        sd.as_bytes()
    );
    assert_eq!(
        open(Some(&root), "Child", Some(&txn))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EACCES)
    );
    assert_eq!(get(&saved, b"A", Some(&txn))?, 2); // existing handle rights
    child.set_security(SecInfo::DACL, &sd, None)?;
    let generation = child.info()?.hive_generation;
    txn.commit()?;
    assert_eq!(
        child.info()?.hive_generation,
        generation,
        "read-only commit published a write"
    );
    println!(
        "READ SNAPSHOT: first-read binding, values, metadata, enumeration, GUID replacement, current authorization and read-only gates passed"
    );

    let layer = format!("read-snapshot-{}", std::process::id());
    layers::create(&layer, 50, true)?;
    child
        .set_value(b"Layered", ValueType::DWORD, &7u32.to_le_bytes())
        .call()?;
    child
        .set_value(b"Layered", ValueType::DWORD, &8u32.to_le_bytes())
        .layer(&layer)
        .call()?;
    let (txn, view) = snapshot(&root)?;
    assert_eq!(get(&view, b"Layered", Some(&txn))?, 8);
    layers::set_enabled(&layer, false)?;
    assert_eq!(get(&child, b"Layered", None)?, 7);
    assert_eq!(get(&view, b"Layered", Some(&txn))?, 8);
    drop(txn);
    layers::delete(&layer)?;
    println!("READ SNAPSHOT: frozen layer selection passed");

    set(&child, b"A", 0, None)?;
    set(&child, b"B", 0, None)?;
    let writer_key = Arc::clone(&child);
    let writer = thread::spawn(move || -> peios::Result<()> {
        for n in 1..=60 {
            let txn = Transaction::begin()?;
            set(&writer_key, b"A", n, Some(&txn))?;
            set(&writer_key, b"B", n, Some(&txn))?;
            txn.commit()?;
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    });
    for _ in 0..60 {
        let (txn, view) = snapshot(&root)?;
        let a = get(&view, b"A", Some(&txn))?;
        thread::yield_now();
        let b = get(&view, b"B", Some(&txn))?;
        assert_eq!(a, b, "mixed committed configurations");
    }
    writer.join().unwrap()?;
    // Repeated close must release the source's read-only quota.
    for _ in 0..40 {
        drop(snapshot(&root)?);
    }
    println!("READ SNAPSHOT: concurrent atomic updates and repeated close passed");
    let parameters = Key::open(
        None,
        "Machine/System/Registry",
        KeyAccess::ALL_ACCESS,
        OpenFlags::empty(),
    )?;
    let previous = parameters.query_value(b"TransactionTimeoutMs", None).ok();
    set(&parameters, b"TransactionTimeoutMs", 1000, None)?;
    let (expired, _) = snapshot(&root)?;
    match previous {
        Some(previous) => {
            parameters
                .set_value(b"TransactionTimeoutMs", previous.ty, &previous.data)
                .call()?;
        }
        None => {
            parameters.delete_value(b"TransactionTimeoutMs", None, None)?;
        }
    }
    thread::sleep(Duration::from_millis(1250));
    assert_eq!(expired.status()?.state, TxnState::TimedOut);
    assert_eq!(
        get(&child, b"A", Some(&expired))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ETIMEDOUT)
    );
    drop(expired);
    drop(snapshot(&root)?);
    println!("READ SNAPSHOT: lifetime expiry and fresh capture after expiry passed");
    drop(volatile);
    drop(child);
    drop(saved);
    drop(replace);
    root.delete_tree(None, None)?;
    println!("READ SNAPSHOT: native qualification passed");
    Ok(())
}
fn main() {
    assert_eq!(
        std::env::var("PEIOS_DISPOSABLE_REGISTRY_TEST").as_deref(),
        Ok("yes"),
        "requires explicit disposable-guest opt-in"
    );
    run().expect("native Registry snapshot qualification");
}
