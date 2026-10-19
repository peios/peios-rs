use peios::event::EventRing;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
#[test]
fn event_snapshot_survives_overwrite_and_close() {
    let path = std::env::temp_dir().join(format!("peios-event-snapshot-{}", std::process::id()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    let capacity = 4096u64;
    file.set_len(8192 + 2 * capacity).unwrap();
    file.write_all_at(b"KMESRING", 0).unwrap();
    file.write_all_at(&1u32.to_le_bytes(), 8).unwrap();
    file.write_all_at(&capacity.to_le_bytes(), 16).unwrap();
    file.write_all_at(&8192u64.to_le_bytes(), 24).unwrap();
    file.write_all_at(&79u64.to_le_bytes(), 64).unwrap();
    let mut event = [0u8; 79];
    event[..4].copy_from_slice(&79u32.to_le_bytes());
    event[4..8].copy_from_slice(&78u32.to_le_bytes());
    event[75..77].copy_from_slice(&1u16.to_le_bytes());
    event[77] = b'a';
    event[78] = 1;
    file.write_all_at(&event, 8192).unwrap();
    let ring = EventRing::map(file.try_clone().unwrap().into(), capacity).unwrap();
    let (borrowed, _) = ring.event_at(0).unwrap();
    assert_eq!(borrowed.event_type, "a");
    let before = borrowed.payload[0];
    file.write_all_at(&[0xff, 2], 8192 + 77).unwrap();
    drop(ring);
    assert_eq!(
        borrowed.payload[0], before,
        "snapshot changed after producer overwrite"
    );
}
