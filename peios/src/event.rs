//! KMES events: emit (producer) and drain (consumer).
//!
//! KMES is Peios's sole event path. The kernel stamps each event with trusted
//! metadata — a timestamp, a per-CPU sequence, the CPU id, the identity GUIDs —
//! and writes it into a per-CPU lock-free ring buffer; there is no other way to
//! emit or observe events. Each payload is a single MessagePack value: build it
//! and parse it with the [`crate::msgpack`] module.
//!
//! Producers call [`emit`] / [`emit_batch`] (these need `SeAuditPrivilege`),
//! asking an [`EventPolicy`] first whether the event's type is switched on, so
//! that a type that is off costs no payload (PGSS §6.9). Consumers attach to a CPU's ring and drain it. Two consumer paths are offered:
//! the high-level [`EventReader`], which owns the attach + mmap and hides the
//! lock-free drain (barriers, lapping recovery, lost-event accounting, resize,
//! futex wait — just loop [`next`](EventReader::next) / [`wait`](EventReader::wait));
//! and the low-level [`EventRing`], for callers that drive the read position and
//! the empty / lapping / generation checks themselves.
//!
//! Each [`Event`] owns its header, UTF-8 event type and payload. Its contents
//! remain valid after subsequent reads, ring overwrites and reader closure.

use core::ffi::{c_char, c_void};
use std::os::fd::{AsRawFd, OwnedFd};

use peios_sys as sys;

use crate::error::{Error, Result};
use crate::util::{check, check_fd};

/// The kernel's classification of an event's origin (`origin_class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginClass {
    /// Emitted from userspace (the only class a producer can stamp).
    Userspace,
    /// Emitted by KMES itself.
    Kmes,
    /// Emitted by KACS.
    Kacs,
    /// Emitted by LCS.
    Lcs,
    /// Any other class, by raw discriminant.
    Other(u8),
}

impl OriginClass {
    fn from_raw(v: u8) -> OriginClass {
        match v {
            0 => OriginClass::Userspace,
            1 => OriginClass::Kmes,
            2 => OriginClass::Kacs,
            3 => OriginClass::Lcs,
            other => OriginClass::Other(other),
        }
    }
}

/// One entry of an [`emit_batch`] call: a borrowed event kind and payload.
#[derive(Debug, Clone, Copy)]
pub struct EmitEntry<'a> {
    /// Length-counted UTF-8 event kind (e.g. `"my.app.login"`); not NUL-terminated.
    pub event_type: &'a str,
    /// The payload: one well-formed MessagePack value (see [`crate::msgpack`]).
    pub payload: &'a [u8],
}

/// Emit a single event.
///
/// `event_type` is a length-counted UTF-8 event kind (e.g. `"my.app.login"`,
/// non-empty); `payload` is one well-formed MessagePack value. Requires
/// `SeAuditPrivilege`.
pub fn emit(event_type: &str, payload: &[u8]) -> Result<()> {
    let (type_len, payload_len) = event_lengths(event_type.len(), payload.len())?;
    // SAFETY: (ptr, len) from live slices; `event_type` is passed length-counted
    // (not NUL-terminated), `payload` as raw bytes.
    check(unsafe {
        sys::peios_event_emit(
            event_type.as_ptr().cast::<c_char>(),
            type_len,
            payload.as_ptr().cast::<c_void>(),
            payload_len,
        )
    })
}

/// Emit several events in one call, amortizing the per-call overhead (one
/// timestamp / identity capture / wake covers all).
///
/// Returns the number actually emitted. On success that is `entries.len()`; on
/// failure the error is from the first entry that failed, and the returned count
/// is how many preceded it. Rate-limiting is all-or-nothing (an `EAGAIN` emits
/// none). Requires `SeAuditPrivilege`.
pub fn emit_batch(entries: &[EmitEntry<'_>]) -> Result<usize> {
    let count = u32::try_from(entries.len()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let raw: Vec<sys::peios_event_entry> = entries
        .iter()
        .map(|entry| {
            let (event_type_len, payload_len) =
                event_lengths(entry.event_type.len(), entry.payload.len())?;
            Ok(sys::peios_event_entry {
                event_type: entry.event_type.as_ptr().cast::<c_char>(),
                event_type_len,
                payload: entry.payload.as_ptr().cast::<c_void>(),
                payload_len,
            })
        })
        .collect::<Result<_>>()?;
    let mut emitted = 0u32;
    // SAFETY: `raw` borrows the live entry slices for the call; `emitted` is
    // writable and receives the count regardless of success or failure.
    let r = unsafe { sys::peios_event_emit_batch(raw.as_ptr(), count, &mut emitted) };
    if r == 0 {
        Ok(emitted as usize)
    } else {
        Err(Error::last_os_error())
    }
}

fn event_lengths(type_len: usize, payload_len: usize) -> Result<(u16, u32)> {
    let type_len = u16::try_from(type_len).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    let payload_len = u32::try_from(payload_len).map_err(|_| Error::from_raw_os_error(EINVAL))?;
    Ok((type_len, payload_len))
}

/// An event type's tier (PGSS §6.8): what the emission policy decides when
/// nothing in the registry is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Always on; never consults the policy.
    Essential,
    /// On unless the policy switches it off.
    Standard,
    /// Off unless the policy switches it on.
    Verbose,
    /// Off unless the policy switches it on.
    Debug,
}

impl Tier {
    fn raw(self) -> u32 {
        match self {
            Tier::Essential => sys::PEIOS_EVENT_TIER_ESSENTIAL,
            Tier::Standard => sys::PEIOS_EVENT_TIER_STANDARD,
            Tier::Verbose => sys::PEIOS_EVENT_TIER_VERBOSE,
            Tier::Debug => sys::PEIOS_EVENT_TIER_DEBUG,
        }
    }
}

/// A cached, watched view of the emission policy, `Machine\Generic\Events`
/// (PGSS §6.9).
///
/// Ask it before building a payload; [`emit_with`](Self::emit_with) does both.
/// It keeps each type's setting current with a registry watch, so a committed
/// change applies to the next decision; without a readable registry every
/// decision is by tier. It is safe to share between threads (decisions are
/// serialised), but not across `fork()`: a child opens its own.
pub struct EventPolicy {
    raw: std::sync::Mutex<*mut sys::peios_event_policy>,
}

// SAFETY: the libpeios handle is usable from any thread, one at a time; the
// mutex is what makes it one at a time.
unsafe impl Send for EventPolicy {}
// SAFETY: as above — every access goes through the mutex.
unsafe impl Sync for EventPolicy {}

impl EventPolicy {
    /// Open a view of the policy. Fails only for want of memory: with no
    /// registry, it decides by tier until one appears.
    pub fn open() -> Result<EventPolicy> {
        // SAFETY: a plain call returning an owned handle or NULL/errno.
        let raw = unsafe { sys::peios_event_policy_open() };
        if raw.is_null() {
            Err(Error::last_os_error())
        } else {
            Ok(EventPolicy {
                raw: std::sync::Mutex::new(raw),
            })
        }
    }

    /// Is `event_type` at `tier` switched on? An error is caller error only
    /// (`EINVAL`: a malformed type, or one longer than 65535 bytes); registry
    /// trouble falls back to the tier.
    pub fn enabled(&self, event_type: &str, tier: Tier) -> Result<bool> {
        let len = u16::try_from(event_type.len()).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let raw = self.raw.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: a live handle, used under the lock; (ptr, len) from a live str.
        let r = unsafe {
            sys::peios_event_policy_enabled(
                *raw,
                event_type.as_ptr().cast::<c_char>(),
                len,
                tier.raw(),
            )
        };
        match r {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(Error::last_os_error()),
        }
    }

    /// Emit an event if its type is switched on, building the payload only
    /// then. Returns whether it was emitted.
    pub fn emit_with<P, F>(&self, event_type: &str, tier: Tier, build: F) -> Result<bool>
    where
        P: AsRef<[u8]>,
        F: FnOnce() -> P,
    {
        if !self.enabled(event_type, tier)? {
            return Ok(false);
        }
        emit(event_type, build().as_ref())?;
        Ok(true)
    }
}

impl Drop for EventPolicy {
    fn drop(&mut self) {
        let raw = *self.raw.get_mut().unwrap_or_else(|e| e.into_inner());
        // SAFETY: `raw` came from _open and is closed exactly once.
        unsafe { sys::peios_event_policy_close(raw) };
    }
}

impl std::fmt::Debug for EventPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventPolicy").finish_non_exhaustive()
    }
}

/// A parsed event.
///
/// All fields are owned, so later reads and ring overwrites cannot change them.
/// `payload` is a MessagePack value; decode it with [`crate::msgpack`].
#[derive(Debug, Clone)]
pub struct Event {
    /// Nanoseconds since the Unix epoch (`CLOCK_REALTIME`).
    pub timestamp: u64,
    /// Per-CPU, per-boot monotonic sequence (a gap signals lost events).
    pub sequence: u64,
    /// The id of the CPU that stamped the event.
    pub cpu_id: u16,
    /// The classification of the event's origin.
    pub origin_class: OriginClass,
    /// The effective token's identity GUID.
    pub effective_token_guid: [u8; 16],
    /// The true (real) token's identity GUID.
    pub true_token_guid: [u8; 16],
    /// The originating process's identity GUID.
    pub process_guid: [u8; 16],
    /// The owned UTF-8 event kind.
    pub event_type: String,
    /// The owned MessagePack payload bytes.
    pub payload: Vec<u8>,
}

impl Event {
    /// Copy the fields and data from a validated C event view.
    ///
    /// # Safety
    /// Both pointer ranges must stay readable until this function returns.
    /// For a live mapping, callers must reject the result if the producer
    /// overwrites its slot or changes the generation during the copy.
    unsafe fn from_raw(raw: &sys::peios_event) -> Result<Event> {
        // Read through raw pointers: low-level events still reference memory
        // that the kernel may overwrite. Validation is over the owned copy.
        let type_bytes =
            unsafe { copy_event_bytes(raw.event_type.cast(), raw.event_type_len as usize) };
        let event_type =
            String::from_utf8(type_bytes).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        let payload = unsafe { copy_event_bytes(raw.payload.cast(), raw.payload_len as usize) };
        Ok(Event {
            timestamp: raw.timestamp,
            sequence: raw.sequence,
            cpu_id: raw.cpu_id,
            origin_class: OriginClass::from_raw(raw.origin_class),
            effective_token_guid: raw.effective_token_guid,
            true_token_guid: raw.true_token_guid,
            process_guid: raw.process_guid,
            event_type,
            payload,
        })
    }
}

/// Copy externally mutable bytes without creating references to them.
///
/// # Safety
/// `source` must remain readable for `length` bytes throughout this call.
unsafe fn copy_event_bytes(source: *const u8, length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    for offset in 0..length {
        // SAFETY: the caller guarantees the mapped or reader-owned range.
        bytes.push(unsafe { source.add(offset).read_volatile() });
    }
    bytes
}

/// An all-zero `peios_event` to fill as a `next` / `event_at` out-param.
fn zeroed_event() -> sys::peios_event {
    sys::peios_event {
        timestamp: 0,
        sequence: 0,
        cpu_id: 0,
        origin_class: 0,
        effective_token_guid: [0; 16],
        true_token_guid: [0; 16],
        process_guid: [0; 16],
        event_type: core::ptr::null(),
        event_type_len: 0,
        payload: core::ptr::null(),
        payload_len: 0,
    }
}

/// The high-level event reader: it owns a CPU ring's attach + mmap and hides the
/// lock-free drain. Open it, then loop [`next`](Self::next) /
/// [`wait`](Self::wait).
pub struct EventReader {
    raw: *mut sys::peios_event_reader,
}

impl EventReader {
    /// Attach to CPU `cpu_id` and map its ring, ready to drain. CPU slots can
    /// contain holes; an `EINVAL` does not mark the end of the slot range. Requires
    /// `SeSecurityPrivilege`.
    pub fn open(cpu_id: u32) -> Result<EventReader> {
        // SAFETY: a plain call returning an owned reader or NULL/errno.
        let raw = unsafe { sys::peios_event_reader_open(cpu_id) };
        if raw.is_null() {
            Err(Error::last_os_error())
        } else {
            Ok(EventReader { raw })
        }
    }

    /// Fetch the next event, or `Ok(None)` if none is available right now
    /// (consider [`wait`](Self::wait) then).
    ///
    /// The returned event owns its data and survives later reads or closure.
    // None means temporarily empty, so this cursor is not a fused iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Event>> {
        let mut out = zeroed_event();
        // SAFETY: live reader; `out` is a writable out-param.
        let r = unsafe { sys::peios_event_reader_next(self.raw, &mut out) };
        match r {
            1 => {
                // SAFETY: libpeios 0.5.12 stores a validated snapshot in the
                // reader, unchanged until its next read. Exclusive access here
                // prevents another read while we make the Rust-owned copy.
                Ok(Some(unsafe { Event::from_raw(&out) }?))
            }
            0 => Ok(None),
            _ => Err(Error::last_os_error()),
        }
    }

    /// Block until events are available or `timeout_ms` elapses (negative =
    /// forever). Returns `true` to drain now (call [`next`](Self::next)), `false`
    /// on timeout or interruption.
    pub fn wait(&mut self, timeout_ms: i32) -> Result<bool> {
        // SAFETY: live reader.
        let r = unsafe { sys::peios_event_reader_wait(self.raw, timeout_ms) };
        match r {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(Error::last_os_error()),
        }
    }

    /// The cumulative count of lost events (overwritten or dropped), inferred
    /// from sequence gaps.
    pub fn lost(&self) -> u64 {
        // SAFETY: live reader; a pure read.
        unsafe { sys::peios_event_reader_lost(self.raw) }
    }
}

impl Drop for EventReader {
    fn drop(&mut self) {
        // SAFETY: `raw` came from _open and is closed exactly once.
        unsafe { sys::peios_event_reader_close(self.raw) };
    }
}

/// Attach to CPU `cpu_id`'s ring buffer for the low-level path.
///
/// Returns the ring fd and data-region capacity. CPU slots can contain holes;
/// use the raw `peios_sys::peios_event_slot_count` bound when enumerating. Requires
/// `SeSecurityPrivilege`. Map the returned fd with [`EventRing::map`].
pub fn attach(cpu_id: u32) -> Result<(OwnedFd, u64)> {
    let mut capacity = 0u64;
    // SAFETY: `capacity` is a writable out-param; the call returns a fresh owned
    // fd or -1/errno.
    let fd = check_fd(unsafe { sys::peios_event_attach(cpu_id, &mut capacity) })?;
    Ok((fd, capacity))
}

/// A mapped ring buffer for callers that drive the drain themselves.
///
/// The accessors apply the correct memory barriers; the caller owns the read
/// position (a free-running byte counter — an event lives at
/// `read_pos & (capacity - 1)`) and the empty ([`write_pos`](Self::write_pos)) /
/// lapping ([`tail_pos`](Self::tail_pos)) / [`generation`](Self::generation)
/// checks. The ring owns its mmap and the underlying fd; both are released on
/// drop.
pub struct EventRing {
    raw: sys::peios_event_ring,
    // Keeps the attach fd owned for the life of the mapping. The kernel mapping
    // is unmapped before this is dropped (declaration order: `raw` then `_fd`).
    _fd: OwnedFd,
}

impl EventRing {
    /// Map (and validate) a ring `fd` from [`attach`] with its reported
    /// `capacity`. The `EventRing` takes ownership of the fd.
    pub fn map(fd: OwnedFd, capacity: u64) -> Result<EventRing> {
        let mut raw = sys::peios_event_ring { _opaque: [0; 4] };
        // SAFETY: `fd` is a live, owned ring fd; `raw` is a writable out-ring.
        check(unsafe { sys::peios_event_ring_map(fd.as_raw_fd(), capacity, &mut raw) })?;
        Ok(EventRing { raw, _fd: fd })
    }

    /// The data-region capacity in bytes (a power of two).
    pub fn capacity(&self) -> u64 {
        // SAFETY: `raw` is a mapped ring.
        unsafe { sys::peios_event_ring_capacity(&self.raw) }
    }

    /// The producer's write position (acquire-loaded) — the empty check.
    pub fn write_pos(&self) -> u64 {
        // SAFETY: `raw` is a mapped ring.
        unsafe { sys::peios_event_ring_write_pos(&self.raw) }
    }

    /// The oldest still-readable position (acquire-loaded) — the lapping check.
    pub fn tail_pos(&self) -> u64 {
        // SAFETY: `raw` is a mapped ring.
        unsafe { sys::peios_event_ring_tail_pos(&self.raw) }
    }

    /// The ring generation (bumped on resize).
    pub fn generation(&self) -> u64 {
        // SAFETY: `raw` is a mapped ring.
        unsafe { sys::peios_event_ring_generation(&self.raw) }
    }

    /// Arm (`set == true`) or clear the advisory wake flag before sleeping.
    pub fn set_need_wake(&self, set: bool) {
        // SAFETY: `raw` is a mapped ring.
        unsafe { sys::peios_event_ring_set_need_wake(&self.raw, set as core::ffi::c_int) };
    }

    /// Parse the event at `read_pos`, returning it and its byte size (advance
    /// `read_pos` by that size). The caller must have confirmed `read_pos` is in
    /// `[tail_pos, write_pos)`.
    ///
    /// Returns an owned snapshot. Empty, overwritten or resized slots return
    /// `EAGAIN`; a generation change requires remapping the ring.
    pub fn event_at(&self, read_pos: u64) -> Result<(Event, usize)> {
        let generation = self.generation();
        let write = self.write_pos();
        if read_pos < self.tail_pos() || read_pos >= write {
            return Err(Error::from_raw_os_error(libc::EAGAIN));
        }
        let mut out = zeroed_event();
        // SAFETY: live mapping and writable output; libpeios bounds-checks
        // pointers using a local header copy rather than shared references.
        let size = unsafe { sys::peios_event_ring_event_at(&self.raw, read_pos, &mut out) };
        let event = if size < 0 {
            Err(Error::last_os_error())
        } else if size as u64 > write - read_pos {
            Err(Error::from_raw_os_error(EINVAL))
        } else {
            // SAFETY: the mapping stays live and libpeios validated both ranges.
            // Kernel writes do not invalidate the allocation; copy with raw reads.
            unsafe { Event::from_raw(&out) }
        };
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        if self.tail_pos() > read_pos || self.generation() != generation {
            return Err(Error::from_raw_os_error(libc::EAGAIN));
        }
        let event = event?;
        Ok((event, size as usize))
    }

    /// Futex-wait until events past `read_pos` may be available or `timeout_ms`
    /// elapses (negative = forever). Returns `true` to drain now, `false` on
    /// timeout or interruption.
    pub fn wait(&self, read_pos: u64, timeout_ms: i32) -> Result<bool> {
        // SAFETY: `raw` is a mapped ring.
        let r = unsafe { sys::peios_event_ring_wait(&self.raw, read_pos, timeout_ms) };
        match r {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(Error::last_os_error()),
        }
    }
}

impl Drop for EventRing {
    fn drop(&mut self) {
        // SAFETY: `raw` was mapped by _map and is unmapped exactly once, before
        // the owned fd it was mapped from (`_fd`) is closed.
        unsafe { sys::peios_event_ring_unmap(&mut self.raw) };
    }
}

const EINVAL: i32 = libc::EINVAL;

#[cfg(test)]
mod tests {
    use super::*;

    // Off a Peios kernel the registry cannot be read, so the policy decides by
    // tier: what PGSS §6.9 requires of an emitter with no readable policy.
    #[test]
    fn policy_without_a_registry_decides_by_tier() {
        let p = EventPolicy::open().unwrap();
        assert!(p.enabled("a.b.c", Tier::Essential).unwrap());
        assert!(p.enabled("a.b.c", Tier::Standard).unwrap());
        assert!(!p.enabled("a.b.c", Tier::Verbose).unwrap());
        assert!(!p.enabled("a.b.c", Tier::Debug).unwrap());
    }

    #[test]
    fn policy_rejects_malformed_types() {
        let p = EventPolicy::open().unwrap();
        for bad in ["", "a..b", "a.b\\c.d"] {
            let e = p.enabled(bad, Tier::Standard).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(EINVAL), "{bad:?}");
        }
        let long = "a.".repeat(40000) + "b";
        assert_eq!(
            p.enabled(&long, Tier::Standard).unwrap_err().raw_os_error(),
            Some(EINVAL)
        );
    }

    #[test]
    fn emit_with_builds_nothing_for_an_off_type() {
        let p = EventPolicy::open().unwrap();
        let emitted = p
            .emit_with("a.b.c", Tier::Debug, || -> Vec<u8> {
                panic!("built a payload for a type that is off")
            })
            .unwrap();
        assert!(!emitted);
    }

    #[test]
    fn policy_is_shareable_between_threads() {
        let p = std::sync::Arc::new(EventPolicy::open().unwrap());
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        let t = std::format!("t{i}.x.y");
                        assert!(p.enabled(&t, Tier::Standard).unwrap());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}

#[cfg(test)]
mod length_tests {
    use super::*;

    #[test]
    fn rejects_oversized_names_before_entering_the_kernel() {
        let name = "a".repeat(usize::from(u16::MAX) + 1);
        assert_eq!(
            emit(&name, &[0xc0]).unwrap_err().raw_os_error(),
            Some(EINVAL)
        );
        let entries = [EmitEntry {
            event_type: &name,
            payload: &[0xc0],
        }];
        assert_eq!(
            emit_batch(&entries).unwrap_err().raw_os_error(),
            Some(EINVAL)
        );
    }

    #[test]
    fn length_boundaries_match_the_c_abi() {
        assert_eq!(
            event_lengths(u16::MAX as usize, u32::MAX as usize).unwrap(),
            (u16::MAX, u32::MAX)
        );
        assert!(event_lengths(u16::MAX as usize + 1, 0).is_err());
        if usize::BITS > 32 {
            assert!(event_lengths(1, u32::MAX as usize + 1).is_err());
        }
    }
}
