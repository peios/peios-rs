//! KMES events: emit (producer) and drain (consumer).
//!
//! KMES is Peios's sole event path. The kernel stamps each event with trusted
//! metadata — a timestamp, a per-CPU sequence, the CPU id, the identity GUIDs —
//! and writes it into a per-CPU lock-free ring buffer; there is no other way to
//! emit or observe events. Each payload is a single MessagePack value: build it
//! and parse it with the [`crate::msgpack`] module.
//!
//! Producers call [`emit`] / [`emit_batch`] (these need `SeAuditPrivilege`).
//! Consumers attach to a CPU's ring and drain it. Two consumer paths are offered:
//! the high-level [`EventReader`], which owns the attach + mmap and hides the
//! lock-free drain (barriers, lapping recovery, lost-event accounting, resize,
//! futex wait — just loop [`next`](EventReader::next) / [`wait`](EventReader::wait));
//! and the low-level [`EventRing`], for callers that drive the read position and
//! the empty / lapping / generation checks themselves.
//!
//! An [`Event`]'s header is copied by value, but its `event_type` and `payload`
//! borrow the ring mapping and are valid only until the next read — so the
//! readers hand them out as a *lending* borrow tied to `&mut self` / `&self`
//! rather than via [`Iterator`]. Copy out what you need before continuing.

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
    // SAFETY: (ptr, len) from live slices; `event_type` is passed length-counted
    // (not NUL-terminated), `payload` as raw bytes.
    check(unsafe {
        sys::peios_event_emit(
            event_type.as_ptr().cast::<c_char>(),
            event_type.len() as u16,
            payload.as_ptr().cast::<c_void>(),
            payload.len() as u32,
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
    let raw: Vec<sys::peios_event_entry> = entries
        .iter()
        .map(|e| sys::peios_event_entry {
            event_type: e.event_type.as_ptr().cast::<c_char>(),
            event_type_len: e.event_type.len() as u16,
            payload: e.payload.as_ptr().cast::<c_void>(),
            payload_len: e.payload.len() as u32,
        })
        .collect();
    let mut emitted = 0u32;
    // SAFETY: `raw` borrows the live entry slices for the call; `emitted` is
    // writable and receives the count regardless of success or failure.
    let r = unsafe {
        sys::peios_event_emit_batch(raw.as_ptr(), raw.len() as u32, &mut emitted)
    };
    if r == 0 {
        Ok(emitted as usize)
    } else {
        Err(Error::last_os_error())
    }
}

/// A parsed event.
///
/// The kernel-stamped header is held by value; `event_type` and `payload` borrow
/// the ring mapping (`'a`) and are valid only until the next read — copy out what
/// you need before draining further. `payload` is a MessagePack value (decode it
/// with [`crate::msgpack`]).
#[derive(Debug, Clone, Copy)]
pub struct Event<'a> {
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
    /// The event kind, borrowing the ring mapping.
    pub event_type: &'a str,
    /// The MessagePack payload bytes, borrowing the ring mapping.
    pub payload: &'a [u8],
}

impl<'a> Event<'a> {
    /// Build an [`Event`] from a populated `peios_event` out-struct, tying its
    /// borrowed `event_type` / `payload` to the lifetime `'a`.
    ///
    /// # Safety
    ///
    /// `raw` must be a `peios_event` filled by libpeios whose `event_type` /
    /// `payload` pointers reference a mapping that outlives `'a` and is not
    /// advanced over for the duration of `'a`.
    unsafe fn from_raw(raw: &sys::peios_event) -> Result<Event<'a>> {
        // SAFETY (caller contract): (ptr, len) name `event_type_len` bytes inside
        // the live ring mapping borrowed for 'a.
        let type_bytes = unsafe {
            core::slice::from_raw_parts(
                raw.event_type.cast::<u8>(),
                raw.event_type_len as usize,
            )
        };
        let event_type =
            core::str::from_utf8(type_bytes).map_err(|_| Error::from_raw_os_error(EINVAL))?;
        // SAFETY (caller contract): `payload_len` bytes inside the live mapping.
        let payload = unsafe {
            core::slice::from_raw_parts(
                raw.payload.cast::<u8>(),
                raw.payload_len as usize,
            )
        };
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
    /// Attach to CPU `cpu_id` and map its ring, ready to drain. Discover the CPU
    /// count by counting up from `0` until this fails with `EINVAL`. Requires
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
    /// The returned [`Event`] borrows `&mut self`: its `event_type` / `payload`
    /// point into the reader's ring and stay valid only until the next call, so
    /// this is a lending borrow rather than an [`Iterator`].
    // The lending borrow makes `Iterator` impossible, so `next` is an inherent
    // cursor method by design — the std-trait-confusion lint does not apply.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Event<'_>>> {
        let mut out = zeroed_event();
        // SAFETY: live reader; `out` is a writable out-param.
        let r = unsafe { sys::peios_event_reader_next(self.raw, &mut out) };
        match r {
            1 => {
                // SAFETY: libpeios filled `out` with pointers into this reader's
                // ring mapping, valid until the next call — and the returned
                // Event borrows `&mut self`, which forbids that next call until
                // it is dropped.
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
/// Returns the ring fd and the data-region capacity. Discover the CPU count by
/// counting up from `0` until this fails with `EINVAL`. Requires
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
    /// The returned [`Event`] borrows the ring mapping (`&self`), so it is a
    /// lending borrow: copy out what you need before advancing past the slot.
    pub fn event_at(&self, read_pos: u64) -> Result<(Event<'_>, usize)> {
        let mut out = zeroed_event();
        // SAFETY: `raw` is a mapped ring; `out` is a writable out-param.
        let n = unsafe { sys::peios_event_ring_event_at(&self.raw, read_pos, &mut out) };
        if n < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: libpeios filled `out` with pointers into this ring's mapping;
        // the returned Event borrows `&self`, which keeps the mapping alive.
        let event = unsafe { Event::from_raw(&out) }?;
        Ok((event, n as usize))
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

const EINVAL: i32 = 22;
