//! An in-house MessagePack codec: a [`Writer`] (encoder), a [`Reader`]
//! (decoder cursor), and a [`validate`] check.
//!
//! KMES event payloads are MessagePack and the kernel only structurally
//! validates them on emit, so userspace owns the encode/decode. This module is
//! that path. Integers are written in their smallest form; `str` values must be
//! valid UTF-8 (use `bin` for arbitrary bytes); a valid payload is exactly one
//! top-level value, and an empty buffer is not valid.
//!
//! The [`Writer`] is sticky-error like the security builders: its setters cannot
//! fail individually; the first error latches and surfaces at
//! [`Writer::to_bytes`] / [`Writer::error`].

use core::ffi::{c_char, c_void};
use core::marker::PhantomData;

use peios_sys as sys;

use crate::error::{Error, Result};
use crate::util::{check, check_len};

/// The default nesting bound for [`validate`], matching the kernel's emit-time
/// limit (the top-level value is depth 1).
pub const DEFAULT_MAX_DEPTH: u32 = sys::KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT;

/// The value kind reported by [`Reader::peek`]. Integers (signed and unsigned,
/// all widths) report as [`Type::Int`]; read them with [`Reader::read_int`] /
/// [`Reader::read_uint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    /// The `nil` value.
    Nil,
    /// A boolean.
    Bool,
    /// An integer (signed or unsigned, any width).
    Int,
    /// A floating-point value.
    Float,
    /// A UTF-8 string.
    Str,
    /// A binary blob.
    Bin,
    /// An array header.
    Array,
    /// A map header.
    Map,
    /// An extension value.
    Ext,
}

impl Type {
    /// Map a raw `enum peios_mp_type` discriminant, or `None` if unrecognized.
    fn from_raw(v: sys::peios_mp_type) -> Option<Type> {
        match v {
            sys::peios_mp_type_PEIOS_MP_NIL => Some(Type::Nil),
            sys::peios_mp_type_PEIOS_MP_BOOL => Some(Type::Bool),
            sys::peios_mp_type_PEIOS_MP_INT => Some(Type::Int),
            sys::peios_mp_type_PEIOS_MP_FLOAT => Some(Type::Float),
            sys::peios_mp_type_PEIOS_MP_STR => Some(Type::Str),
            sys::peios_mp_type_PEIOS_MP_BIN => Some(Type::Bin),
            sys::peios_mp_type_PEIOS_MP_ARRAY => Some(Type::Array),
            sys::peios_mp_type_PEIOS_MP_MAP => Some(Type::Map),
            sys::peios_mp_type_PEIOS_MP_EXT => Some(Type::Ext),
            _ => None,
        }
    }
}

/// A heap-backed MessagePack encoder.
///
/// Infallible chained setters append values to the buffer; the first error
/// latches and surfaces at [`to_bytes`](Self::to_bytes) / [`error`](Self::error).
/// Containers are written header-first: after [`write_array`](Self::write_array) /
/// [`write_map`](Self::write_map) write exactly `count` values (a map needs `count`
/// key/value PAIRS, i.e. `2 * count` values). An under- or over-filled
/// container is reported at [`to_bytes`](Self::to_bytes).
pub struct Writer {
    raw: *mut sys::peios_mp_writer,
}

impl Writer {
    /// Create an empty writer.
    pub fn new() -> Writer {
        // SAFETY: _new returns an owned writer or null on allocation failure.
        let raw = unsafe { sys::peios_mp_writer_new() };
        assert!(!raw.is_null(), "peios_mp_writer_new: out of memory");
        Writer { raw }
    }

    /// Reset to empty, clearing the latched error and reusing the writer.
    pub fn reset(&mut self) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_writer_reset(self.raw) };
        self
    }

    /// Write a `nil`.
    pub fn write_nil(&mut self) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_nil(self.raw) };
        self
    }

    /// Write a boolean.
    pub fn write_bool(&mut self, v: bool) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_bool(self.raw, v) };
        self
    }

    /// Write a signed integer (in its smallest MessagePack form).
    pub fn write_int(&mut self, v: i64) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_int(self.raw, v) };
        self
    }

    /// Write an unsigned integer (in its smallest MessagePack form).
    pub fn write_uint(&mut self, v: u64) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_uint(self.raw, v) };
        self
    }

    /// Write a floating-point value.
    pub fn write_float(&mut self, v: f64) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_float(self.raw, v) };
        self
    }

    /// Write a UTF-8 string.
    pub fn write_str(&mut self, s: &str) -> &mut Self {
        // SAFETY: live writer; (ptr, len) from a live `&str`.
        unsafe { sys::peios_mp_write_str(self.raw, s.as_ptr().cast::<c_char>(), s.len()) };
        self
    }

    /// Write a binary blob.
    pub fn write_bin(&mut self, b: &[u8]) -> &mut Self {
        // SAFETY: live writer; (ptr, len) from a live slice.
        unsafe { sys::peios_mp_write_bin(self.raw, b.as_ptr().cast(), b.len()) };
        self
    }

    /// Write an array header; follow with exactly `count` values.
    pub fn write_array(&mut self, count: u32) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_array(self.raw, count) };
        self
    }

    /// Write a map header; follow with exactly `count` key/value PAIRS.
    pub fn write_map(&mut self, count: u32) -> &mut Self {
        // SAFETY: live writer.
        unsafe { sys::peios_mp_write_map(self.raw, count) };
        self
    }

    /// Write an extension value with signed type id `ext_type`.
    pub fn write_ext(&mut self, ext_type: i8, b: &[u8]) -> &mut Self {
        // SAFETY: live writer; (ptr, len) from a live slice.
        unsafe { sys::peios_mp_write_ext(self.raw, ext_type, b.as_ptr().cast(), b.len()) };
        self
    }

    /// Append pre-encoded MessagePack bytes verbatim (the escape hatch). The
    /// whole buffer is still structurally validated at [`to_bytes`](Self::to_bytes).
    pub fn write_raw(&mut self, b: &[u8]) -> &mut Self {
        // SAFETY: live writer; (ptr, len) from a live slice.
        unsafe { sys::peios_mp_write_raw(self.raw, b.as_ptr().cast(), b.len()) };
        self
    }

    /// The latched error, if any.
    pub fn error(&self) -> Result<()> {
        // SAFETY: live writer.
        let e = unsafe { sys::peios_mp_writer_error(self.raw) };
        if e == 0 {
            Ok(())
        } else {
            Err(Error::from_raw_os_error(e))
        }
    }

    /// Confirm the buffer is exactly one well-formed top-level value and copy it
    /// into owned bytes, or surface the latched error.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out: *const c_void = core::ptr::null();
        // SAFETY: live writer; `out` writable. The returned pointer borrows the
        // writer (valid until the next mutation), so we copy immediately.
        let n = unsafe { sys::peios_mp_writer_bytes(self.raw, &mut out) };
        let len = check_len(n)?;
        if out.is_null() {
            return Err(Error::from_raw_os_error(EINVAL));
        }
        // SAFETY: libpeios returned `len` valid bytes at `out`, valid until the
        // next writer mutation — we copy them out now.
        Ok(unsafe { core::slice::from_raw_parts(out.cast::<u8>(), len) }.to_vec())
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // SAFETY: `raw` came from _new and is dropped exactly once.
        unsafe { sys::peios_mp_writer_free(self.raw) };
    }
}

/// A decode cursor over a borrowed MessagePack buffer.
///
/// Each read consumes one value on success and leaves the cursor untouched on a
/// type mismatch or truncation (an `EINVAL` error). Borrowed `str` / `bin` /
/// `ext` bytes point into the original buffer and live as long as it (`'a`).
pub struct Reader<'a> {
    raw: sys::peios_mp_reader,
    _buf: PhantomData<&'a [u8]>,
}

impl<'a> Reader<'a> {
    /// Initialize a cursor over `buf`.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        let mut raw = sys::peios_mp_reader { _opaque: [0; 4] };
        // SAFETY: `raw` is a writable reader; (ptr, len) from a live slice that
        // outlives the reader by the `'a` bound.
        unsafe { sys::peios_mp_reader_init(&mut raw, buf.as_ptr().cast(), buf.len()) };
        Reader {
            raw,
            _buf: PhantomData,
        }
    }

    /// The number of unconsumed bytes remaining in the buffer.
    pub fn remaining(&self) -> usize {
        // SAFETY: `raw` is an initialized reader.
        unsafe { sys::peios_mp_reader_remaining(&self.raw) }
    }

    /// The [`Type`] of the next value without consuming it, or `None` at
    /// end-of-input or on an invalid lead byte.
    pub fn peek(&self) -> Option<Type> {
        // SAFETY: `raw` is an initialized reader.
        let t = unsafe { sys::peios_mp_peek(&self.raw) };
        if t < 0 {
            None
        } else {
            Type::from_raw(t as sys::peios_mp_type)
        }
    }

    /// Read a `nil`.
    pub fn read_nil(&mut self) -> Result<()> {
        // SAFETY: `raw` is an initialized reader.
        check(unsafe { sys::peios_mp_read_nil(&mut self.raw) })
    }

    /// Read a boolean.
    pub fn read_bool(&mut self) -> Result<bool> {
        let mut out = false;
        // SAFETY: `raw` is an initialized reader; `out` writable.
        check(unsafe { sys::peios_mp_read_bool(&mut self.raw, &mut out) })?;
        Ok(out)
    }

    /// Read an integer as signed.
    pub fn read_int(&mut self) -> Result<i64> {
        let mut out = 0i64;
        // SAFETY: `raw` is an initialized reader; `out` writable.
        check(unsafe { sys::peios_mp_read_int(&mut self.raw, &mut out) })?;
        Ok(out)
    }

    /// Read an integer as unsigned.
    pub fn read_uint(&mut self) -> Result<u64> {
        let mut out = 0u64;
        // SAFETY: `raw` is an initialized reader; `out` writable.
        check(unsafe { sys::peios_mp_read_uint(&mut self.raw, &mut out) })?;
        Ok(out)
    }

    /// Read a floating-point value.
    pub fn read_float(&mut self) -> Result<f64> {
        let mut out = 0.0f64;
        // SAFETY: `raw` is an initialized reader; `out` writable.
        check(unsafe { sys::peios_mp_read_float(&mut self.raw, &mut out) })?;
        Ok(out)
    }

    /// Read a string, borrowing its UTF-8 bytes from the buffer.
    pub fn read_str(&mut self) -> Result<&'a str> {
        let mut out: *const c_char = core::ptr::null();
        // SAFETY: `raw` is an initialized reader; `out` writable.
        let n = unsafe { sys::peios_mp_read_str(&mut self.raw, &mut out) };
        let len = check_len(n)?;
        if out.is_null() {
            return Err(Error::from_raw_os_error(EINVAL));
        }
        // SAFETY: libpeios returned `len` bytes at `out` inside the buffer this
        // reader borrows ('a).
        let bytes = unsafe { core::slice::from_raw_parts(out.cast::<u8>(), len) };
        core::str::from_utf8(bytes).map_err(|_| Error::from_raw_os_error(EINVAL))
    }

    /// Read a binary blob, borrowing its bytes from the buffer.
    pub fn read_bin(&mut self) -> Result<&'a [u8]> {
        let mut out: *const c_void = core::ptr::null();
        // SAFETY: `raw` is an initialized reader; `out` writable.
        let n = unsafe { sys::peios_mp_read_bin(&mut self.raw, &mut out) };
        let len = check_len(n)?;
        if out.is_null() {
            return Err(Error::from_raw_os_error(EINVAL));
        }
        // SAFETY: libpeios returned `len` bytes at `out` inside the buffer this
        // reader borrows ('a).
        Ok(unsafe { core::slice::from_raw_parts(out.cast::<u8>(), len) })
    }

    /// Consume an array header, returning its element count. Read that many
    /// values next.
    pub fn read_array(&mut self) -> Result<usize> {
        // SAFETY: `raw` is an initialized reader.
        check_len(unsafe { sys::peios_mp_read_array(&mut self.raw) })
    }

    /// Consume a map header, returning its key/value PAIR count. Read `2 * count`
    /// values next.
    pub fn read_map(&mut self) -> Result<usize> {
        // SAFETY: `raw` is an initialized reader.
        check_len(unsafe { sys::peios_mp_read_map(&mut self.raw) })
    }

    /// Read an extension value, returning its signed type id and its bytes
    /// borrowed from the buffer.
    pub fn read_ext(&mut self) -> Result<(i8, &'a [u8])> {
        let mut ty = 0i8;
        let mut out: *const c_void = core::ptr::null();
        // SAFETY: `raw` is an initialized reader; out-params writable.
        let n = unsafe { sys::peios_mp_read_ext(&mut self.raw, &mut ty, &mut out) };
        let len = check_len(n)?;
        if out.is_null() {
            return Err(Error::from_raw_os_error(EINVAL));
        }
        // SAFETY: libpeios returned `len` bytes at `out` inside the buffer this
        // reader borrows ('a).
        Ok((ty, unsafe {
            core::slice::from_raw_parts(out.cast::<u8>(), len)
        }))
    }

    /// Skip exactly one complete value (descending into nested containers).
    pub fn skip(&mut self) -> Result<()> {
        // SAFETY: `raw` is an initialized reader.
        check(unsafe { sys::peios_mp_skip(&mut self.raw) })
    }
}

/// Confirm `buf` is exactly one well-formed MessagePack value: UTF-8 strings,
/// nesting bounded by `max_depth` (the top-level value is depth 1), no trailing
/// bytes, non-empty. A success means the kernel's event emit calls will accept
/// the payload at this depth bound. Pass [`DEFAULT_MAX_DEPTH`] for the default
/// emit limit.
pub fn validate(buf: &[u8], max_depth: u32) -> Result<()> {
    // SAFETY: (ptr, len) from a live slice.
    check(unsafe { sys::peios_mp_validate(buf.as_ptr().cast(), buf.len(), max_depth) })
}

const EINVAL: i32 = 22;
