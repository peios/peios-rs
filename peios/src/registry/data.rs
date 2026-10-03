//! Value data, decoded by its type.
//!
//! The kernel keeps value data as opaque bytes beside a type tag, and does not
//! check that the bytes fit the tag. Peios encodes strings as UTF-8 throughout:
//!
//! | Type | Bytes |
//! |---|---|
//! | `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK` | UTF-8, then one NUL |
//! | `REG_MULTI_SZ` | each string in UTF-8 and a NUL, then a final NUL |
//! | `REG_DWORD` | a `u32`, little-endian |
//! | `REG_DWORD_BIG_ENDIAN` | a `u32`, big-endian |
//! | `REG_QWORD` | a `u64`, little-endian |
//! | `REG_BINARY` | the bytes themselves |
//! | `REG_NONE` | nothing |
//!
//! [`Data::decode`] forgives a missing or doubled terminating NUL, but nothing
//! that would lose information: a string that is not UTF-8, or a number of the
//! wrong length, stays [`Data::Raw`]. [`Data::encode`] writes the forms above.

use super::ValueType;

/// A value's data, decoded by its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_NONE` with no bytes.
    None,
    /// `REG_SZ`.
    Sz(String),
    /// `REG_EXPAND_SZ`: a string whose `%VAR%` references are left unexpanded.
    ExpandSz(String),
    /// `REG_LINK`: a link's target path.
    Link(String),
    /// `REG_MULTI_SZ`. Empty strings are not kept: a NUL ends each string, so
    /// two in a row end the list.
    MultiSz(Vec<String>),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_DWORD_BIG_ENDIAN`.
    DwordBigEndian(u32),
    /// `REG_QWORD`.
    Qword(u64),
    /// `REG_BINARY`.
    Binary(Vec<u8>),
    /// Bytes that do not decode as their type says, or of a type with no
    /// decoding here (the resource lists, `REG_TOMBSTONE`, an unknown tag).
    Raw(ValueType, Vec<u8>),
}

impl Data {
    /// Decodes `bytes` stored as `ty`.
    pub fn decode(ty: ValueType, bytes: &[u8]) -> Data {
        let raw = || Data::Raw(ty, bytes.to_vec());
        match ty {
            ValueType::NONE if bytes.is_empty() => Data::None,
            ValueType::SZ => string(bytes).map_or_else(raw, Data::Sz),
            ValueType::EXPAND_SZ => string(bytes).map_or_else(raw, Data::ExpandSz),
            ValueType::LINK => string(bytes).map_or_else(raw, Data::Link),
            ValueType::MULTI_SZ => strings(bytes).map_or_else(raw, Data::MultiSz),
            ValueType::DWORD => bytes
                .try_into()
                .map_or_else(|_| raw(), |b| Data::Dword(u32::from_le_bytes(b))),
            ValueType::DWORD_BIG_ENDIAN => bytes
                .try_into()
                .map_or_else(|_| raw(), |b| Data::DwordBigEndian(u32::from_be_bytes(b))),
            ValueType::QWORD => bytes
                .try_into()
                .map_or_else(|_| raw(), |b| Data::Qword(u64::from_le_bytes(b))),
            ValueType::BINARY => Data::Binary(bytes.to_vec()),
            _ => raw(),
        }
    }

    /// The type this data is stored as.
    pub fn ty(&self) -> ValueType {
        match self {
            Data::None => ValueType::NONE,
            Data::Sz(_) => ValueType::SZ,
            Data::ExpandSz(_) => ValueType::EXPAND_SZ,
            Data::Link(_) => ValueType::LINK,
            Data::MultiSz(_) => ValueType::MULTI_SZ,
            Data::Dword(_) => ValueType::DWORD,
            Data::DwordBigEndian(_) => ValueType::DWORD_BIG_ENDIAN,
            Data::Qword(_) => ValueType::QWORD,
            Data::Binary(_) => ValueType::BINARY,
            Data::Raw(ty, _) => *ty,
        }
    }

    /// The bytes to store, as the table in the module's documentation says.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Data::None => Vec::new(),
            Data::Sz(s) | Data::ExpandSz(s) | Data::Link(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                bytes
            }
            Data::MultiSz(list) => {
                let mut bytes = Vec::new();
                for s in list {
                    bytes.extend_from_slice(s.as_bytes());
                    bytes.push(0);
                }
                bytes.push(0);
                bytes
            }
            Data::Dword(n) => n.to_le_bytes().to_vec(),
            Data::DwordBigEndian(n) => n.to_be_bytes().to_vec(),
            Data::Qword(n) => n.to_le_bytes().to_vec(),
            Data::Binary(bytes) | Data::Raw(_, bytes) => bytes.clone(),
        }
    }
}

/// A string's bytes without their terminating NULs, if they are UTF-8 with no
/// NUL inside.
fn string(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    let text = core::str::from_utf8(&bytes[..end]).ok()?;
    (!text.contains('\0')).then(|| text.to_owned())
}

/// A list's strings, if every one is UTF-8.
fn strings(bytes: &[u8]) -> Option<Vec<String>> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| core::str::from_utf8(s).ok().map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Data, ValueType};

    #[test]
    fn each_type_round_trips() {
        for data in [
            Data::None,
            Data::Sz("dark".into()),
            Data::ExpandSz("%HOME%/x".into()),
            Data::Link(r"Machine\System".into()),
            Data::MultiSz(vec!["alpha".into(), "beta".into()]),
            Data::MultiSz(Vec::new()),
            Data::Dword(4096),
            Data::DwordBigEndian(0x0102_0304),
            Data::Qword(9_000_000_000),
            Data::Binary(vec![0xde, 0xad]),
            Data::Raw(ValueType::TOMBSTONE, Vec::new()),
        ] {
            assert_eq!(Data::decode(data.ty(), &data.encode()), data);
        }
    }

    #[test]
    fn strings_are_utf8_with_one_nul() {
        assert_eq!(Data::Sz("hi".into()).encode(), b"hi\0");
        assert_eq!(
            Data::MultiSz(vec!["a".into(), "b".into()]).encode(),
            b"a\0b\0\0"
        );
        assert_eq!(Data::DwordBigEndian(1).encode(), [0, 0, 0, 1]);
    }

    #[test]
    fn missing_or_extra_terminators_are_forgiven() {
        assert_eq!(Data::decode(ValueType::SZ, b"hi"), Data::Sz("hi".into()));
        assert_eq!(
            Data::decode(ValueType::SZ, b"hi\0\0"),
            Data::Sz("hi".into())
        );
        assert_eq!(Data::decode(ValueType::SZ, b""), Data::Sz(String::new()));
        assert_eq!(
            Data::decode(ValueType::MULTI_SZ, b"a\0b"),
            Data::MultiSz(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn what_would_lose_bytes_stays_raw() {
        let raw = |ty: ValueType, bytes: &[u8]| Data::Raw(ty, bytes.to_vec());
        assert_eq!(
            Data::decode(ValueType::SZ, b"\xff\0"),
            raw(ValueType::SZ, b"\xff\0")
        );
        assert_eq!(
            Data::decode(ValueType::SZ, b"a\0b\0"),
            raw(ValueType::SZ, b"a\0b\0")
        );
        assert_eq!(
            Data::decode(ValueType::MULTI_SZ, b"a\0\xfe\0\0"),
            raw(ValueType::MULTI_SZ, b"a\0\xfe\0\0")
        );
        assert_eq!(
            Data::decode(ValueType::DWORD, &[1, 2, 3]),
            raw(ValueType::DWORD, &[1, 2, 3])
        );
        assert_eq!(
            Data::decode(ValueType::QWORD, &[0; 4]),
            raw(ValueType::QWORD, &[0; 4])
        );
        assert_eq!(
            Data::decode(ValueType::NONE, &[7]),
            raw(ValueType::NONE, &[7])
        );
        assert_eq!(
            Data::decode(ValueType(0x99), &[7]),
            raw(ValueType(0x99), &[7])
        );
    }
}
