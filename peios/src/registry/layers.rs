//! Layers, as the registry keeps them (LCS TRM §5.3).
//!
//! Each layer is a key under [`LAYERS`] named for it, holding three values:
//!
//! | Value | Type | When missing |
//! |---|---|---|
//! | `Precedence` | `REG_DWORD` | 0 |
//! | `Enabled` | `REG_DWORD`, 0 or 1 | enabled |
//! | `Owner` | `REG_BINARY`, a SID | the SID of whoever created it |
//!
//! Creating the key creates the layer, and deleting it deletes the layer.
//! A value of the wrong type, a `REG_DWORD` that is not four bytes, or an
//! `Enabled` above 1 is malformed: the kernel keeps the layer as it last
//! knew it rather than read it. The base layer, [`BASE`], always exists,
//! at precedence 0 and enabled, whether or not it has a key here; it
//! cannot be changed or deleted.
//!
//! Who may do what is the metadata key's descriptor's to say, except that
//! a precedence above 0 also needs `SeTcbPrivilege` (LCS TRM §5.3.4).

use super::{CreateFlags, Data, Key, KeyAccess, OpenFlags, Transaction, ValueType};
use crate::error::{Error, Result};
use crate::security::{Sid, SidRef};

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;

/// The key that holds a key for each layer.
pub const LAYERS: &str = r"Machine\System\Registry\Layers";

/// The layer a write goes to when it names none.
pub const BASE: &str = "base";

/// One layer, as its metadata key says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// The layer's name, as its key spells it.
    pub name: String,
    /// Where it stands: a higher precedence wins over a lower one.
    pub precedence: u32,
    /// Whether its entries take part in resolution for everyone, and not
    /// only for threads whose tokens name it.
    pub enabled: bool,
    /// Who it says owns it. Informational: it grants nothing.
    pub owner: Option<Sid>,
    /// Whether a value is malformed, so that the kernel goes by what it
    /// last knew of the layer rather than by what is shown here.
    pub malformed: bool,
}

/// Every layer, the base layer included, the highest precedence first and
/// then by name.
pub fn list() -> Result<Vec<Layer>> {
    let names = match Key::open(
        None,
        LAYERS,
        KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ) {
        Ok(layers) => layers
            .subkeys(None)
            .map(|subkey| subkey.map(|subkey| String::from_utf8_lossy(&subkey.name).into_owned()))
            .collect::<Result<Vec<_>>>()?,
        Err(e) if e.raw_os_error() == Some(ENOENT) => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut layers = names
        .iter()
        .map(|name| read(name))
        .collect::<Result<Vec<_>>>()?;
    // The base layer is the kernel's whatever its key says (§5.3.2).
    layers.retain(|layer| !is_base(&layer.name));
    layers.push(Layer {
        name: BASE.into(),
        precedence: 0,
        enabled: true,
        owner: None,
        malformed: false,
    });
    layers.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(layers)
}

/// The layer `name`, as its metadata key says.
pub fn read(name: &str) -> Result<Layer> {
    let key = open(name, KeyAccess::QUERY_VALUE)?;
    let value = |value: &str| match key.query_value(value.as_bytes(), None) {
        Ok(value) => Ok(Some(Data::decode(value.ty, &value.data))),
        Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(None),
        Err(e) => Err(e),
    };
    let mut malformed = false;
    let precedence = match value("Precedence")? {
        Some(Data::Dword(precedence)) => precedence,
        None => 0,
        Some(_) => {
            malformed = true;
            0
        }
    };
    let enabled = match value("Enabled")? {
        Some(Data::Dword(enabled @ (0 | 1))) => enabled == 1,
        None => true,
        Some(_) => {
            malformed = true;
            true
        }
    };
    let owner = match value("Owner")? {
        Some(Data::Binary(bytes)) => match SidRef::from_bytes(&bytes) {
            Some(sid) => Some(Sid::from_ref(sid)),
            None => {
                malformed = true;
                None
            }
        },
        None => None,
        Some(_) => {
            malformed = true;
            None
        }
    };
    Ok(Layer {
        name: name.into(),
        precedence,
        enabled,
        owner,
        malformed,
    })
}

/// Creates the layer `name`, in one transaction so that its values are all
/// there when the kernel first reads them. Its owner is whoever creates
/// it. A precedence above 0 needs `SeTcbPrivilege`.
pub fn create(name: &str, precedence: u32, enabled: bool) -> Result<()> {
    if is_base(name) || name.is_empty() || name.contains(['\\', '/']) {
        return Err(Error::from_raw_os_error(EINVAL));
    }
    let layers = Key::open(None, LAYERS, KeyAccess::CREATE_SUB_KEY, OpenFlags::empty())?;
    let txn = Transaction::begin()?;
    let (key, _) = Key::create(
        Some(&layers),
        name,
        KeyAccess::SET_VALUE,
        CreateFlags::empty(),
        None,
        Some(&txn),
    )?;
    key.set_value(b"Precedence", ValueType::DWORD, &precedence.to_le_bytes())
        .in_txn(&txn)
        .call()?;
    key.set_value(
        b"Enabled",
        ValueType::DWORD,
        &u32::from(enabled).to_le_bytes(),
    )
    .in_txn(&txn)
    .call()?;
    txn.commit()
}

/// Sets the layer's precedence. Above 0 needs `SeTcbPrivilege`.
pub fn set_precedence(name: &str, precedence: u32) -> Result<()> {
    set(
        name,
        "Precedence",
        ValueType::DWORD,
        &precedence.to_le_bytes(),
    )
}

/// Enables or disables the layer.
pub fn set_enabled(name: &str, enabled: bool) -> Result<()> {
    set(
        name,
        "Enabled",
        ValueType::DWORD,
        &u32::from(enabled).to_le_bytes(),
    )
}

/// Says who owns the layer. It grants them nothing.
pub fn set_owner(name: &str, owner: &SidRef) -> Result<()> {
    set(name, "Owner", ValueType::BINARY, owner.as_bytes())
}

/// Deletes the layer, and with it every entry written into it.
pub fn delete(name: &str) -> Result<()> {
    if is_base(name) {
        return Err(Error::from_raw_os_error(EINVAL));
    }
    open(name, KeyAccess::DELETE)?.delete_key(None, None)
}

fn set(name: &str, value: &str, ty: ValueType, data: &[u8]) -> Result<()> {
    if is_base(name) {
        return Err(Error::from_raw_os_error(EINVAL));
    }
    open(name, KeyAccess::SET_VALUE)?
        .set_value(value.as_bytes(), ty, data)
        .call()
}

fn open(name: &str, access: KeyAccess) -> Result<Key> {
    Key::open(
        None,
        &format!("{LAYERS}\\{name}"),
        access,
        OpenFlags::empty(),
    )
}

/// Layer names are compared as the registry compares names, without regard
/// to case.
fn is_base(name: &str) -> bool {
    name.to_lowercase() == BASE
}
