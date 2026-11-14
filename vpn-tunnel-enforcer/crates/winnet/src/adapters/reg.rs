//! Registry reads (HKLM, 64-bit view) for adapter facts IP Helper does not expose. Read-only.
use std::collections::HashMap;

use windows::core::GUID;

use super::ffi::parse_guid;
use crate::registry::{Access, Hive, Key, View};

/// Network adapter device class (GUID_DEVCLASS_NET): one `NNNN` subkey per installed adapter.
const NET_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
/// One `{guid}\Connection\Name` per adapter Windows knows, including disabled and hidden ones.
const NET_CONNECTIONS: &str =
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
const TCPIP_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

/// NDIS class-key facts of one adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ClassInfo {
    /// `Characteristics` (NCF_* flags); an absent value reads as 0.
    pub characteristics: u32,
    /// `ComponentId`, lowercase (`wintun`, `tap0901`, `wireguard`, `pci\ven_…`).
    pub component_id: Option<String>,
}

/// `None` when the key does not exist.
fn open(path: &str) -> windows::core::Result<Option<Key>> {
    Key::open(Hive::LocalMachine, path, Access::Read, View::Bits64)
}

/// Class-key facts by adapter GUID (`NetCfgInstanceId`). Subkeys that cannot be read are skipped:
/// an adapter without a readable class key counts as "not hidden, driver unknown".
pub(super) fn class_keys() -> windows::core::Result<HashMap<GUID, ClassInfo>> {
    let Some(root) = open(NET_CLASS)? else {
        return Ok(HashMap::new());
    };
    let mut out = HashMap::new();
    for name in root.subkey_names()? {
        // Only the `NNNN` instance keys; `Properties` is not readable without elevation.
        if name.len() != 4 || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(Some(key)) = root.open_subkey(&name, Access::Read) else {
            continue;
        };
        let Ok(Some(guid)) = key
            .string("NetCfgInstanceId")
            .map(|s| s.as_deref().and_then(parse_guid))
        else {
            continue;
        };
        let Ok(characteristics) = key.dword("Characteristics") else {
            continue;
        };
        let component_id = key
            .string("ComponentId")
            .ok()
            .flatten()
            .map(|s| s.to_ascii_lowercase());
        out.insert(
            guid,
            ClassInfo {
                characteristics: characteristics.unwrap_or(0),
                component_id,
            },
        );
    }
    Ok(out)
}

/// The statically configured IPv4 DNS servers of an adapter (`NameServer`), raw; `None` when the
/// value or the interface key is absent (DHCP).
pub(super) fn name_server(guid: &GUID) -> windows::core::Result<Option<String>> {
    match open(&format!(r"{TCPIP_INTERFACES}\{{{guid:?}}}"))? {
        Some(key) => key.string("NameServer"),
        None => Ok(None),
    }
}

/// Connection names of every adapter Windows knows (`…\Network\{class}\*\Connection\Name`),
/// including disabled, hidden and currently absent ones.
pub(super) fn connection_names() -> windows::core::Result<Vec<String>> {
    let Some(root) = open(NET_CONNECTIONS)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for sub in root.subkey_names()? {
        // `Descriptions` and similar keys have no `Connection` subkey; unreadable keys are skipped.
        let connection = root.open_subkey(&format!(r"{sub}\Connection"), Access::Read);
        if let Ok(Some(key)) = connection
            && let Ok(Some(name)) = key.string("Name")
        {
            out.push(name);
        }
    }
    Ok(out)
}
