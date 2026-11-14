//! The helper service in Settings > Apps: an uninstall entry under HKLM, written by the install
//! verb with the registration and removed with it (the uninstall verb, the last user's leave).
//! Settings starts `UninstallString` unelevated, so it is `request-uninstall`, which asks Windows
//! to run the `uninstall` verb elevated (one prompt, as `request-install`); tools that run a quiet
//! uninstall elevated get `uninstall` itself. The per-user app keeps its own HKCU entry.
use std::path::Path;

use vpnte_base::i18n::Lang;
use vpnte_winnet::registry::{self, Hive, Key, View};
use windows::Win32::Globalization::GetSystemDefaultUILanguage;

use crate::paths::SERVICE_NAME;

/// The entry's name, in the machine's language (ru or en).
pub const DISPLAY_NAME: &str = "service.entry.displayName";
/// Shown under the name; the per-user app's own entry names no publisher.
pub const PUBLISHER: &str = "VPN Tunnel Enforcer";

/// Where an entry lives: [`Place::machine`] for real; tests pass a throw-away HKCU key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub hive: Hive,
    pub path: String,
}

impl Place {
    /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VpnTunnelEnforcerService`.
    pub fn machine() -> Place {
        Place {
            hive: Hive::LocalMachine,
            path: format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{SERVICE_NAME}"),
        }
    }
}

/// What the entry says about an installed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The installed service exe (in its Program Files folder).
    pub exe: &'a Path,
    /// The service's version.
    pub version: &'a str,
    /// Bytes the install placed (the exe and the engines).
    pub bytes: u64,
    pub lang: Lang,
}

/// Writes (or rewrites, on an upgrade) the entry at `place`.
pub fn write(place: &Place, entry: &Entry) -> windows::core::Result<()> {
    let (key, _) = Key::create(place.hive, &place.path, View::Bits64)?;
    let exe = entry.exe.display();
    let folder = entry.exe.parent().unwrap_or(entry.exe).display();
    key.set_string("DisplayName", &display_name(entry.lang))?;
    key.set_string("DisplayVersion", entry.version)?;
    key.set_string("Publisher", PUBLISHER)?;
    key.set_string("InstallLocation", &folder.to_string())?;
    key.set_string("DisplayIcon", &format!("{exe},0"))?;
    let kib = u32::try_from(entry.bytes.div_ceil(1024)).unwrap_or(u32::MAX);
    key.set_dword("EstimatedSize", kib)?;
    key.set_dword("NoModify", 1)?;
    key.set_dword("NoRepair", 1)?;
    key.set_string("UninstallString", &format!("\"{exe}\" request-uninstall"))?;
    key.set_string("QuietUninstallString", &format!("\"{exe}\" uninstall"))
}

/// Removes the entry at `place`; `false` when there was none.
pub fn remove(place: &Place) -> windows::core::Result<bool> {
    registry::delete_key(place.hive, &place.path, View::Bits64)
}

/// Whether an entry at `place` names `version` (`false`: none, or another version).
pub fn names(place: &Place, version: &str) -> bool {
    let key = Key::open(
        place.hive,
        &place.path,
        registry::Access::Read,
        View::Bits64,
    );
    let listed = key
        .ok()
        .flatten()
        .and_then(|key| key.string("DisplayVersion").ok());
    listed.flatten().is_some_and(|listed| listed == version)
}

/// The machine's display language: Russian -> `ru`, anything else -> `en` (the entry is for every
/// account of the PC, so not the installing administrator's own language).
pub fn system_lang() -> Lang {
    // SAFETY: no arguments and no preconditions.
    let id = unsafe { GetSystemDefaultUILanguage() };
    // PRIMARYLANGID(id) == LANG_RUSSIAN
    if id & 0x3ff == 0x19 {
        Lang::Ru
    } else {
        Lang::En
    }
}

/// The name in `lang`, read from this crate's own fragment: the verbs' processes register no
/// locale catalog (a missing text reads as its key, as everywhere).
fn display_name(lang: Lang) -> String {
    let (ru, en) = crate::LOCALES[0];
    let fragment = match lang {
        Lang::Ru => ru,
        Lang::En => en,
    };
    let parsed = serde_json::from_str::<serde_json::Value>(fragment).ok();
    let name = parsed.as_ref().and_then(|value| {
        let mut value = value;
        for part in DISPLAY_NAME.split('.') {
            value = value.get(part)?;
        }
        value.as_str().map(str::to_owned)
    });
    name.unwrap_or_else(|| DISPLAY_NAME.to_owned())
}

#[cfg(test)]
mod tests;
