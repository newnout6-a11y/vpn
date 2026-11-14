//! Undo a per-app "notifications off" switch that Windows keeps in the registry. Reading the
//! state is [`super::notification_setting`]; the reset stays registry-based because WinRT has
//! no setter for it.
use vpnte_base::{AppError, AppResult};

use crate::registry::{Access, Hive, Key, View};
use crate::win;

/// Ids the old Electron app may have been blocked under (its `app.getName()`), for the reset only.
pub const LEGACY_AUMIDS: &[&str] = &["VPN Tunnel Enforcer", "vpn-tunnel-enforcer"];

const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";

/// What [`reset_os_block`] did, per AUMID.
#[derive(Debug, Default)]
pub struct ResetReport {
    /// AUMIDs whose block was removed.
    pub cleared: Vec<String>,
    /// AUMIDs that could not be checked or cleared (`Permission` or `Internal`).
    pub errors: Vec<(String, AppError)>,
}

/// Removes the per-app block of each AUMID: deletes `Enabled` only when it is exactly 0, so an
/// explicit allow, every other value and the key itself stay. A non-DWORD `Enabled` is an error.
pub fn reset_os_block(aumids: &[&str]) -> ResetReport {
    reset_under(SETTINGS_KEY, aumids)
}

fn reset_under(base: &str, aumids: &[&str]) -> ResetReport {
    let mut report = ResetReport::default();
    for &aumid in aumids {
        match clear_block(&format!(r"{base}\{aumid}")) {
            Ok(true) => report.cleared.push(aumid.to_owned()),
            Ok(false) => {}
            Err(e) => report.errors.push((aumid.to_owned(), e)),
        }
    }
    report
}

fn clear_block(path: &str) -> AppResult<bool> {
    let os = |e: windows::core::Error| AppError::new(win::error_kind(&e)).with_source(e);
    let Some(key) =
        Key::open(Hive::CurrentUser, path, Access::ReadWrite, View::Native).map_err(os)?
    else {
        return Ok(false);
    };
    // A value of another type is an error (`ERROR_UNSUPPORTED_TYPE`), never "not blocked".
    if key.dword("Enabled").map_err(os)? != Some(0) {
        return Ok(false);
    }
    key.delete_value("Enabled").map_err(os)
}

#[cfg(test)]
mod tests {
    use vpnte_base::ErrorKind;

    use super::*;
    use crate::registry::{TestKey, Value};

    /// The throw-away key stands in for the Notifications\Settings key.
    fn set(t: &TestKey, aumid: &str, name: &str, value: Value) {
        let path = format!(r"{}\{aumid}", t.path);
        let (key, _) = Key::create(Hive::CurrentUser, &path, View::Native).unwrap();
        key.set(name, &value).unwrap();
    }

    fn has_value(t: &TestKey, aumid: &str, name: &str) -> bool {
        let path = format!(r"{}\{aumid}", t.path);
        Key::open(Hive::CurrentUser, &path, Access::Read, View::Native)
            .unwrap()
            .is_some_and(|key| key.value(name).unwrap().is_some())
    }

    /// AT-00-004/005: only a blocking `Enabled=0` is cleared; an explicit allow, other values and
    /// the subkey stay.
    #[test]
    fn clears_only_blocked_values() {
        let t = TestKey::new();
        set(&t, "com.vpntunnelenforcer.app", "Enabled", Value::Dword(1));
        set(&t, "vpnte-legacy", "Enabled", Value::Dword(0));
        set(&t, "vpnte-legacy", "ShowInActionCenter", Value::Dword(1));
        let report = reset_under(&t.path, &["com.vpntunnelenforcer.app", "vpnte-legacy"]);
        assert_eq!(report.cleared, ["vpnte-legacy"]);
        assert!(report.errors.is_empty());
        assert!(has_value(&t, "com.vpntunnelenforcer.app", "Enabled"));
        assert!(!has_value(&t, "vpnte-legacy", "Enabled"));
        assert!(has_value(&t, "vpnte-legacy", "ShowInActionCenter"));
    }

    /// AT-00-004: a missing key or value is "nothing to clear", not an error.
    #[test]
    fn missing_values_clear_nothing() {
        let t = TestKey::new();
        set(&t, "no-enabled", "Other", Value::Dword(0));
        let report = reset_under(&t.path, &["no-key", "no-enabled"]);
        assert!(report.cleared.is_empty());
        assert!(report.errors.is_empty());
    }

    /// AT-00-004: a non-DWORD `Enabled` is an internal error for that AUMID only; successful
    /// clears of other AUMIDs are kept beside it.
    #[test]
    fn non_dword_is_internal_and_other_clears_survive() {
        let t = TestKey::new();
        set(&t, "com.vpntunnelenforcer.app", "Enabled", Value::Dword(0));
        set(&t, "vpnte-legacy", "Enabled", Value::Sz("0".into()));
        let report = reset_under(&t.path, &["com.vpntunnelenforcer.app", "vpnte-legacy"]);
        assert_eq!(report.cleared, ["com.vpntunnelenforcer.app"]);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].0, "vpnte-legacy");
        assert_eq!(report.errors[0].1.kind, ErrorKind::Internal);
        assert!(has_value(&t, "vpnte-legacy", "Enabled"));
    }
}
