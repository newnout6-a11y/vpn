//! Per-user environment variables (`HKCU\Environment`) and the `WM_SETTINGCHANGE` broadcast that
//! makes Explorer, and so every process started afterwards, pick them up.
//!
//! Values keep their registry type: a `REG_EXPAND_SZ` original (`%USERPROFILE%\bin`) must come back
//! as `REG_EXPAND_SZ` after a rollback, and there is no length limit (the old `setx` lost the type
//! and truncated at 1024 characters, spec E1 / AT-09-003). Running processes keep their old
//! environment; the app never changes its own (Rust 2024 `set_var` is unsafe with threads).
use std::time::Duration;

use windows::Win32::Foundation::{
    E_INVALIDARG, ERROR_TIMEOUT, ERROR_UNSUPPORTED_TYPE, GetLastError, LPARAM, WPARAM,
};
use windows::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use windows::core::{Result, w};

use crate::registry::{Access, Hive, Key, Value, View};

/// Time each top-level window gets to handle the broadcast (the old app used 5 s).
pub const BROADCAST_TIMEOUT: Duration = Duration::from_secs(5);

/// A per-user variable with its registry type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvValue {
    /// `REG_SZ`: used literally.
    Plain(String),
    /// `REG_EXPAND_SZ`: `%VAR%` references are expanded by whoever reads it.
    Expandable(String),
}

impl EnvValue {
    /// The stored text (unexpanded).
    pub fn text(&self) -> &str {
        match self {
            EnvValue::Plain(s) | EnvValue::Expandable(s) => s,
        }
    }

    fn to_registry(&self) -> Value {
        match self {
            EnvValue::Plain(s) => Value::Sz(s.clone()),
            EnvValue::Expandable(s) => Value::ExpandSz(s.clone()),
        }
    }
}

/// Where per-user variables live: `HKCU\Environment`, or another HKCU key for tests and tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEnv {
    path: String,
}

impl UserEnv {
    /// The real per-user environment of the account this process runs as.
    pub fn current_user() -> Self {
        Self::under("Environment")
    }

    /// Variables kept under another key of HKCU (tests point this at a throw-away key).
    pub fn under(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    /// Reads a variable; `None` when it is not set. A value of another registry type is an error:
    /// it could not be restored faithfully, so it must not pass for "absent".
    pub fn get(&self, name: &str) -> Result<Option<EnvValue>> {
        check_name(name)?;
        let Some(key) = Key::open(Hive::CurrentUser, &self.path, Access::Read, View::Native)?
        else {
            return Ok(None);
        };
        match key.value(name)? {
            None => Ok(None),
            Some(Value::Sz(s)) => Ok(Some(EnvValue::Plain(s))),
            Some(Value::ExpandSz(s)) => Ok(Some(EnvValue::Expandable(s))),
            Some(_) => Err(ERROR_UNSUPPORTED_TYPE.into()),
        }
    }

    /// Sets a variable with the given type. Call [`broadcast_change`] once after a batch.
    pub fn set(&self, name: &str, value: &EnvValue) -> Result<()> {
        check_name(name)?;
        let (key, _) = Key::create(Hive::CurrentUser, &self.path, View::Native)?;
        key.set(name, &value.to_registry())
    }

    /// Deletes a variable; `false` when it was not set. Call [`broadcast_change`] after a batch.
    pub fn remove(&self, name: &str) -> Result<bool> {
        check_name(name)?;
        match Key::open(
            Hive::CurrentUser,
            &self.path,
            Access::ReadWrite,
            View::Native,
        )? {
            Some(key) => key.delete_value(name),
            None => Ok(false),
        }
    }
}

/// Non-empty and without `=` (it separates name and value in an environment block).
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('=') {
        return Err(E_INVALIDARG.into());
    }
    Ok(())
}

/// Broadcasts `WM_SETTINGCHANGE` with `"Environment"` so Explorer re-reads the variables.
///
/// Blocking: every responsive top-level window may take up to `timeout`, hung ones are skipped
/// (`SMTO_ABORTIFHUNG`). Run it on a blocking thread.
pub fn broadcast_change(timeout: Duration) -> Result<()> {
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    let area = w!("Environment");
    let mut result = 0usize;
    // SAFETY: `area` is a static NUL-terminated string; receivers only read it during the call.
    let sent = unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(area.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            ms,
            Some(&mut result),
        )
    };
    if sent.0 != 0 {
        return Ok(());
    }
    // SAFETY: reads this thread's last-error value, set by the failed call above.
    let err = unsafe { GetLastError() };
    Err(if err.is_ok() { ERROR_TIMEOUT } else { err }.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::TestKey;

    #[test]
    fn variables_round_trip_with_their_type() {
        let t = TestKey::new();
        let env = UserEnv::under(&t.path);
        assert_eq!(
            env.get("HTTP_PROXY").unwrap(),
            None,
            "missing key reads as unset"
        );
        assert!(!env.remove("HTTP_PROXY").unwrap());

        let plain = EnvValue::Plain("socks5h://127.0.0.1:10808".into());
        env.set("HTTP_PROXY", &plain).unwrap();
        assert_eq!(
            env.get("http_proxy").unwrap(),
            Some(plain),
            "names are case-insensitive"
        );

        let expand = EnvValue::Expandable("http://%PROXY_HOST%:8080".into());
        env.set("HTTPS_PROXY", &expand).unwrap();
        assert_eq!(env.get("HTTPS_PROXY").unwrap(), Some(expand.clone()));
        assert_eq!(expand.text(), "http://%PROXY_HOST%:8080");

        assert!(env.remove("HTTP_PROXY").unwrap());
        assert_eq!(env.get("HTTP_PROXY").unwrap(), None);
    }

    /// AT-09-003: no `setx` 1024-character truncation.
    #[test]
    fn long_values_are_not_truncated() {
        let t = TestKey::new();
        let env = UserEnv::under(&t.path);
        for len in [1023, 1024, 1025, 4096] {
            let value = EnvValue::Plain("x".repeat(len));
            env.set("LONG", &value).unwrap();
            assert_eq!(env.get("LONG").unwrap(), Some(value), "length {len}");
        }
    }

    #[test]
    fn foreign_types_and_bad_names_are_errors() {
        let t = TestKey::new();
        let env = UserEnv::under(&t.path);
        let (key, _) = Key::create(Hive::CurrentUser, &t.path, View::Native).unwrap();
        key.set_dword("NUMBER", 1).unwrap();
        assert!(env.get("NUMBER").is_err(), "a DWORD must not read as unset");
        for name in ["", "A=B"] {
            assert!(env.get(name).is_err());
            assert!(env.set(name, &EnvValue::Plain("x".into())).is_err());
            assert!(env.remove(name).is_err());
        }
    }

    /// Harmless: the real environment is unchanged, so receivers re-read the same values.
    #[test]
    fn broadcast_completes() {
        broadcast_change(Duration::from_millis(200)).unwrap();
    }
}
