//! The `RunOnce` value of the logon restore: while a proxy-mode session holds journalled tweaks,
//! Windows runs `"<exe>" --restore-proxy` once at the user's next sign-in (it deletes the value
//! before it starts the command). Per user, no admin.
use std::path::Path;

use vpnte_automation::tweaks::RollbackReport;
use vpnte_core::paths::ENV_DATA_DIR;
use vpnte_winnet::registry::{Access, Hive, Key, View};

/// Under HKCU: Windows runs each value of it once, at the next sign-in.
pub const RUN_ONCE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
/// Our value under [`RUN_ONCE_KEY`].
pub const VALUE: &str = "VPN Tunnel Enforcer proxy restore";
/// Windows runs a `Run` / `RunOnce` command line of at most this many characters.
const MAX_COMMAND: usize = 260;

/// The value and where it lives (tests: a throw-away key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonValue {
    key: String,
    command: String,
}

impl LogonValue {
    /// The real value for this exe. `None` on an overridden data dir (`VPNTE_DATA_DIR`: tests,
    /// portable runs): Windows starts the value without this process's environment, so it
    /// would restore the default data dir's journal, not this one.
    pub fn current() -> Option<Self> {
        if std::env::var_os(ENV_DATA_DIR).is_some_and(|v| !v.is_empty()) {
            return None;
        }
        Self::under(RUN_ONCE_KEY, &std::env::current_exe().ok()?)
    }

    /// The value under the HKCU `key` for `exe` (`None`: the path is not valid Unicode, or the
    /// command would be longer than Windows runs).
    pub fn under(key: &str, exe: &Path) -> Option<Self> {
        let command = format!("\"{}\" {}", exe.to_str()?, super::FLAG);
        (command.encode_utf16().count() <= MAX_COMMAND).then(|| Self {
            key: key.to_owned(),
            command,
        })
    }

    /// Writes the value unless it is there already. Blocking (registry).
    pub fn set(&self) -> windows::core::Result<()> {
        let (key, _) = Key::create(Hive::CurrentUser, &self.key, View::Native)?;
        // Every apply of a session arms it again; Windows asks programs not to keep rewriting
        // `RunOnce` entries.
        if key.string(VALUE).ok().flatten().as_deref() == Some(self.command.as_str()) {
            return Ok(());
        }
        key.set_string(VALUE, &self.command)
    }

    /// Removes the value; an absent one is fine (`false`). Blocking.
    pub fn clear(&self) -> windows::core::Result<bool> {
        match Key::open(
            Hive::CurrentUser,
            &self.key,
            Access::ReadWrite,
            View::Native,
        )? {
            Some(key) => key.delete_value(VALUE),
            None => Ok(false),
        }
    }

    /// Follows a rollback of the session: removed once nothing is journalled any more, kept
    /// (written again) while values wait for a retry. A failure is only logged: the next
    /// start's recovery still rolls back.
    pub fn follow(&self, report: &RollbackReport) {
        let result = if report.is_complete() {
            self.clear().map(drop)
        } else {
            self.set()
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, complete = report.is_complete(), "logon restore value not updated");
        }
    }
}
