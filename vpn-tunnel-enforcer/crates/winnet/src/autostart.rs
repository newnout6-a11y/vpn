//! Start at logon through the per-user `Run` value (`HKCU\Software\Microsoft\Windows\
//! CurrentVersion\Run`, data `"<exe>" --autostart`), which needs no administrator rights: the app
//! runs unelevated (`asInvoker`), so the elevated logon task of 1.x is no longer needed, and
//! [`sync`] removes it where it may. Task Manager's "Startup apps" switch lives in
//! `…\Explorer\StartupApproved\Run`: an entry the user switched off there is reported as
//! [`AutostartState::DisabledByUser`] and never switched back on.
//!
//! The Task Scheduler readers ([`read_task`], [`delete_task`], [`delete_task_folder`], over COM
//! `ITaskService`, no `schtasks`) stay for the 1.x task and the legacy cleanup.
use std::path::{Path, PathBuf};

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{E_ACCESSDENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ITaskFolder, ITaskService, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface, Result};

use crate::registry::{Access, Hive, Key, Value, View};
use crate::win::{self, Apartment, Com};

/// The per-user `Run` key (under HKCU).
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Task Manager's on / off switches for the entries of [`RUN_KEY`] (under HKCU).
pub const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// Name of our value under [`RUN_KEY`].
pub const RUN_VALUE: &str = "VPN Tunnel Enforcer";
/// Name of the 1.x logon task in the Task Scheduler root folder ([`sync`] deletes it).
pub const TASK_NAME: &str = "VPN Tunnel Enforcer";
/// Command-line flag of the autostart entry, so the app can tell a logon start from a manual one.
pub const AUTOSTART_ARG: &str = "--autostart";

/// What the OS has registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutostartState {
    Absent,
    /// `matches_exe`: the value runs this exe with [`AUTOSTART_ARG`]; `false` for a stale one,
    /// e.g. another path (a moved portable copy) or a value without the flag.
    Present {
        matches_exe: bool,
    },
    /// The value exists but the user switched it off in Task Manager: Windows does not run it,
    /// and the app never switches it back on (it may still re-point a stale one).
    DisabledByUser {
        matches_exe: bool,
    },
}

impl AutostartState {
    /// For the settings page while the entry is switched off in Task Manager.
    pub fn hint(self) -> Option<Msg> {
        matches!(self, AutostartState::DisabledByUser { .. })
            .then(|| Msg::new("winnet.autostart.disabledByUser"))
    }
}

/// Writes (or replaces) the `Run` value for `exe`, or deletes it; deleting an absent value
/// succeeds. Needs no elevation.
pub fn set(enabled: bool, exe: &Path) -> Result<()> {
    REAL.set(enabled, exe)
}

/// Reads the value back. `Err` means "unknown" (for example access denied), never "absent".
pub fn state(exe: &Path) -> Result<AutostartState> {
    REAL.state(exe)
}

/// The OS side of autostart, so the checked toggle can run against a fake in tests.
pub trait AutostartOs {
    /// Writes or deletes the entry.
    fn apply(&self, enabled: bool) -> Result<()>;
    /// Reads the entry back; `Err` = unknown.
    fn read(&self) -> Result<AutostartState>;
    /// Deletes the 1.x logon task; `Ok(false)` when it is absent or may not be deleted.
    fn remove_legacy_task(&self) -> Result<bool>;
}

/// The real `Run` value for one exe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunValue {
    pub exe: PathBuf,
}

impl AutostartOs for RunValue {
    fn apply(&self, enabled: bool) -> Result<()> {
        set(enabled, &self.exe)
    }
    fn read(&self) -> Result<AutostartState> {
        state(&self.exe)
    }
    fn remove_legacy_task(&self) -> Result<bool> {
        match delete_task(TASK_NAME) {
            // The 1.x task ran with the highest privileges, so an unelevated process may not
            // delete it: the installer's elevated cleanup does. Not an error here.
            Err(e) if e.code() == E_ACCESSDENIED => {
                tracing::info!("the 1.x logon task needs elevation to be removed; kept");
                Ok(false)
            }
            other => other,
        }
    }
}

/// One failed step of a checked change.
#[derive(Debug, thiserror::Error)]
pub enum Step {
    #[error("registry: {0}")]
    Os(#[from] windows::core::Error),
    #[error("readback: expected {expected:?}, found {found:?}")]
    Readback {
        expected: AutostartState,
        found: AutostartState,
    },
    #[error("saving the setting: {0}")]
    Persist(Box<AppError>),
}

/// Why a checked change did not take effect.
#[derive(Debug, thiserror::Error)]
pub enum AutostartError {
    /// Nothing changed: the OS refused, or the change was undone (and verified) after the step.
    #[error("autostart unchanged: {0}")]
    Unchanged(Step),
    /// The change failed and so did the undo: what the OS has is unknown.
    #[error("Autostart state is unknown: {cause}; restoring the previous state failed: {restore}")]
    Unknown { cause: Step, restore: Step },
}

impl From<AutostartError> for AppError {
    fn from(err: AutostartError) -> Self {
        let denied = |step: &Step| matches!(step, Step::Os(e) if e.code() == E_ACCESSDENIED);
        let (kind, key) = match &err {
            AutostartError::Unknown { .. } => {
                (ErrorKind::Internal, "winnet.autostart.stateUnknown")
            }
            // HKCU needs no elevation: a refusal comes from a policy or a security product.
            AutostartError::Unchanged(step) if denied(step) => {
                (ErrorKind::Permission, "winnet.autostart.denied")
            }
            AutostartError::Unchanged(Step::Persist(e)) => (e.kind, "winnet.autostart.failed"),
            AutostartError::Unchanged(_) => (ErrorKind::Internal, "winnet.autostart.failed"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Changes autostart and the stored flag together, so the flag never claims a state the OS does
/// not have (storage spec §3.8): apply, read back, then `persist(enabled)`. A refused apply changes
/// nothing; a failed read-back or persist re-applies `previous` and verifies it. `persist` must
/// re-read the settings and change only the flag, so a save made meanwhile is kept. An entry the
/// user switched off in Task Manager counts as applied: the app's part is done and the switch is
/// the user's ([`AutostartState::hint`] tells them). Blocking (registry): run it on a blocking thread.
pub fn set_checked(
    os: &impl AutostartOs,
    previous: bool,
    enabled: bool,
    persist: impl FnOnce(bool) -> AppResult<()>,
) -> std::result::Result<(), AutostartError> {
    os.apply(enabled)
        .map_err(|e| AutostartError::Unchanged(Step::Os(e)))?;
    let cause = match verify(os, enabled)
        .and_then(|()| persist(enabled).map_err(|e| Step::Persist(Box::new(e))))
    {
        Ok(()) => return Ok(()),
        Err(cause) => cause,
    };
    tracing::warn!(%cause, "autostart change failed, restoring the previous state");
    match os
        .apply(previous)
        .map_err(Step::Os)
        .and_then(|()| verify(os, previous))
    {
        Ok(()) => Err(AutostartError::Unchanged(cause)),
        Err(restore) => {
            tracing::error!(%cause, %restore, "autostart state is unknown");
            Err(AutostartError::Unknown { cause, restore })
        }
    }
}

/// Startup sync: makes the OS match the stored flag, acting only on a mismatch (the old app ran an
/// elevated delete on every start), and removes the 1.x logon task. A stale value (old exe) counts
/// as a mismatch; an entry switched off in Task Manager does not. Returns whether it changed
/// anything; the caller logs a failure and carries on.
pub fn sync(os: &impl AutostartOs, enabled: bool) -> Result<bool> {
    let legacy = os.remove_legacy_task();
    let acted = if satisfies(os.read()?, enabled) {
        false
    } else {
        os.apply(enabled)?;
        true
    };
    Ok(legacy? | acted)
}

/// The state a successful `apply(enabled)` reads back as (for messages).
fn wanted(enabled: bool) -> AutostartState {
    if enabled {
        AutostartState::Present { matches_exe: true }
    } else {
        AutostartState::Absent
    }
}

fn satisfies(state: AutostartState, enabled: bool) -> bool {
    match state {
        AutostartState::Absent => !enabled,
        AutostartState::Present { matches_exe }
        | AutostartState::DisabledByUser { matches_exe } => enabled && matches_exe,
    }
}

fn verify(os: &impl AutostartOs, enabled: bool) -> std::result::Result<(), Step> {
    let found = os.read()?;
    if satisfies(found, enabled) {
        Ok(())
    } else {
        Err(Step::Readback {
            expected: wanted(enabled),
            found,
        })
    }
}

/// Where the entry lives: the real keys, or throw-away keys in tests.
#[derive(Debug, Clone, Copy)]
struct Place<'a> {
    run: &'a str,
    approved: &'a str,
    name: &'a str,
}

const REAL: Place<'static> = Place {
    run: RUN_KEY,
    approved: APPROVED_KEY,
    name: RUN_VALUE,
};

impl Place<'_> {
    fn set(&self, enabled: bool, exe: &Path) -> Result<()> {
        if enabled {
            let (key, _) = Key::create(Hive::CurrentUser, self.run, View::Native)?;
            return key.set_string(self.name, &command(exe));
        }
        if let Some(key) = Key::open(Hive::CurrentUser, self.run, Access::ReadWrite, View::Native)?
        {
            key.delete_value(self.name)?;
        }
        Ok(())
    }

    fn state(&self, exe: &Path) -> Result<AutostartState> {
        let Some(key) = Key::open(Hive::CurrentUser, self.run, Access::Read, View::Native)? else {
            return Ok(AutostartState::Absent);
        };
        let matches_exe = match key.value(self.name)? {
            None => return Ok(AutostartState::Absent),
            Some(Value::Sz(text) | Value::ExpandSz(text)) => runs_exe(&text, exe),
            // Another type under our name is not ours to keep: stale, rewritten by `sync`.
            Some(_) => false,
        };
        Ok(if self.switched_off()? {
            AutostartState::DisabledByUser { matches_exe }
        } else {
            AutostartState::Present { matches_exe }
        })
    }

    /// Task Manager's switch: binary data whose first byte is even while the entry is on (02, 06)
    /// and odd once the user switched it off (03, followed by the FILETIME of the change). No
    /// value means the switch was never touched: on.
    fn switched_off(&self) -> Result<bool> {
        let Some(key) = Key::open(Hive::CurrentUser, self.approved, Access::Read, View::Native)?
        else {
            return Ok(false);
        };
        Ok(match key.value(self.name)? {
            Some(Value::Raw { data, .. }) => data.first().is_some_and(|b| b & 1 == 1),
            _ => false,
        })
    }
}

/// The data of our `Run` value: the quoted exe and the flag.
fn command(exe: &Path) -> String {
    format!("\"{}\" {AUTOSTART_ARG}", exe.display())
}

/// The command line runs `exe` with exactly [`AUTOSTART_ARG`].
fn runs_exe(command: &str, exe: &Path) -> bool {
    let command = command.trim();
    let (path, args) = match command.strip_prefix('"') {
        Some(rest) => rest.split_once('"').unwrap_or((rest, "")),
        None => command.split_once(' ').unwrap_or((command, "")),
    };
    same_exe(path, exe) && args.trim() == AUTOSTART_ARG
}

/// Compares a registered path with `exe`: case-insensitive like the file system, quotes and
/// slash style ignored (`schtasks /TR "\"<path>\""` stored the path quoted).
fn same_exe(registered: &str, exe: &Path) -> bool {
    let norm = |s: &str| -> Vec<u16> {
        s.trim()
            .trim_matches('"')
            .replace('/', "\\")
            .encode_utf16()
            .collect()
    };
    win::eq_ignore_case(&norm(registered), &norm(&exe.to_string_lossy()))
}

/// One exec action of a registered task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAction {
    pub path: String,
    pub arguments: String,
}

/// A registered task, as far as the legacy cleanup needs to judge it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    /// The principal's user id as stored: an account name (possibly localized) or a SID string.
    pub user_id: String,
    /// `false` when disabled: the task never starts.
    pub enabled: bool,
    pub exec: Vec<ExecAction>,
    /// Actions of other kinds (e-mail, message, COM handler).
    pub other_actions: usize,
}

/// Reads a task by path (`"VPN Tunnel Enforcer"`, `r"\VPNTE\BootRecoveryTask"`); `None` when it
/// or its folder does not exist. `Err` means unknown (for example access denied).
pub fn read_task(path: &str) -> Result<Option<TaskInfo>> {
    let _com = Com::enter(Apartment::Mta);
    let (_service, folder) = connect()?;
    // SAFETY: plain COM call; the BSTR outlives it.
    let task = match unsafe { folder.GetTask(&BSTR::from(path)) } {
        Ok(task) => task,
        Err(e) if is_absent(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut info = TaskInfo {
        user_id: String::new(),
        enabled: false,
        exec: Vec::new(),
        other_actions: 0,
    };
    // SAFETY: plain COM getters on live interfaces; out-pointers are valid locals.
    unsafe {
        info.enabled = task.Enabled()?.as_bool();
        let definition = task.Definition()?;
        let mut user = BSTR::new();
        definition.Principal()?.UserId(&mut user)?;
        info.user_id = user.to_string();
        let actions = definition.Actions()?;
        let mut count = 0;
        actions.Count(&mut count)?;
        // The collection is 1-based.
        for index in 1..=count {
            let Ok(exec) = actions.get_Item(index)?.cast::<IExecAction>() else {
                info.other_actions += 1;
                continue;
            };
            let (mut path, mut arguments) = (BSTR::new(), BSTR::new());
            exec.Path(&mut path)?;
            exec.Arguments(&mut arguments)?;
            info.exec.push(ExecAction {
                path: path.to_string(),
                arguments: arguments.to_string(),
            });
        }
    }
    Ok(Some(info))
}

/// Deletes a task by path; `false` when it (or its folder) did not exist. Needs elevation for
/// tasks of other principals or with the highest run level.
pub fn delete_task(path: &str) -> Result<bool> {
    let _com = Com::enter(Apartment::Mta);
    let (_service, folder) = connect()?;
    // SAFETY: plain COM call; the BSTR outlives it.
    match unsafe { folder.DeleteTask(&BSTR::from(path), 0) } {
        Ok(()) => Ok(true),
        Err(e) if is_absent(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Deletes an empty task folder (`r"\VPNTE"`); `false` when it did not exist. A folder that still
/// holds tasks is an error (`ERROR_DIR_NOT_EMPTY`) and is kept.
pub fn delete_task_folder(path: &str) -> Result<bool> {
    let _com = Com::enter(Apartment::Mta);
    let (_service, folder) = connect()?;
    // SAFETY: plain COM call; the BSTR outlives it.
    match unsafe { folder.DeleteFolder(&BSTR::from(path), 0) } {
        Ok(()) => Ok(true),
        Err(e) if is_absent(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// "No such task / folder" (`ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`): the only answers
/// that mean absent; anything else (access denied included) is unknown.
fn is_absent(e: &windows::core::Error) -> bool {
    e.code() == ERROR_FILE_NOT_FOUND.to_hresult() || e.code() == ERROR_PATH_NOT_FOUND.to_hresult()
}

fn connect() -> Result<(ITaskService, ITaskFolder)> {
    // SAFETY: COM is initialised on this thread (`Com`); empty VARIANTs mean "local machine,
    // current user".
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let empty = VARIANT::default();
        service.Connect(&empty, &empty, &empty, &empty)?;
        let folder = service.GetFolder(&BSTR::from("\\"))?;
        Ok((service, folder))
    }
}

#[cfg(test)]
mod tests;
