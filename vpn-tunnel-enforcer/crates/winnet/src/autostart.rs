//! Start at logon through a Task Scheduler task, registered over COM (`ITaskService`, no `schtasks`).
//!
//! The task runs the current exe with [`AUTOSTART_ARG`] at the current user's logon, elevated (a
//! task is the only UAC-free way to start an admin app at logon), with an explicit definition:
//! `schtasks` defaults stopped the app on battery and after 72 hours (spec B12).
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{
    E_ACCESSDENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, VARIANT_FALSE,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskDefinition, ITaskFolder, ITaskService, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface, PCWSTR, PWSTR, Result};

use crate::win::{self, Apartment, Com};

/// Name of the task in the Task Scheduler root folder (the old app used the same one).
pub const TASK_NAME: &str = "VPN Tunnel Enforcer";
/// Command-line flag the task passes, so the app can tell a logon start from a manual one.
pub const AUTOSTART_ARG: &str = "--autostart";

/// What the OS has registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutostartState {
    Absent,
    /// `matches_exe`: the task is enabled and runs this exe with [`AUTOSTART_ARG`]; `false` for a
    /// stale task, e.g. the old Electron one (other path, or the same path without the flag and
    /// with the old limits), or one disabled in Task Scheduler (start-up "optimizers" do that).
    Present {
        matches_exe: bool,
    },
}

/// Registers (or replaces) the task for `exe`, or deletes it; deleting an absent task succeeds.
/// Registering needs an elevated process.
pub fn set(enabled: bool, exe: &Path) -> Result<()> {
    set_task(TASK_NAME, enabled, exe)
}

/// Reads the task back. `Err` means "unknown" (for example access denied), never "absent".
pub fn state(exe: &Path) -> Result<AutostartState> {
    state_of(TASK_NAME, exe)
}

/// The OS side of autostart, so the checked toggle can run against a fake in tests.
pub trait AutostartOs {
    /// Registers or deletes the task.
    fn apply(&self, enabled: bool) -> Result<()>;
    /// Reads the task back; `Err` = unknown.
    fn read(&self) -> Result<AutostartState>;
}

/// The real task for one exe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonTask {
    pub exe: PathBuf,
}

impl AutostartOs for LogonTask {
    fn apply(&self, enabled: bool) -> Result<()> {
        set(enabled, &self.exe)
    }
    fn read(&self) -> Result<AutostartState> {
        state(&self.exe)
    }
}

/// One failed step of a checked change.
#[derive(Debug, thiserror::Error)]
pub enum Step {
    #[error("task scheduler: {0}")]
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
            AutostartError::Unknown { .. } => (ErrorKind::Internal, "winnet.autostart.unknown"),
            AutostartError::Unchanged(step) if denied(step) => {
                (ErrorKind::Permission, "winnet.autostart.needsAdmin")
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
/// re-read the settings and change only the flag, so a save made meanwhile is kept.
/// Blocking (COM): run it on a blocking thread.
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
/// elevated delete on every start). A stale task (old exe) counts as a mismatch. Returns whether
/// it changed anything; the caller logs a failure and carries on.
pub fn sync(os: &impl AutostartOs, enabled: bool) -> Result<bool> {
    if os.read()? == wanted(enabled) {
        return Ok(false);
    }
    os.apply(enabled)?;
    Ok(true)
}

fn wanted(enabled: bool) -> AutostartState {
    if enabled {
        AutostartState::Present { matches_exe: true }
    } else {
        AutostartState::Absent
    }
}

fn verify(os: &impl AutostartOs, enabled: bool) -> std::result::Result<(), Step> {
    let (expected, found) = (wanted(enabled), os.read()?);
    if found == expected {
        Ok(())
    } else {
        Err(Step::Readback { expected, found })
    }
}

fn set_task(name: &str, enabled: bool, exe: &Path) -> Result<()> {
    if !enabled {
        return delete_task(name).map(drop);
    }
    let _com = Com::enter(Apartment::Mta);
    let (service, folder) = connect()?;
    let user = current_user()?;
    let definition = build_definition(&service, exe, &user)?;
    // SAFETY: plain COM call; every argument outlives it.
    unsafe {
        folder.RegisterTaskDefinition(
            &BSTR::from(name),
            &definition,
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from(user.as_str()),
            &VARIANT::default(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            &VARIANT::default(),
        )
    }?;
    Ok(())
}

fn state_of(name: &str, exe: &Path) -> Result<AutostartState> {
    Ok(match read_task(name)? {
        None => AutostartState::Absent,
        Some(task) => AutostartState::Present {
            matches_exe: runs_exe(&task, exe),
        },
    })
}

/// The task is enabled and its only action is `exe --autostart`.
fn runs_exe(task: &TaskInfo, exe: &Path) -> bool {
    task.enabled
        && task.other_actions == 0
        && matches!(task.exec.as_slice(), [action]
            if same_exe(&action.path, exe) && action.arguments.trim() == AUTOSTART_ARG)
}

/// One exec action of a registered task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAction {
    pub path: String,
    pub arguments: String,
}

/// A registered task, as far as autostart and the legacy cleanup need to judge it.
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

/// The definition `set(true, ..)` registers; separate so it can be checked without registering.
fn build_definition(service: &ITaskService, exe: &Path, user: &str) -> Result<ITaskDefinition> {
    let user = BSTR::from(user);
    // SAFETY: plain COM calls on live interfaces; every BSTR outlives the call it is passed to.
    unsafe {
        let definition = service.NewTask(0)?;
        let info = definition.RegistrationInfo()?;
        info.SetAuthor(&BSTR::from(TASK_NAME))?;
        info.SetDescription(&BSTR::from("Starts VPN Tunnel Enforcer at logon."))?;

        let principal = definition.Principal()?;
        principal.SetUserId(&user)?;
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

        let settings = definition.Settings()?;
        settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
        settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
        settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;
        settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;
        // The default 7 starts the app below normal CPU, I/O and memory priority, and the engines
        // inherit that class; 4 = normal, the level Microsoft gives interactive tasks.
        settings.SetPriority(4)?;

        // Without a UserId the trigger fires at ANY user's logon.
        let trigger: ILogonTrigger = definition.Triggers()?.Create(TASK_TRIGGER_LOGON)?.cast()?;
        trigger.SetUserId(&user)?;

        let action: IExecAction = definition.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
        action.SetPath(&wide_bstr(exe.as_os_str()))?;
        action.SetArguments(&BSTR::from(AUTOSTART_ARG))?;
        if let Some(dir) = exe.parent() {
            action.SetWorkingDirectory(&wide_bstr(dir.as_os_str()))?;
        }
        Ok(definition)
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

fn wide_bstr(s: &OsStr) -> BSTR {
    BSTR::from_wide(&s.encode_wide().collect::<Vec<u16>>())
}

/// `DOMAIN\user` of this process's token, the form the Task Scheduler documents for `UserId`.
fn current_user() -> Result<String> {
    let token = win::process_token()?;
    let mut len = 0u32;
    // SAFETY: a size query with no buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER by design.
    let _ = unsafe { GetTokenInformation(*token, TokenUser, None, 0, &mut len) };
    // `usize` elements keep the pointer inside TOKEN_USER aligned.
    let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>()).max(1)];
    let size = (buf.len() * size_of::<usize>()) as u32;
    // SAFETY: `buf` has `size` writable, pointer-aligned bytes.
    unsafe {
        GetTokenInformation(
            *token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            size,
            &mut len,
        )
    }?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let (mut name_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: a size query; `sid` stays valid while `buf` lives.
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers have the lengths passed with them.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// Compares a task's action path with `exe`: case-insensitive like the file system, quotes and
/// slash style ignored (`schtasks /TR "\"<path>\""` stored the path quoted).
fn same_exe(task_path: &str, exe: &Path) -> bool {
    let norm = |s: &str| -> Vec<u16> {
        s.trim()
            .trim_matches('"')
            .replace('/', "\\")
            .encode_utf16()
            .collect()
    };
    win::eq_ignore_case(&norm(task_path), &norm(&exe.to_string_lossy()))
}

#[cfg(test)]
mod tests;
