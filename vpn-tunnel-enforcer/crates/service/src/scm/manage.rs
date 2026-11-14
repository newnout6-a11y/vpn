//! Service registration through the SCM (`windows` crate, no extra dependency): create or update,
//! security, failure recovery, start, stop, delete, and the installed binary path the app checks
//! the pipe server against.
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    ENUM_SERVICE_TYPE, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    QueryServiceStatusEx, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW, SERVICE_NO_CHANGE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_SID_INFO,
    SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity,
    StartServiceW,
};
use windows::core::{BOOL, HSTRING, PCWSTR, PWSTR};

use crate::paths::{DISPLAY_NAME, SERVICE_NAME};
use crate::sddl::{self, SecurityDescriptor};

/// `DELETE` standard right.
const DELETE: u32 = 0x1_0000;

/// An SCM handle, closed on drop.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: opened by OpenSCManagerW / OpenServiceW / CreateServiceW, closed once.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn manager(access: u32) -> windows::core::Result<Sc> {
    // SAFETY: local machine, default database.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }.map(Sc)
}

fn open(access: u32) -> windows::core::Result<Option<Sc>> {
    let scm = manager(SC_MANAGER_CONNECT)?;
    // SAFETY: valid manager handle and name.
    match unsafe { OpenServiceW(scm.0, &HSTRING::from(SERVICE_NAME), access) } {
        Ok(h) => Ok(Some(Sc(h))),
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => Ok(None),
        Err(e) => Err(e),
    }
}

/// The SCM command line: quoted (a path with spaces left unquoted lets a planted
/// `C:\Program.exe` run as SYSTEM) plus the `run` verb.
pub fn command_line(exe: &Path) -> String {
    format!("\"{}\" run", exe.display())
}

/// Creates the service (LocalSystem, automatic start, own process) or points an existing one at
/// `exe`, then applies description, service SID, recovery and the restricted DACL.
pub fn create_or_update(exe: &Path, description: &str) -> windows::core::Result<()> {
    let service = match open(SERVICE_ALL_ACCESS)? {
        Some(existing) => {
            reconfigure(&existing, exe)?;
            existing
        }
        None => {
            let scm = manager(SC_MANAGER_ALL_ACCESS)?;
            // SAFETY: valid strings; None account = LocalSystem.
            let h = unsafe {
                CreateServiceW(
                    scm.0,
                    &HSTRING::from(SERVICE_NAME),
                    &HSTRING::from(DISPLAY_NAME),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    &HSTRING::from(command_line(exe)),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                )
            }?;
            Sc(h)
        }
    };
    configure(&service, description)
}

fn reconfigure(service: &Sc, exe: &Path) -> windows::core::Result<()> {
    // SAFETY: valid handle and strings; null strings keep the other fields.
    unsafe {
        windows::Win32::System::Services::ChangeServiceConfigW(
            service.0,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            &HSTRING::from(command_line(exe)),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            &HSTRING::from(DISPLAY_NAME),
        )
    }
}

/// Restarts after a failure: 5 s, 10 s, then 60 s; the count resets after a day without one.
const RECOVERY_DELAYS_MS: [u32; 3] = [5_000, 10_000, 60_000];
const RECOVERY_RESET_S: u32 = 24 * 60 * 60;

fn configure(service: &Sc, description: &str) -> windows::core::Result<()> {
    let mut text: Vec<u16> = description.encode_utf16().chain(Some(0)).collect();
    let describe = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(text.as_mut_ptr()),
    };
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    let mut actions = RECOVERY_DELAYS_MS.map(|delay| SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: delay,
    });
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: RECOVERY_RESET_S,
        lpRebootMsg: PWSTR::null(),
        lpCommand: PWSTR::null(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // Also recover when the service stops itself with an error, not only on a crash.
    let on_error = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: BOOL(1),
    };
    let sd = SecurityDescriptor::from_sddl(sddl::SERVICE_SDDL)?;
    let ptr = |p: *const c_void| Some(p);
    // SAFETY: each info struct (and what it points at) lives until the calls return.
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            ptr((&raw const describe).cast()),
        )?;
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            ptr((&raw const sid).cast()),
        )?;
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            ptr((&raw const failure).cast()),
        )?;
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            ptr((&raw const on_error).cast()),
        )?;
        SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, sd.as_ptr())?;
    }
    Ok(())
}

fn status(service: &Sc) -> windows::core::Result<SERVICE_STATUS_PROCESS> {
    let mut buf = [0u8; size_of::<SERVICE_STATUS_PROCESS>()];
    let mut needed = 0u32;
    // SAFETY: the buffer has the struct's size; read back unaligned below.
    unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(&mut buf),
            &mut needed,
        )?;
        Ok(std::ptr::read_unaligned(buf.as_ptr().cast()))
    }
}

/// Polls (only during install / uninstall) until the state is reached; `false` on timeout.
fn wait_state(
    service: &Sc,
    want: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    limit: Duration,
) -> windows::core::Result<bool> {
    let deadline = Instant::now() + limit;
    loop {
        if status(service)?.dwCurrentState == want {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Starts the service and waits until it runs.
pub fn start(limit: Duration) -> windows::core::Result<bool> {
    let Some(service) = open(SERVICE_START | SERVICE_QUERY_STATUS)? else {
        return Err(ERROR_SERVICE_DOES_NOT_EXIST.into());
    };
    if status(&service)?.dwCurrentState != SERVICE_RUNNING {
        // SAFETY: valid handle, no arguments.
        unsafe { StartServiceW(service.0, None) }?;
    }
    wait_state(&service, SERVICE_RUNNING, limit)
}

/// Stops the service if it runs and waits for `STOPPED` (`Ok(true)` also when not installed).
pub fn stop(limit: Duration) -> windows::core::Result<bool> {
    let Some(service) = open(SERVICE_STOP | SERVICE_QUERY_STATUS)? else {
        return Ok(true);
    };
    let mut last = SERVICE_STATUS::default();
    // SAFETY: valid handle and out struct.
    match unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut last) } {
        Ok(()) => {}
        Err(e) if e.code() == ERROR_SERVICE_NOT_ACTIVE.to_hresult() => return Ok(true),
        Err(e) => return Err(e),
    }
    wait_state(&service, SERVICE_STOPPED, limit)
}

/// Sets the start type of an installed service: `false` = disabled, so the SCM's recovery cannot
/// start it again while its files are replaced or removed (review service-a13); `true` = back to
/// automatic. Nothing to do when it is not installed.
pub fn set_enabled(enabled: bool) -> windows::core::Result<()> {
    let Some(service) = open(SERVICE_CHANGE_CONFIG)? else {
        return Ok(());
    };
    let start = if enabled {
        SERVICE_AUTO_START
    } else {
        SERVICE_DISABLED
    };
    // SAFETY: valid handle; "no change" values and null strings keep every other field.
    unsafe {
        windows::Win32::System::Services::ChangeServiceConfigW(
            service.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
}

/// Marks the service for deletion (the SCM removes it once stopped and every handle closed).
pub fn delete() -> windows::core::Result<()> {
    if let Some(service) = open(DELETE)? {
        // SAFETY: valid handle opened with DELETE.
        marked(unsafe { DeleteService(service.0) })?;
    }
    Ok(())
}

/// Already marked for deletion (an earlier run whose stop hung) is what `delete` wants.
fn marked(deleted: windows::core::Result<()>) -> windows::core::Result<()> {
    match deleted {
        Err(e) if e.code() == ERROR_SERVICE_MARKED_FOR_DELETE.to_hresult() => Ok(()),
        other => other,
    }
}

/// The running service's process id (`None`: not installed or not running): the elevated tests
/// end it the hard way to check what a crash leaves behind.
pub fn process_id() -> windows::core::Result<Option<u32>> {
    let Some(service) = open(SERVICE_QUERY_STATUS)? else {
        return Ok(None);
    };
    let s = status(&service)?;
    Ok((s.dwCurrentState == SERVICE_RUNNING && s.dwProcessId != 0).then_some(s.dwProcessId))
}

/// The installed service's executable (`None`: not installed). The app compares the pipe
/// server's image with it.
pub fn installed_binary() -> windows::core::Result<Option<PathBuf>> {
    let Some(service) = open(SERVICE_QUERY_CONFIG)? else {
        return Ok(None);
    };
    let mut needed = 0u32;
    // SAFETY: size query (fails with ERROR_INSUFFICIENT_BUFFER, sets `needed`).
    let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds `needed` bytes, 8-byte aligned.
    let config = unsafe {
        let config = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        QueryServiceConfigW(service.0, Some(config), needed, &mut needed)?;
        (*config).lpBinaryPathName.to_string().ok()
    };
    Ok(config.as_deref().and_then(exe_of_command_line))
}

/// `"C:\…\vpnte-service.exe" run` -> `C:\…\vpnte-service.exe`.
pub fn exe_of_command_line(line: &str) -> Option<PathBuf> {
    let rest = line.trim().strip_prefix('"')?;
    let (exe, _) = rest.split_once('"')?;
    Some(PathBuf::from(exe))
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::*;

    /// Review service-a13: a rerun after a hung stop finds the service marked for deletion; that
    /// is done, not a failure. Other errors stay errors.
    #[test]
    fn already_marked_for_deletion_counts_as_deleted() {
        assert!(marked(Err(ERROR_SERVICE_MARKED_FOR_DELETE.into())).is_ok());
        assert!(marked(Err(ERROR_ACCESS_DENIED.into())).is_err());
        assert!(marked(Ok(())).is_ok());
    }
}
