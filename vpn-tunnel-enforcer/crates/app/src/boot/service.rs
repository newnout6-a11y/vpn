//! The helper service as the app finds it (owner decision 12.11.2026): installed (the SCM knows
//! it; the pipe's server is checked against its exe at every connect) or not, and the one
//! elevated step the app may ask Windows for — the service's own install verb, from Settings.
use std::path::PathBuf;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_service::per_user::{self, Elevated};
use vpnte_service::scm::manage;

/// The service exe next to the app's (the installer and the portable archive ship it there).
const SERVICE_EXE: &str = "vpnte-service.exe";

/// Set to anything, the process never reaches an installed helper service: the integration
/// tests' child app (unit tests never do). It only takes the service away, never points
/// anywhere else.
pub const ENV_NO_SERVICE: &str = "VPNTE_NO_SERVICE";

/// The installed service's exe, as the SCM has it. `None` with [`ENV_NO_SERVICE`] set and in
/// unit tests (outside [`RealService`]): a test run on a PC where the owner installed the
/// service never touches it.
pub fn installed_binary() -> windows::core::Result<Option<PathBuf>> {
    if !reachable() {
        return Ok(None);
    }
    manage::installed_binary()
}

fn reachable() -> bool {
    #[cfg(test)]
    if !REAL_SERVICE.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    std::env::var_os(ENV_NO_SERVICE).is_none()
}

#[cfg(test)]
static REAL_SERVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// While alive, unit tests reach the installed service: only an elevated test that installed
/// its own (CI's runner, after its elevation check), never one on a PC with a real service.
#[cfg(test)]
pub(crate) struct RealService(());

#[cfg(test)]
impl RealService {
    pub(crate) fn allow() -> Self {
        REAL_SERVICE.store(true, std::sync::atomic::Ordering::Relaxed);
        Self(())
    }
}

#[cfg(test)]
impl Drop for RealService {
    fn drop(&mut self) {
        REAL_SERVICE.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The service is registered with the SCM.
pub fn installed() -> bool {
    match installed_binary() {
        Ok(found) => found.is_some(),
        Err(err) => {
            tracing::warn!(error = %err, "service registration unreadable");
            false
        }
    }
}

/// The helper service as the SCM sees it right now (p-live-fix): after a Windows restart the
/// app's autostart runs at sign-in, in parallel with the automatic services, so "registered but
/// not answering yet" is normal for a while.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Not registered (or out of a test's reach, see [`installed_binary`]).
    Missing,
    /// Registered and stopped: Windows starts it at boot, its recovery restarts it after a crash.
    Stopped,
    /// `START_PENDING` / `CONTINUE_PENDING`: coming up.
    Starting,
    /// `RUNNING`: its pipe is there or about to be.
    Running,
    /// `STOP_PENDING`, `PAUSE_PENDING`, `PAUSED`: going away.
    Stopping,
}

impl Presence {
    /// The service is on its way up (or up): worth waiting for its pipe.
    pub fn coming(self) -> bool {
        matches!(self, Presence::Starting | Presence::Running)
    }
}

/// The service's [`Presence`]; an SCM it cannot read counts as missing (logged).
pub fn presence() -> Presence {
    if !reachable() {
        return Presence::Missing;
    }
    scm_presence().unwrap_or_else(|err| {
        tracing::warn!(error = %err, "service state unreadable");
        Presence::Missing
    })
}

fn scm_presence() -> windows::core::Result<Presence> {
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
        SC_MANAGER_CONNECT, SERVICE_CONTINUE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
    };
    use windows::core::{HSTRING, PCWSTR};

    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: opened below, closed once.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }
    // SAFETY: local machine, default database, connect right only.
    let scm =
        Handle(unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }?);
    let name = HSTRING::from(vpnte_service::paths::SERVICE_NAME);
    // SAFETY: a valid manager handle and name; query right only (any user has it).
    let service = match unsafe { OpenServiceW(scm.0, &name, SERVICE_QUERY_STATUS) } {
        Ok(handle) => Handle(handle),
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
            return Ok(Presence::Missing);
        }
        Err(e) => return Err(e),
    };
    let mut status = SERVICE_STATUS::default();
    // SAFETY: a valid service handle and a writable status struct.
    unsafe { QueryServiceStatus(service.0, &mut status) }?;
    Ok(match status.dwCurrentState {
        SERVICE_RUNNING => Presence::Running,
        SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => Presence::Starting,
        SERVICE_STOPPED => Presence::Stopped,
        _ => Presence::Stopping,
    })
}

fn service_exe() -> AppResult<PathBuf> {
    let exe = std::env::current_exe().map_err(AppError::internal)?;
    let path = exe.with_file_name(SERVICE_EXE);
    if path.is_file() {
        Ok(path)
    } else {
        Err(AppError::msg(
            ErrorKind::Validation,
            Msg::new("app.service.notShipped"),
        ))
    }
}

/// Asks Windows to run `vpnte-service.exe install` elevated (its prompt; the app itself never
/// elevates) and waits. `Ok(true)` installed, `Ok(false)` nobody approved the prompt: nothing
/// else happens, proxy mode goes on. Blocking.
pub fn request_install() -> AppResult<bool> {
    let exe = service_exe()?;
    let elevated = per_user::request_install(&exe, None).map_err(|e| {
        AppError::msg(ErrorKind::Internal, Msg::new("app.service.installFailed")).with_source(e)
    })?;
    match elevated {
        Elevated::Exited(0) => Ok(installed()),
        Elevated::Declined => Ok(false),
        Elevated::Exited(code) => Err(AppError::msg(
            ErrorKind::Internal,
            Msg::new("app.service.installFailed"),
        )
        .with_source(std::io::Error::other(format!("install exited with {code}")))),
    }
}

#[cfg(test)]
mod tests {
    /// A test never sees the owner's installed service (two backend tests failed on a PC that
    /// has it, and a connect would have reached it).
    #[test]
    fn tests_never_see_an_installed_service() {
        assert_eq!(super::installed_binary().unwrap(), None);
        assert!(!super::installed());
        assert_eq!(super::presence(), super::Presence::Missing);
    }

    #[test]
    fn only_a_service_on_its_way_up_is_waited_for() {
        use super::Presence::*;
        let coming: Vec<bool> = [Missing, Stopped, Starting, Running, Stopping]
            .iter()
            .map(|p| p.coming())
            .collect();
        assert_eq!(coming, [false, false, true, true, false]);
    }
}
