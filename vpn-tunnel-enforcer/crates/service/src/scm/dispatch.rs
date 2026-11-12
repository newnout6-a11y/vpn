//! Running under the SCM: the dispatcher, the control handler and status reports. The service's
//! own work runs in the function handed to [`dispatch`], on the SCM's service thread.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};
use windows::core::{HSTRING, PWSTR};

use crate::paths::SERVICE_NAME;

/// What the service body gets: the stop request and status reporting.
#[derive(Clone)]
pub struct Control {
    /// Cancelled on STOP, SHUTDOWN and PRESHUTDOWN.
    pub stop: CancellationToken,
}

impl Control {
    /// Tells the SCM the service runs and accepts stop / shutdown.
    pub fn running(&self) {
        report(SERVICE_RUNNING, 0, Duration::ZERO);
    }

    /// Asks the SCM for `hint` more time while stopping.
    pub fn stopping(&self, hint: Duration) {
        report(SERVICE_STOP_PENDING, 0, hint);
    }
}

type Body = fn(Control) -> u32;

static BODY: OnceLock<Body> = OnceLock::new();
static STOP: OnceLock<CancellationToken> = OnceLock::new();
static HANDLE: AtomicIsize = AtomicIsize::new(0);
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);

/// Connects to the SCM and runs `body` as the service; returns when it stopped. Fails with
/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when not started by the SCM.
pub fn dispatch(body: Body) -> windows::core::Result<()> {
    let _ = BODY.set(body);
    let mut name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table (and the name it points at) lives until the dispatcher returns.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let stop = STOP.get_or_init(CancellationToken::new).clone();
    // SAFETY: static name string; the handler only touches statics.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(&HSTRING::from(SERVICE_NAME), Some(handler), None) };
    let Ok(handle) = handle else {
        return;
    };
    HANDLE.store(handle.0 as isize, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0, Duration::from_secs(30));
    let code = match BODY.get() {
        Some(body) => body(Control { stop }),
        None => 1,
    };
    report(SERVICE_STOPPED, code, Duration::ZERO);
}

unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
            // Engine stop (≤ 3 s grace) plus WFP cleanup fit well inside this hint.
            report(SERVICE_STOP_PENDING, 0, Duration::from_secs(15));
            if let Some(stop) = STOP.get() {
                stop.cancel();
            }
            NO_ERROR.0
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR.0,
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, exit: u32, hint: Duration) {
    let raw = HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let accepts = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        // 1066 = ERROR_SERVICE_SPECIFIC_ERROR: the SCM then reads our own code (and recovers).
        dwWin32ExitCode: if exit == 0 { 0 } else { 1066 },
        dwServiceSpecificExitCode: exit,
        dwCheckPoint: if pending {
            CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            0
        },
        dwWaitHint: u32::try_from(hint.as_millis()).unwrap_or(u32::MAX),
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and stays valid for the
    // process lifetime; the status struct is a local.
    unsafe {
        let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(raw as *mut _), &status);
    }
}
