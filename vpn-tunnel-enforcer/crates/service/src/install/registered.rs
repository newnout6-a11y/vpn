//! Whether the service is registered with a start type other than disabled, read straight from
//! the SCM. The uninstall disables the service as its first step, so a service start that
//! overlaps an uninstall leaves the Settings > Apps entry alone (review tailsa-a4).
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_START_TYPE,
};
use windows::core::{HSTRING, PCWSTR};

use crate::paths::SERVICE_NAME;

/// Registered and not disabled (`false` also when the SCM cannot be read).
pub(crate) fn enabled() -> bool {
    // SAFETY: local machine, default database; each handle opened here is closed here once.
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let service = OpenServiceW(scm, &HSTRING::from(SERVICE_NAME), SERVICE_QUERY_CONFIG);
        let _ = CloseServiceHandle(scm);
        let Ok(service) = service else {
            return false;
        };
        let start = start_type(service);
        let _ = CloseServiceHandle(service);
        start.is_some_and(|start| start != SERVICE_DISABLED)
    }
}

/// The start type of the open `service` (opened with `SERVICE_QUERY_CONFIG`).
fn start_type(service: SC_HANDLE) -> Option<SERVICE_START_TYPE> {
    let mut needed = 0u32;
    // SAFETY: size query (fails with ERROR_INSUFFICIENT_BUFFER and sets `needed`).
    let _ = unsafe { QueryServiceConfigW(service, None, 0, &mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    let config = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: `buf` holds `needed` bytes, 8-byte aligned, and outlives the read below.
    unsafe {
        QueryServiceConfigW(service, Some(config), needed, &mut needed).ok()?;
        Some((*config).dwStartType)
    }
}
