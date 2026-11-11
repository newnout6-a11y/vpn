//! Native system reads for the report and snapshots (blocking but fast): running processes,
//! service state, OS version, memory, host name.
use std::mem::size_of;

use serde::Serialize;
use vpnte_winnet::registry::{Access, Hive, Key, View};
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, WIN32_ERROR};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_STATUS,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::core::{HSTRING, Owned, PCWSTR};

/// A running process (image file name only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
}

/// Every running process (Toolhelp snapshot).
pub fn processes() -> windows::core::Result<Vec<ProcessRow>> {
    // SAFETY: plain call; the handle is owned right below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    // SAFETY: the snapshot handle is ours and closed only by `Owned`.
    let snap = unsafe { Owned::new(snap) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut rows = Vec::new();
    // SAFETY: `entry` is a valid PROCESSENTRY32W with `dwSize` set, for both calls.
    let mut step = unsafe { Process32FirstW(*snap, &mut entry) };
    loop {
        if let Err(err) = step {
            return match WIN32_ERROR::from_error(&err) {
                Some(ERROR_NO_MORE_FILES) => Ok(rows),
                _ => Err(err),
            };
        }
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        rows.push(ProcessRow {
            pid: entry.th32ProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..len]),
        });
        // SAFETY: as above.
        step = unsafe { Process32NextW(*snap, &mut entry) };
    }
}

/// Configured start type of a service (registry `Start`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStart {
    Boot,
    System,
    Auto,
    Manual,
    Disabled,
    Unknown,
}

/// State of one service. `running: None` = the state could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceRow {
    pub name: String,
    pub present: bool,
    pub running: Option<bool>,
    pub start: ServiceStart,
}

/// Service state over the SCM (query rights only, works unelevated) plus the start type from
/// `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start`.
pub fn service(name: &str) -> ServiceRow {
    let key = Key::open(
        Hive::LocalMachine,
        &format!(r"SYSTEM\CurrentControlSet\Services\{name}"),
        Access::Read,
        View::Native,
    );
    let (present, start) = match key {
        Ok(Some(key)) => (
            true,
            match key.dword("Start") {
                Ok(Some(0)) => ServiceStart::Boot,
                Ok(Some(1)) => ServiceStart::System,
                Ok(Some(2)) => ServiceStart::Auto,
                Ok(Some(3)) => ServiceStart::Manual,
                Ok(Some(4)) => ServiceStart::Disabled,
                _ => ServiceStart::Unknown,
            },
        ),
        Ok(None) => (false, ServiceStart::Unknown),
        Err(_) => (true, ServiceStart::Unknown),
    };
    let running = if present {
        running(name).ok()
    } else {
        Some(false)
    };
    ServiceRow {
        name: name.to_owned(),
        present,
        running,
        start,
    }
}

fn running(name: &str) -> windows::core::Result<bool> {
    // SAFETY: plain calls; both handles are owned and closed by `Owned` (SC_HANDLE: Free).
    let scm = unsafe {
        Owned::new(OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        )?)
    };
    let svc_name = HSTRING::from(name);
    // SAFETY: as above; `svc_name` outlives the call.
    let svc = unsafe { Owned::new(OpenServiceW(*scm, &svc_name, SERVICE_QUERY_STATUS)?) };
    let mut status = SERVICE_STATUS::default();
    // SAFETY: `status` is a valid out-parameter.
    unsafe { QueryServiceStatus(*svc, &mut status) }?;
    Ok(status.dwCurrentState == SERVICE_RUNNING)
}

/// OS facts for reports: `Windows 11 Pro 24H2 (26100.4061)` style parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OsInfo {
    pub product: Option<String>,
    pub display_version: Option<String>,
    /// `<CurrentBuild>.<UBR>`.
    pub build: Option<String>,
    pub arch: &'static str,
    pub hostname: Option<String>,
    pub mem_total_mb: Option<u64>,
    pub mem_free_mb: Option<u64>,
}

/// Reads the OS version (registry), architecture, host name and physical memory.
pub fn os_info() -> OsInfo {
    let key = Key::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        Access::Read,
        View::Native,
    )
    .ok()
    .flatten();
    let text = |name: &str| key.as_ref().and_then(|k| k.string(name).ok().flatten());
    let build_no = text("CurrentBuild").and_then(|b| b.parse::<u32>().ok());
    let build = text("CurrentBuild").map(|b| {
        match key.as_ref().and_then(|k| k.dword("UBR").ok().flatten()) {
            Some(ubr) => format!("{b}.{ubr}"),
            None => b,
        }
    });
    // `ProductName` still says "Windows 10" on Windows 11 (build 22000 and later).
    let product = text("ProductName").map(|p| match build_no {
        Some(n) if n >= 22_000 => p.replacen("Windows 10", "Windows 11", 1),
        _ => p,
    });
    let mut mem = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `mem` is a valid MEMORYSTATUSEX with `dwLength` set.
    let mem_ok = unsafe { GlobalMemoryStatusEx(&mut mem) }.is_ok();
    OsInfo {
        product,
        display_version: text("DisplayVersion"),
        build,
        arch: std::env::consts::ARCH,
        hostname: std::env::var("COMPUTERNAME").ok().filter(|h| !h.is_empty()),
        mem_total_mb: mem_ok.then_some(mem.ullTotalPhys / (1024 * 1024)),
        mem_free_mb: mem_ok.then_some(mem.ullAvailPhys / (1024 * 1024)),
    }
}
