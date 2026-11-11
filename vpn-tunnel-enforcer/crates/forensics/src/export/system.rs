//! `system-info.json`: OS build, memory, CPU and versions (DX:59-75 without Electron / Node, plus
//! the engine versions). Best effort: a value that cannot be read is `null`.
use serde_json::{Value, json};
use vpnte_winnet::registry::{Access, Hive, Key, View};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const CPU0: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const MIB: u64 = 1024 * 1024;

/// The document; `engines` are `(name, version)` pairs (`sing-box`, `xray`).
pub(super) fn system_info(now: &str, app_version: &str, engines: &[(String, String)]) -> Value {
    let os = open(CURRENT_VERSION);
    let os_str = |name: &str| os.as_ref().and_then(|k| k.string(name).ok().flatten());
    let os_dword = |name: &str| os.as_ref().and_then(|k| k.dword(name).ok().flatten());
    let release = match (
        os_dword("CurrentMajorVersionNumber"),
        os_dword("CurrentMinorVersionNumber"),
        os_str("CurrentBuild"),
    ) {
        (Some(major), Some(minor), Some(build)) => Some(match os_dword("UBR") {
            Some(ubr) => format!("{major}.{minor}.{build}.{ubr}"),
            None => format!("{major}.{minor}.{build}"),
        }),
        _ => None,
    };
    let cpu_model = open(CPU0)
        .and_then(|k| k.string("ProcessorNameString").ok().flatten())
        .map(|s| s.trim().to_string());
    let memory = memory();
    let engines: serde_json::Map<String, Value> = engines
        .iter()
        .map(|(name, version)| (name.clone(), Value::from(version.as_str())))
        .collect();
    json!({
        "timestamp": now,
        "hostname": std::env::var("COMPUTERNAME").ok(),
        "osType": "Windows_NT",
        "osRelease": release,
        "osProduct": os_str("ProductName"),
        "osDisplayVersion": os_str("DisplayVersion"),
        "arch": std::env::consts::ARCH,
        "totalMemMB": memory.map(|m| m.ullTotalPhys / MIB),
        "freeMemMB": memory.map(|m| m.ullAvailPhys / MIB),
        "cpuCount": std::thread::available_parallelism().ok().map(|n| n.get()),
        "cpuModel": cpu_model,
        "appVersion": app_version,
        "engines": engines,
    })
}

fn open(path: &str) -> Option<Key> {
    Key::open(Hive::LocalMachine, path, Access::Read, View::Native)
        .ok()
        .flatten()
}

fn memory() -> Option<MEMORYSTATUSEX> {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status` is a valid, writable MEMORYSTATUSEX with `dwLength` set as the API requires.
    unsafe { GlobalMemoryStatusEx(&mut status) }.ok()?;
    Some(status)
}
