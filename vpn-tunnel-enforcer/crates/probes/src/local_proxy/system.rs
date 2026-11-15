//! OS reads behind the detector (blocking; call from `spawn_blocking`): client config files,
//! system proxy settings (WinINet registry, WinHTTP, environment) and TCP listeners.
use std::path::{Path, PathBuf};

use serde::Serialize;
use vpnte_winnet::process::{self, TcpState, Transport};
use vpnte_winnet::registry::{Access, Hive, Key, View};
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_PROXY_INFO, WinHttpGetDefaultProxyConfiguration,
};
use windows::core::PWSTR;

use super::candidates::{
    CONFIG_DIRS, CONFIG_EXTENSIONS, CONFIG_MAX_BYTES, Candidate, ListenerRow, Source,
    config_candidates, proxy_server_candidates, text_candidates,
};

/// Environment variables that carry a proxy URL (checked upper- and lower-case).
pub const PROXY_ENV: [&str; 3] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"];

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// WinINet (per-user "Internet Settings") proxy configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WinInet {
    pub proxy_enable: Option<bool>,
    pub proxy_server: Option<String>,
    pub auto_config_url: Option<String>,
    pub auto_detect: Option<bool>,
}

/// Every system-level proxy setting a client may have written. `None` = could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxy {
    pub wininet: Option<WinInet>,
    /// WinHTTP default proxy (`netsh winhttp`): `Some(None)` = direct access.
    pub winhttp: Option<Option<String>>,
    /// Proxy variables of this process's environment, as set.
    pub env: Vec<(String, String)>,
}

impl SystemProxy {
    /// Reads all three sources; a failed read leaves its field `None`.
    pub fn read() -> Self {
        Self {
            wininet: read_wininet().ok().flatten(),
            winhttp: read_winhttp().ok(),
            env: read_env(),
        }
    }

    /// Loopback candidates in the old order: environment, WinHTTP, WinINet (`ProxyServer` only
    /// while `ProxyEnable == 1`, the PAC URL always).
    pub fn candidates(&self) -> Vec<Candidate> {
        let mut out = Vec::new();
        for (name, value) in &self.env {
            out.extend(text_candidates(
                value,
                &Source::System(format!("env:{name}")),
            ));
        }
        if let Some(Some(value)) = &self.winhttp {
            out.extend(proxy_server_candidates(
                value,
                &Source::System("winhttp".into()),
            ));
        }
        if let Some(w) = &self.wininet {
            let source = Source::System("wininet".into());
            if w.proxy_enable == Some(true)
                && let Some(server) = &w.proxy_server
            {
                out.extend(proxy_server_candidates(server, &source));
            }
            if let Some(pac) = &w.auto_config_url {
                out.extend(text_candidates(pac, &source));
            }
        }
        out
    }
}

fn read_env() -> Vec<(String, String)> {
    PROXY_ENV
        .iter()
        .flat_map(|name| [name.to_string(), name.to_ascii_lowercase()])
        .filter_map(|name| {
            let value = std::env::var(&name).ok().filter(|v| !v.trim().is_empty())?;
            Some((name, value))
        })
        .collect()
}

fn read_wininet() -> windows::core::Result<Option<WinInet>> {
    let Some(key) = Key::open(
        Hive::CurrentUser,
        INTERNET_SETTINGS,
        Access::Read,
        View::Native,
    )?
    else {
        return Ok(None);
    };
    // A value of an unexpected type reads as "unset" here: this is a hint, not a journal.
    Ok(Some(WinInet {
        proxy_enable: key.dword("ProxyEnable").ok().flatten().map(|v| v == 1),
        proxy_server: key
            .string("ProxyServer")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty()),
        auto_config_url: key
            .string("AutoConfigURL")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty()),
        auto_detect: key.dword("AutoDetect").ok().flatten().map(|v| v == 1),
    }))
}

fn take_pwstr(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: WinHTTP returned a NUL-terminated string it allocated with GlobalAlloc; it is read
    // once and then freed exactly once with GlobalFree, as the API requires.
    let text = unsafe { p.to_string() }.ok();
    // SAFETY: see above; the pointer is not used afterwards.
    let _ = unsafe { GlobalFree(Some(HGLOBAL(p.0.cast()))) };
    text
}

/// WinHTTP default proxy: `None` for direct access.
pub fn read_winhttp() -> windows::core::Result<Option<String>> {
    let mut info = WINHTTP_PROXY_INFO::default();
    // SAFETY: `info` is a valid out-parameter for the duration of the call.
    unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) }?;
    let proxy = take_pwstr(info.lpszProxy);
    let _bypass = take_pwstr(info.lpszProxyBypass);
    Ok(proxy
        .filter(|p| info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && !p.trim().is_empty()))
}

/// `%APPDATA%` and `%LOCALAPPDATA%`, where clients keep their configs.
pub fn config_roots() -> Vec<PathBuf> {
    ["APPDATA", "LOCALAPPDATA"]
        .iter()
        .filter_map(|v| {
            std::env::var_os(v)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .collect()
}

/// Candidates from the top-level config files of the known client directories under `roots`.
pub fn scan_configs(roots: &[PathBuf]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for root in roots {
        for dir in CONFIG_DIRS {
            out.extend(scan_dir(&root.join(dir)));
        }
    }
    out
}

fn scan_dir(dir: &Path) -> Vec<Candidate> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| CONFIG_EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x)))
        })
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        if std::fs::metadata(&path).map_or(true, |m| m.len() > CONFIG_MAX_BYTES) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.extend(config_candidates(&String::from_utf8_lossy(&bytes), &name));
    }
    out
}

/// TCP listeners with the owning image name (unreadable images stay `None`).
pub fn listener_rows() -> windows::core::Result<Vec<ListenerRow>> {
    let rows = process::socket_table()?;
    Ok(rows
        .into_iter()
        .filter(|r| r.transport == Transport::Tcp && r.state == Some(TcpState::Listen))
        .map(|r| ListenerRow {
            local: r.local,
            pid: r.pid,
            process: process::image_path(r.pid)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())),
        })
        .collect())
}
