//! The per-user system proxy: the WinINet settings of the default (LAN) connection, the ones the
//! Internet Options "LAN settings" dialog shows. Read and written only through the documented
//! per-connection options, never by editing `ProxyEnable` / `ProxyServer` under HKCU: WinINet
//! keeps the real state in the `DefaultConnectionSettings` blob, and a direct value edit leaves
//! the two disagreeing. Per user, no elevation (unless a machine-wide proxy policy is set, which
//! then refuses the write). Blocking: call from a blocking thread.
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinInet::{
    INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
    INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN, INTERNET_PER_CONN_AUTOCONFIG_URL,
    INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI, INTERNET_PER_CONN_OPTION_LISTW,
    INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER,
    InternetQueryOptionW, InternetSetOptionW, PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL,
    PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
};
use windows::core::{PWSTR, Result};

use crate::win;

/// The proxy settings of the default connection as plain data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyConfig {
    /// "Use a proxy server" (`PROXY_TYPE_PROXY`).
    pub use_proxy: bool,
    /// `host:port` for every protocol, or `http=host:port;https=…`; empty when unset.
    pub server: String,
    /// Addresses that go direct, `;`-separated (`<local>` = names without a dot); empty when unset.
    pub bypass: String,
    /// "Use setup script" (`PROXY_TYPE_AUTO_PROXY_URL`).
    pub use_pac: bool,
    /// Address of the setup (PAC) script; empty when unset.
    pub pac_url: String,
    /// "Automatically detect settings" (WPAD, `PROXY_TYPE_AUTO_DETECT`).
    pub auto_detect: bool,
}

/// Reads the settings of the default connection.
pub fn read() -> Result<ProxyConfig> {
    let flags = read_flags()?;
    let mut options = [
        option(INTERNET_PER_CONN_PROXY_SERVER),
        option(INTERNET_PER_CONN_PROXY_BYPASS),
        option(INTERNET_PER_CONN_AUTOCONFIG_URL),
    ];
    query(&mut options)?;
    // SAFETY: a successful query left a WinINet-allocated string (or null) in every slot.
    let [server, bypass, pac_url] = options.map(|o| unsafe { take_string(o.Value.pszValue) });
    Ok(ProxyConfig {
        use_proxy: flags & PROXY_TYPE_PROXY != 0,
        server,
        bypass,
        use_pac: flags & PROXY_TYPE_AUTO_PROXY_URL != 0,
        pac_url,
        auto_detect: flags & PROXY_TYPE_AUTO_DETECT != 0,
    })
}

/// Writes every field, then tells running WinINet clients to reload: `SETTINGS_CHANGED`, then
/// `REFRESH`, stopping at the first failure, which is the answer (the old app's order).
pub fn write(config: &ProxyConfig) -> Result<()> {
    let mut flags = PROXY_TYPE_DIRECT;
    for (on, flag) in [
        (config.use_proxy, PROXY_TYPE_PROXY),
        (config.use_pac, PROXY_TYPE_AUTO_PROXY_URL),
        (config.auto_detect, PROXY_TYPE_AUTO_DETECT),
    ] {
        if on {
            flags |= flag;
        }
    }
    // An empty string is written as "" (not null): unambiguous "unset" on every version.
    let mut server = win::wide(&config.server);
    let mut bypass = win::wide(&config.bypass);
    let mut pac_url = win::wide(&config.pac_url);
    let mut flag_option = option(INTERNET_PER_CONN_FLAGS);
    flag_option.Value.dwValue = flags;
    let text = |id, buf: &mut Vec<u16>| {
        let mut o = option(id);
        o.Value.pszValue = PWSTR(buf.as_mut_ptr());
        o
    };
    // Microsoft: query through FLAGS_UI, but restore through FLAGS on every version.
    let mut options = [
        flag_option,
        text(INTERNET_PER_CONN_PROXY_SERVER, &mut server),
        text(INTERNET_PER_CONN_PROXY_BYPASS, &mut bypass),
        text(INTERNET_PER_CONN_AUTOCONFIG_URL, &mut pac_url),
    ];
    let list = list(&mut options);
    // SAFETY: `list` points at `options`, whose strings point into the buffers above; all of
    // them outlive the call, and the size is the size of the list structure.
    unsafe {
        InternetSetOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some((&raw const list).cast()),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )
    }?;
    for notify in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        // SAFETY: both options take no buffer.
        unsafe { InternetSetOptionW(None, notify, None, 0) }?;
    }
    Ok(())
}

/// The connection type as the dialog shows it. Since IE 8 `FLAGS` may lose the auto-detect bit
/// after a failed detection while the checkbox stays on; `FLAGS_UI` keeps the user's choice and
/// is rejected (`ERROR_INVALID_PARAMETER`) only by systems that predate it.
fn read_flags() -> Result<u32> {
    let mut ui = [option(INTERNET_PER_CONN(INTERNET_PER_CONN_FLAGS_UI))];
    match query(&mut ui) {
        // SAFETY: a successful query of a flags option fills `dwValue`.
        Ok(()) => return Ok(unsafe { ui[0].Value.dwValue }),
        Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => {}
        Err(e) => return Err(e),
    }
    let mut plain = [option(INTERNET_PER_CONN_FLAGS)];
    query(&mut plain)?;
    // SAFETY: as above.
    Ok(unsafe { plain[0].Value.dwValue })
}

fn option(id: INTERNET_PER_CONN) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: id,
        ..Default::default()
    }
}

/// The option list of the default (LAN) connection: a null connection name.
fn list(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> INTERNET_PER_CONN_OPTION_LISTW {
    INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: PWSTR::null(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    }
}

fn query(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> Result<()> {
    let mut list = list(options);
    let mut size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
    // SAFETY: `list` points at `options`, which outlive the call; `size` is the list's size.
    unsafe {
        InternetQueryOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some((&raw mut list).cast()),
            &mut size,
        )
    }
}

/// Copies a string a query returned and frees it.
///
/// # Safety
/// `value` is null or a NUL-terminated string WinINet allocated for this caller, not used again.
unsafe fn take_string(value: PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller.
    let text = unsafe { win::read_wide(value.0) };
    // SAFETY: WinINet allocates query results with GlobalAlloc; freed exactly once. The wrapper
    // reports the documented null result of a successful free as an error, so it is ignored.
    let _ = unsafe { GlobalFree(Some(HGLOBAL(value.0.cast()))) };
    text
}

#[cfg(test)]
mod tests;
