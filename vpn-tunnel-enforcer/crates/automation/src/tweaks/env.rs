//! Soft-mode environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` = the proxy URL and
//! `NO_PROXY` = `localhost,127.0.0.1,::1` (keeps the local proxy itself un-proxied), per user in
//! `HKCU\Environment` through `vpnte_winnet::env`. Only processes started afterwards (and
//! Explorer, after the broadcast) see them; running terminals keep their old environment. The
//! app's own environment is never changed: its HTTP clients choose proxies explicitly.
use std::io;

use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_winnet::env::{EnvValue, UserEnv};

use super::endpoint::proxy_url;
use super::journal::{EnvVar, Feature, Target, Val};

/// `NO_PROXY` while Soft mode is on.
pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// The four variables for `addr`.
pub fn plan(addr: &HostPort, kind: ProxyKind) -> Vec<(Feature, Target, Val)> {
    let url = proxy_url(addr, kind);
    EnvVar::ALL
        .into_iter()
        .map(|var| {
            let value = match var {
                EnvVar::NoProxy => NO_PROXY.to_owned(),
                _ => url.clone(),
            };
            (Feature::SoftEnv, Target::Env { var }, Val::Sz(value))
        })
        .collect()
}

/// Current value with its registry type; another type is an error (it could not be restored).
pub fn read(env: &UserEnv, var: EnvVar) -> io::Result<Val> {
    Ok(match env.get(var.name()).map_err(os_error)? {
        None => Val::Absent,
        Some(EnvValue::Plain(s)) => Val::Sz(s),
        Some(EnvValue::Expandable(s)) => Val::ExpandSz(s),
    })
}

/// Sets (keeping the given type) or removes a variable. `HKCU\Environment` always exists, so
/// nothing is ever created.
pub fn write(env: &UserEnv, var: EnvVar, value: &Val) -> io::Result<bool> {
    let name = var.name();
    match value {
        Val::Absent => env.remove(name).map(drop),
        Val::Sz(s) => env.set(name, &EnvValue::Plain(s.clone())),
        Val::ExpandSz(s) => env.set(name, &EnvValue::Expandable(s.clone())),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "environment values are strings",
            ));
        }
    }
    .map_err(os_error)?;
    Ok(false)
}

/// A Win32 failure as an `io::Error` whose kind is meaningful (`windows` maps the HRESULT as a
/// raw OS code, which hides "access denied" behind `Uncategorized`).
pub fn os_error(e: windows::core::Error) -> io::Error {
    let hr = e.code().0 as u32;
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((hr & 0xFFFF) as i32)
    } else {
        io::Error::other(e)
    }
}
