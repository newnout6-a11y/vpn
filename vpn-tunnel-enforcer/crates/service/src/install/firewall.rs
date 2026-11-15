//! Windows Firewall rules sing-box made for the service's engines. sing-tun's system / mixed
//! stack adds an inbound allow rule named `sing-tun (<absolute path of sing-box.exe>)` the first
//! time a TUN comes up (lab F-8, 14.11.2026: the rule outlived both uninstalls). The removal
//! deletes every such rule for a file in the service's folder.
use std::path::Path;

use vpnte_base::{AppError, AppResult};
use windows::Win32::Foundation::{E_ACCESSDENIED, RPC_E_CHANGED_MODE};
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, INetFwRule, NetFwPolicy2};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH, VariantClear};
use windows::core::{BSTR, Interface};

/// A name the same rule may keep after `Remove` (several rules can share one name): the removal
/// looks again this many times.
const ROUNDS: usize = 4;

/// The firewall's rule names as the removal needs them (tests: a fake).
pub(crate) trait Rules {
    /// Every rule name, duplicates kept.
    fn names(&self) -> AppResult<Vec<String>>;
    /// Removes one rule of this name.
    fn remove(&self, name: &str) -> AppResult<()>;
}

/// `sing-tun (<path>)` for a file inside `dir`. sing-tun names the rule after
/// `filepath.Abs(argv[0])`, so the path keeps the launcher's spelling: compared ignoring case
/// and a `\\?\` prefix.
pub(crate) fn is_engine_rule(name: &str, dir: &Path) -> bool {
    let Some(path) = name
        .strip_prefix("sing-tun (")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let Some(dir) = dir.to_str().map(|d| d.trim_end_matches('\\')) else {
        return false;
    };
    path.len() > dir.len() + 1
        && path.is_char_boundary(dir.len())
        && path[..dir.len()].eq_ignore_ascii_case(dir)
        && path[dir.len()..].starts_with('\\')
}

/// Removes every engine rule of `dir`, looking again until none is left; how many went.
pub(crate) fn remove_engine_rules(rules: &dyn Rules, dir: &Path) -> AppResult<usize> {
    let mut removed = 0;
    for _ in 0..ROUNDS {
        let ours: Vec<String> = rules
            .names()?
            .into_iter()
            .filter(|name| is_engine_rule(name, dir))
            .collect();
        if ours.is_empty() {
            return Ok(removed);
        }
        for name in &ours {
            rules.remove(name)?;
            removed += 1;
        }
    }
    Err(AppError::internal(std::io::Error::other(
        "engine firewall rules still present after repeated removal",
    )))
}

/// Removes the engine rules of `dir` from the real firewall (logged; the removal goes on
/// whatever happens here: a leftover rule allows only our deleted engine's inbound).
pub(crate) fn remove_for(dir: &Path) {
    match WindowsFirewall::open().and_then(|fw| remove_engine_rules(&fw, dir)) {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "engine firewall rules removed"),
        Err(err) => tracing::warn!(error = ?err.source, "engine firewall rules not removed"),
    }
}

/// The Windows Firewall policy (`INetFwPolicy2`). Fields drop in order: the policy is released
/// before this thread leaves COM.
struct WindowsFirewall {
    policy: INetFwPolicy2,
    _com: Com,
}

/// This thread's COM apartment, left on drop when it was entered here.
struct Com(bool);

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx of `WindowsFirewall::open`.
            unsafe { CoUninitialize() };
        }
    }
}

impl WindowsFirewall {
    fn open() -> AppResult<Self> {
        // SAFETY: plain COM initialisation of this thread; balanced by `Com` when it succeeded.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // An apartment another caller set up on this thread serves an in-proc object as well.
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            return Err(AppError::internal(windows::core::Error::from_hresult(hr)));
        }
        let com = Com(hr.is_ok());
        // SAFETY: COM is initialised on this thread for the lifetime of `com`.
        let policy = unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(AppError::internal)?;
        Ok(Self { policy, _com: com })
    }
}

impl Rules for WindowsFirewall {
    fn names(&self) -> AppResult<Vec<String>> {
        // SAFETY: live interface pointers; each VARIANT is cleared after its dispatch pointer was
        // cloned (AddRef), so nothing leaks or is released twice.
        unsafe {
            let items: IEnumVARIANT = self
                .policy
                .Rules()
                .and_then(|rules| rules._NewEnum())
                .and_then(|e| e.cast())
                .map_err(AppError::internal)?;
            let mut names = Vec::new();
            loop {
                let mut slot = [VARIANT::default()];
                let mut fetched = 0u32;
                items
                    .Next(&mut slot, &mut fetched)
                    .ok()
                    .map_err(AppError::internal)?;
                if fetched == 0 {
                    return Ok(names);
                }
                let inner = &slot[0].Anonymous.Anonymous;
                let dispatch = match inner.vt {
                    VT_DISPATCH => (*inner.Anonymous.pdispVal).clone(),
                    _ => None,
                };
                VariantClear(&mut slot[0]).map_err(AppError::internal)?;
                if let Some(rule) = dispatch.and_then(|d| d.cast::<INetFwRule>().ok()) {
                    names.push(rule.Name().map_err(AppError::internal)?.to_string());
                }
            }
        }
    }

    fn remove(&self, name: &str) -> AppResult<()> {
        // SAFETY: live interface pointer; the BSTR outlives the call.
        let removed = unsafe {
            self.policy
                .Rules()
                .and_then(|rules| rules.Remove(&BSTR::from(name)))
        };
        match removed {
            Ok(()) => Ok(()),
            Err(err) if err.code() == E_ACCESSDENIED => Err(AppError::internal(err)),
            // Typically the name went with an earlier call; the next look decides.
            Err(err) => {
                tracing::debug!(error = %err, "firewall rule removal failed");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;

    fn dir() -> PathBuf {
        PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer Service")
    }

    /// Lab F-8 (p-live2): the rule sing-tun made for the service's sing-box is ours, in any
    /// spelling of the path; another program's rule, or one for a file elsewhere, is not.
    #[test]
    fn engine_rules_are_told_by_their_path() {
        for name in [
            r"sing-tun (C:\Program Files\VPN Tunnel Enforcer Service\sing-box.exe)",
            r"sing-tun (c:\program files\vpn tunnel enforcer service\sing-box.exe)",
            r"sing-tun (\\?\C:\Program Files\VPN Tunnel Enforcer Service\sing-box.exe)",
            r"sing-tun (C:\Program Files\VPN Tunnel Enforcer Service\engines\1.14.5\sing-box.exe)",
        ] {
            assert!(is_engine_rule(name, &dir()), "{name}");
        }
        for name in [
            r"sing-tun (C:\Program Files\Happ\sing-box.exe)",
            r"sing-tun (C:\Program Files\VPN Tunnel Enforcer Service2\sing-box.exe)",
            r"sing-tun (C:\Program Files\VPN Tunnel Enforcer Service)",
            r"Happ (C:\Program Files\VPN Tunnel Enforcer Service\sing-box.exe)",
            "sing-tun",
        ] {
            assert!(!is_engine_rule(name, &dir()), "{name}");
        }
    }

    /// A firewall whose rule list the test sees (several rules may share a name).
    struct Fake(RefCell<Vec<String>>);

    impl Rules for Fake {
        fn names(&self) -> AppResult<Vec<String>> {
            Ok(self.0.borrow().clone())
        }
        fn remove(&self, name: &str) -> AppResult<()> {
            let mut rules = self.0.borrow_mut();
            if let Some(at) = rules.iter().position(|r| r == name) {
                rules.remove(at);
            }
            Ok(())
        }
    }

    /// Every engine rule goes, duplicates included; every other rule stays.
    #[test]
    fn the_removal_takes_every_engine_rule_and_nothing_else() {
        let ours = r"sing-tun (C:\Program Files\VPN Tunnel Enforcer Service\sing-box.exe)";
        let fw = Fake(RefCell::new(vec![
            ours.into(),
            "Happ".into(),
            ours.into(),
            r"sing-tun (C:\Tools\sing-box.exe)".into(),
        ]));
        assert_eq!(remove_engine_rules(&fw, &dir()).unwrap(), 2);
        assert_eq!(
            *fw.0.borrow(),
            ["Happ", r"sing-tun (C:\Tools\sing-box.exe)"]
        );
        assert_eq!(remove_engine_rules(&fw, &dir()).unwrap(), 0);
    }
}
