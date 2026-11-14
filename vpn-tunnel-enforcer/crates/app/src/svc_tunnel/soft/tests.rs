//! The «Не через прокси» follower on throw-away places: an in-memory system proxy and an
//! `HKCU\Software\VPNTE-Test-*` key instead of the user's environment. Nothing here touches the
//! real system proxy, and only this test changes the process-wide list.
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use vpnte_automation::hardening;
use vpnte_automation::tweaks::sysproxy::Bypass;
use vpnte_automation::tweaks::{SoftSystem, SystemProxy};
use vpnte_winnet::env::{EnvValue, UserEnv};
use vpnte_winnet::registry::{self, Hive, View};
use vpnte_winnet::sysproxy::ProxyConfig;

use super::*;

/// An in-memory system proxy whose writes fail while `.1` is set.
#[derive(Debug, Default)]
struct MemProxy(Mutex<ProxyConfig>, AtomicBool);

impl SystemProxy for MemProxy {
    fn read(&self) -> io::Result<ProxyConfig> {
        Ok(self.0.lock().clone())
    }
    fn write(&self, config: &ProxyConfig) -> io::Result<()> {
        if self.1.load(Ordering::Relaxed) {
            return Err(io::Error::other("write refused"));
        }
        *self.0.lock() = config.clone();
        Ok(())
    }
}

/// A throw-away journal dir and registry root, removed on drop.
struct Place {
    dir: PathBuf,
    key: String,
}

impl Place {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple();
        let dir = std::env::temp_dir().join(format!("vpnte-app-soft-follow-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            key: format!(r"Software\VPNTE-Test-soft-follow-{id}"),
        }
    }

    fn system(&self, proxy: &Arc<MemProxy>) -> SoftSystem {
        SoftSystem {
            proxy: proxy.clone(),
            env: UserEnv::under(self.key.clone()),
            git: None,
            gradle_home: None,
            studio_root: None,
            broadcast: false,
            check_user: false,
        }
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.key, View::Native);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn users_proxy() -> ProxyConfig {
    ProxyConfig {
        use_proxy: true,
        server: "proxy.example:3128".into(),
        bypass: "<local>".into(),
        ..ProxyConfig::default()
    }
}

/// The items of `sites` in each reader's syntax, as the keeper hands them over.
fn list(sites: &[&str]) -> Bypass {
    Bypass {
        proxy_override: sites
            .iter()
            .flat_map(|s| [s.to_string(), format!("*.{s}")])
            .collect(),
        no_proxy: sites
            .iter()
            .flat_map(|s| [s.to_string(), format!(".{s}")])
            .collect(),
    }
}

/// pbypass-a1/b1: the engine re-reads the rules at every restart, crash restarts included, so
/// an entry the rules no longer justify leaves the running session at once. Another program's
/// proxy stays the user's to take back, and «Вернуть» brings the list skipped meanwhile
/// (fixlists-a1); a failed write is reported for a retry (fixlists-b6); an ended session is not
/// applied again.
#[tokio::test]
async fn the_running_session_follows_the_list() {
    let place = Place::new();
    let proxy = Arc::new(MemProxy(Mutex::new(users_proxy()), AtomicBool::new(false)));
    let journal = Arc::new(Journal::open(&place.dir, hardening::admit));
    let soft = Soft::new(journal.clone(), place.system(&proxy));
    let addr = HostPort::parse("127.0.0.1:20811").unwrap();
    let session = Applied {
        soft: soft.clone(),
        journal,
        addr: addr.clone(),
        kind: ProxyKind::Http,
        dev: DevTargets::default(),
    };
    let none = DevTargets::default();

    sysproxy::set_bypass(list(&["bank.example", "shop.example"]));
    soft.apply(addr.clone(), ProxyKind::Http, none)
        .await
        .unwrap();
    assert_eq!(bring_up_to_date(&session).await, Follow::Current);

    // The user moved bank.example to the VPN: the next list drops it.
    sysproxy::set_bypass(list(&["shop.example"]));
    assert_eq!(bring_up_to_date(&session).await, Follow::Applied);
    let want = sysproxy::applied_with(&addr, &list(&["shop.example"]));
    assert_eq!(*proxy.0.lock(), want);
    let env = UserEnv::under(place.key.clone());
    let no_proxy = env.get("NO_PROXY").unwrap();
    assert!(
        matches!(&no_proxy, Some(EnvValue::Plain(v)) if v.ends_with(",shop.example,.shop.example")),
        "{no_proxy:?}"
    );
    assert_eq!(bring_up_to_date(&session).await, Follow::Current);

    // Another program took the proxy over: left to the user.
    *proxy.0.lock() = users_proxy();
    sysproxy::set_bypass(list(&["other.example"]));
    assert_eq!(bring_up_to_date(&session).await, Follow::NotOurs);
    assert_eq!(*proxy.0.lock(), users_proxy());

    // «Вернуть»: the proxy comes back with the list changed meanwhile, not the old one.
    let took = retake(&soft, Some(&session)).await.unwrap();
    assert_eq!(took, Follow::Applied);
    let want = sysproxy::applied_with(&addr, &list(&["other.example"]));
    assert_eq!(*proxy.0.lock(), want);
    assert_eq!(bring_up_to_date(&session).await, Follow::Current);

    // A write that fails is undone and reported for a retry, which applies it.
    proxy.1.store(true, Ordering::Relaxed);
    sysproxy::set_bypass(list(&["retry.example"]));
    assert_eq!(bring_up_to_date(&session).await, Follow::Failed);
    assert_eq!(*proxy.0.lock(), want, "the old list stays");
    proxy.1.store(false, Ordering::Relaxed);
    assert_eq!(bring_up_to_date(&session).await, Follow::Applied);
    let want = sysproxy::applied_with(&addr, &list(&["retry.example"]));
    assert_eq!(*proxy.0.lock(), want);

    // The session ended: its rollback is final.
    soft.rollback().await.unwrap();
    sysproxy::set_bypass(list(&["late.example"]));
    assert_eq!(bring_up_to_date(&session).await, Follow::Current);
    assert_eq!(*proxy.0.lock(), users_proxy());
    assert_eq!(env.get("NO_PROXY").unwrap(), None);
    sysproxy::set_bypass(Bypass::default());
}

/// fixlists-b6: a failed write is tried again after a pause that doubles, a few times.
#[test]
fn a_failed_write_is_tried_again_a_few_times() {
    assert_eq!(retry_after(0), None);
    assert_eq!(retry_after(1), Some(RETRY));
    assert_eq!(retry_after(2), Some(RETRY * 2));
    assert_eq!(retry_after(RETRIES), Some(RETRY * 2u32.pow(RETRIES - 1)));
    assert_eq!(retry_after(RETRIES + 1), None);
}
