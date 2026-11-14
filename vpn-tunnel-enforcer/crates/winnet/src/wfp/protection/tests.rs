//! State-machine tests of [`Protection`] over a fake backend (firewall-recovery §6.5, §7.2).
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use vpnte_base::types::{KillSwitchLevel, Notice};
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::{Owner, Protection};
use crate::wfp::backend::{Backend, Census, RemoveReport};
use crate::wfp::engine::{Lifetime, ProviderInfo, WfpError};
use crate::wfp::model::{
    Conn, EnginePaths, ExceptionTarget, KillSwitchException, KillSwitchState, ProtectionError,
    ProtectionSettings,
};
use crate::wfp::spec::{AppId, Cond, FilterSpec, Layer};

/// EPT_S_NOT_REGISTERED: what a call returns after BFE restarted.
const RPC_LOST: WfpError = WfpError {
    op: "fake",
    code: 1753,
};
/// FWP_E_TXN_IN_PROGRESS: any other WFP failure.
const FAIL: WfpError = WfpError {
    op: "fake",
    code: 0x8032_000E,
};

#[derive(Default)]
struct World {
    next_id: u64,
    dynamic: BTreeMap<u64, FilterSpec>,
    persistent: BTreeMap<u64, FilterSpec>,
    fail_dynamic: bool,
    fail_persistent: bool,
    /// The next call finds the dynamic session gone (BFE restart).
    lose_session: bool,
    missing: Vec<PathBuf>,
    /// IPv4 exception networks installed after every dynamic change, in order.
    exception_history: Vec<Vec<String>>,
    /// Filters deleted and added by each change.
    churn: Vec<(usize, usize)>,
    /// The lifetime of the last session-set change (`None` before the first).
    lifetime: Option<Lifetime>,
    provider: Option<ProviderInfo>,
}

impl World {
    fn apply(&mut self, persistent: bool, delete: &[u64], add: &[FilterSpec]) -> Vec<u64> {
        self.churn.push((delete.len(), add.len()));
        let first = self.next_id + 1;
        self.next_id += add.len() as u64;
        let ids: Vec<u64> = (first..=self.next_id).collect();
        let set = match persistent {
            true => &mut self.persistent,
            false => &mut self.dynamic,
        };
        for id in delete {
            set.remove(id);
        }
        set.extend(ids.iter().copied().zip(add.iter().cloned()));
        ids
    }
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<World>>);

impl Fake {
    fn groups(&self, persistent: bool) -> Vec<&'static str> {
        let w = self.0.lock();
        let set = match persistent {
            true => &w.persistent,
            false => &w.dynamic,
        };
        let mut names: Vec<_> = set.values().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        names
    }
    fn has(&self, persistent: bool, name: &str) -> bool {
        self.groups(persistent).contains(&name)
    }
    fn lost(w: &mut World) -> bool {
        if w.lose_session {
            w.lose_session = false;
            w.dynamic.clear();
            return true;
        }
        false
    }
}

impl Backend for Fake {
    fn app_id(&mut self, exe: &Path) -> Result<Arc<AppId>, WfpError> {
        match self.0.lock().missing.iter().any(|m| m == exe) {
            true => Err(WfpError {
                op: "fake",
                code: 2,
            }),
            false => Ok(Arc::new(AppId::from_bytes(
                exe.to_string_lossy().as_bytes().to_vec(),
            ))),
        }
    }
    fn provider(&mut self) -> Result<Option<ProviderInfo>, WfpError> {
        Ok(self.0.lock().provider.clone())
    }
    fn ensure(&mut self, service: Option<&str>) -> Result<u16, WfpError> {
        let mut w = self.0.lock();
        if w.provider.is_none() {
            w.provider = Some(ProviderInfo {
                flags: 1,
                service_name: service.map(str::to_owned),
            });
        }
        Ok(65533)
    }
    fn change_session(
        &mut self,
        lifetime: Lifetime,
        delete: Option<&[u64]>,
        add: &[FilterSpec],
    ) -> Result<Vec<u64>, WfpError> {
        let mut w = self.0.lock();
        if Self::lost(&mut w) {
            return Err(RPC_LOST);
        }
        if w.fail_dynamic {
            return Err(FAIL);
        }
        w.lifetime = Some(lifetime);
        let all: Vec<u64> = w.dynamic.keys().copied().collect();
        let ids = w.apply(false, delete.unwrap_or(&all), add);
        let nets = w
            .dynamic
            .values()
            .filter(|s| s.name == "exception_ip" && s.layer == Layer::Connect4)
            .filter_map(|s| match &s.conds[..] {
                [Cond::RemoteV4(n)] => Some(n.to_string()),
                _ => None,
            })
            .collect();
        w.exception_history.push(nets);
        Ok(ids)
    }
    fn change_persistent(
        &mut self,
        delete: Option<&[u64]>,
        add: &[FilterSpec],
    ) -> Result<Vec<u64>, WfpError> {
        let mut w = self.0.lock();
        if w.fail_persistent {
            return Err(FAIL);
        }
        let all: Vec<u64> = w.persistent.keys().copied().collect();
        Ok(w.apply(true, delete.unwrap_or(&all), add))
    }
    fn census(&mut self) -> Result<Census, WfpError> {
        let mut w = self.0.lock();
        if Self::lost(&mut w) {
            return Err(RPC_LOST);
        }
        Ok(Census {
            dynamic: w.dynamic.keys().copied().collect(),
            persistent: w.persistent.keys().copied().collect(),
            session_block: w
                .dynamic
                .values()
                .any(|s| s.name == "block4" && s.layer == Layer::Connect4),
        })
    }
    fn close_dynamic(&mut self) {
        let mut w = self.0.lock();
        // Static filters stay when their session closes.
        if w.lifetime != Some(Lifetime::Static) {
            w.dynamic.clear();
        }
    }
    fn remove_all(&mut self) -> Result<RemoveReport, WfpError> {
        let mut w = self.0.lock();
        let filters = w.dynamic.len() + w.persistent.len();
        w.dynamic.clear();
        w.persistent.clear();
        w.provider = None;
        Ok(RemoveReport {
            filters,
            sublayer: true,
            provider: true,
        })
    }
}

fn protection(level: KillSwitchLevel) -> (Protection, Fake) {
    let fake = Fake::default();
    (over(&fake, level, Owner::App), fake)
}

/// The helper service's owner, as the tests name it.
fn service_owner() -> Owner {
    Owner::Service("VpnteTestService".into())
}

/// A new owner process over the same filters (a restart after a crash, say).
fn over(fake: &Fake, level: KillSwitchLevel, owner: Owner) -> Protection {
    let engines = EnginePaths {
        singbox: r"C:\vpnte\resources\sing-box.exe".into(),
        xray: None,
        external_proxy: None,
    };
    let settings = ProtectionSettings {
        level,
        ..ProtectionSettings::default()
    };
    Protection::with_backend(
        engines,
        r"C:\vpnte\vpnte.exe".into(),
        settings,
        owner,
        Box::new(fake.clone()),
    )
}

/// A protection where "Always" is in force (the helper service owns it).
fn with_service(level: KillSwitchLevel) -> (Protection, Fake) {
    let fake = Fake::default();
    (over(&fake, level, service_owner()), fake)
}

/// Persist callback that records every saved level.
#[derive(Clone, Default)]
struct Store {
    saved: Arc<Mutex<Vec<ProtectionSettings>>>,
    fail: bool,
}

impl Store {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }
    fn persist(&self, s: &ProtectionSettings) -> AppResult<()> {
        if self.fail {
            return Err(AppError::new(ErrorKind::Internal));
        }
        self.saved.lock().push(s.clone());
        Ok(())
    }
    fn levels(&self) -> Vec<KillSwitchLevel> {
        self.saved.lock().iter().map(|s| s.level).collect()
    }
}

fn drain(rx: &mut tokio::sync::broadcast::Receiver<Notice>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(n) = rx.try_recv() {
        out.push(n.body.map(|b| b.key.into_owned()).unwrap_or_default());
    }
    out
}

fn ip(id: &str, value: &str) -> KillSwitchException {
    let target = ExceptionTarget::Ip(crate::wfp::validate::parse_ip_or_cidr(value).unwrap());
    KillSwitchException {
        id: id.into(),
        target,
        label: "label".into(),
    }
}

/// AT-03-001 / AT-03-003 (ks-a arming): "If the VPN drops" leaves a first connect alone (only
/// leak protection's DNS / IPv6 block and the TUN address permit, review D1 / R1), blocks
/// everything once the TUN is up, keeps the block after a drop (quietly: the tunnel's paused
/// state tells the user) and goes away on disconnect.
#[test]
fn standard_session_lifecycle() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    let mut rx = p.notices();
    p.startup().unwrap();
    assert!(fake.groups(false).is_empty() && fake.groups(true).is_empty());
    assert_eq!(p.status().kill_switch, KillSwitchState::Armed);
    assert!(p.session_guarded());

    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert!(
        !fake.has(false, "block4"),
        "not armed before the first tunnel-up"
    );
    assert!(fake.has(false, "dns") && fake.has(false, "tun_addr"));
    assert_eq!(p.status().kill_switch, KillSwitchState::Armed);
    p.tun_up(7).unwrap();
    assert!(fake.has(false, "block4") && fake.has(false, "tun") && fake.has(false, "dns"));
    assert!(!fake.has(false, "tun_addr"));
    assert_eq!(p.status().kill_switch, KillSwitchState::Engaged);

    p.tun_lost().unwrap();
    assert!(fake.has(false, "block4") && fake.has(false, "dns") && !fake.has(false, "tun"));
    let status = p.status();
    assert_eq!(
        (status.conn, status.kill_switch),
        (Conn::Dropped, KillSwitchState::Blocking)
    );
    assert!(drain(&mut rx).is_empty(), "no notice of its own");

    p.disconnected().unwrap();
    assert!(fake.groups(false).is_empty());
    assert_eq!(p.status().dynamic_filters, Some(0));
    assert_eq!(p.status().kill_switch, KillSwitchState::Armed);
}

/// ks-a (research 5.3 "first connect fails", tunnel capture): a connect that never came up
/// leaves the internet alone; with leak protection off nothing is installed at all.
#[test]
fn first_connect_that_never_came_up_leaves_the_internet_alone() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    let mut toggles = p.settings().toggles();
    toggles.leak_protection = false;
    p.update_settings(toggles).unwrap();
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert!(fake.groups(false).is_empty());
    p.tun_lost().unwrap();
    assert!(
        fake.groups(false).is_empty(),
        "a TUN that never came up arms nothing"
    );
    p.disconnected().unwrap();
    assert!(fake.groups(false).is_empty());
}

/// ks-a (research 5.3 "planned reconnect", tunnel capture): a server switch or settings restart
/// (preserved stop, then a new `connect_begin` / `tun_up`) keeps the block with no gap; the new
/// TUN's permit replaces the old one.
#[test]
fn planned_reconnect_keeps_the_block_without_a_gap() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    p.tun_up(7).unwrap();
    let blocks = |f: &Fake| -> Vec<u64> {
        let w = f.0.lock();
        let ids = w
            .dynamic
            .iter()
            .filter(|(_, s)| s.name.starts_with("block"));
        ids.map(|(id, _)| *id).collect()
    };
    let before = blocks(&fake);
    assert!(!before.is_empty());
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert_eq!(blocks(&fake), before, "held through the gap");
    assert_eq!(p.status().kill_switch, KillSwitchState::Blocking);
    p.tun_up(8).unwrap();
    assert_eq!(blocks(&fake), before, "the same filters, never re-created");
    assert!(fake.has(false, "tun"));
}

const TUN_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 168, 250, 253);

/// Review D2 / E-D3: the TUN is dual-stack with `dns_mode: native` exactly when our filters
/// guard the session (kill switch on, or leak protection).
#[test]
fn session_guard_follows_the_settings() {
    let (p, _) = protection(KillSwitchLevel::Off);
    assert!(p.session_guarded(), "leak protection is on by default");
    let mut toggles = p.settings().toggles();
    toggles.leak_protection = false;
    p.update_settings(toggles).unwrap();
    assert!(!p.session_guarded());
    p.set_level(KillSwitchLevel::Strict, &|_| Ok(())).unwrap();
    assert!(p.session_guarded());
}

/// B2 / AT-03-010 with the helper service: "Always" is persistent from startup and survives
/// disconnect and shutdown, quietly (the tunnel's state tells the user).
#[test]
fn strict_survives_disconnect_and_shutdown() {
    let (p, fake) = with_service(KillSwitchLevel::Strict);
    let mut rx = p.notices();
    p.startup().unwrap();
    assert!(fake.has(true, "block4") && fake.has(true, "engine") && fake.groups(false).is_empty());
    p.connect_begin(&[PathBuf::from(r"C:\Happ\core\xray.exe")], &[])
        .unwrap();
    assert_eq!(fake.groups(false), ["dns", "session"]);
    p.tun_up(9).unwrap();
    assert_eq!(fake.groups(false), ["dns", "session", "tun"]);
    p.disconnected().unwrap();
    p.shutdown();
    assert!(fake.has(true, "block6") && fake.groups(false).is_empty());
    assert_eq!(p.status().kill_switch, KillSwitchState::Blocking);
    assert!(drain(&mut rx).is_empty());
}

/// ks-a / F-190 departure: without the helper service a stored "strict" works as "If the VPN
/// drops": persistent leftovers of an earlier strict run go at startup, nothing persistent is
/// installed, the stored value stays, and the service flag brings "Always" back.
#[test]
fn strict_without_the_service_works_as_on_drop() {
    let (p, fake) = protection(KillSwitchLevel::Strict);
    let leftover = crate::wfp::spec::block4();
    fake.0.lock().apply(true, &[], &leftover);
    p.startup().unwrap();
    assert!(fake.groups(true).is_empty(), "leftovers removed");
    assert_eq!(p.settings().level, KillSwitchLevel::Strict);
    assert_eq!(p.level_in_force(), KillSwitchLevel::Standard);
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert!(!fake.has(false, "block4"));
    p.tun_up(5).unwrap();
    assert!(fake.has(false, "block4") && fake.groups(true).is_empty());
    p.disconnected().unwrap();
    assert!(fake.groups(false).is_empty() && fake.groups(true).is_empty());
    let service = over(&fake, KillSwitchLevel::Strict, service_owner());
    service.startup().unwrap();
    assert!(fake.has(true, "block4"), "the service keeps Always");
}

/// §6.5: entering "Always" saves the choice before any effect; leaving it saves last.
#[test]
fn strict_persistence_order() {
    let (p, fake) = with_service(KillSwitchLevel::Off);
    p.startup().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (f, s) = (fake.clone(), seen.clone());
    let persist = move |st: &ProtectionSettings| -> AppResult<()> {
        s.lock().push((st.level, f.0.lock().persistent.len()));
        Ok(())
    };
    p.set_level(KillSwitchLevel::Strict, &persist).unwrap();
    assert!(fake.has(true, "block4"));
    p.set_level(KillSwitchLevel::Off, &persist).unwrap();
    assert!(fake.groups(true).is_empty());
    assert_eq!(
        *seen.lock(),
        [(KillSwitchLevel::Strict, 0), (KillSwitchLevel::Off, 0)]
    );
}

/// AT-03-012 ("does not report a successful level change if firewall disable fails"): a
/// failure while leaving strict keeps strict, nothing is saved, the blocks stay.
#[test]
fn leaving_strict_fails_closed() {
    let (p, fake) = with_service(KillSwitchLevel::Strict);
    p.startup().unwrap();
    fake.0.lock().fail_persistent = true;
    let store = Store::default();
    let err = p
        .set_level(KillSwitchLevel::Off, &|s| store.persist(s))
        .unwrap_err();
    assert!(matches!(err, ProtectionError::Wfp { .. }));
    assert_eq!(p.settings().level, KillSwitchLevel::Strict);
    assert!(store.levels().is_empty());
    assert!(fake.has(true, "block4"));

    fake.0.lock().fail_persistent = false;
    let failing = Store::failing();
    let err = p
        .set_level(KillSwitchLevel::Off, &|s| failing.persist(s))
        .unwrap_err();
    assert!(matches!(err, ProtectionError::Persist(_)));
    assert_eq!(p.settings().level, KillSwitchLevel::Strict);
    assert!(fake.has(true, "block4"), "a failed save re-installs strict");
}

/// AT-03-003 (§7.2): an engage failure leaves the level `off` and stores nothing; "If the VPN
/// drops" set while connected engages at once (the tunnel is up: the session is armed).
#[test]
fn level_switch_while_connected() {
    let (p, fake) = protection(KillSwitchLevel::Off);
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    p.tun_up(3).unwrap();
    assert!(
        fake.has(false, "block6") && !fake.has(false, "block4"),
        "leak protection only"
    );
    fake.0.lock().fail_dynamic = true;
    let store = Store::default();
    assert!(
        p.set_level(KillSwitchLevel::Standard, &|s| store.persist(s))
            .is_err()
    );
    assert_eq!(p.settings().level, KillSwitchLevel::Off);
    assert!(store.levels().is_empty());
    assert!(!fake.has(false, "block4"));

    fake.0.lock().fail_dynamic = false;
    p.set_level(KillSwitchLevel::Standard, &|s| store.persist(s))
        .unwrap();
    assert_eq!(store.levels(), [KillSwitchLevel::Standard]);
    assert!(fake.has(false, "block4") && fake.has(false, "tun"));
    assert_eq!(p.status().kill_switch, KillSwitchState::Engaged);
}

/// AT-03-008 ("compensates the real exception set if store persistence fails"): WFP sees
/// `['192.0.2.1']` then `[]`, the list stays empty.
#[test]
fn exception_persist_failure_reapplies_previous_set() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    fake.0.lock().exception_history.clear();
    let failing = Store::failing();
    let err = p
        .add_exception(ip("a", "192.0.2.1"), &|s| failing.persist(s))
        .unwrap_err();
    assert!(matches!(err, ProtectionError::Persist(_)));
    assert_eq!(
        fake.0.lock().exception_history,
        [vec!["192.0.2.1/32".to_string()], vec![]]
    );
    assert!(p.settings().exceptions.is_empty());
}

/// AT-03-008 ("serializes 50 concurrent changes"): the WFP layer sees cumulative lists of
/// length 1..=50 in order and the store ends with 50.
#[test]
fn fifty_concurrent_adds_are_serialized() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    fake.0.lock().exception_history.clear();
    let p = Arc::new(p);
    let store = Store::default();
    let threads: Vec<_> = (0..50u32)
        .map(|i| {
            let (p, store) = (p.clone(), store.clone());
            std::thread::spawn(move || {
                let e = ip(&format!("e{i}"), &format!("198.51.100.{}", i + 1));
                p.add_exception(e, &|s| store.persist(s)).unwrap();
            })
        })
        .collect();
    threads.into_iter().for_each(|t| t.join().unwrap());
    let lens: Vec<usize> = fake
        .0
        .lock()
        .exception_history
        .iter()
        .map(Vec::len)
        .collect();
    assert_eq!(lens, (1..=50).collect::<Vec<_>>());
    assert_eq!(
        store.saved.lock().last().map(|s| s.exceptions.len()),
        Some(50)
    );
    assert_eq!(p.settings().exceptions.len(), 50);
}

/// B34 / AT-03-009: a list from an import is validated before any effect: `/0`, a relative
/// path, a duplicate, an unknown id on removal.
#[test]
fn exception_lists_are_validated_before_effects() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    let store = Store::default();
    let wide = KillSwitchException {
        target: ExceptionTarget::Ip("0.0.0.0/0".parse().unwrap()),
        ..ip("w", "10.0.0.1")
    };
    let relative = KillSwitchException {
        target: ExceptionTarget::App("relative/x.exe".into()),
        ..ip("r", "10.0.0.1")
    };
    for bad in [
        vec![wide],
        vec![relative],
        vec![ip("a", "192.0.2.1/24"), ip("b", "192.0.2.0/24")],
    ] {
        let err = p.set_exceptions(bad, &|s| store.persist(s)).unwrap_err();
        assert!(matches!(err, ProtectionError::Validation(_)), "{err}");
    }
    let err = p
        .remove_exception("nope", &|s| store.persist(s))
        .unwrap_err();
    assert_eq!(err.msg().key, "winnet.wfp.exception.notFound");
    assert!(store.levels().is_empty() && fake.groups(false).is_empty());
}

/// owner-decisions §2.7 delta 3: a stored app exception whose file vanished is skipped for the
/// engage (less is allowed), listed in the status and announced once.
#[test]
fn vanished_app_exception_is_skipped() {
    let gone = PathBuf::from(r"C:\Tools\gone.exe");
    let stale = KillSwitchException {
        id: "gone".into(),
        target: ExceptionTarget::App(gone.clone()),
        label: "Old tool".into(),
    };
    let fake = Fake::default();
    fake.0.lock().missing.push(gone);
    let settings = ProtectionSettings {
        level: KillSwitchLevel::Standard,
        exceptions: vec![stale, ip("net", "192.0.2.0/24")],
        ..ProtectionSettings::default()
    };
    let engines = EnginePaths {
        singbox: r"C:\vpnte\resources\sing-box.exe".into(),
        ..EnginePaths::default()
    };
    let p = Protection::with_backend(
        engines,
        r"C:\vpnte\vpnte.exe".into(),
        settings,
        Owner::App,
        Box::new(fake.clone()),
    );
    let store = Store::default();
    let mut rx = p.notices();
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    p.tun_up(5).unwrap();
    assert!(!fake.has(false, "exception_app") && fake.has(false, "exception_ip"));
    assert_eq!(drain(&mut rx), ["winnet.wfp.notice.exceptionSkipped"]);
    assert_eq!(p.status().skipped_exceptions, ["gone"]);
    p.remove_exception("net", &|s| store.persist(s)).unwrap();
    assert_eq!(
        p.settings().exceptions.len(),
        1,
        "a list with the stale entry is still accepted"
    );
    p.remove_exception("gone", &|s| store.persist(s)).unwrap();
    assert!(p.status().skipped_exceptions.is_empty());
}

/// §6.5: a missing per-session program refuses the connect before anything changes.
#[test]
fn missing_session_program_refuses_connect() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    let missing = PathBuf::from(r"C:\Happ\core\missing.exe");
    fake.0.lock().missing.push(missing.clone());
    let err = p
        .connect_begin(std::slice::from_ref(&missing), &[])
        .unwrap_err();
    assert!(matches!(&err, ProtectionError::EngineMissing(path) if *path == missing));
    assert_eq!(p.status().conn, Conn::Disconnected);
    assert!(fake.groups(false).is_empty());
}

/// §6.5 watchdog: a BFE restart drops the dynamic session; the next tick reopens and
/// re-applies; a filter deleted behind our back is restored too.
#[test]
fn watchdog_reapplies_after_bfe_restart() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    p.tun_up(11).unwrap();
    let full = fake.0.lock().dynamic.len();
    fake.0.lock().lose_session = true;
    p.watchdog_tick();
    assert_eq!(fake.0.lock().dynamic.len(), full);
    assert_eq!(p.status().kill_switch, KillSwitchState::Engaged);

    let first = *fake.0.lock().dynamic.keys().next().unwrap();
    fake.0.lock().dynamic.remove(&first);
    p.watchdog_tick();
    assert_eq!(fake.0.lock().dynamic.len(), full);
    p.watchdog_tick();
    assert!(p.status().last_verified.is_some());
}

/// §6.7: the maintenance reset is refused while connected; in strict it removes everything and
/// switches the level off.
#[test]
fn reset_network_protection() {
    let (p, fake) = with_service(KillSwitchLevel::Strict);
    p.startup().unwrap();
    p.connect_begin(&[], &[]).unwrap();
    let store = Store::default();
    assert!(matches!(
        p.reset(&|s| store.persist(s)),
        Err(ProtectionError::SessionActive)
    ));
    p.disconnected().unwrap();
    let report = p.reset(&|s| store.persist(s)).unwrap();
    assert!(report.filters > 0 && report.sublayer && report.provider);
    assert!(fake.groups(true).is_empty());
    assert_eq!(
        (p.settings().level, store.levels()),
        (KillSwitchLevel::Off, vec![KillSwitchLevel::Off])
    );
}

/// §6.5 update_settings: public Wi-Fi compatibility off adds the DNS block to the strict set
/// outside a session; a failed apply keeps the previous switches.
#[test]
fn switches_apply_or_stay() {
    let (p, fake) = with_service(KillSwitchLevel::Strict);
    p.startup().unwrap();
    assert!(!fake.has(true, "dns"), "LAN resolvers stay reachable");
    let mut toggles = p.settings().toggles();
    toggles.public_wifi_compat = false;
    p.update_settings(toggles).unwrap();
    assert!(fake.has(true, "dns"));
    fake.0.lock().fail_persistent = true;
    toggles.allow_lan = false;
    assert!(p.update_settings(toggles).is_err());
    assert!(p.settings().allow_lan && fake.has(true, "lan"));
    assert_eq!(p.status().kill_switch, KillSwitchState::Failed);
}

/// Review R2: a change deletes and adds only the filters that differ (one transaction each):
/// an IPv4 exception is a C4 + A4 pair, a new TUN LUID replaces the four `tun` permits.
#[test]
fn changes_touch_only_what_differs() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    p.tun_up(7).unwrap();
    let store = Store::default();
    fake.0.lock().churn.clear();
    p.add_exception(ip("a", "192.0.2.1"), &|s| store.persist(s))
        .unwrap();
    p.tun_up(8).unwrap();
    p.remove_exception("a", &|s| store.persist(s)).unwrap();
    p.tun_up(8).unwrap();
    assert_eq!(fake.0.lock().churn, [(0, 2), (4, 4), (2, 0)]);
}

mod owners;
