//! Tests of the three list pages over a throw-away backend (temp data dir, fake tunnel): no
//! network, no real dialog, no browser, no system change.
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{broadcast, watch};
use vpnte_automation::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, NoticeCategory, OpError,
    RuntimeId, SessionInfo, SwitchError,
};
use vpnte_automation::scheduler::{Scheduler, Schedules};
use vpnte_base::types::{AdaptiveMode, ClientDevice, Notice, Owner};
use vpnte_base::{AppError, ErrorKind};
use vpnte_core::store::Store;
use vpnte_servers::store::AddTarget;
use vpnte_tunnel::fsm::TunnelState;
use vpnte_ui::schedule::{
    Capture, HhMm, ScheduleApi, ScheduleEntry, ScheduleInput, ScheduleSnapshot, Upstream,
};
use vpnte_ui::split_tunnel::{AppKind, AppRule, SplitApp, SplitSnapshot, SplitTunnelApi};
use vpnte_ui::traffic_history::{DomainRow, SiteInfo, TrafficHistoryApi, TrafficSnapshot};
use vpnte_ui::widgets::Load;

use super::{ScheduleService, SplitService, TrafficService};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};
use crate::services::Backend;
use crate::svc_tunnel::DomainHistory;
use vpnte_tunnel::api::TunStatus;

/// Waits (at most 10 s) until the pushed state satisfies `what` and returns it.
async fn until<T: Clone>(rx: &mut watch::Receiver<T>, what: impl Fn(&T) -> bool) -> T {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            {
                let now = rx.borrow_and_update();
                if what(&now) {
                    return now.clone();
                }
            }
            rx.changed().await.expect("publisher alive");
        }
    })
    .await
    .expect("state reached in time")
}

/// The message key of an error, with its kind.
fn refusal(err: &AppError) -> (ErrorKind, String) {
    (err.kind, err.user_msg().key.to_string())
}

fn leaf_keys(prefix: &str, value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                leaf_keys(&key, v, out);
            }
        }
        _ => {
            out.insert(prefix.to_owned());
        }
    }
}

fn keys_of(json: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    leaf_keys(
        "",
        &serde_json::from_str(json).expect("valid JSON"),
        &mut out,
    );
    out
}

/// AT-09-011: the fragments are valid JSON with the same keys in ru and en, all under
/// `app.lists`; every `app.lists.*` key the sources name exists, and the fragment and the keys
/// reused from other layers are registered by `svc_core::locale_layers`.
#[test]
fn locales_paired_and_complete() {
    let (ru, en) = (
        include_str!("../../locales/app-lists.ru.json"),
        include_str!("../../locales/app-lists.en.json"),
    );
    let (ru_keys, en_keys) = (keys_of(ru), keys_of(en));
    assert_eq!(ru_keys, en_keys);
    assert!(ru_keys.iter().all(|k| k.starts_with("app.lists.")));
    let sources = [
        include_str!("mod.rs"),
        include_str!("schedule.rs"),
        include_str!("split.rs"),
        include_str!("traffic.rs"),
    ];
    let named: BTreeSet<&str> = sources
        .iter()
        .flat_map(|src| src.split('"').skip(1).step_by(2))
        .filter(|s| s.starts_with("app.lists."))
        .collect();
    // Every key of the fragment is named in the sources (no dead keys) and the reverse below.
    assert_eq!(named.len(), ru_keys.len(), "{named:?}");
    for key in &named {
        assert!(ru_keys.contains(*key), "missing {key}");
    }
    let layers = crate::svc_core::locale_layers();
    assert!(layers.contains(&(ru, en)));
    let (mut all_ru, mut all_en) = (BTreeSet::new(), BTreeSet::new());
    for (ru, en) in &layers {
        all_ru.extend(keys_of(ru));
        all_en.extend(keys_of(en));
    }
    for key in [
        "app.settings.dialog.pickApp",
        "app.settings.dialog.programs",
        "app.settings.dialog.allFiles",
        "app.logs.trafficUnavailable",
        "automation.scheduler.notFound",
        "automation.scheduler.profileRequired",
        "engine.routing.split.badName",
        "engine.routing.split.badPath",
    ] {
        assert!(all_ru.contains(key) && all_en.contains(key), "{key}");
    }
}

fn hhmm(hour: u16, minute: u16) -> HhMm {
    HhMm::new(hour, minute).expect("valid time")
}

fn input(name: &str, enabled: bool, upstream: Upstream, profile_id: &str) -> ScheduleInput {
    ScheduleInput {
        name: name.into(),
        enabled,
        days: vec![1, 3, 5],
        start: hhmm(22, 0),
        end: hhmm(6, 30),
        profile_id: profile_id.into(),
        capture: Capture::Proxy,
        upstream,
    }
}

fn entries(snapshot: &ScheduleSnapshot) -> Vec<ScheduleEntry> {
    match &snapshot.schedules {
        Load::Ready(list) => list.clone(),
        other => panic!("schedules not ready: {other:?}"),
    }
}

fn schedule_backend(dir: &TempDir) -> Arc<Backend> {
    backend(dir, FakeTunnel::new(false))
}

/// The page over a scheduler of its own `schedules.json` (its reconcile task is the
/// automation's and is not run here: `Idle` is never asked to connect).
fn schedule_api(backend: &Arc<Backend>) -> ScheduleService<Idle> {
    let store = Arc::new(Store::<Schedules>::open(&backend.dirs.root));
    let scheduler = Arc::new(Scheduler::new(store.clone(), Arc::new(Idle)));
    ScheduleService::start(backend.clone(), store, scheduler, false)
}

/// A coordinator with no tunnel behind it (the reconcile task does not run in these tests).
struct Idle;

impl Coordinator for Idle {
    fn session(&self) -> Option<SessionInfo> {
        None
    }
    fn left_by(&self) -> Option<Owner> {
        None
    }

    fn busy(&self) -> bool {
        false
    }

    fn connect(
        &self,
        _owner: Owner,
        _req: ConnectRequest,
    ) -> impl Future<Output = Result<ConnectOutcome, OpError>> + Send {
        std::future::ready(Err(OpError::Conflict))
    }

    fn disconnect(&self, _owner: Owner) -> impl Future<Output = Result<(), OpError>> + Send {
        std::future::ready(Ok(()))
    }

    fn switch_profile(
        &self,
        _owner: Owner,
        _profile_id: &str,
    ) -> impl Future<Output = Result<(), SwitchError>> + Send {
        std::future::ready(Err(SwitchError::NotStarted(OpError::Conflict)))
    }

    fn adaptive_restart(
        &self,
        _owner: Owner,
        _mode: AdaptiveMode,
        _sibling: Option<&str>,
    ) -> impl Future<Output = Result<RuntimeId, OpError>> + Send {
        std::future::ready(Err(OpError::Conflict))
    }

    fn events(&self) -> broadcast::Receiver<LifecycleEvent> {
        broadcast::channel(1).1
    }

    fn notify(&self, _category: NoticeCategory, _notice: Notice) {}
}

/// Adds one server from a fake key; the first one added becomes the selected server.
fn add_server(backend: &Backend, name: &str) -> String {
    let key = format!(
        "vless://11111111-2222-3333-4444-555555555555@{name}.example.net:443?security=tls&sni={name}.example.net#{name}"
    );
    let parsed = vpnte_servers::parse::parse_text(&key).expect("parse");
    let report = backend
        .servers
        .add(
            parsed.profiles,
            AddTarget::Keys {
                group: None,
                device: ClientDevice::Pc,
            },
        )
        .expect("add");
    report.added[0].as_str().to_owned()
}

/// The list API: CRUD is pushed before each call returns, schedules can be switched on (the
/// automation's reconcile task fires them), both choices are stored apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedules_are_edited_through_the_scheduler() {
    let dir = TempDir::new("lists-schedule-crud");
    let backend = schedule_backend(&dir);
    let api = schedule_api(&backend);
    let mut state = api.state();
    assert!(entries(&state.borrow()).is_empty());
    assert!(!state.borrow().tun_available);

    api.create(input("  Work  ", true, Upstream::LocalProxy, ""))
        .await
        .expect("create");
    let list = entries(&state.borrow_and_update());
    assert_eq!(list.len(), 1);
    let created = &list[0];
    assert_eq!(created.name, "Work");
    assert!(created.enabled);
    assert_eq!(created.days, vec![1, 3, 5]);
    assert_eq!((created.start, created.end), (hhmm(22, 0), hhmm(6, 30)));
    assert_eq!(
        (created.capture, created.upstream),
        (Capture::Proxy, Upstream::LocalProxy)
    );
    assert_eq!(created.profile_id, "");
    let id = created.id.clone();

    let mut renamed = input("Evenings", false, Upstream::LocalProxy, "");
    renamed.capture = Capture::Tun;
    renamed.days = vec![6, 0, 6];
    api.update(id.clone(), renamed).await.expect("update");
    let list = entries(&state.borrow_and_update());
    assert_eq!(
        (list[0].id.as_str(), list[0].name.as_str()),
        (id.as_str(), "Evenings")
    );
    assert_eq!(list[0].days, vec![0, 6], "stored sorted without duplicates");
    assert_eq!(list[0].capture, Capture::Tun);
    let stored = std::fs::read_to_string(backend.dirs.root.join("schedules.json")).unwrap();
    assert!(
        stored.contains("\"capture\": \"tun\"") && stored.contains("\"upstream\": \"local-proxy\"")
    );

    api.set_enabled(id.clone(), true).await.expect("switch on");
    assert!(entries(&state.borrow_and_update())[0].enabled);
    let err = api
        .set_enabled("missing".into(), false)
        .await
        .expect_err("unknown id");
    assert_eq!(err.user_msg().key, "automation.scheduler.notFound");

    api.delete(id.clone()).await.expect("delete");
    assert!(entries(&state.borrow_and_update()).is_empty());
    api.delete(id).await.expect("unknown id is no error");
}

/// «Текущий сервер» of a server schedule is stored as the server selected at save time (the
/// scheduler needs a concrete one); without any server the scheduler's own refusal is shown.
/// The server picker lists name and protocol only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_schedule_takes_the_selected_server() {
    let dir = TempDir::new("lists-schedule-direct");
    let backend = schedule_backend(&dir);
    let api = schedule_api(&backend);
    let mut state = api.state();

    let err = api
        .create(input("Night", false, Upstream::Server, ""))
        .await
        .expect_err("no server");
    assert_eq!(
        refusal(&err),
        (
            ErrorKind::Validation,
            "automation.scheduler.profileRequired".into()
        )
    );

    let first = add_server(&backend, "one");
    let second = add_server(&backend, "two");
    let snapshot = until(&mut state, |s| s.servers.len() == 2).await;
    assert_eq!(snapshot.servers[0].id, first);
    assert_eq!(snapshot.servers[0].name, "one");
    assert_eq!(snapshot.servers[0].protocol, "vless");

    api.create(input("Night", false, Upstream::Server, ""))
        .await
        .expect("current server");
    api.create(input("Late", false, Upstream::Server, &second))
        .await
        .expect("picked server");
    let list = entries(&state.borrow_and_update());
    assert_eq!(list[0].profile_id, first);
    assert_eq!(list[1].profile_id, second);
}

/// Schedules already in `schedules.json` (an import from the old app, the old one-word mode)
/// are shown as stored, switched-on ones included; days keep the stored numbering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_schedules_are_projected_as_stored() {
    let dir = TempDir::new("lists-schedule-stored");
    let backend = schedule_backend(&dir);
    let doc = serde_json::json!({
        "schemaVersion": 1,
        "schedules": [{
            "id": "s-1", "name": "Weekend", "enabled": true, "days": [0, 6],
            "startTime": "09:05", "endTime": "09:05", "profileId": "p-9", "mode": "direct"
        }]
    });
    std::fs::write(
        backend.dirs.root.join("schedules.json"),
        serde_json::to_vec_pretty(&doc).expect("json"),
    )
    .expect("write");
    let api = schedule_api(&backend);
    let state = api.state();
    let list = entries(&state.borrow());
    assert_eq!(list.len(), 1);
    let entry = &list[0];
    assert_eq!((entry.id.as_str(), entry.name.as_str()), ("s-1", "Weekend"));
    assert!(entry.enabled);
    assert_eq!(entry.days, vec![0, 6]);
    assert_eq!((entry.start, entry.end), (hhmm(9, 5), hhmm(9, 5)));
    assert_eq!(entry.profile_id, "p-9");
    assert_eq!(
        (entry.capture, entry.upstream),
        (Capture::Tun, Upstream::Server)
    );
}

fn apps(snapshot: &SplitSnapshot) -> Vec<SplitApp> {
    match &snapshot.apps {
        Load::Ready(list) => list.clone(),
        other => panic!("apps not ready: {other:?}"),
    }
}

/// AT-06-008 (backend side): a program is an entry for its exact, normalised path (a real
/// file, rule «Нет», named after its folder), a command an entry for its name (quotes and a
/// pasted path stripped, `.exe` added, rule «Напрямую»); adding either again returns the
/// existing entry; bad input is refused with the engine's own message; a removed program is
/// remembered so a rescan does not bring it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_entries_by_path_and_by_name() {
    let dir = TempDir::new("lists-split-entries");
    let backend = backend(&dir, FakeTunnel::new(false));
    let api = SplitService::start(backend.clone());

    // A command first, so the page's first look finds a list and runs no discovery.
    let command = api
        .add_process(r#""C:\Tools\yt-dlp""#.into())
        .await
        .expect("process");
    assert_eq!(
        (command.kind, command.path.as_str(), command.rule),
        (AppKind::Process, "yt-dlp.exe", AppRule::Direct)
    );
    let mut state = api.state();
    assert_eq!(apps(&state.borrow()), vec![command.clone()]);
    api.set_rule(command.id.clone(), AppRule::Vpn)
        .await
        .expect("rule");
    let again = api.add_process("YT-DLP.EXE".into()).await.expect("again");
    assert_eq!(
        (again.id.as_str(), again.rule),
        (command.id.as_str(), AppRule::Direct)
    );
    let err = api.add_process("two words".into()).await.expect_err("bad");
    assert_eq!(
        refusal(&err),
        (ErrorKind::Validation, "engine.routing.split.badName".into())
    );

    let folder = dir.0.join("Demo Tool");
    std::fs::create_dir_all(&folder).expect("folder");
    let exe = folder.join("tool.exe");
    std::fs::write(&exe, b"MZ").expect("exe");
    let program = api.add_program(exe.clone()).await.expect("program");
    assert_eq!(
        (program.kind, program.rule, program.name.as_str()),
        (AppKind::App, AppRule::None, "Demo Tool")
    );
    assert!(program.path.eq_ignore_ascii_case(&exe.to_string_lossy()));
    let same = api.add_program(exe.clone()).await.expect("same path");
    assert_eq!(same.id, program.id);
    let err = api
        .add_program(folder.join("missing.exe"))
        .await
        .expect_err("missing");
    assert_eq!(
        refusal(&err),
        (ErrorKind::Validation, "app.lists.apps.fileMissing".into())
    );
    let err = api
        .add_program("tool.exe".into())
        .await
        .expect_err("relative");
    assert_eq!(
        refusal(&err),
        (ErrorKind::Validation, "engine.routing.split.badPath".into())
    );

    api.set_rule(program.id.clone(), AppRule::Vpn)
        .await
        .expect("vpn");
    let list = apps(&state.borrow_and_update());
    assert_eq!(list.len(), 2);
    assert_eq!(
        (list[1].id.as_str(), list[1].rule),
        (program.id.as_str(), AppRule::Vpn)
    );
    let gone = (ErrorKind::Conflict, "app.lists.apps.gone".to_owned());
    let err = api.set_rule("not-an-id".into(), AppRule::Vpn).await;
    assert_eq!(refusal(&err.expect_err("bad id")), gone);
    let err = api
        .set_rule(uuid::Uuid::new_v4().to_string(), AppRule::Vpn)
        .await;
    assert_eq!(refusal(&err.expect_err("unknown id")), gone);

    api.remove(program.id.clone()).await.expect("remove");
    api.remove(program.id.clone())
        .await
        .expect("removed already");
    api.remove("not-an-id".into()).await.expect("never known");
    assert_eq!(apps(&state.borrow_and_update()), vec![again]);
    let key = program.path.to_lowercase();
    assert!(
        backend
            .rules
            .read(|d| d.split_tunnel.removed_paths.contains(&key))
    );
}

/// The first look at an empty list finds the installed apps once (rule «Нет», `Loading`
/// meanwhile); «Обновить» merges again without duplicates; a later look does not rescan.
/// Reads the uninstall keys and `%LOCALAPPDATA%\Programs` only (no change).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_look_at_an_empty_list_discovers_once() {
    let dir = TempDir::new("lists-split-discover");
    let api = SplitService::start(backend(&dir, FakeTunnel::new(false)));
    let mut state = api.state();
    let found = apps(&until(&mut state, |s| matches!(s.apps, Load::Ready(_))).await);
    assert!(
        found
            .iter()
            .all(|a| a.kind == AppKind::App && a.rule == AppRule::None)
    );
    assert_eq!(api.refresh().await.expect("rescan"), 0, "merged already");
    let _second_look = api.state();
    assert_eq!(apps(&state.borrow()).len(), found.len());
}

/// A history file as the service writes it (a newer domain, one seen only in DNS answers,
/// equal `last_seen` ordered by name).
const HISTORY: &str = r#"{
  "schemaVersion": 1,
  "domains": {
    "a.example.com": { "domain": "a.example.com", "firstSeen": 1000, "lastSeen": 5000,
      "connections": 3, "lookups": 7, "bytesUp": 10, "bytesDown": 20 },
    "b.example.org": { "domain": "b.example.org", "firstSeen": 2000, "lastSeen": 9000,
      "lookups": 4 },
    "c.example.net": { "domain": "c.example.net", "firstSeen": 3000, "lastSeen": 5000,
      "connections": 1, "bytesUp": 1, "bytesDown": 2, "outbound": "proxy-out" }
  }
}"#;

fn write_history(backend: &Backend, body: &str) {
    let path = backend
        .dirs
        .root
        .join("history")
        .join("traffic-domains.json");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("history dir");
    std::fs::write(path, body).expect("history");
}

/// The process's domain history over `backend`'s data dir (what was written before is its
/// content); no engine runs, so no line and no session ever arrive.
fn domain_history(backend: &Backend) -> Arc<DomainHistory> {
    let status = watch::channel(TunStatus::default()).1;
    DomainHistory::open(backend, status, broadcast::channel(8).1)
}

fn domains(snapshot: &TrafficSnapshot) -> Vec<DomainRow> {
    match &snapshot.domains {
        Load::Ready(rows) => rows.to_vec(),
        other => panic!("domains not ready: {other:?}"),
    }
}

/// U-18: the rows are what the history service holds (its file read with a BOM), newest first,
/// `count` by the forensics visits rule (connections, else DNS lookups), no IP, no site names
/// while the lookups are off; `tunnel_up` follows the tunnel while the page looks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_rows_come_from_the_history_service() {
    let dir = TempDir::new("lists-traffic-rows");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&dir, tunnel.clone());
    write_history(&backend, &format!("\u{feff}{HISTORY}"));
    let api = TrafficService::start(backend.clone(), domain_history(&backend));
    let mut state = api.state();
    let snapshot = until(&mut state, |s| matches!(s.domains, Load::Ready(_))).await;
    let rows = domains(&snapshot);
    let names: Vec<&str> = rows.iter().map(|r| r.domain.as_str()).collect();
    assert_eq!(names, ["b.example.org", "a.example.com", "c.example.net"]);
    assert_eq!(rows.iter().map(|r| r.count).collect::<Vec<_>>(), [4, 3, 1]);
    let a = &rows[1];
    assert_eq!(
        (a.first_seen, a.last_seen, a.bytes_up, a.bytes_down),
        (1000, 5000, 10, 20)
    );
    assert!(rows.iter().all(|r| r.site == SiteInfo::None));
    assert!(!snapshot.tunnel_up);

    tunnel
        .snapshot
        .send_modify(|s| s.state = TunnelState::Connected);
    until(&mut state, |s| s.tunnel_up).await;
}

/// A domain the engine's DNS answers name reaches the open page without a reload; «clear»
/// empties the list and saves the empty history at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_lines_and_clear_reach_the_page() {
    let dir = TempDir::new("lists-traffic-live");
    let backend = backend(&dir, FakeTunnel::new(false));
    write_history(&backend, HISTORY);
    let history = domain_history(&backend);
    let api = TrafficService::start(backend.clone(), history.clone());
    let mut state = api.state();
    history.history.observe_log_line(
        "+0300 2026-09-25 17:17:06 INFO [42 1ms] dns: exchanged A news.example.org. 60 IN A 198.51.100.7",
    );
    let rows = domains(&until(&mut state, |s| domains(s).len() == 4).await);
    assert!(rows.iter().any(|r| r.domain == "news.example.org"));

    api.clear().await.expect("cleared");
    assert!(domains(&state.borrow()).is_empty());
    let saved = std::fs::read_to_string(
        backend
            .dirs
            .root
            .join("history")
            .join("traffic-domains.json"),
    )
    .expect("saved");
    assert!(!saved.contains("example"), "{saved}");
}

/// Site info follows the lookup state of each entry; without one a row has none.
#[test]
fn site_info_follows_the_enrichment_state() {
    use vpnte_forensics::domains::DomainRecord;
    use vpnte_forensics::enrichment::{DomainEnrichment, EnrichStatus, HistoryEntry};
    let entry = |domain: &str, status: Option<EnrichStatus>| HistoryEntry {
        record: DomainRecord {
            domain: domain.into(),
            first_seen: 1,
            last_seen: 2,
            connections: 1,
            lookups: 0,
            bytes_up: 0,
            bytes_down: 0,
            outbound: None,
        },
        enrichment: status.map(|status| DomainEnrichment {
            status,
            site_name: Some("Example".into()),
            title: Some("Example site".into()),
            description: None,
            canonical_url: None,
            favicon_url: None,
            fetched_at: 1,
        }),
    };
    let rows = super::traffic::rows(vec![
        entry("a.example", None),
        entry("b.example", Some(EnrichStatus::Pending)),
        entry("c.example", Some(EnrichStatus::Ready)),
        entry("d.example", Some(EnrichStatus::Unavailable)),
    ]);
    let sites: Vec<SiteInfo> = rows.into_iter().map(|r| r.site).collect();
    assert_eq!(
        sites,
        [
            SiteInfo::None,
            SiteInfo::Pending,
            SiteInfo::Ready {
                name: Some("Example".into()),
                title: Some("Example site".into()),
            },
            SiteInfo::Unavailable,
        ]
    );
}

/// Only `https://<plain host>` links are opened (nothing here reaches the browser).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_plain_site_links_are_opened() {
    let dir = TempDir::new("lists-traffic-links");
    let backend = backend(&dir, FakeTunnel::new(false));
    let api = TrafficService::start(backend.clone(), domain_history(&backend));
    for url in [
        "",
        "http://example.com",
        "https://example.com/path",
        "https://example.com:8443",
        "https://user@example.com",
        "https://exa mple.com",
        "https://.example.com",
        "javascript:alert(1)",
        "file:///C:/Windows",
    ] {
        let err = api.open_site(url.into()).await.expect_err(url);
        assert_eq!(
            refusal(&err),
            (ErrorKind::Validation, "app.lists.traffic.badLink".into()),
            "{url}"
        );
    }
}

/// The three pages mount over exactly the boxes `contexts` hands to `launch` and render without
/// a panic (no WebView: mutations are dropped): every API the pages take from context is there,
/// with the type they ask for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pages_render_over_the_package_contexts() {
    use std::rc::Rc;

    use dioxus::core::NoOpMutations;
    use dioxus::prelude::*;
    use vpnte_ui::schedule::SchedulePage;
    use vpnte_ui::split_tunnel::SplitTunnelPage;
    use vpnte_ui::traffic_history::TrafficHistoryPage;
    use vpnte_ui::widgets::Toasts;

    fn root() -> Element {
        Toasts::use_provider();
        rsx! {
            SchedulePage {}
            SplitTunnelPage {}
            TrafficHistoryPage {}
        }
    }

    let dir = TempDir::new("lists-dom");
    let backend = backend(&dir, FakeTunnel::new(false));
    write_history(&backend, HISTORY);
    let schedule: Rc<dyn ScheduleApi> = Rc::new(schedule_api(&backend));
    let contexts = super::with_schedule(&backend, schedule, domain_history(&backend));
    // `use_context` finds a root context by its exact type: these are the types the pages ask
    // for (a missing one does not fail the render below, so check them here).
    assert_eq!(contexts.len(), 3);
    assert!(contexts[0].downcast_ref::<Rc<dyn ScheduleApi>>().is_some());
    assert!(
        contexts[1]
            .downcast_ref::<Rc<dyn SplitTunnelApi>>()
            .is_some()
    );
    assert!(
        contexts[2]
            .downcast_ref::<Rc<dyn TrafficHistoryApi>>()
            .is_some()
    );
    let mut dom = VirtualDom::new(root);
    for context in contexts {
        dom.insert_any_root_context(context);
    }
    dom.rebuild_in_place();
    for _ in 0..6 {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(60)) => {}
        }
        dom.render_immediate(&mut NoOpMutations);
    }
}

/// b4: the next event says how its schedule takes the traffic, so the page marks a TUN one
/// unavailable in an unelevated app (its start would answer `Permission`).
#[test]
fn the_next_event_carries_its_capture() {
    use vpnte_automation::schedule::{self as core, HhMm as CoreTime};
    use vpnte_automation::scheduler::{BoundaryKind, Upcoming};
    let time = |h| CoreTime::new(h, 0).expect("valid time");
    let work = core::ScheduleEntry {
        id: "w".into(),
        name: "Work".into(),
        enabled: true,
        days: vec![1],
        start_time: time(9),
        end_time: time(18),
        profile_id: String::new(),
        capture: core::Capture::Tun,
        upstream: core::Upstream::LocalProxy,
    };
    let upcoming = Upcoming {
        kind: BoundaryKind::Start,
        at: 5,
        schedule_id: "w".into(),
    };
    let next = super::schedule::next_event(&upcoming, &[work]).expect("named");
    assert_eq!((next.name.as_str(), next.capture), ("Work", Capture::Tun));
    assert!(!next.capture.available(false));
}
