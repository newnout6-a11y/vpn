//! The system-proxy tweak against in-memory settings: nothing here touches the real proxy.
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use vpnte_base::types::ProxyKind;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Backend, EnvVar, Journal, Record, no_registry};
use crate::tweaks::test_support::{FakeProxy, corporate};

fn addr(s: &str) -> HostPort {
    HostPort::parse(s).unwrap()
}

/// A backend that only knows the system proxy.
struct ProxyOnly(Arc<dyn SystemProxy>);

impl Backend for ProxyOnly {
    fn read(&self, _: &Target) -> io::Result<Val> {
        read(&*self.0)
    }
    fn write(&self, _: &Target, value: &Val) -> io::Result<bool> {
        write(&*self.0, value)
    }
    fn prune(&self, _: &Target) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_applied_value_names_the_mixed_inbound_for_every_protocol() {
    for (text, server) in [
        ("127.0.0.1:10808", "127.0.0.1:10808"),
        ("[::1]:2080", "[::1]:2080"),
        ("localhost:1080", "localhost:1080"),
    ] {
        let config = applied(&addr(text));
        assert_eq!(config.server, server);
        assert!(config.use_proxy && !config.use_pac && !config.auto_detect);
        assert_eq!(
            (config.bypass.as_str(), config.pac_url.as_str()),
            (BYPASS, "")
        );
    }
    let steps = plan(&addr("127.0.0.1:10808"));
    assert_eq!(steps.len(), 1);
    let (feature, target, value) = &steps[0];
    assert_eq!(
        (*feature, target),
        (Feature::SoftProxy, &Target::SystemProxy)
    );
    assert_eq!(decode(value), Some(applied(&addr("127.0.0.1:10808"))));
}

/// Equal settings encode to equal journal values; anything malformed is refused.
#[test]
fn the_journal_form_is_canonical_and_strict() {
    let config = corporate();
    assert_eq!(encode(&config), encode(&config.clone()));
    assert_eq!(decode(&encode(&config)), Some(config.clone()));
    let big = ProxyConfig {
        bypass: "x;".repeat(MAX_TEXT),
        ..ProxyConfig::default()
    };
    for bad in [
        Val::Absent,
        Val::Sz("{}".into()),
        Val::Text("not json".into()),
        Val::Text(r#"{"useProxy": "yes"}"#.into()),
        encode(&big),
    ] {
        assert_eq!(decode(&bad), None, "{bad:?}");
    }
    let err = write(&*FakeProxy::with(config.clone()), &Val::Absent).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

/// Records whether the journal on disk already holds the baseline when the write happens.
#[derive(Debug)]
struct Watching {
    inner: Arc<FakeProxy>,
    journal: PathBuf,
    seen: Mutex<Vec<bool>>,
}

impl SystemProxy for Watching {
    fn read(&self) -> io::Result<ProxyConfig> {
        self.inner.read()
    }
    fn write(&self, config: &ProxyConfig) -> io::Result<()> {
        let text = std::fs::read_to_string(&self.journal).unwrap_or_default();
        self.seen.lock().push(text.contains("wpad.corp.example"));
        self.inner.write(config)
    }
}

/// The baseline is journalled BEFORE the write (a crash in between leaves an obligation, never an
/// orphaned proxy) and comes back exactly; a second rollback finds nothing to do.
#[test]
fn the_baseline_is_journalled_before_the_write_and_restored_exactly() {
    let dir = TempDir::new("sysproxy");
    let journal = Journal::open(dir.path(), no_registry);
    let watching = Arc::new(Watching {
        inner: FakeProxy::with(corporate()),
        journal: dir.path().join("tweaks.json"),
        seen: Mutex::default(),
    });
    let backend = ProxyOnly(watching.clone());
    journal
        .apply(&backend, &plan(&addr("127.0.0.1:10808")))
        .unwrap();
    assert_eq!(*watching.seen.lock(), [true]);
    assert_eq!(
        journal.records(Feature::SoftProxy),
        vec![Record {
            feature: Feature::SoftProxy,
            target: Target::SystemProxy,
            baseline: encode(&corporate()),
            applied: encode(&applied(&addr("127.0.0.1:10808"))),
            created: false,
        }]
    );
    let report = journal.rollback(&backend, &[Feature::SoftProxy]);
    assert_eq!(report.restored, vec![Target::SystemProxy]);
    assert_eq!(watching.inner.get(), corporate());
    assert!(!journal.is_applied(Feature::SoftProxy));
    assert!(
        journal
            .rollback(&backend, &[Feature::SoftProxy])
            .restored
            .is_empty()
    );
}

/// A record whose feature or value does not fit the system proxy is dropped at load.
#[test]
fn foreign_records_are_not_admitted() {
    let dir = TempDir::new("sysproxy");
    let good = Record {
        feature: Feature::SoftProxy,
        target: Target::SystemProxy,
        baseline: encode(&corporate()),
        applied: encode(&applied(&addr("127.0.0.1:1"))),
        created: false,
    };
    let wrong_feature = Record {
        feature: Feature::SoftEnv,
        ..good.clone()
    };
    let wrong_value = Record {
        baseline: Val::Text("{".into()),
        ..good.clone()
    };
    let doc = serde_json::json!({
        "schemaVersion": 1,
        "records": [good, wrong_feature, wrong_value],
    });
    std::fs::write(dir.path().join("tweaks.json"), doc.to_string()).unwrap();
    let journal = Journal::open(dir.path(), no_registry);
    assert_eq!(journal.records(Feature::SoftProxy), vec![good]);
    assert!(!journal.is_applied(Feature::SoftEnv));
}

fn entries() -> Bypass {
    Bypass {
        proxy_override: ["corp.example", "*.corp.example", "<local>", "10.*"]
            .map(String::from)
            .to_vec(),
        no_proxy: ["corp.example", ".corp.example", "10.0.0.0/8"]
            .map(String::from)
            .to_vec(),
    }
}

/// «Не через прокси» (RU-2026 item 14 a-b): the entries follow the local ones in each reader's
/// list, and what Soft already lists is not repeated.
#[test]
fn the_bypass_entries_follow_the_local_ones() {
    let ours = addr("127.0.0.1:10808");
    let config = applied_with(&ours, &entries());
    assert_eq!(
        config.bypass,
        "localhost;127.*;[::1];<local>;corp.example;*.corp.example;10.*"
    );
    assert_eq!(applied_with(&ours, &Bypass::default()).bypass, BYPASS);
    let vars = crate::tweaks::env::plan_with(&ours, ProxyKind::Http, &entries());
    let no_proxy = vars
        .iter()
        .find(|(_, t, _)| {
            *t == Target::Env {
                var: EnvVar::NoProxy,
            }
        })
        .map(|(_, _, v)| v.clone());
    assert_eq!(
        no_proxy,
        Some(Val::Sz(
            "localhost,127.0.0.1,::1,corp.example,.corp.example,10.0.0.0/8".into()
        ))
    );
}

/// A list changed mid-session lands at the next apply; until then the session reads back the
/// list it wrote.
#[test]
fn a_session_keeps_the_list_it_took() {
    let mut lists = Lists {
        next: entries(),
        ..Lists::default()
    };
    assert_eq!(lists.take(), entries());
    lists.next = Bypass::default();
    assert_eq!(lists.taken, entries());
    assert_eq!(lists.take(), Bypass::default());
}

/// Whatever the caller hands over, the text stays inside the journal's value limit.
#[test]
fn an_oversized_list_is_cut_at_the_limit() {
    let many = Bypass {
        proxy_override: (0..5000).map(|n| format!("host{n}.example")).collect(),
        no_proxy: Vec::new(),
    };
    let config = applied_with(&addr("127.0.0.1:1"), &many);
    assert!(config.bypass.len() <= MAX_BYPASS);
    assert!(config.bypass.starts_with(BYPASS));
    assert_eq!(decode(&encode(&config)), Some(config));
}

/// The system proxy and the variables of one in-memory session.
struct SessionFake {
    proxy: Arc<FakeProxy>,
    env: Mutex<std::collections::HashMap<EnvVar, Val>>,
}

impl Backend for SessionFake {
    fn read(&self, target: &Target) -> io::Result<Val> {
        match target {
            Target::Env { var } => Ok(self.env.lock().get(var).cloned().unwrap_or(Val::Absent)),
            _ => read(&*self.proxy),
        }
    }
    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        match target {
            Target::Env { var } => {
                let mut env = self.env.lock();
                match value {
                    Val::Absent => env.remove(var),
                    v => env.insert(*var, v.clone()),
                };
                Ok(false)
            }
            _ => write(&*self.proxy, value),
        }
    }
    fn prune(&self, _: &Target) -> io::Result<()> {
        Ok(())
    }
}

/// The entries are journalled with the rest of the value, so every rollback (stop, the crash
/// guardian, the logon restore: all journal rollbacks) brings the user's setting back exactly.
#[test]
fn the_bypass_list_round_trips_through_the_journal() {
    let dir = TempDir::new("sysproxy");
    let journal = Journal::open(dir.path(), no_registry);
    let fake = SessionFake {
        proxy: FakeProxy::with(corporate()),
        env: Mutex::default(),
    };
    let ours = addr("127.0.0.1:10808");
    let mut steps = vec![(
        Feature::SoftProxy,
        Target::SystemProxy,
        encode(&applied_with(&ours, &entries())),
    )];
    steps.extend(crate::tweaks::env::plan_with(
        &ours,
        ProxyKind::Http,
        &entries(),
    ));
    journal.apply(&fake, &steps).unwrap();
    assert_eq!(fake.proxy.get(), applied_with(&ours, &entries()));
    let no_proxy = fake.env.lock().get(&EnvVar::NoProxy).cloned();
    assert!(matches!(no_proxy, Some(Val::Sz(s)) if s.ends_with(",10.0.0.0/8")));

    let report = journal.rollback(&fake, &[Feature::SoftProxy, Feature::SoftEnv]);
    assert!(report.is_complete() && report.kept_user_value.is_empty());
    assert_eq!(fake.proxy.get(), corporate());
    assert!(fake.env.lock().is_empty());
}
