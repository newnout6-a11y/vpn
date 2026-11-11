//! The system-proxy tweak against in-memory settings: nothing here touches the real proxy.
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Backend, Journal, Record, no_registry};
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
