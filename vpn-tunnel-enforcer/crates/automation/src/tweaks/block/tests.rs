//! Gradle / vmoptions block vectors (spec §7.6, D-06 / G2 / G3 / G8) through the journal and the
//! production backend, on temp files.
use std::path::{Path, PathBuf};

use vpnte_winnet::env::UserEnv;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Feature, Journal, Target, TweakError, no_registry};
use crate::tweaks::soft::SoftSystem;
use crate::tweaks::test_support::FakeProxy;

/// Only file targets are used here: the environment key is never touched.
fn files_only() -> SoftSystem {
    SoftSystem {
        proxy: FakeProxy::with(Default::default()),
        env: UserEnv::under(r"Software\VPNTE-Test-tweaks-unused"),
        git: None,
        gradle_home: None,
        studio_root: None,
        broadcast: false,
        check_user: false,
    }
}

struct Gradle {
    dir: TempDir,
    journal: Journal,
    sys: SoftSystem,
}

impl Gradle {
    fn new() -> Self {
        let dir = TempDir::new("tweaks");
        let journal = Journal::open(&dir.path().join("data"), no_registry);
        Self {
            dir,
            journal,
            sys: files_only(),
        }
    }

    fn props(&self) -> PathBuf {
        self.dir.path().join("gradle.properties")
    }

    fn apply(&self, addr: &str, kind: ProxyKind) -> Result<(), TweakError> {
        let addr = HostPort::parse(addr).unwrap();
        let target = Target::Block {
            kind: BlockKind::Gradle,
            path: self.props(),
        };
        let text = render(BlockKind::Gradle, &addr, kind);
        self.journal
            .apply(&self.sys, &[(Feature::DevGradle, target, Val::Text(text))])
    }

    fn rollback(&self) {
        assert!(
            self.journal
                .rollback(&self.sys, &[Feature::DevGradle])
                .is_complete()
        );
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.props()).unwrap()
    }

    fn write(&self, text: &str) {
        std::fs::write(self.props(), text).unwrap();
    }
}

/// D-06: apply → rollback → user edit → apply → rollback keeps the edit (the old whole-file
/// backup brought back `-Xmx1g`).
#[test]
fn user_edits_survive_repeated_cycles() {
    let g = Gradle::new();
    g.write("org.gradle.jvmargs=-Xmx1g\n");
    g.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    g.rollback();
    assert_eq!(g.text(), "org.gradle.jvmargs=-Xmx1g\n");
    g.write("org.gradle.jvmargs=-Xmx2g\n");
    g.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    g.rollback();
    assert_eq!(g.text(), "org.gradle.jvmargs=-Xmx2g\n");
}

/// socks then http: exactly one managed block and no stale SOCKS line; an edit above the block
/// made while it is applied survives too.
#[test]
fn switching_kind_leaves_one_block() {
    let g = Gradle::new();
    g.write("a=1\r\nb=2");
    g.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    g.apply("127.0.0.1:10809", ProxyKind::Http).unwrap();
    let text = g.text();
    assert_eq!(
        text.matches("# >>> VPN Tunnel Enforcer (managed) >>>")
            .count(),
        1
    );
    assert!(!text.contains("socksProxy"), "{text}");
    assert_eq!(
        text,
        "a=1\r\nb=2\r\n# >>> VPN Tunnel Enforcer (managed) >>>\r\n\
         systemProp.http.proxyHost=127.0.0.1\r\nsystemProp.http.proxyPort=10809\r\n\
         systemProp.https.proxyHost=127.0.0.1\r\nsystemProp.https.proxyPort=10809\r\n\
         systemProp.http.nonProxyHosts=localhost|127.*|[::1]\r\n# <<< VPN Tunnel Enforcer <<<\r\n",
        "CRLF kept, block appended at the end"
    );
    g.write(&text.replacen("a=1", "a=3", 1));
    g.rollback();
    assert_eq!(g.text(), "a=3\r\nb=2\r\n");
}

/// G8: a file that did not exist before the apply is deleted by the rollback.
#[test]
fn a_created_file_is_removed() {
    let g = Gradle::new();
    g.apply("localhost:1080", ProxyKind::Socks5).unwrap();
    assert!(g.journal.records(Feature::DevGradle)[0].created);
    g.rollback();
    assert!(!g.props().exists());
}

/// G3: an address with a newline never reaches a writer; a damaged block aborts with no write.
#[test]
fn bad_input_writes_nothing() {
    assert!(HostPort::parse("127.0.0.1\nsystemProp.evil=1:1080").is_err());
    assert!(HostPort::parse("127.0.0.1:1080\nsystemProp.evil=1").is_err());
    let g = Gradle::new();
    let damaged = "x=1\n# >>> VPN Tunnel Enforcer (managed) >>>\nsystemProp.socksProxyHost=h\n";
    g.write(damaged);
    assert!(matches!(
        g.apply("127.0.0.1:10808", ProxyKind::Socks5),
        Err(TweakError::Unreadable(..))
    ));
    assert_eq!(g.text(), damaged);
    assert!(!g.journal.is_applied(Feature::DevGradle));
}

/// A block whose lines are not ours is not a block: the journal will not admit it either.
#[test]
fn only_managed_lines_form_a_block() {
    let addr = HostPort::parse("[::1]:10808").unwrap();
    for kind in [BlockKind::Gradle, BlockKind::VmOptions] {
        for proxy in [ProxyKind::Socks5, ProxyKind::Http] {
            assert!(is_block(kind, &render(kind, &addr, proxy)));
        }
    }
    let vm = render(BlockKind::VmOptions, &addr, ProxyKind::Http);
    assert_eq!(
        vm,
        "# VPN-Tunnel-Enforcer\n-Dhttp.proxyHost=::1\n-Dhttp.proxyPort=10808\n\
         -Dhttps.proxyHost=::1\n-Dhttps.proxyPort=10808\n\
         -Dhttp.nonProxyHosts=localhost|127.0.0.1\n# /VPN-Tunnel-Enforcer\n"
    );
    assert!(!is_block(BlockKind::Gradle, &vm));
    let evil = "# VPN-Tunnel-Enforcer\n-javaagent:evil.jar\n# /VPN-Tunnel-Enforcer\n";
    assert!(!is_block(BlockKind::VmOptions, evil));
}

fn lines_of(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What three old applies left: the old strip rule removed only the header line, so earlier
/// blocks stay as headerless runs (GRD:52, GRD:57-60).
pub(crate) const OLD_THREE_APPLIES: &str = "org.gradle.jvmargs=-Xmx1g\n\
\n\
systemProp.socksProxyHost=127.0.0.1\n\
systemProp.socksProxyPort=10808\n\
systemProp.http.nonProxyHosts=localhost|127.*|[::1]\n\
\n\
systemProp.socksProxyHost=127.0.0.1\n\
systemProp.socksProxyPort=10808\n\
systemProp.http.nonProxyHosts=localhost|127.*|[::1]\n\
# VPN Tunnel Enforcer\n\
systemProp.http.proxyHost=127.0.0.1\n\
systemProp.http.proxyPort=10809\n\
systemProp.https.proxyHost=127.0.0.1\n\
systemProp.https.proxyPort=10809\n\
systemProp.http.nonProxyHosts=localhost|127.*|[::1]\n\
org.gradle.caching=true\n";

/// Legacy cleanup (§7.6): after three old applies and a later user line only the user's lines
/// remain; with the old backup at hand, a managed key the user had before is kept.
#[test]
fn old_leftovers_are_removed_line_exact() {
    let dir = TempDir::new("tweaks");
    let path = dir.path().join("gradle.properties");
    std::fs::write(&path, OLD_THREE_APPLIES).unwrap();
    let ours = legacy_gradle_lines(OLD_THREE_APPLIES, None);
    assert_eq!(ours.len(), 8, "{ours:?}");
    assert_eq!(
        read_lines(&path, &ours).unwrap(),
        Val::Text(ours.join("\n"))
    );
    remove_lines(&path, &ours).unwrap();
    let left: Vec<String> = lines_of(&path)
        .into_iter()
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        left,
        ["org.gradle.jvmargs=-Xmx1g", "org.gradle.caching=true"]
    );
    assert_eq!(read_lines(&path, &ours).unwrap(), Val::Absent);

    let backup =
        "systemProp.http.nonProxyHosts=localhost|127.*|[::1]\nsystemProp.socksProxyPort=10808\n";
    let ours = legacy_gradle_lines(OLD_THREE_APPLIES, Some(backup));
    assert!(
        !ours.iter().any(|l| backup.lines().any(|b| b == l)),
        "{ours:?}"
    );
    assert!(ours.contains(&"# VPN Tunnel Enforcer".to_owned()));
    assert!(ours.contains(&"systemProp.http.proxyPort=10809".to_owned()));
    assert!(legacy_gradle_lines("a=1\nsystemProp.http.proxyHost=corp\n", None).is_empty());
}
