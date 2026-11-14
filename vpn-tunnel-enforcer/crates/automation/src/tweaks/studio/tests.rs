//! Android Studio vectors (spec §7.6 `androidStudio.test.ts`, AS1 / AS2) on temp directories.
use std::path::{Path, PathBuf};

use vpnte_winnet::env::UserEnv;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Journal, TweakError, no_registry};
use crate::tweaks::soft::SoftSystem;
use crate::tweaks::test_support::FakeProxy;

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

struct Studio {
    dir: TempDir,
    journal: Journal,
    sys: SoftSystem,
}

impl Studio {
    fn new() -> Self {
        let dir = TempDir::new("tweaks");
        std::fs::create_dir_all(dir.path().join("Google").join("AndroidStudio2024.2")).unwrap();
        let journal = Journal::open(&dir.path().join("data"), no_registry);
        Self {
            dir,
            journal,
            sys: files_only(),
        }
    }

    fn install(&self) -> PathBuf {
        self.dir.path().join("Google").join("AndroidStudio2024.2")
    }

    fn settings(&self) -> PathBuf {
        settings_file(&self.install())
    }

    fn apply(&self, addr: &str, kind: ProxyKind) -> Result<(), TweakError> {
        let addr = HostPort::parse(addr).unwrap();
        self.journal
            .apply(&self.sys, &plan(&self.install(), &addr, kind))
    }

    fn rollback(&self) {
        let report = self.journal.rollback(&self.sys, &[Feature::DevStudio]);
        assert!(report.is_complete(), "{report:?}");
    }
}

fn mkdirs(root: &Path, names: &[&str]) {
    for name in names {
        std::fs::create_dir_all(root.join(name)).unwrap();
    }
}

/// Newest version only; a Preview sorts below the release of the same number; files and other
/// names are ignored; no settings root is "not installed", never an error.
#[test]
fn the_newest_install_is_chosen() {
    let dir = TempDir::new("tweaks");
    let root = dir.path();
    assert_eq!(newest_install(&root.join("missing")).unwrap(), None);
    assert_eq!(newest_install(root).unwrap(), None);
    mkdirs(
        root,
        &[
            "AndroidStudio2023.1",
            "AndroidStudio2024.2",
            "AndroidStudioPreview2024.2.1",
        ],
    );
    mkdirs(
        root,
        &[
            "AndroidStudio2024.2.1",
            "AndroidStudioX",
            "IntelliJIdea2099.1",
        ],
    );
    std::fs::write(root.join("AndroidStudio2099.1"), "a file").unwrap();
    assert_eq!(
        newest_install(root).unwrap(),
        Some(root.join("AndroidStudio2024.2.1"))
    );
    mkdirs(root, &["AndroidStudioPreview2024.3"]);
    assert_eq!(
        newest_install(root).unwrap(),
        Some(root.join("AndroidStudioPreview2024.3"))
    );
}

const SOCKS_FILE: &str = "<application>
  <component name=\"HttpConfigurable\">
    <option name=\"USE_HTTP_PROXY\" value=\"true\" />
    <option name=\"PROXY_HOST\" value=\"127.0.0.1\" />
    <option name=\"PROXY_PORT\" value=\"10808\" />
    <option name=\"PROXY_TYPE_IS_SOCKS\" value=\"true\" />
  </component>
</application>
";

/// A settings file we created: apply socks, apply http, rollback = not applied, file removed.
#[test]
fn a_created_settings_file_is_removed() {
    let s = Studio::new();
    s.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    assert_eq!(std::fs::read_to_string(s.settings()).unwrap(), SOCKS_FILE);
    s.apply("127.0.0.1:10809", ProxyKind::Http).unwrap();
    let text = std::fs::read_to_string(s.settings()).unwrap();
    assert!(text.contains(r#"<option name="PROXY_TYPE_IS_SOCKS" value="false" />"#));
    assert!(text.contains(r#"<option name="PROXY_PORT" value="10809" />"#));
    s.rollback();
    assert!(!s.settings().exists());
    assert!(!s.journal.is_applied(Feature::DevStudio));
}

const USER_FILE: &str = "<application>
  <component name=\"HttpConfigurable\">
    <option name=\"PROXY_HOST\" value=\"corp.example\" />
    <option name=\"PROXY_PORT\" value=\"3128\" />
    <option name=\"PROXY_EXCEPTIONS\" value=\"*.corp, localhost\" />
  </component>
  <component name=\"Other\"><option name=\"X\" value=\"y\" /></component>
</application>
";

/// Existing options are edited one by one: `PROXY_EXCEPTIONS` survives, repeated applies never
/// rewrite the baseline, and the rollback gives the file back byte for byte.
#[test]
fn the_users_options_survive() {
    let s = Studio::new();
    std::fs::create_dir_all(s.settings().parent().unwrap()).unwrap();
    std::fs::write(s.settings(), USER_FILE).unwrap();
    s.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    s.apply("[::1]:10809", ProxyKind::Http).unwrap();
    let text = std::fs::read_to_string(s.settings()).unwrap();
    assert!(text.contains(r#"<option name="PROXY_EXCEPTIONS" value="*.corp, localhost" />"#));
    assert!(text.contains(r#"<option name="PROXY_HOST" value="::1" />"#));
    let baselines: Vec<Val> = s
        .journal
        .records(Feature::DevStudio)
        .into_iter()
        .map(|r| r.baseline)
        .collect();
    let text_val = |v: &str| Val::Text(v.into());
    assert_eq!(
        baselines,
        [
            Val::Absent,
            text_val("corp.example"),
            text_val("3128"),
            Val::Absent
        ]
    );
    s.rollback();
    assert_eq!(std::fs::read_to_string(s.settings()).unwrap(), USER_FILE);
}

/// JVM options go only into a vmoptions file the user already has (a proxy-only file would
/// replace the IDE's own options on older launchers).
#[test]
fn jvm_options_only_in_an_existing_file() {
    let s = Studio::new();
    let addr = HostPort::parse("127.0.0.1:10808").unwrap();
    assert_eq!(plan(&s.install(), &addr, ProxyKind::Socks5).len(), 4);
    let vm = vmoptions_file(&s.install());
    std::fs::write(&vm, "-Xmx2048m\n").unwrap();
    s.apply("127.0.0.1:10808", ProxyKind::Socks5).unwrap();
    assert_eq!(
        std::fs::read_to_string(&vm).unwrap(),
        "-Xmx2048m\n# VPN-Tunnel-Enforcer\n-DsocksProxyHost=127.0.0.1\n-DsocksProxyPort=10808\n\
         -Dhttp.nonProxyHosts=localhost|127.0.0.1\n# /VPN-Tunnel-Enforcer\n"
    );
    s.rollback();
    assert_eq!(std::fs::read_to_string(&vm).unwrap(), "-Xmx2048m\n");
    assert!(!s.settings().exists());
}

/// A settings file we cannot read safely is left alone: nothing written, nothing journalled.
#[test]
fn unexpected_layouts_are_not_guessed_at() {
    let doubled = "<application>\n  <component name=\"HttpConfigurable\">\n  </component>\n  \
                   <component name=\"HttpConfigurable\" />\n</application>\n";
    let nested = "<application>\n  <component name=\"HttpConfigurable\">\n    \
                  <option name=\"PROXY_HOST\"><value>x</value></option>\n  </component>\n</application>\n";
    let no_app = "<settings />\n";
    for content in [doubled, nested, no_app] {
        let s = Studio::new();
        std::fs::create_dir_all(s.settings().parent().unwrap()).unwrap();
        std::fs::write(s.settings(), content).unwrap();
        let result = s.apply("127.0.0.1:10808", ProxyKind::Socks5);
        assert!(result.is_err(), "{content}");
        assert_eq!(std::fs::read_to_string(s.settings()).unwrap(), content);
        assert!(!s.journal.is_applied(Feature::DevStudio));
    }
}

/// A self-closing application element gets the component; values are XML-escaped both ways.
#[test]
fn values_are_escaped_and_empty_files_extended() {
    let dir = TempDir::new("tweaks");
    let path = dir.path().join("proxy.settings.xml");
    std::fs::write(&path, "<application />\n").unwrap();
    let odd = Val::Text(r#"a&b"<c>'"#.into());
    assert!(!write_option(&path, StudioOption::ProxyHost, &odd).unwrap());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains(r#"value="a&amp;b&quot;&lt;c&gt;&apos;""#),
        "{text}"
    );
    assert_eq!(read_option(&path, StudioOption::ProxyHost).unwrap(), odd);
    write_option(&path, StudioOption::ProxyHost, &Val::Absent).unwrap();
    assert_eq!(
        read_option(&path, StudioOption::ProxyHost).unwrap(),
        Val::Absent
    );
    prune(&path).unwrap();
    assert!(!path.exists(), "nothing but an empty component was left");
}
