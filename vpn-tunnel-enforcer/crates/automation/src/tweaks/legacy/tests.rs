//! Legacy import vectors (spec §6.8 "Legacy import", §7.6 legacy cleanup) on temp fixtures.
use vpnte_winnet::env::UserEnv;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Journal, no_registry};
use crate::tweaks::soft::{SOFT_FEATURES, SoftSystem};
use crate::tweaks::test_support::Fake;

fn sz(s: &str) -> Val {
    Val::Sz(s.into())
}

fn env(var: EnvVar) -> Target {
    Target::Env { var }
}

fn git(key: GitKey) -> Target {
    Target::Git { key }
}

const SOCKS: &str = "socks5h://127.0.0.1:10808";

fn receipts(dir: &TempDir) -> LegacySources {
    LegacySources {
        receipts_dir: Some(dir.path().join(".vpnte")),
        gradle_props: None,
        studio_root: None,
    }
}

/// Env and Git receipts become records for the values that still hold the old app's; the normal
/// rollback then restores the originals (an expandable one as such) and leaves a value the user
/// changed alone. The import runs once.
#[test]
fn receipts_become_obligations() {
    let dir = TempDir::new("tweaks");
    let src = receipts(&dir);
    let vpnte = dir.path().join(".vpnte");
    std::fs::create_dir_all(&vpnte).unwrap();
    std::fs::write(
        vpnte.join("env-proxy-backup.json"),
        r#"{"schemaVersion":0,"createdAt":1,"httpProxy":"http://%CORP_HOST%:8080","httpsProxy":null,"allProxy":null,"noProxy":"localhost"}"#,
    )
    .unwrap();
    std::fs::write(
        vpnte.join("git-proxy-backup.json"),
        r#"{"schemaVersion":0,"createdAt":1,"httpProxy":null,"httpsProxy":"http://corp:8443"}"#,
    )
    .unwrap();
    let fake = Fake::with(&[
        (env(EnvVar::HttpProxy), sz(SOCKS)),
        (env(EnvVar::HttpsProxy), sz(SOCKS)),
        (env(EnvVar::AllProxy), sz("user value")),
        (env(EnvVar::NoProxy), sz("localhost,127.0.0.1,::1")),
        (git(GitKey::HttpProxy), Val::Text(SOCKS.into())),
        (git(GitKey::HttpsProxy), Val::Text(SOCKS.into())),
    ]);
    let journal = Journal::open(&dir.path().join("data"), no_registry);
    let report = import(&journal, &fake, &src);
    assert_eq!(
        report,
        LegacyReport {
            adopted: 5,
            notice: None
        }
    );
    assert_eq!(fake.write_count(), 0, "the import writes nothing");

    let rollback = journal.rollback(&fake, &SOFT_FEATURES);
    assert!(rollback.is_complete());
    assert_eq!(
        fake.get(&env(EnvVar::HttpProxy)),
        Val::ExpandSz("http://%CORP_HOST%:8080".into())
    );
    assert_eq!(fake.get(&env(EnvVar::HttpsProxy)), Val::Absent);
    assert_eq!(fake.get(&env(EnvVar::AllProxy)), sz("user value"));
    assert_eq!(fake.get(&env(EnvVar::NoProxy)), sz("localhost"));
    assert_eq!(fake.get(&git(GitKey::HttpProxy)), Val::Absent);
    assert_eq!(
        fake.get(&git(GitKey::HttpsProxy)),
        Val::Text("http://corp:8443".into())
    );
    assert!(
        vpnte.join("env-proxy-backup.json").is_file(),
        "old files are never deleted"
    );

    fake.set(&env(EnvVar::HttpProxy), sz(SOCKS));
    assert_eq!(
        import(&journal, &fake, &src),
        LegacyReport::default(),
        "once only"
    );
    assert!(Journal::open(&dir.path().join("data"), no_registry).legacy_imported());
}

/// A pending marker without its receipt: no records (nothing is known about the originals), one
/// warning naming the variables that still look like the old app's values.
#[test]
fn a_lost_receipt_only_warns() {
    let dir = TempDir::new("tweaks");
    let vpnte = dir.path().join(".vpnte");
    std::fs::create_dir_all(&vpnte).unwrap();
    std::fs::write(vpnte.join("env-proxy-backup.json.pending"), "").unwrap();
    let fake = Fake::with(&[
        (env(EnvVar::HttpProxy), sz(SOCKS)),
        (env(EnvVar::HttpsProxy), sz("http://corp:8080")),
        (env(EnvVar::NoProxy), sz("localhost,127.0.0.1,::1")),
    ]);
    let journal = Journal::open(&dir.path().join("data"), no_registry);
    let report = import(&journal, &fake, &receipts(&dir));
    assert_eq!(report.adopted, 0);
    let notice = report.notice.unwrap();
    assert_eq!(notice.key, "automation.tweaks.legacyLeftovers");
    assert_eq!(notice.args[0].1, "HTTP_PROXY, HTTPS_PROXY, NO_PROXY");
    assert!(!journal.is_applied(Feature::SoftEnv));
}

const OLD_GRADLE: &str = "org.gradle.jvmargs=-Xmx1g\n\nsystemProp.socksProxyHost=127.0.0.1\n\
systemProp.socksProxyPort=10808\nsystemProp.http.nonProxyHosts=localhost|127.*|[::1]\n\
# VPN Tunnel Enforcer\nsystemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=10809\n\
systemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=10809\n\
systemProp.http.nonProxyHosts=localhost|127.*|[::1]\norg.gradle.caching=true\n";

const OLD_VM: &str = "-Xmx1g\n# VPN-Tunnel-Enforcer\n-DsocksProxyHost=127.0.0.1\n\
-DsocksProxyPort=10808\n-Dhttp.nonProxyHosts=localhost|127.0.0.1\n# /VPN-Tunnel-Enforcer\n";

const OLD_OTHER_XML: &str = "<application>\n  <component name=\"HttpConfigurable\">\n    \
<option name=\"USE_HTTP_PROXY\" value=\"true\" />\n    <option name=\"PROXY_HOST\" value=\"127.0.0.1\" />\n    \
<option name=\"PROXY_PORT\" value=\"10808\" />\n    <option name=\"PROXY_TYPE_IS_SOCKS\" value=\"true\" />\n  \
</component>\n</application>\n";

const BACKUP_OTHER_XML: &str = "<application>\n  <component name=\"HttpConfigurable\">\n    \
<option name=\"PROXY_HOST\" value=\"corp\" />\n    <option name=\"PROXY_PORT\" value=\"3128\" />\n  \
</component>\n</application>\n";

/// Gradle leftovers go line-exact (the user's later line stays, the old backup is never
/// restored); Android Studio loses only the old block and options, back to the backup's values;
/// a version without provenance is not touched.
#[test]
fn old_files_are_cleaned_exactly() {
    let dir = TempDir::new("tweaks");
    let props = dir.path().join(".gradle").join("gradle.properties");
    std::fs::create_dir_all(props.parent().unwrap()).unwrap();
    std::fs::write(&props, OLD_GRADLE).unwrap();
    let root = dir.path().join("Google");
    let old = root.join("AndroidStudio2023.1");
    let options = old.join("options");
    std::fs::create_dir_all(&options).unwrap();
    std::fs::write(old.join("studio64.exe.vmoptions"), OLD_VM).unwrap();
    std::fs::write(options.join("other.xml"), OLD_OTHER_XML).unwrap();
    std::fs::write(options.join("other.xml.vpn-backup"), BACKUP_OTHER_XML).unwrap();
    let foreign = root.join("AndroidStudio2024.1").join("options");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("other.xml"), OLD_OTHER_XML).unwrap();

    let sys = SoftSystem {
        env: UserEnv::under(r"Software\VPNTE-Test-tweaks-unused"),
        git: None,
        gradle_home: None,
        studio_root: None,
        broadcast: false,
        check_user: false,
    };
    let src = LegacySources {
        receipts_dir: None,
        gradle_props: Some(props.clone()),
        studio_root: Some(root.clone()),
    };
    let journal = Journal::open(&dir.path().join("data"), no_registry);
    let report = import(&journal, &sys, &src);
    assert_eq!(report.adopted, 6, "gradle lines + vm block + 4 options");

    assert!(journal.rollback(&sys, &SOFT_FEATURES).is_complete());
    let gradle = std::fs::read_to_string(&props).unwrap();
    let left: Vec<&str> = gradle.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        left,
        ["org.gradle.jvmargs=-Xmx1g", "org.gradle.caching=true"]
    );
    assert_eq!(
        std::fs::read_to_string(old.join("studio64.exe.vmoptions")).unwrap(),
        "-Xmx1g\n"
    );
    let xml = std::fs::read_to_string(options.join("other.xml")).unwrap();
    assert!(
        xml.contains(r#"<option name="PROXY_HOST" value="corp" />"#),
        "{xml}"
    );
    assert!(
        xml.contains(r#"<option name="PROXY_PORT" value="3128" />"#),
        "{xml}"
    );
    assert!(
        !xml.contains("USE_HTTP_PROXY") && !xml.contains("PROXY_TYPE_IS_SOCKS"),
        "{xml}"
    );
    assert_eq!(
        std::fs::read_to_string(foreign.join("other.xml")).unwrap(),
        OLD_OTHER_XML,
        "no provenance: untouched"
    );
    assert!(options.join("other.xml.vpn-backup").is_file());
}
