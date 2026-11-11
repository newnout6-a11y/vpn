//! Soft mode end to end on throw-away places: an in-memory system proxy, an HKCU test key instead
//! of `HKCU\Environment`, temp directories instead of `~\.gradle` and `%APPDATA%\Google`.
use std::sync::Arc;

use vpnte_base::AppError;
use vpnte_winnet::env::EnvValue;
use vpnte_winnet::sysproxy::ProxyConfig;

use super::*;
use crate::test_support::{TempDir, TestKey};
use crate::tweaks::journal::no_registry;
use crate::tweaks::test_support::{FakeProxy, corporate};

fn system(key: &TestKey, dir: &TempDir, proxy: &Arc<FakeProxy>) -> SoftSystem {
    SoftSystem {
        proxy: proxy.clone(),
        env: UserEnv::under(&key.0),
        git: None,
        gradle_home: Some(dir.path().join(".gradle")),
        studio_root: Some(dir.path().join("Google")),
        broadcast: false,
        check_user: false,
    }
}

fn soft(key: &TestKey, dir: &TempDir) -> Soft {
    soft_with(key, dir, &FakeProxy::with(ProxyConfig::default()))
}

fn soft_with(key: &TestKey, dir: &TempDir, proxy: &Arc<FakeProxy>) -> Soft {
    let journal = Arc::new(Journal::open(&dir.path().join("data"), no_registry));
    Soft::new(journal, system(key, dir, proxy))
}

fn addr(s: &str) -> HostPort {
    HostPort::parse(s).unwrap()
}

/// E1 (F-117) and AT-09-003: a `REG_EXPAND_SZ` original comes back as `REG_EXPAND_SZ`, and long
/// values round-trip byte-exact (no `setx` truncation at 1024 characters).
#[test]
fn originals_come_back_with_their_type_and_length() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let soft = soft(&key, &dir);
    let env = UserEnv::under(&key.0);
    let expand = EnvValue::Expandable("http://%PROXY_HOST%:8080".into());
    env.set("HTTP_PROXY", &expand).unwrap();
    for len in [1023, 1024, 1025, 4096] {
        let long = EnvValue::Plain("x".repeat(len));
        env.set("ALL_PROXY", &long).unwrap();
        soft.apply_blocking(
            &addr("127.0.0.1:10808"),
            ProxyKind::Socks5,
            DevTargets::default(),
        )
        .unwrap();
        let socks = Some(EnvValue::Plain("socks5h://127.0.0.1:10808".into()));
        assert_eq!(env.get("HTTP_PROXY").unwrap(), socks);
        assert_eq!(env.get("ALL_PROXY").unwrap(), socks);
        assert_eq!(
            env.get("NO_PROXY").unwrap(),
            Some(EnvValue::Plain(env::NO_PROXY.into()))
        );
        assert!(soft.is_applied());
        assert!(soft.rollback_blocking().is_complete());
        assert_eq!(
            env.get("HTTP_PROXY").unwrap(),
            Some(expand.clone()),
            "{len}"
        );
        assert_eq!(env.get("ALL_PROXY").unwrap(), Some(long), "{len}");
        assert_eq!(env.get("HTTPS_PROXY").unwrap(), None);
        assert_eq!(env.get("NO_PROXY").unwrap(), None);
        assert!(!soft.is_applied());
    }
}

/// Missing tools are reported as not detected and nothing is created for them (spec AS1).
#[test]
fn missing_tools_are_skipped_without_creating_anything() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let soft = soft(&key, &dir);
    let all = DevTargets {
        git: true,
        gradle: true,
        android_studio: true,
    };
    let report = soft
        .apply_blocking(&addr("127.0.0.1:10808"), ProxyKind::Socks5, all)
        .unwrap();
    assert_eq!(report.applied, vec![Feature::SoftProxy, Feature::SoftEnv]);
    assert_eq!(
        report.not_detected,
        vec![Feature::DevGit, Feature::DevGradle, Feature::DevStudio]
    );
    assert!(!dir.path().join(".gradle").exists());
    assert!(!dir.path().join("Google").exists());
    let status = soft.status_blocking();
    assert_eq!(
        (status.env, status.gradle),
        (TweakState::On, TweakState::Off)
    );
    assert!(soft.rollback_blocking().is_complete());
    let err: AppError = TweakError::NotDetected(Feature::DevGit).into();
    assert_eq!(err.user_msg().args[0].1, "Git");
}

/// Spec G6: the dev targets belong to the Soft session. A refresh that drops a target rolls it
/// back; the stop rolls back everything and leaves the user's own lines untouched.
#[test]
fn dev_targets_follow_the_session() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let soft = soft(&key, &dir);
    let gradle_home = dir.path().join(".gradle");
    std::fs::create_dir_all(&gradle_home).unwrap();
    let props = gradle_home.join("gradle.properties");
    std::fs::write(&props, "org.gradle.jvmargs=-Xmx1g\n").unwrap();
    let install = dir.path().join("Google").join("AndroidStudio2024.2");
    std::fs::create_dir_all(&install).unwrap();
    let settings = studio::settings_file(&install);

    let both = DevTargets {
        gradle: true,
        android_studio: true,
        ..DevTargets::default()
    };
    let report = soft
        .apply_blocking(&addr("[::1]:10808"), ProxyKind::Socks5, both)
        .unwrap();
    assert_eq!(
        report.applied,
        vec![
            Feature::SoftProxy,
            Feature::SoftEnv,
            Feature::DevGradle,
            Feature::DevStudio
        ]
    );
    let text = std::fs::read_to_string(&props).unwrap();
    assert!(
        text.starts_with("org.gradle.jvmargs=-Xmx1g\n# >>> VPN Tunnel Enforcer (managed) >>>\n")
    );
    assert!(text.contains("systemProp.socksProxyHost=::1\nsystemProp.socksProxyPort=10808\n"));
    let xml = std::fs::read_to_string(&settings).unwrap();
    assert!(
        xml.contains(r#"<option name="PROXY_HOST" value="::1" />"#),
        "{xml}"
    );
    assert!(xml.contains(r#"<option name="PROXY_TYPE_IS_SOCKS" value="true" />"#));
    assert!(!studio::vmoptions_file(&install).exists(), "never created");
    let status = soft.status_blocking();
    assert_eq!(
        (status.env, status.gradle, status.android_studio, status.git),
        (
            TweakState::On,
            TweakState::On,
            TweakState::On,
            TweakState::Off
        )
    );

    let gradle_only = DevTargets {
        gradle: true,
        ..DevTargets::default()
    };
    let report = soft
        .apply_blocking(&addr("127.0.0.1:10809"), ProxyKind::Http, gradle_only)
        .unwrap();
    assert_eq!(report.dropped.restored.len(), 4, "the four IDE options");
    assert!(
        !settings.exists(),
        "the created settings file is removed again"
    );
    let text = std::fs::read_to_string(&props).unwrap();
    assert!(text.contains("systemProp.https.proxyPort=10809\n"));
    assert!(!text.contains("socksProxy"));

    assert!(soft.rollback_blocking().is_complete());
    assert_eq!(
        std::fs::read_to_string(&props).unwrap(),
        "org.gradle.jvmargs=-Xmx1g\n"
    );
    assert_eq!(UserEnv::under(&key.0).get("HTTP_PROXY").unwrap(), None);
}

/// The async API runs the same work on the blocking pool.
#[tokio::test]
async fn async_api_round_trip() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let soft = soft(&key, &dir);
    soft.apply(
        addr("localhost:1080"),
        ProxyKind::Http,
        DevTargets::default(),
    )
    .await
    .unwrap();
    assert_eq!(soft.status().await.unwrap().env, TweakState::On);
    assert_eq!(
        UserEnv::under(&key.0).get("HTTPS_PROXY").unwrap(),
        Some(EnvValue::Plain("http://localhost:1080".into()))
    );
    assert!(soft.rollback().await.unwrap().is_complete());
    assert_eq!(soft.status().await.unwrap().env, TweakState::Off);
}

/// The opt-in list is stored by the app next to its camelCase settings; missing fields are off.
#[test]
fn dev_targets_are_camel_case() {
    let dev = DevTargets {
        android_studio: true,
        ..DevTargets::default()
    };
    let json = serde_json::to_value(dev).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"git": false, "gradle": false, "androidStudio": true})
    );
    let read: DevTargets = serde_json::from_str(r#"{"androidStudio": true}"#).unwrap();
    assert_eq!(read, dev);
}

/// NOADMIN §2: Soft points the system proxy at the mixed inbound for every protocol (loopback and
/// local names direct, setup script and auto-detection off), keeps the original across a
/// refresh, and restores it exactly on stop.
#[test]
fn the_system_proxy_follows_the_session_and_comes_back_exactly() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let proxy = FakeProxy::with(corporate());
    let soft = soft_with(&key, &dir, &proxy);
    assert_eq!(soft.status_blocking().system_proxy, ProxyOwner::User);

    let none = DevTargets::default();
    soft.apply_blocking(&addr("127.0.0.1:10808"), ProxyKind::Socks5, none)
        .unwrap();
    let ours = proxy.get();
    assert_eq!(
        (ours.use_proxy, ours.server.as_str(), ours.bypass.as_str()),
        (true, "127.0.0.1:10808", "localhost;127.*;[::1];<local>")
    );
    assert!(!ours.use_pac && !ours.auto_detect && ours.pac_url.is_empty());
    assert_eq!(
        UserEnv::under(&key.0).get("ALL_PROXY").unwrap(),
        Some(EnvValue::Plain("socks5h://127.0.0.1:10808".into())),
        "the variables keep the session's scheme"
    );
    assert_eq!(soft.status_blocking().system_proxy, ProxyOwner::Ours);

    soft.apply_blocking(&addr("127.0.0.1:10809"), ProxyKind::Http, none)
        .unwrap();
    assert_eq!(proxy.get().server, "127.0.0.1:10809");
    let report = soft.rollback_blocking();
    assert!(report.is_complete());
    assert!(report.restored.contains(&Target::SystemProxy));
    assert_eq!(
        proxy.get(),
        corporate(),
        "the original, not the first Soft value"
    );
    assert_eq!(soft.status_blocking().system_proxy, ProxyOwner::User);
    assert!(!soft.is_applied());
}

/// F-121 for the system proxy: settings the user changed while Soft was on are kept on stop.
#[test]
fn a_system_proxy_the_user_changed_is_kept() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let proxy = FakeProxy::with(ProxyConfig::default());
    let soft = soft_with(&key, &dir, &proxy);
    soft.apply_blocking(
        &addr("127.0.0.1:10808"),
        ProxyKind::Http,
        DevTargets::default(),
    )
    .unwrap();
    let theirs = ProxyConfig {
        auto_detect: true,
        ..proxy.get()
    };
    *proxy.config.lock() = theirs.clone();
    assert_eq!(soft.status_blocking().system_proxy, ProxyOwner::User);
    let report = soft.rollback_blocking();
    assert_eq!(report.kept_user_value, vec![Target::SystemProxy]);
    assert!(report.is_complete());
    assert_eq!(proxy.get(), theirs);
    assert!(!soft.is_applied());
}

/// An unreadable system proxy aborts the whole apply: no variable is written either; a refused
/// write is undone the same way.
#[test]
fn a_system_proxy_that_fails_changes_nothing() {
    let (key, dir) = (TestKey::new("tweaks"), TempDir::new("tweaks"));
    let proxy = FakeProxy::with(corporate());
    let soft = soft_with(&key, &dir, &proxy);
    let env = UserEnv::under(&key.0);
    let apply = || {
        soft.apply_blocking(
            &addr("127.0.0.1:10808"),
            ProxyKind::Http,
            DevTargets::default(),
        )
    };

    proxy
        .fail_read
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let err = apply().unwrap_err();
    assert_eq!(err.user_msg().key, "automation.tweaks.unreadable");
    assert_eq!(soft.status_blocking().system_proxy, ProxyOwner::Unreadable);
    proxy
        .fail_read
        .store(false, std::sync::atomic::Ordering::Relaxed);

    proxy
        .fail_write
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let err = apply().unwrap_err();
    assert_eq!(err.user_msg().key, "automation.tweaks.writeFailed");

    assert!(proxy.writes.lock().is_empty());
    assert_eq!(proxy.get(), corporate());
    assert_eq!(env.get("HTTP_PROXY").unwrap(), None);
    assert!(!soft.is_applied());
}
