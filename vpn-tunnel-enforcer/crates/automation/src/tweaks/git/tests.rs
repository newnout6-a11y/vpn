//! Git target on a temp global config (`GIT_CONFIG_GLOBAL` for the child only): the user's own
//! `~/.gitconfig` is never read or written. Skipped quietly when Git is not installed or too old
//! to honour `GIT_CONFIG_GLOBAL` (2.32).
use std::process::Command;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::journal::{Journal, TweakError, no_registry};
use crate::tweaks::soft::SoftSystem;
use crate::tweaks::test_support::FakeProxy;

fn git_on(dir: &TempDir) -> Option<GitCli> {
    let mut git = GitCli::find()?;
    let out = Command::new(&git.exe).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let version: Vec<u32> = text
        .split_whitespace()
        .nth(2)?
        .split('.')
        .take(2)
        .filter_map(|p| p.parse().ok())
        .collect();
    if version.as_slice() < [2, 32].as_slice() {
        eprintln!("git {text} is too old for GIT_CONFIG_GLOBAL; skipped");
        return None;
    }
    git.global_file = Some(dir.path().join("gitconfig"));
    Some(git)
}

fn with_git(git: GitCli) -> SoftSystem {
    let mut sys = SoftSystem {
        proxy: FakeProxy::with(Default::default()),
        env: vpnte_winnet::env::UserEnv::under(r"Software\VPNTE-Test-tweaks-unused"),
        git: None,
        gradle_home: None,
        studio_root: None,
        broadcast: false,
        check_user: false,
    };
    sys.git = Some(git);
    sys
}

/// The previous global proxy comes back; a key that was not set is unset again.
#[test]
fn git_proxy_round_trip() {
    let dir = TempDir::new("tweaks");
    let Some(git) = git_on(&dir) else {
        eprintln!("git not found; skipped");
        return;
    };
    assert_eq!(git.read(GitKey::HttpProxy).unwrap(), Val::Absent);
    git.write(GitKey::HttpProxy, &Val::Text("http://corp:8080".into()))
        .unwrap();
    let journal = Journal::open(&dir.path().join("data"), no_registry);
    let sys = with_git(git.clone());
    let addr = HostPort::parse("[::1]:10808").unwrap();
    journal
        .apply(&sys, &plan(&addr, ProxyKind::Socks5))
        .unwrap();
    let ours = Val::Text("socks5h://[::1]:10808".into());
    assert_eq!(git.read(GitKey::HttpProxy).unwrap(), ours);
    assert_eq!(git.read(GitKey::HttpsProxy).unwrap(), ours);
    let file = std::fs::read_to_string(dir.path().join("gitconfig")).unwrap();
    assert!(
        file.contains("socks5h://[::1]:10808"),
        "written to the temp file"
    );

    assert!(journal.rollback(&sys, &[Feature::DevGit]).is_complete());
    assert_eq!(
        git.read(GitKey::HttpProxy).unwrap(),
        Val::Text("http://corp:8080".into())
    );
    assert_eq!(git.read(GitKey::HttpsProxy).unwrap(), Val::Absent);
    git.write(GitKey::HttpsProxy, &Val::Absent).unwrap();
}

/// G7: a Git that cannot be run is "unreadable": the apply aborts and nothing is journalled
/// (the old code took the error for "no proxy" and later deleted the user's real one).
#[test]
fn unreadable_git_aborts_the_apply() {
    let dir = TempDir::new("tweaks");
    let broken = GitCli {
        exe: dir.path().join("no-such-git.exe"),
        global_file: Some(dir.path().join("gitconfig")),
    };
    let journal = Journal::open(&dir.path().join("data"), no_registry);
    let addr = HostPort::parse("127.0.0.1:10808").unwrap();
    let result = journal.apply(&with_git(broken), &plan(&addr, ProxyKind::Socks5));
    assert!(matches!(result, Err(TweakError::Unreadable(..))));
    assert!(!journal.is_applied(Feature::DevGit));
    assert!(!dir.path().join("gitconfig").exists());
}
