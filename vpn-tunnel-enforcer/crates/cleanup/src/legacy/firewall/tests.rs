use std::path::PathBuf;

use super::*;
use crate::test_support::TempDir;

/// AT-03-003 (`firewallRulesApi.test.ts`): ownership by prefix, ordinal ignore case.
#[test]
fn owned_rule_names() {
    let names = [
        "Foreign-VPNTE-killswitch",
        "VPNTE",
        "ordinary-rule",
        "VPNTE-killswitch-allow-one",
        "vpnte-KILLSWITCH-legacy",
    ];
    let owned: Vec<&str> = names.into_iter().filter(|n| is_owned_rule(n)).collect();
    assert_eq!(
        owned,
        ["VPNTE-killswitch-allow-one", "vpnte-KILLSWITCH-legacy"]
    );
    assert!(is_owned_rule("VPNTE-killswitch-legacy (old)"));
    assert!(!is_owned_rule("VPNTE-kill"));
    assert!(!is_owned_rule("Включить VPNTE-killswitch"));
}

/// Review D4: only `sing-tun (<path>)` rules of our engine paths are ours.
#[test]
fn singtun_rules_of_our_engines() {
    let engines = [PathBuf::from(
        r"C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe",
    )];
    let runtime = PathBuf::from(r"C:\ProgramData\VPNTE\runtime");
    let ours = |name: &str| is_singtun_rule(name, &engines, &runtime);
    assert!(ours(
        r"sing-tun (C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe)"
    ));
    assert!(ours(
        r"sing-tun (c:\program files\vpn tunnel enforcer\RESOURCES\sing-box.exe)"
    ));
    assert!(ours(
        r"sing-tun (\\?\C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe)"
    ));
    assert!(ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime\0123456789abcdef0123456789abcdef\tun-runtime\vpnte-sing-box.exe)"
    ));
    assert!(ours(
        r"sing-tun (C:\PROGRAMDATA\vpnte\Runtime\x\TUN-RUNTIME\VPNTE-SING-BOX.EXE)"
    ));
    // Another sing-box client (Happ, v2rayN, ...) and look-alikes stay.
    assert!(!ours(r"sing-tun (C:\Program Files\Happ\core\sing-box.exe)"));
    assert!(!ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime-evil\x\tun-runtime\vpnte-sing-box.exe)"
    ));
    assert!(!ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime\..\tun-runtime\vpnte-sing-box.exe)"
    ));
    assert!(!ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime\a\b\tun-runtime\vpnte-sing-box.exe)"
    ));
    assert!(!ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime\x\tun-runtime\sing-box.exe)"
    ));
    assert!(!ours(
        r"sing-tun (C:\ProgramData\VPNTE\runtime\\tun-runtime\vpnte-sing-box.exe)"
    ));
    assert!(!ours(
        r"C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe"
    ));
    assert!(!ours(
        r"sing-tun C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe"
    ));
}

fn journal(strict_mode: bool, profiles: Vec<(FwProfile, Outbound)>) -> FirewallJournal {
    FirewallJournal {
        strict_mode,
        profiles,
        skipped: Vec::new(),
    }
}

const ALL_BLOCK: [(FwProfile, Action); 3] = [
    (FwProfile::Domain, Action::Block),
    (FwProfile::Private, Action::Block),
    (FwProfile::Public, Action::Block),
];

/// §7.10 legacy vectors: strict evidence resets Block profiles even without a journal or
/// rules; without evidence a Block policy is foreign and untouched.
#[test]
fn strict_evidence_resets_blocks() {
    let p = plan(true, None, false);
    assert_eq!(p, ProfilePlan::ResetBlocks);
    let all_allow: Vec<_> = PROFILES.iter().map(|&p| (p, Action::Allow)).collect();
    assert_eq!(writes(&p, &ALL_BLOCK), all_allow);
    let p = plan(false, None, false);
    assert_eq!(p, ProfilePlan::Untouched);
    assert!(writes(&p, &ALL_BLOCK).is_empty());
    // firewall.json with Domain Block and strictMode true: strict evidence wins.
    let j = journal(true, vec![(FwProfile::Domain, Outbound::Block)]);
    let p = plan(true, Some(&j), true);
    assert_eq!(
        writes(
            &p,
            &[
                (FwProfile::Domain, Action::Block),
                (FwProfile::Private, Action::Allow),
                (FwProfile::Public, Action::Allow)
            ]
        ),
        [(FwProfile::Domain, Action::Allow)]
    );
}

/// AT-03-002: a valid journal restores its values (`NotConfigured` as Allow); our rules
/// without a journal set every profile to Allow.
#[test]
fn journal_restores_and_fallback() {
    let j = journal(
        false,
        vec![
            (FwProfile::Domain, Outbound::Block),
            (FwProfile::Private, Outbound::Allow),
            (FwProfile::Public, Outbound::NotConfigured),
        ],
    );
    let p = plan(false, Some(&j), true);
    let current = [
        (FwProfile::Domain, Action::Allow),
        (FwProfile::Private, Action::Block),
        (FwProfile::Public, Action::Block),
    ];
    assert_eq!(
        writes(&p, &current),
        [
            (FwProfile::Domain, Action::Block),
            (FwProfile::Private, Action::Allow),
            (FwProfile::Public, Action::Allow)
        ]
    );
    let p = plan(false, None, true);
    assert_eq!(p, ProfilePlan::AllowAll);
    let current = [
        (FwProfile::Domain, Action::Allow),
        (FwProfile::Private, Action::Block),
        (FwProfile::Public, Action::Allow),
    ];
    assert_eq!(writes(&p, &current), [(FwProfile::Private, Action::Allow)]);
}

/// Read-only: enumerating rules and profiles works unelevated and changes nothing.
#[test]
fn reads_the_rule_list() {
    let policy = Policy::open().expect("INetFwPolicy2");
    let names = policy.rule_names().expect("rule enumeration");
    assert!(!names.is_empty());
    for profile in PROFILES {
        policy.outbound(profile).expect("profile read");
    }
}

/// An existing path is also compared in its canonical spelling (8.3, case, `\\?\`).
#[test]
fn long_path_spelling() {
    let tmp = TempDir::new("long");
    let dir = tmp.path();
    let exe = tmp.write("Sing-Box.exe", b"x");
    let canonical = long_path(&exe).expect("canonical path");
    assert!(!canonical.to_str().unwrap().starts_with(r"\\?\"));
    let upper = PathBuf::from(exe.to_str().unwrap().to_uppercase());
    assert_eq!(long_path(&upper).as_deref(), Some(canonical.as_path()));
    assert!(long_path(&dir.join("absent.exe")).is_none());
    let rule = format!("sing-tun ({})", canonical.display());
    assert!(is_singtun_rule(
        &rule,
        std::slice::from_ref(&canonical),
        dir
    ));
    assert_eq!(rule_path(&rule), canonical.to_str());
}

/// Acts on this machine: adds a disabled throw-away rule and removes exactly that rule through
/// the same bounded removal loop the cleanup uses (no rule of the old app is touched).
#[test]
#[ignore = "needs elevation"]
fn elevated_removes_exactly_the_matching_rules() {
    use windows::Win32::Foundation::VARIANT_FALSE;
    use windows::Win32::NetworkManagement::WindowsFirewall::{NET_FW_RULE_DIR_IN, NetFwRule};

    let name = format!("vpnte-cleanup-test-{}", std::process::id());
    let policy = Policy::open().expect("INetFwPolicy2");
    // SAFETY: COM is initialised by `policy`; plain property setters on a fresh rule.
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).unwrap();
        rule.SetName(&BSTR::from(name.as_str())).unwrap();
        rule.SetDirection(NET_FW_RULE_DIR_IN).unwrap();
        rule.SetProtocol(6).unwrap();
        rule.SetEnabled(VARIANT_FALSE).unwrap();
        policy.policy.Rules().unwrap().Add(&rule).unwrap();
    }
    assert!(policy.rule_names().unwrap().contains(&name));
    assert_eq!(policy.remove(|n| n == name), Ok(1));
    assert!(!policy.rule_names().unwrap().contains(&name));
}
