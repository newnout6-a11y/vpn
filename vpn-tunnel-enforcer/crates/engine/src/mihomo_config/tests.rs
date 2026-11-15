use std::collections::HashMap;
use std::net::IpAddr;

use super::*;
use crate::test_support::awg_samples::{V1_0, v1_5, v2_0, v3_1};
use crate::test_support::{TempDir, awg_profile, mihomo_endpoints, mihomo_exe};

fn compile(p: &Profile, resolved: &HashMap<String, IpAddr>) -> Result<Compiled, TranslateError> {
    let (socks, hop, controller) = mihomo_endpoints();
    let listen = Listen {
        socks: &socks,
        hop: &hop,
        controller: &controller,
    };
    translate(p, resolved, &listen)
}

/// AT-12-004: the translated config is loopback-only, downloads nothing, stores nothing, and
/// every value it adds to the key is listed (the explicit diff).
#[test]
fn translation_is_loopback_only_and_lists_what_it_adds() {
    let p = awg_profile(&v2_0(), "awg.example.net:51820");
    assert_eq!(hosts(&p), ["awg.example.net"]);
    let resolved = HashMap::from([("awg.example.net".to_owned(), "203.0.113.7".parse().unwrap())]);
    let c = compile(&p, &resolved).unwrap();
    assert_eq!(
        c.applied,
        [Applied::Pinned(1), Applied::Mtu(DEFAULT_MTU), Applied::Dns]
    );
    for line in [
        "allow-lan: false\n",
        "bind-address: \"127.0.0.1\"\n",
        "geo-auto-update: false\n",
        "find-process-mode: \"off\"\n",
        "rules: [\"MATCH,awg\"]\n",
        "\"listen\":\"127.0.0.1\"",
        "- name: \"awg\"",
        "server: \"203.0.113.7\"",
        "mtu: 1376",
        "remote-dns-resolve: true",
        "dns: [\"1.1.1.1\", \"9.9.9.9\"]",
        "h1: \"100000-200000\"",
    ] {
        assert!(c.text.contains(line), "missing {line:?} in\n{}", c.text);
    }
    assert!(
        !c.text.contains("awg.example.net"),
        "mihomo never resolves the endpoint"
    );
    assert!(c.text.contains("external-controller: \"127.0.0.1:"));
    assert!(
        c.secrets
            .contains(&"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_owned())
    );
    assert!(!format!("{c:?}").contains("AQEB"), "Debug hides the keys");
    // A name the app did not resolve is never handed to mihomo.
    assert_eq!(
        compile(&p, &HashMap::new()).unwrap_err(),
        TranslateError::Unresolved
    );
}

/// AT-12-004: every thing mihomo cannot express is named, in one refusal, before any start;
/// AT-12-003 step 1: invalid parameters are refused with their field list.
#[test]
fn preflight_names_every_unsupported_part() {
    let mut p = awg_profile(V1_0, "203.0.113.7:51820");
    preflight(&p).unwrap();
    if let Kind::Amneziawg { wg, .. } = &mut p.kind {
        wg.local_address.push("10.9.0.2/32".parse().unwrap());
        wg.peers[0].reserved = Some([1, 2, 3]);
    }
    p.singbox_extra
        .insert("tls.fragment".into(), serde_json::json!(true));
    let err = preflight(&p).unwrap_err();
    assert_eq!(
        err,
        PreflightError::Unsupported(vec![
            Gap::Option("tls.fragment".into()),
            Gap::SecondAddress,
            Gap::Reserved,
        ])
    );
    let msg = err.msg();
    assert_eq!(msg.key, "engine.lab.preflight.unsupported");
    crate::test_locales::assert_localized(&msg.key);
    assert!(format!("{msg:?}").contains("tls.fragment, Address (second of one family), Reserved"));

    let ranged = awg_profile(&v3_1(), "203.0.113.7:51820\nPersistentKeepalive = 20-40");
    assert_eq!(
        preflight(&ranged),
        Err(PreflightError::Unsupported(vec![Gap::KeepaliveRange]))
    );
    let vless = vpnte_profiles::uri::parse_uri(
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=tls&sni=example.com#v",
    )
    .unwrap();
    assert_eq!(
        preflight(&vless),
        Err(PreflightError::Unsupported(vec![Gap::NotAmneziawg]))
    );
}

/// AT-12-003 step 1: parameters out of bounds are refused before mihomo sees them.
#[test]
fn invalid_parameters_are_refused_with_the_fields() {
    let mut p = awg_profile(V1_0, "203.0.113.7:51820");
    if let Kind::Amneziawg { awg, .. } = &mut p.kind {
        awg.jc = Some(500);
    }
    let err = preflight(&p).unwrap_err();
    let PreflightError::Invalid(invalid) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(invalid.names(), "Jc");
    assert_eq!(err.msg().key, "profiles.awg.invalid");
}

/// AT-12-001 (config compile): the pinned mihomo accepts the translation of every AmneziaWG
/// generation (`mihomo -t`, fake keys, a throw-away home); skipped without the binary.
#[tokio::test]
async fn mihomo_accepts_every_generation() {
    let Some(exe) = mihomo_exe() else {
        eprintln!("skipped: no resources/mihomo.exe (cargo xtask engines)");
        return;
    };
    let runs = TempDir::new("mihomo-check");
    for interface in [V1_0.to_owned(), v1_5(), v2_0(), v3_1()] {
        let p = awg_profile(&interface, "203.0.113.7:51820");
        let c = compile(&p, &HashMap::new()).unwrap();
        crate::mihomo_process::check_config(&exe, runs.path(), &c)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{}", c.text.replace(&c.secrets[0], "<key>")));
    }
    let broken = Compiled {
        text: "proxies:\n  - name: \"awg\"\n    type: wireguard\n    private-key: \"not base64\"\n"
            .into(),
        applied: Vec::new(),
        secrets: vec!["not base64".into()],
        hop: 0,
    };
    let err = crate::mihomo_process::check_config(&exe, runs.path(), &broken)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::mihomo_process::CheckError::Rejected(_)),
        "{err:?}"
    );
    assert!(!err.to_string().contains("not base64"), "{err}");
    assert_eq!(
        std::fs::read_dir(runs.path()).unwrap().count(),
        0,
        "run dirs removed"
    );
}
