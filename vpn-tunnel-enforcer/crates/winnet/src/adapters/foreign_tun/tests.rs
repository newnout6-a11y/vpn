use vpnte_base::ErrorKind;
use windows::core::GUID;

use super::*;
use crate::adapters::{AdapterStatus, UnicastAddress};

fn tunnel(luid: u64, alias: &str, description: &str, addrs: &[&str]) -> Adapter {
    Adapter {
        if_index: luid as u32,
        luid,
        guid: GUID::from_u128(luid.into()),
        alias: alias.into(),
        description: description.into(),
        if_type: 53,
        status: AdapterStatus::Up,
        mac: Vec::new(),
        permanent_mac: Vec::new(),
        hardware: false,
        filter: false,
        hidden: false,
        driver: None,
        ipv4_enabled: true,
        ipv6_enabled: true,
        link_speed_bps: 0,
        addresses: addrs
            .iter()
            .map(|ip| UnicastAddress {
                ip: ip.parse().unwrap(),
                prefix_len: 30,
                dad_state: 4,
                temporary: false,
            })
            .collect(),
        gateways: Vec::new(),
        dns: Vec::new(),
        dns_static: false,
        physical: false,
    }
}

fn route(luid: u64, prefix: &str) -> Route {
    Route {
        if_index: luid as u32,
        luid,
        destination: prefix.parse().unwrap(),
        next_hop: None,
        metric: 0,
        protocol: 3,
    }
}

fn labels(adapters: &[Adapter], own_luid: Option<u64>, own_aliases: &[&str]) -> Vec<String> {
    classify(adapters, &[], own_luid, own_aliases)
        .iter()
        .map(Foreign::label)
        .collect()
}

/// AT-02-002 / AT-03-004: name vectors of tunnel-core §7.15; a shared private subnet is no exemption.
#[test]
fn foreign_by_name() {
    for ip in ["172.19.0.2", "192.168.250.2", "192.168.250.253", "10.8.0.2"] {
        assert_eq!(
            labels(&[tunnel(1, "happ-xray", "x", &[ip])], None, &[]),
            [format!("happ-xray ({ip})")]
        );
    }
    for name in [
        "happ-xray",
        "WireGuard Tunnel",
        "sing-tun",
        "Corporate VPN",
        "wg0",
    ] {
        assert_eq!(
            labels(&[tunnel(1, name, "x", &["fd00::2"])], None, &[]),
            [format!("{name} (fd00::2)")]
        );
    }
    // IPv4 is preferred for the label even when IPv6 comes first.
    assert_eq!(
        labels(
            &[tunnel(1, "wg0", "x", &["fe80::1", "10.8.0.2"])],
            None,
            &[]
        ),
        ["wg0 (10.8.0.2)"]
    );
    assert!(labels(&[], None, &[]).is_empty());
    assert!(
        labels(&[tunnel(1, "happ-xray", "x", &[])], None, &[]).is_empty(),
        "no address"
    );
    assert!(
        labels(&[tunnel(1, "happ-xray", "x", &["127.0.0.1"])], None, &[]).is_empty(),
        "loopback only"
    );
    assert!(
        labels(
            &[tunnel(1, "Wi-Fi", "Intel(R) Wi-Fi 6", &["192.168.1.5"])],
            None,
            &[]
        )
        .is_empty()
    );
    let down = Adapter {
        status: AdapterStatus::Disconnected,
        ..tunnel(1, "wg0", "x", &["10.8.0.2"])
    };
    assert!(labels(&[down], None, &[]).is_empty());
    let filter = Adapter {
        filter: true,
        ..tunnel(
            1,
            "happ-xray-Npcap Packet Driver (NPCAP)-0000",
            "x",
            &["10.8.0.2"],
        )
    };
    assert!(
        labels(&[filter], None, &[]).is_empty(),
        "filter modules are not adapters"
    );
}

/// AT-02-002: our proved adapter (alias + exact IPv4, its IPv6 included) is exempt; a second
/// tunnel is still found; near misses and a stale controller (no own data) are not exempt.
#[test]
fn own_exemption() {
    let own = tunnel(
        1,
        "VPNTE-TUN",
        "sing-tun Tunnel",
        &["192.168.250.253", "fd8b:3f2a:91c4::1"],
    );
    let happ = tunnel(2, "happ-xray", "Happ Tunnel", &["192.168.250.254"]);
    assert_eq!(
        labels(&[own.clone(), happ], None, &["VPNTE-TUN"]),
        ["happ-xray (192.168.250.254)"]
    );
    assert!(
        labels(std::slice::from_ref(&own), Some(1), &[]).is_empty(),
        "by LUID"
    );
    assert_eq!(
        labels(std::slice::from_ref(&own), None, &[]).len(),
        1,
        "stale controller: no exemption"
    );
    let elsewhere = tunnel(3, "happ-xray", "x", &["192.168.250.253"]);
    let other_ip = tunnel(4, "VPNTE-TUN", "x", &["192.168.250.2"]);
    let v6_only = tunnel(5, "VPNTE-TUN", "x", &["fd8b:3f2a:91c4::1"]);
    for a in [elsewhere, other_ip, v6_only] {
        assert_eq!(
            labels(std::slice::from_ref(&a), None, &["VPNTE-TUN"]).len(),
            1,
            "{a:?}"
        );
    }
}

/// AT-03-004 (new): severity from default-capturing routes; description and driver count.
#[test]
fn severity_from_routes() {
    let tap = tunnel(1, "Ethernet 3", "TAP-Windows Adapter V9", &["10.8.0.6"]);
    let home = Adapter {
        driver: Some("wireguard".into()),
        ..tunnel(2, "Home", "Home", &["10.66.0.2"])
    };
    let routes = [
        route(1, "0.0.0.0/1"),
        route(1, "128.0.0.0/1"),
        route(2, "10.66.0.0/24"),
    ];
    let found = classify(&[home, tap], &routes, None, &[]);
    let got: Vec<(&str, Severity)> = found
        .iter()
        .map(|f| (f.name.as_str(), f.severity))
        .collect();
    assert_eq!(
        got,
        [
            ("Ethernet 3", Severity::Conflict),
            ("Home", Severity::Warning)
        ]
    );
    let err = refuse_on_conflict(&found).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "winnet.adapters.foreignTunConflict");
    assert!(
        refuse_on_conflict(&found[1..]).is_ok(),
        "a split tunnel is only a warning"
    );
    for prefix in ["0.0.0.0/0", "::/0", "::/1", "8000::/1"] {
        let one = classify(
            &[tunnel(1, "wg0", "x", &["10.8.0.2"])],
            &[route(1, prefix)],
            None,
            &[],
        );
        assert_eq!(one[0].severity, Severity::Conflict, "{prefix}");
    }
    let wintun = Adapter {
        driver: Some("wintun".into()),
        ..tunnel(3, "Ethernet 4", "Foo", &["10.1.0.2"])
    };
    assert_eq!(
        classify(&[wintun], &[], None, &[]).len(),
        1,
        "any Wintun adapter is tunnel-like"
    );
    // The user's uplink renamed "VPN router" owns the default route but is hardware: not a tunnel.
    let uplink = Adapter {
        hardware: true,
        ..tunnel(
            4,
            "VPN router",
            "Intel(R) Ethernet Controller I225-V",
            &["192.168.1.5"],
        )
    };
    assert!(classify(&[uplink], &[route(4, "0.0.0.0/0")], None, &[]).is_empty());
}

#[test]
fn word_boundaries() {
    for yes in ["tun", "my tun 2", "wg", "wg0", "wg12 home", "corp-wg3"] {
        assert!(tunnel_text(yes), "{yes}");
    }
    for no in [
        "tunnelling",
        "Teredo Tunneling Pseudo-Interface",
        "awg0",
        "wgx",
        "stun",
        "Ethernet 2",
    ] {
        assert!(!tunnel_text(no), "{no}");
    }
    assert!(
        !has_word("tun_x", "tun", false),
        "underscore is a word character"
    );
}

/// Live read on this machine: answers, sorted by severity, never a physical adapter.
#[test]
fn live_detect() {
    let found = detect(None, &[]).expect("detect");
    for f in &found {
        println!(
            "foreign TUN: {} — {} — {:?}",
            f.label(),
            f.description,
            f.severity
        );
    }
    assert!(found.windows(2).all(|w| w[0].severity >= w[1].severity));
    let physical: Vec<u64> = inventory()
        .expect("inventory")
        .iter()
        .filter(|a| a.physical)
        .map(|a| a.luid)
        .collect();
    assert!(found.iter().all(|f| !physical.contains(&f.luid)));
}
