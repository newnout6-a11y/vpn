use std::collections::BTreeSet;

use super::*;
use crate::wfp::spec::{Action, Cond, Layer};

fn id(name: &str) -> Arc<AppId> {
    Arc::new(AppId::from_bytes(name.as_bytes().to_vec()))
}

fn plan(level: KillSwitchLevel, conn: Conn, pwc: bool) -> Plan {
    Plan {
        level,
        leak_protection: true,
        public_wifi_compat: pwc,
        allow_lan: true,
        conn,
        tun_luid: (conn == Conn::Up).then_some(0x1234),
        tun_addrs: Vec::new(),
        engines: vec![id("sing-box"), id("xray")],
        own: Some(id("vpnte")),
        session: Vec::new(),
        exception_apps: vec![id("corp-app")],
        exception_nets: vec![
            "192.0.2.1/24".parse().unwrap(),
            "2001:db8::5/128".parse().unwrap(),
        ],
    }
}

fn groups(specs: &[FilterSpec]) -> BTreeSet<&'static str> {
    specs.iter().map(|s| s.name).collect()
}

fn set(names: &[&'static str]) -> BTreeSet<&'static str> {
    names.iter().copied().collect()
}

const FULL: [&str; 12] = [
    "engine",
    "self",
    "loopback",
    "exception_app",
    "exception_ip",
    "lan",
    "dhcp",
    "dhcp6",
    "ntp",
    "ndp",
    "block4",
    "block6",
];
const V6ONLY: [&str; 9] = [
    "engine",
    "self",
    "loopback",
    "exception_app",
    "exception_ip",
    "lan",
    "dhcp6",
    "ndp",
    "block6",
];

fn plus(base: &[&'static str], extra: &[&'static str]) -> BTreeSet<&'static str> {
    base.iter().chain(extra).copied().collect()
}

fn is_v6(layer: Layer) -> bool {
    matches!(layer, Layer::Connect6 | Layer::Accept6)
}

/// AT-03-001 / AT-03-007 (§7.10, review D1): leak protection with the kill switch off blocks
/// non-TUN IPv6 and non-TUN DNS from `connect_begin` on, but no other IPv4.
#[test]
fn leak_protection_only() {
    let d = desired(&plan(KillSwitchLevel::Off, Conn::Disconnected, true));
    assert_eq!(d, Desired::default());

    let mut p = plan(KillSwitchLevel::Off, Conn::Connecting, true);
    p.session = vec![id("happ-core")];
    let d = desired(&p);
    assert_eq!(groups(&d.dynamic), plus(&V6ONLY, &["session", "dns"]));
    assert!(d.persistent.is_empty());
    let blocks_v4 = d
        .dynamic
        .iter()
        .filter(|s| s.action == Action::Block && !is_v6(s.layer))
        .all(|s| s.name == "dns");
    assert!(blocks_v4, "the only IPv4 block is the DNS block");
    let lan = d.dynamic.iter().filter(|s| s.name == "lan");
    assert!(lan.clone().count() > 0 && lan.into_iter().all(|s| is_v6(s.layer)));

    let d = desired(&plan(KillSwitchLevel::Off, Conn::Up, true));
    assert_eq!(groups(&d.dynamic), plus(&V6ONLY, &["tun", "dns"]));
    let d = desired(&plan(KillSwitchLevel::Off, Conn::Dropped, true));
    assert_eq!(groups(&d.dynamic), plus(&V6ONLY, &["dns"]));

    let mut off = plan(KillSwitchLevel::Off, Conn::Up, true);
    off.leak_protection = false;
    assert_eq!(desired(&off), Desired::default());
}

/// AT-03-001 / AT-03-003 (§7.10, review D1 / D5): standard is dynamic and engaged for the whole
/// session, with the DNS block from `connect_begin` on and after a drop, whatever `pwc` says.
#[test]
fn standard_level() {
    let off = desired(&plan(KillSwitchLevel::Standard, Conn::Disconnected, true));
    assert_eq!(off, Desired::default());
    for pwc in [true, false] {
        let d = desired(&plan(KillSwitchLevel::Standard, Conn::Connecting, pwc));
        assert_eq!(groups(&d.dynamic), plus(&FULL, &["dns"]));
        assert!(d.persistent.is_empty());
        let d = desired(&plan(KillSwitchLevel::Standard, Conn::Dropped, pwc));
        assert_eq!(
            groups(&d.dynamic),
            plus(&FULL, &["dns"]),
            "no tun after a drop"
        );
    }
    let d = desired(&plan(KillSwitchLevel::Standard, Conn::Up, true));
    assert_eq!(groups(&d.dynamic), plus(&FULL, &["tun", "dns"]));
    let mut p = plan(KillSwitchLevel::Standard, Conn::Connecting, true);
    p.session = vec![id("happ-core")];
    assert_eq!(
        groups(&desired(&p).dynamic),
        plus(&FULL, &["session", "dns"])
    );
}

/// AT-03-010 / AT-03-012 (§7.10, review D1): strict is persistent; a session adds only dynamic
/// parts, the DNS block among them as soon as the session starts (unless already persistent).
#[test]
fn strict_level() {
    let d = desired(&plan(KillSwitchLevel::Strict, Conn::Disconnected, true));
    assert_eq!(
        (groups(&d.persistent), d.dynamic.len()),
        (plus(&FULL, &[]), 0)
    );
    let d = desired(&plan(KillSwitchLevel::Strict, Conn::Disconnected, false));
    assert_eq!(
        (groups(&d.persistent), d.dynamic.len()),
        (plus(&FULL, &["dns"]), 0)
    );
    for conn in [Conn::Connecting, Conn::Dropped] {
        let d = desired(&plan(KillSwitchLevel::Strict, conn, true));
        assert_eq!(groups(&d.dynamic), set(&["dns"]), "{conn:?}");
    }
    let mut p = plan(KillSwitchLevel::Strict, Conn::Up, true);
    p.session = vec![id("happ-core")];
    let d = desired(&p);
    assert_eq!(groups(&d.dynamic), set(&["session", "tun", "dns"]));
    assert_eq!(groups(&d.persistent), plus(&FULL, &[]));
    let d = desired(&plan(KillSwitchLevel::Strict, Conn::Up, false));
    assert_eq!(groups(&d.dynamic), set(&["tun"]));
    assert!(d.persistent.iter().any(|s| s.name == "dns"));
    assert!(
        d.persistent
            .iter()
            .all(|s| s.name != "session" && s.name != "tun")
    );
}

/// §7.10 weight order: programs 15 > loopback 14 > tun 13 > exceptions 12 > dns 11 >
/// lan / dhcp / dhcp6 / ntp / ndp 10 > blocks 0; only `dns` and the blocks block.
#[test]
fn weight_order() {
    let mut p = plan(KillSwitchLevel::Standard, Conn::Up, true);
    p.session = vec![id("happ-core")];
    let d = desired(&p);
    let expected = [
        ("engine", 15),
        ("self", 15),
        ("session", 15),
        ("loopback", 14),
        ("tun", 13),
        ("exception_app", 12),
        ("exception_ip", 12),
        ("dns", 11),
        ("lan", 10),
        ("dhcp", 10),
        ("dhcp6", 10),
        ("ntp", 10),
        ("ndp", 10),
        ("block4", 0),
        ("block6", 0),
    ];
    for (name, weight) in expected {
        let specs: Vec<_> = d.dynamic.iter().filter(|s| s.name == name).collect();
        assert!(!specs.is_empty(), "{name} missing");
        assert!(specs.iter().all(|s| s.weight == weight), "{name} weight");
        let blocks = matches!(name, "dns" | "block4" | "block6");
        assert!(
            specs.iter().all(|s| (s.action == Action::Block) == blocks),
            "{name} action"
        );
    }
    assert_eq!(groups(&d.dynamic).len(), expected.len());
}

/// AT-03-012 (§7.3): exceptions keep every core scope; `192.0.2.1` and `2001:db8::5` give a
/// connect + accept pair on their family, an app exception one filter per layer.
#[test]
fn exception_scopes() {
    let mut p = plan(KillSwitchLevel::Standard, Conn::Connecting, true);
    p.exception_nets = vec![
        "192.0.2.1/32".parse().unwrap(),
        "2001:db8::5/128".parse().unwrap(),
    ];
    let d = desired(&p);
    let ips: Vec<_> = d
        .dynamic
        .iter()
        .filter(|s| s.name == "exception_ip")
        .map(|s| (s.layer, s.conds.clone()))
        .collect();
    let v4 = || vec![Cond::RemoteV4("192.0.2.1/32".parse().unwrap())];
    let v6 = || vec![Cond::RemoteV6("2001:db8::5/128".parse().unwrap())];
    let want = [
        (Layer::Connect4, v4()),
        (Layer::Accept4, v4()),
        (Layer::Connect6, v6()),
        (Layer::Accept6, v6()),
    ];
    assert_eq!(ips, want);
    assert_eq!(
        d.dynamic
            .iter()
            .filter(|s| s.name == "exception_app")
            .count(),
        4
    );
    for core in ["engine", "self", "loopback", "block4", "block6"] {
        assert!(d.dynamic.iter().any(|s| s.name == core), "{core}");
    }
}

/// The TUN permit follows the LUID (replaced after an engine restart); LAN can be turned off.
#[test]
fn tun_luid_and_lan_toggle() {
    let mut p = plan(KillSwitchLevel::Standard, Conn::Up, true);
    p.tun_luid = Some(0xbeef);
    p.allow_lan = false;
    let d = desired(&p);
    let tun: Vec<_> = d.dynamic.iter().filter(|s| s.name == "tun").collect();
    assert_eq!(tun.len(), 4);
    assert!(
        tun.iter()
            .all(|s| s.conds == [Cond::LocalInterface(0xbeef)])
    );
    assert!(d.dynamic.iter().all(|s| s.name != "lan"));
}

const TUN_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 168, 250, 253);

/// Review R1: from `connect_begin` until the LUID is known, the TUN's fixed local addresses are
/// permitted (weight of `tun`) on their family's layers, in every level; never afterwards.
#[test]
fn tun_address_permits_are_provisional() {
    let v6: std::net::IpAddr = "fd8b:3f2a:91c4::1".parse().unwrap();
    let mut p = plan(KillSwitchLevel::Standard, Conn::Connecting, true);
    p.tun_addrs = vec![TUN_V4.into(), v6];
    let d = desired(&p);
    let permits: Vec<_> = d
        .dynamic
        .iter()
        .filter(|s| s.name == "tun_addr")
        .inspect(|s| assert_eq!((s.action, s.weight), (Action::Permit, 13)))
        .map(|s| (s.layer, s.conds.clone()))
        .collect();
    let want = [
        (Layer::Connect4, vec![Cond::LocalAddr(TUN_V4.into())]),
        (Layer::Accept4, vec![Cond::LocalAddr(TUN_V4.into())]),
        (Layer::Connect6, vec![Cond::LocalAddr(v6)]),
        (Layer::Accept6, vec![Cond::LocalAddr(v6)]),
    ];
    assert_eq!(permits, want);
    for level in [KillSwitchLevel::Off, KillSwitchLevel::Strict] {
        p.level = level;
        assert!(desired(&p).dynamic.iter().any(|s| s.name == "tun_addr"));
    }
    for conn in [Conn::Up, Conn::Dropped, Conn::Disconnected] {
        p.conn = conn;
        p.tun_luid = (conn == Conn::Up).then_some(9);
        let d = desired(&p);
        assert!(d.dynamic.iter().all(|s| s.name != "tun_addr"), "{conn:?}");
    }
}
