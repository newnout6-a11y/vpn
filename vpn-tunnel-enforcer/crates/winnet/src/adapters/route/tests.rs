use std::cell::Cell;

use windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2;
use windows::Win32::Networking::WinSock::SOCKADDR_INET;

use super::*;
use crate::adapters::{TUN_V4, TUN_V6};

const TUN_LUID: u64 = 0x0035_0000_0000_0007;

fn tun(v6: bool) -> OwnedTun {
    OwnedTun {
        alias: "Ethernet 5".into(),
        luid: TUN_LUID,
        guid: windows::core::GUID::from_u128(0x1234),
        if_index: 7,
        v4: TUN_V4,
        v6: v6.then_some(TUN_V6),
    }
}

fn on(luid: u64, if_index: u32, prefix: &str) -> BestRoute {
    BestRoute {
        if_index,
        luid,
        destination: prefix.parse().unwrap(),
        next_hop: None,
        source: "192.168.250.253".parse().unwrap(),
    }
}

fn raw(if_index: u32, prefix: &str, source: &str) -> RawBest {
    RawBest {
        if_index,
        luid: TUN_LUID,
        prefix: Some((prefix.parse().unwrap(), 1)),
        next_hop: None,
        source: Some(source.parse().unwrap()),
    }
}

/// AT-06-003: the lookup input is a 28-byte `SOCKADDR_INET`, family 2, port and padding zero;
/// the route row is 104 bytes (firewall-recovery §7.6).
#[test]
fn best_route_abi() {
    assert_eq!(size_of::<SOCKADDR_INET>(), 28);
    assert_eq!(size_of::<MIB_IPFORWARD_ROW2>(), 104);
    for dst in CANARIES_V4 {
        // SAFETY: `SOCKADDR_INET` is plain old data of exactly 28 bytes (asserted above).
        let bytes: [u8; 28] = unsafe { std::mem::transmute(ffi::inet_from(IpAddr::V4(dst))) };
        let mut want = [0u8; 28];
        want[0] = 2;
        want[4..8].copy_from_slice(&dst.octets());
        assert_eq!(bytes, want, "{dst}");
        assert_eq!(
            ffi::inet_ip(&ffi::inet_from(IpAddr::V4(dst))),
            Some(IpAddr::V4(dst))
        );
    }
    let v6 = IpAddr::V6(CANARY_V6);
    assert_eq!(ffi::inet_ip(&ffi::inet_from(v6)), Some(v6));
}

/// AT-06-003: a usable answer has an interface, and route prefix and source of the
/// destination's family; index 0 or family 23 for an IPv4 destination fails the read.
#[test]
fn best_route_validation() {
    let dst = IpAddr::V4(CANARIES_V4[0]);
    let ok = check_best(dst, raw(7, "0.0.0.0", "192.168.250.253")).unwrap();
    assert_eq!(
        (ok.if_index, ok.luid, ok.destination.to_string()),
        (7, TUN_LUID, "0.0.0.0/1".into())
    );
    assert!(
        check_best(dst, raw(0, "0.0.0.0", "192.168.250.253")).is_err(),
        "index 0"
    );
    assert!(
        check_best(dst, raw(7, "::", "192.168.250.253")).is_err(),
        "route family 23"
    );
    assert!(
        check_best(dst, raw(7, "0.0.0.0", "fd8b:3f2a:91c4::1")).is_err(),
        "source family 23"
    );
    let none = RawBest {
        prefix: None,
        ..raw(7, "0.0.0.0", "10.0.0.1")
    };
    assert!(check_best(dst, none).is_err(), "unknown family");
    let v6 = check_best(IpAddr::V6(CANARY_V6), raw(7, "::", "fd8b:3f2a:91c4::1")).unwrap();
    assert_eq!(v6.destination.to_string(), "::/1");
}

/// AT-06-003 / AT-02-002: every canary through the TUN → proven, even over fragmented prefixes;
/// one competing answer → not proven without retry; a failing lookup fails the whole read at
/// the call where it happened; the IPv6 canary is asked only for a dual-stack TUN.
#[test]
fn canary_proof() {
    let calls = Cell::new(0);
    let all_tun = |dst: IpAddr| {
        calls.set(calls.get() + 1);
        let prefix = if dst.is_ipv6() {
            "::/1"
        } else if calls.get() == 2 {
            "0.0.0.0/1"
        } else {
            "128.0.0.0/1"
        };
        Ok(on(TUN_LUID, 7, prefix))
    };
    assert!(canaries_through(&tun(false), all_tun).unwrap());
    assert_eq!(calls.replace(0), 3);
    assert!(canaries_through(&tun(true), all_tun).unwrap());
    assert_eq!(calls.replace(0), 4);

    let indices = [TUN_LUID, 8, TUN_LUID];
    let competing = |_| {
        calls.set(calls.get() + 1);
        Ok(on(indices[calls.get() - 1], 8, "0.0.0.0/0"))
    };
    assert!(!canaries_through(&tun(false), competing).unwrap());
    assert_eq!(calls.replace(0), 2, "no retry after a competing route");

    let second_fails = |dst| {
        calls.set(calls.get() + 1);
        match calls.get() {
            2 => check_best(dst, raw(0, "0.0.0.0", "10.0.0.1")),
            _ => Ok(on(TUN_LUID, 7, "0.0.0.0/1")),
        }
    };
    assert!(canaries_through(&tun(false), second_fails).is_err());
    assert_eq!(
        calls.get(),
        2,
        "the whole read fails after exactly two calls"
    );
}

/// Live reads on this machine (lookups only, no packet is sent).
#[test]
fn live_routes() {
    let v4 = routes(Family::V4).expect("IPv4 routes");
    assert!(!v4.is_empty());
    let v6 = routes(Family::V6).expect("IPv6 routes");
    let capturing: Vec<String> = v4
        .iter()
        .chain(&v6)
        .filter(|r| r.destination.prefix_len() <= 1)
        .map(|r| format!("{}@#{} m{}", r.destination, r.if_index, r.metric))
        .collect();
    println!(
        "{} v4 / {} v6 routes; default-capturing: {capturing:?}",
        v4.len(),
        v6.len()
    );

    let best = best_route(IpAddr::V4(CANARIES_V4[0])).expect("best route to 1.1.1.1");
    assert!(best.if_index != 0 && best.source.is_ipv4());
    println!(
        "best route to 1.1.1.1: #{} via {} from {}",
        best.if_index, best.destination, best.source
    );

    if let Some(default) = default_route(Family::V4).expect("default route") {
        assert_eq!(alias_of(default.luid).expect("alias"), default.alias);
        let mtu = interface_mtu(default.luid, Family::V4).expect("mtu");
        assert!(mtu.is_some_and(|m| m >= 576), "{mtu:?}");
        println!(
            "default route: {} #{} metric {} mtu {mtu:?}",
            default.alias, default.if_index, default.metric
        );
    }
    // A LUID that does not exist: no identity, so no proof (and no error).
    assert!(!route_proof(&tun(false)).expect("proof read"));
    assert_eq!(
        interface_mtu(TUN_LUID, Family::V4).expect("absent interface"),
        None
    );
}
