use super::*;

fn addr(ip: &str, prefix_len: u8, dad_state: i32) -> UnicastAddress {
    UnicastAddress {
        ip: ip.parse().unwrap(),
        prefix_len,
        dad_state,
        temporary: false,
    }
}

/// The fixture row of firewall-recovery §7.4 (the owner's Wi-Fi card).
fn wifi() -> Adapter {
    Adapter {
        if_index: 17,
        luid: 71 << 48 | 1,
        guid: GUID::from_u128(0x999d65fe_a8c4_4db3_9f7e_11edd6482144),
        alias: "Беспроводная сеть".into(),
        description: "MediaTek Wi-Fi 6E MT7922 160MHz Wireless LAN Card".into(),
        if_type: 71,
        status: AdapterStatus::Up,
        mac: vec![0x5c, 0xc3, 0x36, 0xf5, 0xa6, 0x0a],
        permanent_mac: vec![0x5c, 0xc3, 0x36, 0xf5, 0xa6, 0x0a],
        hardware: true,
        filter: false,
        hidden: false,
        driver: Some(r"pci\ven_14c3&dev_0616".into()),
        ipv4_enabled: true,
        ipv6_enabled: true,
        link_speed_bps: 866_700_000,
        addresses: vec![addr("10.0.0.5", 24, 4)],
        gateways: vec!["10.0.0.1".parse().unwrap()],
        dns: vec!["1.1.1.1".parse().unwrap()],
        dns_static: false,
        physical: false,
    }
}

fn with(f: impl FnOnce(&mut Adapter)) -> Adapter {
    let mut a = wifi();
    f(&mut a);
    a
}

/// AT-03-005 / AT-03-010: the base row is physical with its gateway, DHCP DNS and IPv6 flag.
#[test]
fn base_row_is_physical() {
    let a = wifi();
    assert!(is_physical(&a));
    assert_eq!(a.gateways_v4(), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    assert_eq!(a.dns_v4(), vec![Ipv4Addr::new(1, 1, 1, 1)]);
    assert!(!a.dns_static && a.ipv6_enabled);
}

/// AT-03-005: exclusions and keeps of firewall-recovery §7.4.
#[test]
fn physical_exclusions() {
    let excluded = [
        with(|a| a.description = "VirtualBox Host-Only Ethernet Adapter".into()),
        with(|a| {
            a.description = "Hyper-V Virtual Ethernet Adapter".into();
            a.hardware = false;
        }),
        with(|a| a.permanent_mac = vec![0; 6]),
        with(|a| a.permanent_mac.clear()),
        with(|a| a.filter = true),
        with(|a| a.hidden = true),
        with(|a| a.status = AdapterStatus::Disconnected),
        // Unbound SR-IOV VF: both bindings off.
        with(|a| {
            a.ipv4_enabled = false;
            a.ipv6_enabled = false;
        }),
    ];
    for a in &excluded {
        assert!(!is_physical(a), "{a:?}");
    }
    let kept = [
        with(|a| a.description = "Microsoft Hyper-V Network Adapter".into()),
        // Bound but no address, DNS or default route yet (DHCP pending).
        with(|a| {
            a.addresses.clear();
            a.dns.clear();
            a.gateways.clear();
        }),
        with(|a| a.ipv4_enabled = false),
        // Not excluded by alias any more (B6): a docking NIC auto-named "Ethernet 5" is real.
        with(|a| a.alias = "Ethernet 5".into()),
    ];
    for a in &kept {
        assert!(is_physical(a), "{a:?}");
    }
}

/// AT-03-005: NDIS characteristics 0x9 hide an adapter; 0x1 and a missing class key do not.
#[test]
fn characteristics_from_class_key() {
    let gaa = GaaRow {
        if_index: 17,
        luid: 7,
        guid: Some(wifi().guid),
        alias: "Wi-Fi".into(),
        description: wifi().description,
        mac: wifi().mac,
        ipv4_enabled: true,
        ipv6_enabled: true,
        if_type: 71,
        oper_status: OPER_UP,
        link_speed_bps: 0,
        addresses: Vec::new(),
        gateways: Vec::new(),
        dns: Vec::new(),
    };
    let row = IfRow {
        luid: 7,
        if_index: 17,
        guid: wifi().guid,
        alias: "Wi-Fi".into(),
        description: wifi().description,
        oper_status: OPER_UP,
        media_disconnected: false,
        permanent_mac: wifi().mac,
        hardware: true,
        filter: false,
    };
    let rows = HashMap::from([(7, row)]);
    let physical_with = |class: Option<u32>| {
        let classes: HashMap<GUID, ClassInfo> = class
            .map(|c| {
                (
                    wifi().guid,
                    ClassInfo {
                        characteristics: c,
                        component_id: None,
                    },
                )
            })
            .into_iter()
            .collect();
        join(vec![gaa.clone()], &rows, &classes, |_| None)[0].physical
    };
    assert!(!physical_with(Some(0x9)));
    assert!(physical_with(Some(0x1)));
    assert!(physical_with(None));
    // An adapter whose interface row vanished mid-read fails closed.
    let joined = join(vec![gaa.clone()], &HashMap::new(), &HashMap::new(), |_| {
        None
    });
    assert!(!joined[0].physical && !joined[0].hardware);
}

/// AT-03-006: topology uplink / internal vSwitch / unbound VF / no-address-yet / our Wintun →
/// exactly the uplink and the adapter still waiting for an address; empty selection → error.
#[test]
fn topology_selection() {
    let uplink = with(|a| {
        a.alias = "uplink".into();
        a.description = "Microsoft Hyper-V Network Adapter".into();
    });
    let internal = with(|a| {
        a.alias = "internal".into();
        a.description = "Hyper-V Virtual Ethernet Adapter".into();
        a.hardware = false;
    });
    let vf = with(|a| {
        a.alias = "vf".into();
        a.ipv4_enabled = false;
        a.ipv6_enabled = false;
    });
    let pending = with(|a| {
        a.alias = "no-address-yet".into();
        a.addresses.clear();
    });
    let tun = with(|a| {
        a.alias = "Ethernet 5".into();
        a.description = "sing-tun Tunnel".into();
        a.hardware = false;
        a.permanent_mac.clear();
        a.driver = Some("wintun".into());
    });
    let all: Vec<Adapter> = [uplink, internal, vf, pending, tun]
        .into_iter()
        .map(|mut a| {
            a.physical = is_physical(&a);
            a
        })
        .collect();
    let selected = select_physical(all).unwrap();
    let names: Vec<&str> = selected.iter().map(|a| a.alias.as_str()).collect();
    assert_eq!(names, ["uplink", "no-address-yet"]);
    assert!(
        select_physical(vec![wifi()]).is_err(),
        "nothing classified physical → error"
    );
}

/// AT-03-005: `NameServer` decides static vs DHCP DNS.
#[test]
fn static_dns_source() {
    assert!(is_static_dns(Some("8.8.8.8")));
    assert!(!is_static_dns(Some("  ")));
    assert!(!is_static_dns(None));
}

/// AT-03-010: gateways skip an on-link `0.0.0.0`; DNS sources are deduplicated across adapters
/// and lose our TUN gateway / resolver.
#[test]
fn gateways_and_dns_sources() {
    let a = with(|a| a.gateways = vec!["0.0.0.0".parse().unwrap(), "10.0.0.1".parse().unwrap()]);
    assert_eq!(a.gateways_v4(), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    let wifi = with(|a| {
        a.dns = ["192.168.1.1", "1.1.1.1", "192.168.250.254", "fe80::1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    });
    let lan = with(|a| {
        a.dns = ["1.1.1.1", "192.168.250.253", "9.9.9.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    });
    let no_dns = with(|a| a.dns.clear());
    let expected: Vec<Ipv4Addr> = ["192.168.1.1", "1.1.1.1", "9.9.9.9"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(dns_sources(&[wifi, no_dns, lan]), expected);
}

/// AT-07-002: status projection and the visible list (firewall-recovery §7.5).
#[test]
fn status_and_visibility() {
    assert_eq!(AdapterStatus::from_oper(1, false), AdapterStatus::Up);
    assert_eq!(
        AdapterStatus::from_oper(2, true),
        AdapterStatus::Disconnected
    );
    assert_eq!(AdapterStatus::from_oper(2, false), AdapterStatus::Disabled);
    assert_eq!(
        AdapterStatus::from_oper(6, false),
        AdapterStatus::NotPresent
    );
    assert!(wifi().is_visible());
    // Characteristics 41 = 0x29 includes NCF_HIDDEN.
    let hidden = with(|a| a.hidden = 41 & NCF_HIDDEN != 0);
    for a in [
        with(|a| a.filter = true),
        hidden,
        with(|a| a.if_type = 24),
        with(|a| a.if_type = 131),
    ] {
        assert!(!a.is_visible(), "{a:?}");
    }
}

/// AT-07-002 / AT-07-012: source addresses keep DAD states other than Invalid / Duplicate, drop
/// link-local; only the Wi-Fi's `192.168.0.192` survives the physical-source filter.
#[test]
fn physical_ipv4_sources() {
    let wifi = with(|a| {
        a.addresses = vec![
            addr("192.168.0.192", 24, 1),
            addr("169.254.1.2", 16, 4),
            addr("10.9.9.9", 8, 0),
            addr("10.8.8.8", 8, 2),
            addr("fe80::fe25:d0db:9892:425c", 64, 4),
            addr("2a00:1450::5", 64, 4),
        ]
    });
    assert_eq!(wifi.source_v4(), vec![Ipv4Addr::new(192, 168, 0, 192)]);
    assert_eq!(
        wifi.global_v6(),
        vec!["2a00:1450::5".parse::<Ipv6Addr>().unwrap()]
    );
    let others = [
        with(|a| {
            a.description = "sing-tun Tunnel".into();
            a.hardware = false;
        }),
        with(|a| a.description = "VirtualBox Host-Only Ethernet Adapter".into()),
        with(|a| a.description = "Hyper-V Virtual Ethernet Adapter (vEthernet)".into()),
        with(|a| a.status = AdapterStatus::Disabled),
        with(|a| a.permanent_mac = vec![0; 6]),
        with(|a| a.if_type = 24),
    ];
    let mut all = vec![wifi];
    all.extend(others.into_iter().map(|mut a| {
        a.addresses = vec![addr("192.168.56.1", 24, 4)];
        a
    }));
    let sources: Vec<Ipv4Addr> = all
        .iter()
        .filter(|a| is_physical(a))
        .flat_map(Adapter::source_v4)
        .collect();
    assert_eq!(sources, vec![Ipv4Addr::new(192, 168, 0, 192)]);
}

/// AT-07-002: an empty or loopback-only enumeration is a failed read.
#[test]
fn implausible_enumeration_is_an_error() {
    assert!(plausible(Vec::new()).is_err());
    assert!(plausible(vec![with(|a| a.if_type = 24)]).is_err());
    assert_eq!(plausible(vec![wifi()]).unwrap().len(), 1);
}

/// AT-07-002: IPv6 text is RFC 5952 (std `Display`), as the old hand-written formatter was.
#[test]
fn ipv6_text() {
    for text in [
        "::",
        "::1",
        "fe80::fe25:d0db:9892:425c",
        "8000::",
        "1:0:2:0:3:0:4:0",
    ] {
        assert_eq!(text.parse::<Ipv6Addr>().unwrap().to_string(), text);
    }
    assert_eq!(Ipv6Addr::from([0u8; 16]).to_string(), "::");
}

/// Live read on this machine (read-only).
#[test]
fn live_inventory() {
    let all = inventory().expect("inventory");
    assert!(all.iter().any(|a| a.if_type != IF_TYPE_SOFTWARE_LOOPBACK));
    for a in &all {
        assert_ne!(a.luid, 0, "{}", a.alias);
        println!(
            "#{:<3} {:<40} {:<45} {:?} hw={} filter={} hidden={} drv={:?} physical={} addrs={}",
            a.if_index,
            a.alias,
            a.description,
            a.status,
            a.hardware,
            a.filter,
            a.hidden,
            a.driver,
            a.physical,
            a.addresses.len()
        );
        // NDIS filter modules show up as "<alias>-<filter name>-0000" interfaces.
        if a.alias.contains("LightWeight Filter-0000") {
            assert!(a.filter && !a.is_visible(), "{}", a.alias);
        }
    }
    let physical = physical_adapters();
    assert_eq!(physical.is_ok(), all.iter().any(|a| a.physical));
    if let Ok(list) = physical {
        assert!(
            list.iter()
                .all(|a| a.hardware && a.is_up() && a.driver.as_deref() != Some("wintun"))
        );
        println!("physical DNS v4: {:?}", physical_dns_v4().expect("dns"));
    }
}

/// Review D3: a Hyper-V host vNIC (by alias or description) marks a switch; other NICs do not.
#[test]
fn hyperv_vnics_are_recognised() {
    let row = |alias: &str, description: &str| IfRow {
        luid: 1,
        if_index: 1,
        guid: GUID::zeroed(),
        alias: alias.into(),
        description: description.into(),
        oper_status: OPER_UP,
        media_disconnected: false,
        permanent_mac: Vec::new(),
        hardware: false,
        filter: false,
    };
    assert!(is_hyperv_vnic(&row(
        "vEthernet (WSL)",
        "Hyper-V Virtual Ethernet Adapter"
    )));
    assert!(is_hyperv_vnic(&row(
        "Ethernet 3",
        "Hyper-V Virtual Ethernet Adapter #2"
    )));
    assert!(!is_hyperv_vnic(&row(
        "Ethernet",
        "Microsoft Hyper-V Network Adapter"
    )));
    assert!(!is_hyperv_vnic(&row("Wi-Fi", "MediaTek Wi-Fi 6E MT7922")));
    assert!(
        hyperv_switch_present().is_ok(),
        "the live interface table reads unelevated"
    );
}
