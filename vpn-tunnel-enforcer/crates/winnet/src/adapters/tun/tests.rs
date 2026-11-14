use std::cell::Cell;
use std::future::{Ready, ready};

use super::*;
use crate::adapters::alias::all_aliases;
use crate::adapters::{TUN_V4, TUN_V6, UnicastAddress};

const LUID: u64 = 0x0035_0000_0000_0007;
const SHORT: Duration = Duration::from_millis(100);
const LONG: Duration = Duration::from_secs(5);

fn row(alias: &str, addrs: &[(&str, u8)]) -> GaaRow {
    GaaRow {
        if_index: 7,
        luid: LUID,
        guid: Some(GUID::from_u128(0xabc)),
        alias: alias.into(),
        description: "sing-tun Tunnel".into(),
        mac: Vec::new(),
        ipv4_enabled: true,
        ipv6_enabled: true,
        if_type: 53,
        oper_status: OPER_UP,
        link_speed_bps: 0,
        addresses: addrs
            .iter()
            .map(|(ip, len)| UnicastAddress {
                ip: ip.parse().unwrap(),
                prefix_len: *len,
                dad_state: 4,
                temporary: false,
            })
            .collect(),
        gateways: Vec::new(),
        dns: Vec::new(),
    }
}

fn ours() -> GaaRow {
    row("Ethernet 5", &[("192.168.250.253", 30)])
}

type Rows = windows::core::Result<Vec<GaaRow>>;

/// A reader that answers at once, as the waits expect of `ffi::adapters_async`.
fn now(mut rows: impl FnMut() -> Rows) -> impl FnMut() -> Ready<Rows> {
    move || ready(rows())
}

fn counting(reads: &Cell<usize>, rows: impl Fn(usize) -> Rows) -> impl FnMut() -> Ready<Rows> {
    now(move || {
        reads.set(reads.get() + 1);
        rows(reads.get())
    })
}

async fn released(rows: Vec<GaaRow>, v6: Option<Ipv6Net>, timeout: Duration) -> Release {
    let reads = Cell::new(0);
    wait_released_with(
        counting(&reads, |_| Ok(rows.clone())),
        &all_aliases(),
        v6,
        timeout,
        &CancellationToken::new(),
    )
    .await
}

/// AT-02-004 / AT-02-005: release vectors of tunnel-core §7.14.
#[tokio::test]
async fn release_vectors() {
    // No owned address: released after one read, without waiting.
    let reads = Cell::new(0);
    let started = Instant::now();
    let r = wait_released_with(
        counting(&reads, |_| Ok(Vec::new())),
        &all_aliases(),
        None,
        LONG,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!((r, reads.get()), (Release::Released, 1));
    assert!(started.elapsed() < RELEASE_POLL);
    // The owned address disappears later.
    let reads = Cell::new(0);
    let later = counting(&reads, |n| {
        Ok(if n < 4 { vec![ours()] } else { Vec::new() })
    });
    assert_eq!(
        wait_released_with(later, &all_aliases(), None, LONG, &CancellationToken::new()).await,
        Release::Released
    );
    assert_eq!(reads.get(), 4);
    // A physical NIC that happens to be called "Ethernet 5" is not our TUN.
    assert_eq!(
        released(
            vec![row("Ethernet 5", &[("192.168.1.20", 24)])],
            None,
            SHORT
        )
        .await,
        Release::Released
    );
    // Legacy address on the legacy alias never goes away → not proven.
    assert_eq!(
        released(vec![row("VPNTE-TUN", &[("172.19.0.1", 30)])], None, SHORT).await,
        Release::Unverified
    );
    // Happ's TUN on 172.19.0.1 is not one of our aliases.
    assert_eq!(
        released(vec![row("happ-xray", &[("172.19.0.1", 30)])], None, SHORT).await,
        Release::Released
    );
    // Our IPv6 (dual-stack TUN) still present → not proven; the old ULA no longer counts.
    let v6_left = row("ethernet 5", &[("fd8b:3f2a:91c4::1", 126)]);
    assert_eq!(
        released(vec![v6_left], Some(TUN_V6), SHORT).await,
        Release::Unverified
    );
    assert_eq!(
        released(
            vec![row("Ethernet 5", &[("fdfe:dcba:9876::1", 126)])],
            Some(TUN_V6),
            SHORT
        )
        .await,
        Release::Released
    );
    // A failed read is never proof of release.
    let reads = Cell::new(0);
    let failing = counting(&reads, |_| {
        Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_FAIL,
        ))
    });
    assert_eq!(
        wait_released_with(
            failing,
            &all_aliases(),
            None,
            LONG,
            &CancellationToken::new()
        )
        .await,
        Release::Unverified
    );
}

/// AT-00-003: cancelled before reading → no read; cancelled while waiting → prompt `Cancelled`.
#[tokio::test]
async fn release_cancellation() {
    let reads = Cell::new(0);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let r = wait_released_with(
        counting(&reads, |_| Ok(vec![ours()])),
        &all_aliases(),
        None,
        LONG,
        &cancel,
    )
    .await;
    assert_eq!((r, reads.get()), (Release::Cancelled, 0));

    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        trigger.cancel();
    });
    let started = Instant::now();
    let r = wait_released_with(
        counting(&reads, |_| Ok(vec![ours()])),
        &all_aliases(),
        None,
        LONG,
        &cancel,
    )
    .await;
    assert_eq!(r, Release::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(1));
}

async fn owned(rows: Vec<GaaRow>, v6: Option<Ipv6Net>) -> Result<OwnedTun, TunAdapterError> {
    wait_owned_with(
        now(move || Ok(rows.clone())),
        "Ethernet 5",
        TUN_V4,
        v6,
        SHORT,
        &CancellationToken::new(),
    )
    .await
}

/// AT-02-002: the TUN is ours only by exact alias + exact /30 (+ our IPv6 when dual-stack), up,
/// and unambiguous; it may appear after a few polls.
#[tokio::test]
async fn owned_tun_identity() {
    let reads = Cell::new(0);
    let appears = counting(&reads, |n| {
        Ok(if n < 3 { Vec::new() } else { vec![ours()] })
    });
    let tun = wait_owned_with(
        appears,
        "ethernet 5",
        TUN_V4,
        None,
        LONG,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        (tun.luid, tun.if_index, tun.guid, tun.alias.as_str()),
        (LUID, 7, GUID::from_u128(0xabc), "Ethernet 5")
    );
    assert_eq!(reads.get(), 3);

    let not_ours = [
        vec![row("Ethernet 5", &[("192.168.1.20", 24)])],
        vec![row("Ethernet 5", &[("192.168.250.253", 24)])],
        vec![row("Ethernet 6", &[("192.168.250.253", 30)])],
        vec![GaaRow {
            oper_status: 2,
            ..ours()
        }],
        vec![ours(), row("ETHERNET 5", &[("10.0.0.2", 8)])],
        vec![GaaRow {
            guid: None,
            ..ours()
        }],
    ];
    for rows in not_ours {
        let err = owned(rows.clone(), None).await.unwrap_err();
        assert!(
            matches!(
                err,
                TunAdapterError::Timeout {
                    last_error: None,
                    ..
                }
            ),
            "{rows:?}"
        );
    }
    // Dual-stack: the IPv6 must be there too.
    assert!(owned(vec![ours()], Some(TUN_V6)).await.is_err());
    let dual = row(
        "Ethernet 5",
        &[
            ("fe80::1", 64),
            ("192.168.250.253", 30),
            ("fd8b:3f2a:91c4::1", 126),
        ],
    );
    assert_eq!(
        owned(vec![dual], Some(TUN_V6)).await.unwrap().v6,
        Some(TUN_V6)
    );
}

/// AT-02-005: a failing read is reported with the timeout; cancellation wins; user messages.
#[tokio::test]
async fn owned_tun_failures() {
    let failing = now(|| {
        Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_FAIL,
        ))
    });
    let err = wait_owned_with(
        failing,
        "Ethernet 5",
        TUN_V4,
        None,
        SHORT,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        TunAdapterError::Timeout {
            last_error: Some(_),
            ..
        }
    ));
    let app = AppError::from(err);
    assert_eq!(app.kind, ErrorKind::Timeout);
    assert_eq!(app.user_msg(), Msg::new("winnet.adapters.tunTimeout"));

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = wait_owned_with(
        now(|| Ok(Vec::new())),
        "Ethernet 5",
        TUN_V4,
        None,
        LONG,
        &cancel,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, TunAdapterError::Cancelled));
    assert_eq!(AppError::from(err).kind, ErrorKind::Cancelled);
}

/// AT-02-002 / AT-06-003: the route proof's identity half (tunnel-core §7.21): fresh identity
/// holds; wrong GUID, other alias, adapter down, wrong address, other index or a vanished
/// LUID do not.
#[test]
fn identity_recheck() {
    let tun = OwnedTun {
        alias: "Ethernet 5".into(),
        luid: LUID,
        guid: GUID::from_u128(0xabc),
        if_index: 7,
        v4: TUN_V4,
        v6: None,
    };
    assert!(identity_in(&[ours()], &tun));
    let broken = [
        GaaRow {
            guid: Some(GUID::from_u128(0xdef)),
            ..ours()
        },
        GaaRow {
            alias: "Ethernet 6".into(),
            ..ours()
        },
        GaaRow {
            oper_status: 2,
            ..ours()
        },
        row("Ethernet 5", &[("192.168.250.250", 30)]),
        GaaRow {
            if_index: 9,
            ..ours()
        },
        GaaRow { luid: 1, ..ours() },
    ];
    for r in broken {
        assert!(!identity_in(std::slice::from_ref(&r), &tun), "{r:?}");
    }
    assert!(!identity_in(
        &[ours()],
        &OwnedTun {
            v6: Some(TUN_V6),
            ..tun
        }
    ));
}

/// Live reads on this machine: no adapter of ours exists, the Wi-Fi does.
#[tokio::test]
async fn live_tun_reads() {
    assert!(!adapter_present(LUID).expect("absent LUID"));
    let present = ffi::adapters()
        .expect("adapters")
        .into_iter()
        .find(|r| r.oper_status == OPER_UP && r.if_type != 24);
    if let Some(up) = present {
        assert!(
            adapter_present(up.luid).expect("present LUID"),
            "{}",
            up.alias
        );
    }
    let none = CancellationToken::new();
    assert_eq!(
        wait_released(&all_aliases(), Some(TUN_V6), SHORT, &none).await,
        Release::Released
    );
    let err = wait_owned_tun("VPNTE-TEST-NO-SUCH", TUN_V4, None, SHORT, &none)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TunAdapterError::Timeout {
            last_error: None,
            ..
        }
    ));
}

/// speed3 S3-04 measurement read: the loopback interface's 127.0.0.1 is Preferred, its IPv4
/// binding has a `DadTransmits` value; an absent interface carries neither (no error).
#[test]
fn the_settle_read_names_the_dad_state() {
    let absent = tun_settle(LUID).expect("absent LUID");
    assert_eq!(
        absent,
        TunSettle {
            dad_state: None,
            dad_transmits: None
        }
    );
    let rows = ffi::adapters().expect("adapters");
    let Some(lo) = rows.iter().find(|r| r.if_type == 24) else {
        return;
    };
    let dad = ffi::unicast_dad(lo.luid, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    assert_eq!(
        dad.expect("loopback read"),
        Some(super::super::inventory::DAD_PREFERRED)
    );
    let lo = tun_settle(lo.luid).expect("loopback");
    assert!(
        lo.dad_state.is_none() && lo.dad_transmits.is_some(),
        "{lo:?}"
    );
}
