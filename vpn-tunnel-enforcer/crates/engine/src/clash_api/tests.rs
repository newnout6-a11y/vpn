use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::singbox_process::testkit::singbox_config;
use crate::singbox_process::{READY_TIMEOUT, STOP_TIMEOUT, SingBoxProcess};
use crate::test_support::singbox_exe;

const SLOTS: [&str; 2] = ["vpnte-upstream-a", "vpnte-upstream-b"];

fn selection(body: &str) -> Result<Selection, ClashError> {
    parse_selection(body.as_bytes())
}

/// xray-engine 7 "Selector contract": the read-back must be a Selector whose `now` is the slot
/// and whose `all` is exactly the two distinct slot tags.
#[test]
fn readback_vectors() {
    let good = r#"{"type":"Selector","name":"proxy-out","udp":true,"history":[],"now":"vpnte-upstream-b","all":["vpnte-upstream-a","vpnte-upstream-b"]}"#;
    assert!(confirms(&selection(good).unwrap(), SLOTS[1], &SLOTS));
    assert!(
        !confirms(&selection(good).unwrap(), SLOTS[0], &SLOTS),
        "wrong now"
    );
    for bad in ["null", "[]", "{}", "42", r#"{"type":"Selector","all":"x"}"#] {
        assert!(selection(bad).is_err(), "{bad}");
    }
    let mismatches = [
        r#"{"type":"Direct","now":"vpnte-upstream-b","all":["vpnte-upstream-a","vpnte-upstream-b"]}"#,
        r#"{"type":"Selector","now":"vpnte-upstream-b","all":["vpnte-upstream-b","vpnte-upstream-b"]}"#,
        r#"{"type":"Selector","now":"vpnte-upstream-b","all":["vpnte-upstream-a","vpnte-upstream-b","direct-out"]}"#,
        r#"{"type":"Selector","now":"vpnte-upstream-b","all":["vpnte-upstream-b"]}"#,
        r#"{"type":"Selector","now":"vpnte-upstream-b"}"#,
    ];
    for body in mismatches {
        assert!(
            !confirms(&selection(body).unwrap(), SLOTS[1], &SLOTS),
            "{body}"
        );
    }
    // The expected list is a set too: a duplicate never stands in for a missing member.
    let dup = [SLOTS[1], SLOTS[1]];
    assert!(!confirms(&selection(good).unwrap(), SLOTS[1], &dup));
}

/// xray-engine 7: controller port 0 or a malformed secret is refused before any request.
#[test]
fn endpoint_prevalidation() {
    let secret = "a".repeat(32);
    assert!(
        ClashEndpoint {
            port: 25551,
            secret: secret.clone()
        }
        .is_valid()
    );
    assert!(
        ClashApi::new(&ClashEndpoint {
            port: 0,
            secret: secret.clone()
        })
        .is_err()
    );
    for bad in [
        "a".repeat(31),
        "g".repeat(32),
        String::new(),
        format!("{secret}0"),
    ] {
        let ep = ClashEndpoint {
            port: 25551,
            secret: bad.clone(),
        };
        assert!(
            matches!(ClashApi::new(&ep), Err(ClashError::Invalid)),
            "{bad}"
        );
    }
    let ep = ClashEndpoint::allocate(&[]).unwrap();
    assert!(ep.is_valid());
    assert_eq!(
        format!("{ep:?}"),
        format!("ClashEndpoint(127.0.0.1:{})", ep.port)
    );
    assert!(valid_tag("proxy-out").is_ok());
    assert!(
        valid_tag("").is_err()
            && valid_tag("a\nb").is_err()
            && valid_tag(&"x".repeat(300)).is_err()
    );
}

/// traffic-forensics 2.3: a sing-box 1.14 `/connections` answer (ports are strings, nil slices
/// are `null`, odd counters do not discard the snapshot).
#[test]
fn connections_snapshot_parses_leniently() {
    let body = r#"{"downloadTotal":2048,"uploadTotal":512,"memory":0,"connections":[
        {"id":"c1","metadata":{"network":"tcp","type":"tun/tun-in","sourceIP":"172.19.0.1","destinationIP":"203.0.113.7",
         "sourcePort":"50123","destinationPort":"443","host":"example.com","dnsMode":"normal","processPath":"C:\\app\\a.exe"},
         "upload":10,"download":20.5,"start":"2026-11-11T08:00:00Z","chains":["vpnte-upstream-a","proxy-out"],"rule":"final","rulePayload":""},
        {"id":"c2","metadata":{"host":null},"upload":-1,"download":"x","chains":null},
        "garbage"]}"#;
    let snap = parse_connections(body.as_bytes()).unwrap();
    assert_eq!((snap.download_total, snap.upload_total), (2048, 512));
    assert_eq!(snap.connections.len(), 2);
    let c1 = &snap.connections[0];
    assert_eq!((c1.upload, c1.download), (10, 20));
    assert_eq!(c1.metadata.host, "example.com");
    assert_eq!(c1.metadata.destination_port, "443");
    assert_eq!(c1.metadata.inbound, "tun/tun-in");
    assert_eq!(c1.metadata.process_path, "C:\\app\\a.exe");
    assert_eq!(c1.chains.last().map(String::as_str), Some("proxy-out"));
    let c2 = &snap.connections[1];
    assert_eq!((c2.upload, c2.download, c2.chains.len()), (0, 0, 0));
    assert!(
        parse_connections(br#"{"connections":null}"#)
            .unwrap()
            .connections
            .is_empty()
    );
    assert!(parse_connections(br#"{"connections":{}}"#).is_err());
    assert!(parse_connections(b"[]").is_err());
}

#[test]
fn errors_map_to_app_errors() {
    let e = AppError::from(ClashError::NotConfirmed);
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "engine.clash.notConfirmed")
    );
    assert_eq!(AppError::from(ClashError::Timeout).kind, ErrorKind::Network);
    assert_eq!(
        AppError::from(ClashError::Status(401)).user_msg().key,
        "engine.clash.badAnswer"
    );
}

/// A one-purpose HTTP server: answers every request with `answer(method)`; `None` = never answers.
async fn fake_controller(answer: fn(&str) -> Option<String>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text[..head_end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() < head_end + 4 + length {
                        continue;
                    }
                    let method = text.split(' ').next().unwrap_or("").to_owned();
                    buf.drain(..head_end + 4 + length);
                    match answer(&method) {
                        Some(resp) => {
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        None => std::future::pending::<()>().await,
                    }
                }
            });
        }
    });
    port
}

fn api(port: u16) -> ClashApi {
    ClashApi::new(&ClashEndpoint {
        port,
        secret: "0123456789abcdef0123456789abcdef".into(),
    })
    .unwrap()
}

/// protectedOutboundSwitch: a PUT that "succeeds" while the read-back shows another member is
/// not a confirmed switch; a controller that never answers fails after the one 1 s deadline.
#[tokio::test]
async fn unconfirmed_and_silent_controllers() {
    let port = fake_controller(|method| {
        Some(match method {
            "PUT" => "HTTP/1.1 204 No Content\r\n\r\n".to_owned(),
            _ => {
                let body = r#"{"type":"Selector","now":"vpnte-upstream-a","all":["vpnte-upstream-a","vpnte-upstream-b"]}"#;
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
            }
        })
    })
    .await;
    let err = api(port)
        .select("proxy-out", SLOTS[1], &SLOTS)
        .await
        .unwrap_err();
    assert!(matches!(err, ClashError::NotConfirmed), "{err:?}");
    api(port)
        .select("proxy-out", SLOTS[0], &SLOTS)
        .await
        .unwrap();

    let silent = fake_controller(|_| None).await;
    let started = std::time::Instant::now();
    let err = api(silent)
        .select("proxy-out", SLOTS[1], &SLOTS)
        .await
        .unwrap_err();
    assert!(matches!(err, ClashError::Timeout), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_millis(1800),
        "{:?}",
        started.elapsed()
    );

    let redirect = fake_controller(|_| {
        Some(
            "HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n"
                .into(),
        )
    })
    .await;
    assert!(matches!(
        api(redirect).version().await,
        Err(ClashError::Status(302))
    ));
}

/// The real sing-box Clash API: version, protected select with read-back, a wrong secret, an
/// unknown member, the connections snapshot (one loopback flow through the mixed inbound) and
/// one traffic tick.
#[tokio::test]
async fn real_controller_round_trip() {
    let Some(exe) = singbox_exe() else { return };
    let clash = ClashEndpoint::allocate(&[]).unwrap();
    let mixed = ports::alloc_port(false, &[clash.port]).unwrap();
    let creds = ports::creds();
    let sb =
        SingBoxProcess::spawn(&exe, &singbox_config(mixed, &creds, Some(&clash)), None).unwrap();
    sb.wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap();
    let api = ClashApi::new(&clash).unwrap();

    assert!(api.version().await.unwrap().starts_with("sing-box 1.14"));
    let before = api.selection("proxy-out").await.unwrap();
    assert_eq!(
        (before.kind.as_str(), before.now.as_str()),
        ("Selector", SLOTS[0])
    );
    api.select("proxy-out", SLOTS[1], &SLOTS).await.unwrap();
    assert_eq!(api.selection("proxy-out").await.unwrap().now, SLOTS[1]);
    let extra = ["vpnte-upstream-a", "vpnte-upstream-b", "direct-out"];
    assert!(matches!(
        api.select("proxy-out", SLOTS[0], &extra).await,
        Err(ClashError::NotConfirmed)
    ));
    assert!(matches!(
        api.select("proxy-out", "no-such", &SLOTS).await,
        Err(ClashError::Status(400))
    ));
    let wrong = ClashApi::new(&ClashEndpoint {
        port: clash.port,
        secret: ports::secret(),
    })
    .unwrap();
    assert!(matches!(
        wrong.version().await,
        Err(ClashError::Status(401))
    ));

    let target = vpnte_core::net::HostPort::new("127.0.0.1", clash.port).unwrap();
    let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], mixed));
    let flow = vpnte_core::socks5::connect(proxy, Some(&creds), &target, Duration::from_secs(3))
        .await
        .unwrap();
    let snap = api.connections().await.unwrap();
    let ours = snap
        .connections
        .iter()
        .find(|c| c.metadata.destination_port == clash.port.to_string());
    let ours = ours.expect("the loopback flow is listed");
    assert_eq!(ours.chains.first().map(String::as_str), Some("direct-out"));
    assert!(ours.metadata.inbound.starts_with("mixed/"));
    drop(flow);
    let _tick = api.traffic().await.unwrap();

    sb.terminate(STOP_TIMEOUT).await.unwrap();
    assert!(matches!(
        api.version().await,
        Err(ClashError::Transport(_) | ClashError::Timeout)
    ));
}
