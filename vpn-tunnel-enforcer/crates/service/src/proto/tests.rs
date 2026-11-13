//! Protocol round trips and refusals (pipe decoder: malformed, oversized, unknown).
use super::frame::{self, FrameError, MAX_FRAME};
use super::*;
use vpnte_base::types::KillSwitchLevel;

fn profile() -> Profile {
    vpnte_profiles::uri::parse_uri("trojan://fake-pass@example.com:443?security=tls#Test")
        .expect("test profile")
}

fn start() -> TunnelStart {
    TunnelStart {
        upstream: Upstream::Server(Box::new(ServerUpstream {
            id: "srv-1".into(),
            profile: profile(),
            device: None,
            engine: EnginePref::Auto,
        })),
        routing: RoutingInputs {
            smart_ru: true,
            split_direct: vec![r"(?i)^C:\\Games\\.*\.exe$".into()],
            ..RoutingInputs::default()
        },
        protection: ProtectionSettings {
            level: KillSwitchLevel::Standard,
            ..ProtectionSettings::default()
        },
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    }
}

fn round_trip(request: Request) {
    let sent = ClientFrame { id: 7, request };
    let bytes = frame::encode(&sent).expect("encode");
    assert_eq!(
        u32::from_le_bytes(bytes[..4].try_into().expect("prefix")) as usize,
        bytes.len() - 4
    );
    let back: ClientFrame = frame::decode(&bytes[4..]).expect("decode");
    assert_eq!(back, sent);
}

#[test]
fn every_request_round_trips() {
    round_trip(Request::Hello(Hello {
        protocol: PROTOCOL,
        app_version: "2.0.0".into(),
    }));
    round_trip(Request::Start(Box::new(start())));
    round_trip(Request::Restart(Box::new(start())));
    round_trip(Request::Switch(Box::new(start())));
    round_trip(Request::Stop(StopTunnel {
        preserve_protection: true,
        preserve_last: false,
    }));
    round_trip(Request::RestartWithLast {
        reason: "settings changed".into(),
    });
    round_trip(Request::RestartAdaptive(Box::new(AdaptiveRestart {
        mode: AdaptiveMode::TlsCompatibility,
        reason: "dpi".into(),
        server: None,
    })));
    round_trip(Request::Inputs(Box::default()));
    round_trip(Request::Status);
    round_trip(Request::KillSwitch(Box::default()));
    round_trip(Request::Cleanup);
    round_trip(Request::ForgetMe);
    let local = Upstream::LocalProxy {
        addr: "127.0.0.1:10808".parse().expect("addr"),
        kind: ProxyKind::Socks5,
    };
    round_trip(Request::Start(Box::new(TunnelStart {
        upstream: local,
        ..start()
    })));
}

#[test]
fn server_frames_round_trip() {
    let frames = [
        ServerFrame::Reply {
            id: 1,
            reply: Box::new(Reply::Welcome {
                protocol: 1,
                service_version: "2.0.0".into(),
            }),
        },
        ServerFrame::Failed {
            id: 2,
            error: WireError::new(ErrorCode::Busy, ErrorKind::Conflict, "service.pipe.busy"),
        },
        ServerFrame::Event {
            event: Box::new(Event::Status(Box::default())),
        },
        ServerFrame::Event {
            event: Box::new(Event::Tunnel(TunnelEventWire::RestartScheduled {
                delay_ms: 2000,
            })),
        },
    ];
    for sent in frames {
        let bytes = frame::encode(&sent).expect("encode");
        let back: ServerFrame = frame::decode(&bytes[4..]).expect("decode");
        assert_eq!(back, sent);
    }
}

#[test]
fn versions_one_apart_negotiate_down() {
    assert_eq!(negotiate(1, 1), Some(1));
    assert_eq!(negotiate(2, 1), Some(1));
    assert_eq!(negotiate(1, 2), Some(1));
    assert_eq!(negotiate(3, 1), None);
    assert_eq!(negotiate(PROTOCOL, 2), Some(2), "one version back");
    assert_eq!(negotiate(0, 1), None);
    assert_eq!(negotiate(PROTOCOL, PROTOCOL), Some(PROTOCOL));
}

/// Protocol 3 (p-smart-lists): the rule sets ride a start as an optional field; a version-2
/// service never sees it (it refuses unknown fields), and an input without it still reads.
#[test]
fn the_rule_sets_are_spoken_from_protocol_3_only() {
    let resources = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
    let sets = vpnte_engine::routing::rulesets::handover::RuleSetFiles::read(std::path::Path::new(
        resources,
    ));
    assert!(sets.is_some(), "the bundled lists");
    let mut with = start();
    with.routing.rule_sets = sets;
    let requests = [
        Request::Start(Box::new(with.clone())),
        Request::Restart(Box::new(with.clone())),
        Request::Switch(Box::new(with.clone())),
        Request::Inputs(Box::new(with.routing.clone())),
    ];
    for request in requests {
        let three = serde_json::to_string(&request.clone().speak(3)).expect("json");
        assert!(three.contains("\"ruleSets\""));
        let back: Request = serde_json::from_str(&three).expect("a version-3 service reads it");
        assert_eq!(back, request);
        let two = serde_json::to_string(&request.speak(2)).expect("json");
        assert!(!two.contains("ruleSets"), "{}", &two[..two.len().min(200)]);
    }
    let without = serde_json::to_string(&start().routing).expect("json");
    assert!(!without.contains("ruleSets"));
    let read: RoutingInputs = serde_json::from_str(&without).expect("reads");
    assert_eq!(read.rule_sets, None);
}

#[test]
fn unknown_requests_and_fields_are_refused() {
    // A request type this version does not know: no ClientFrame, but the id is readable.
    let newer = br#"{"id":9,"request":{"type":"launchRocket","data":{}}}"#;
    assert!(frame::decode::<ClientFrame>(newer).is_err());
    assert_eq!(frame::request_id(newer), Some(9));
    // An unknown field is an error, never ignored.
    let extra = br#"{"id":3,"request":{"type":"hello","data":{"protocol":1,"appVersion":"2","exec":"cmd"}}}"#;
    assert!(frame::decode::<ClientFrame>(extra).is_err());
    let stop = br#"{"id":4,"request":{"type":"stop","data":{"preserveLast":true,"path":"C:/x"}}}"#;
    assert!(frame::decode::<ClientFrame>(stop).is_err());
    // A raw engine config is not a request.
    let raw = br#"{"id":5,"request":{"type":"start","data":{"inbounds":[],"outbounds":[]}}}"#;
    assert!(frame::decode::<ClientFrame>(raw).is_err());
}

#[test]
fn malformed_frames_are_refused() {
    for body in [
        &b"not json"[..],
        b"{",
        b"[]",
        b"{\"request\":{\"type\":\"status\"}}",
    ] {
        assert!(frame::decode::<ClientFrame>(body).is_err(), "{body:?}");
    }
    assert_eq!(frame::request_id(b"{\"request\":{}}"), None);
}

async fn read_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, FrameError> {
    let mut reader = bytes.as_slice();
    frame::read_frame(&mut reader).await
}

#[tokio::test]
async fn oversized_empty_and_truncated_frames_are_refused() {
    let over = u32::try_from(MAX_FRAME + 1)
        .expect("fits")
        .to_le_bytes()
        .to_vec();
    assert!(matches!(read_bytes(over).await, Err(FrameError::Length(_))));
    assert!(matches!(
        read_bytes(0u32.to_le_bytes().to_vec()).await,
        Err(FrameError::Length(0))
    ));
    assert!(matches!(
        read_bytes(Vec::new()).await,
        Err(FrameError::Closed)
    ));
    let mut cut = 10u32.to_le_bytes().to_vec();
    cut.extend_from_slice(b"{}");
    assert!(matches!(read_bytes(cut).await, Err(FrameError::Io(_))));
    let big = "x".repeat(MAX_FRAME);
    assert!(matches!(frame::encode(&big), Err(FrameError::Length(_))));
}

#[tokio::test]
async fn frames_follow_each_other_on_one_stream() {
    let mut bytes = frame::encode(&ClientFrame {
        id: 1,
        request: Request::Status,
    })
    .expect("encode");
    bytes.extend(
        frame::encode(&ClientFrame {
            id: 2,
            request: Request::Cleanup,
        })
        .expect("encode"),
    );
    let mut reader = bytes.as_slice();
    let first: ClientFrame =
        frame::decode(&frame::read_frame(&mut reader).await.expect("first")).expect("json");
    let second: ClientFrame =
        frame::decode(&frame::read_frame(&mut reader).await.expect("second")).expect("json");
    assert_eq!((first.id, second.id), (1, 2));
    assert!(matches!(
        frame::read_frame(&mut reader).await,
        Err(FrameError::Closed)
    ));
}
