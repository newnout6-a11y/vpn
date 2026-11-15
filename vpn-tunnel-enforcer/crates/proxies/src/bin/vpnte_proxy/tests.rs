use super::*;

fn parse(args: &[&str]) -> Result<Command, String> {
    parse_args(args.iter().map(|a| (*a).to_owned()))
}

fn run_args(args: &[&str]) -> Args {
    match parse(args) {
        Ok(Command::Run(args)) => args,
        other => panic!("{args:?}: {other:?}"),
    }
}

fn slot(n: u64) -> Slot {
    Slot::new(n).unwrap()
}

/// cmd style: `ACTION [TARGET] [PORT] [SLOT]`; no arguments = start slot 1.
#[test]
fn positional_syntax() {
    let args = run_args(&["rotate", " de ", "18000", "2"]);
    let expected = Args {
        action: Action::Rotate,
        target: "de".into(),
        port: Some(18000),
        slot: slot(2),
        json: false,
    };
    assert_eq!(args, expected);
    let args = run_args(&[]);
    assert_eq!(
        (args.action, args.port, args.slot, args.json),
        (Action::Start, None, Slot::DEFAULT, false)
    );
    let args = run_args(&["STOP", "", "0", "3"]);
    assert_eq!(
        (args.action, args.target.as_str(), args.port, args.slot),
        (Action::Stop, "", None, slot(3))
    );
    assert_eq!(run_args(&["trigger", "p-1"]).action, Action::Trigger);
}

/// ps1 style: named parameters (any case, unique prefixes, `-Name:value`, `--name=value`);
/// positional words fill the parameters not given by name, in order.
#[test]
fn named_syntax() {
    let args = run_args(&[
        "-Action", "connect", "-Target", "p-1", "-Slot", "3", "-Json",
    ]);
    let expected = Args {
        action: Action::Connect,
        target: "p-1".into(),
        port: None,
        slot: slot(3),
        json: true,
    };
    assert_eq!(args, expected);
    let args = run_args(&["-s", "2", "-J", "status"]);
    assert_eq!(
        (args.action, args.slot, args.json),
        (Action::Status, slot(2), true)
    );
    let args = run_args(&["--slot=4", "--port", "18001", "rotate", "nl"]);
    assert_eq!(
        (args.action, args.target.as_str(), args.port, args.slot),
        (Action::Rotate, "nl", Some(18001), slot(4))
    );
    let args = run_args(&["-Slot:2", "-Json:$false", "-act", "list"]);
    assert_eq!(
        (args.action, args.slot, args.json),
        (Action::List, slot(2), false)
    );
    let args = run_args(&["-Target", "us", "start", "17000"]);
    assert_eq!(
        (args.action, args.target.as_str(), args.port),
        (Action::Start, "us", Some(17000))
    );
}

/// Bad command lines are usage errors (exit 2); help variants print the usage.
#[test]
fn usage_errors_and_help() {
    for bad in [
        &["fly"][..],
        &["start", "", "70000"],
        &["start", "", "", "0"],
        &["start", "", "", "47547"],
        &["start", "de", "1", "2", "extra"],
        &["-Slot"],
        &["-x", "1"],
        &["-Slot", "1", "-Slot", "2"],
        &["-", "start"],
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
    for help in ["-h", "--help", "/?", "-?", "help"] {
        assert_eq!(parse(&["status", help]), Ok(Command::Help));
    }
}

fn request(args: &[&str]) -> Result<(&'static str, String), String> {
    request_for(&run_args(args))
}

/// The request table of the old scripts (spec §2.21), except that `port` is sent only when
/// the user gave one.
#[test]
fn requests_like_the_old_scripts() {
    let get = |path: &str| Ok(("GET", path.to_owned()));
    let post = |path: &str| Ok(("POST", path.to_owned()));
    assert_eq!(
        request(&["status", "", "", "2"]),
        get("/status?slot=2&format=text")
    );
    assert_eq!(request(&["status", "-Json"]), get("/status?slot=1"));
    assert_eq!(request(&["stop"]), post("/stop?slot=1&format=text"));
    assert_eq!(request(&[]), post("/start?slot=1&format=text"));
    assert_eq!(
        request(&["start", "United States"]),
        post("/start?slot=1&format=text&country=United+States")
    );
    assert_eq!(
        request(&["rotate", "", "18000", "2"]),
        post("/rotate?slot=2&port=18000&format=text")
    );
    assert_eq!(
        request(&["connect", "p 1&x"]),
        post("/connect?slot=1&format=text&id=p+1%26x")
    );
    assert_eq!(
        request(&["trigger", "p-1", "-Json"]),
        post("/trigger?slot=1&id=p-1")
    );
    assert_eq!(request(&["list"]), get("/list?format=text"));
    assert_eq!(request(&["list", "nl", "-Json"]), get("/list?country=nl"));
    assert_eq!(request(&["instances"]), get("/instances?format=text"));
    assert_eq!(request(&["instances", "-Json"]), get("/instances"));
    assert_eq!(
        request(&["profiles-health", "g1"]),
        post("/profiles/healthcheck?format=text&groupId=g1")
    );
    assert_eq!(
        request(&["connect"]),
        Err("Usage: vpnte-proxy connect <profileId>".into())
    );
    assert_eq!(
        request(&["trigger", " "]),
        Err("Usage: vpnte-proxy trigger <profileId>".into())
    );
    assert_eq!(
        request(&["profiles-health"]),
        Err("Usage: vpnte-proxy profiles-health <groupId>".into())
    );
}

/// A throw-away directory under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut suffix = [0u8; 4];
        getrandom::fill(&mut suffix).unwrap();
        let name = format!(
            "vpnte-cli-{tag}-{}-{}",
            std::process::id(),
            hex::encode(suffix)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(dir: &TempDir) -> Env {
    Env {
        url_override: None,
        token_override: None,
        data_dir: Some(dir.0.clone()),
        app_exe: None,
    }
}

/// Answers `requests` connections: 200 `stopped` for the right token, else 401.
fn stub_server(token: &'static str, requests: usize) -> u16 {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            let reply = if request.contains(&format!("x-vpnte-control-token: {token}\r\n")) {
                "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nstopped\n"
            } else {
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\nConnection: close\r\n\r\nunauthorized\n"
            };
            stream.write_all(reply.as_bytes()).unwrap();
        }
    });
    port
}

fn write_discovery(dir: &TempDir, port: u16, token: &str) {
    let endpoint =
        format!(r#"{{"host": "127.0.0.1", "port": {port}, "url": "http://127.0.0.1:{port}"}}"#);
    std::fs::write(dir.0.join(ENDPOINT_FILE), endpoint).unwrap();
    std::fs::write(dir.0.join(TOKEN_FILE), format!("{token}\n")).unwrap();
}

/// Discovery order: a loopback `VPNTE_CONTROL_URL`, else the endpoint file, else the default;
/// `VPNTE_CONTROL_TOKEN` before the token file.
#[test]
fn discovery_order() {
    let dir = TempDir::new("order");
    let mut env = env(&dir);
    assert_eq!(env.control_url(false), ControlUrl::local_default());
    assert_eq!(env.token(), (None, true));
    write_discovery(&dir, 50123, "file-token");
    assert_eq!(env.control_url(false).to_string(), "http://127.0.0.1:50123");
    assert_eq!(env.token(), (Some("file-token".into()), true));
    env.url_override = Some("http://evil.example:1".into());
    assert_eq!(env.control_url(false).to_string(), "http://127.0.0.1:50123");
    env.url_override = Some(" http://localhost:50124/ ".into());
    assert_eq!(env.control_url(false).to_string(), "http://localhost:50124");
    env.token_override = Some(" env-token ".into());
    assert_eq!(env.token(), (Some("env-token".into()), false));
}

/// B-7: liveness is an authenticated `GET /status`; a running API is used as found and the
/// app is never relaunched for it, nor for a rejected token.
#[test]
fn liveness_uses_the_token() {
    let dir = TempDir::new("live");
    let port = stub_server("good-token", 3);
    write_discovery(&dir, port, "good-token");
    let never = |_: &std::path::Path| -> std::io::Result<()> { panic!("must not launch") };
    let (url, token) = ensure_api(&env(&dir), never).unwrap();
    assert_eq!((url.port(), token.as_str()), (port, "good-token"));

    write_discovery(&dir, port, "stale-token");
    let mut with_exe = env(&dir);
    with_exe.app_exe = Some(dir.0.join("VPN Tunnel Enforcer.exe"));
    let err = ensure_api(&with_exe, never).unwrap_err();
    assert!(err.contains("token was rejected"), "{err}");
}

/// Nothing listening: without the app next to the CLI it is an error at once; with it the
/// app is started (here: a stub that refuses) instead of waiting.
#[test]
fn down_api_starts_the_app() {
    let dir = TempDir::new("down");
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let never = |_: &std::path::Path| -> std::io::Result<()> { panic!("must not launch") };
    let err = ensure_api(&env(&dir), never).unwrap_err();
    assert!(
        err.starts_with("External proxy control token was not found."),
        "{err}"
    );
    write_discovery(&dir, port, "some-token");
    let err = ensure_api(&env(&dir), never).unwrap_err();
    assert!(err.starts_with(NOT_RUNNING), "{err}");

    let mut with_exe = env(&dir);
    let exe = dir.0.join("VPN Tunnel Enforcer.exe");
    with_exe.app_exe = Some(exe.clone());
    let launched = std::cell::Cell::new(None);
    let err = ensure_api(&with_exe, |path| {
        launched.set(Some(path.to_owned()));
        Err(std::io::Error::other("refused in test"))
    })
    .unwrap_err();
    assert_eq!(launched.take(), Some(exe));
    assert!(
        err.contains("cannot start") && err.contains("refused in test"),
        "{err}"
    );
}
