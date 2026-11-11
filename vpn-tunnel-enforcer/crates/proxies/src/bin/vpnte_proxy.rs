//! `vpnte-proxy.exe`: console client of the external-proxy control API, replacing the old
//! `vpnte-proxy.ps1` / `.cmd`. Both old syntaxes work: positional `ACTION [TARGET] [PORT] [SLOT]`
//! and named `-Action/-Target/-Port/-Slot/-Json` (any case, unique prefixes, `--long` and
//! `-Name:value` forms). Exit codes: 0 ok, 1 API / token error, 2 usage.
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use url::form_urlencoded;
use vpnte_proxies::control::client::{ControlUrl, ENV_CONTROL_TOKEN, ENV_CONTROL_URL, discover};
use vpnte_proxies::control::{ENDPOINT_FILE, TOKEN_FILE, read_token};
use vpnte_proxies::slot::{MAX_SLOT, Slot};

const USAGE: &str = "\
Usage: vpnte-proxy [ACTION] [TARGET] [PORT] [SLOT] [-Json]
       vpnte-proxy -Action <action> [-Target <text>] [-Port <n>] [-Slot <n>] [-Json]

Actions:
  start [country]            start the slot (default action)
  rotate [country]           move the slot to the next server
  connect <profileId>        start the slot with this server (trigger = connect)
  stop | status              stop / show the slot
  instances                  list running proxies
  list [country]             servers usable as a proxy
  profiles-health <groupId>  check the keys of a server group

PORT  listen port for start/rotate/connect (0 or omitted: keep the slot's port;
      slot N starts on 17990+N-1). SLOT  1..47546, default 1.
-Json prints the JSON answer instead of text.
Environment: VPNTE_CONTROL_URL (loopback http URL), VPNTE_CONTROL_TOKEN.";

/// What to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Rotate,
    Connect,
    Trigger,
    List,
    ProfilesHealth,
    Stop,
    Status,
    Instances,
}

impl Action {
    const ALL: [(&'static str, Action); 9] = [
        ("start", Action::Start),
        ("rotate", Action::Rotate),
        ("connect", Action::Connect),
        ("trigger", Action::Trigger),
        ("list", Action::List),
        ("profiles-health", Action::ProfilesHealth),
        ("stop", Action::Stop),
        ("status", Action::Status),
        ("instances", Action::Instances),
    ];

    fn parse(raw: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(raw.trim()))
            .map(|&(_, action)| action)
    }

    fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|&&(_, a)| a == self)
            .map_or("start", |&(name, _)| name)
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    action: Action,
    target: String,
    /// Only a port the user gave is sent (the old CLIs always sent 17989+SLOT, which moved a
    /// custom-port slot back to its default port on rotate).
    port: Option<u16>,
    slot: Slot,
    json: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run(Args),
    Help,
}

/// Parameters in PowerShell's positional order.
const PARAMS: [&str; 4] = ["action", "target", "port", "slot"];

/// Parses the command line the way PowerShell bound the old script: named parameters first,
/// then the positional words fill the parameters still unbound, in declaration order.
fn parse_args(argv: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut named: [Option<String>; 4] = Default::default();
    let mut json = false;
    let mut positional = Vec::new();
    let mut argv = argv.into_iter();
    while let Some(arg) = argv.next() {
        if matches!(
            arg.as_str(),
            "-h" | "--help" | "-?" | "/?" | "-help" | "help"
        ) {
            return Ok(Command::Help);
        }
        let Some(flag) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            positional.push(arg);
            continue;
        };
        let (name, inline) = match flag.split_once([':', '=']) {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (flag, None),
        };
        let name = name.to_ascii_lowercase();
        if !name.is_empty() && "json".starts_with(&name) {
            json = !inline.is_some_and(|v| v.trim_start_matches('$').eq_ignore_ascii_case("false"));
            continue;
        }
        let index = PARAMS
            .iter()
            .position(|p| !name.is_empty() && p.starts_with(&name))
            .ok_or_else(|| format!("Unknown parameter '{arg}'."))?;
        let value = inline
            .or_else(|| argv.next())
            .ok_or_else(|| format!("Missing value for -{}.", PARAMS[index]))?;
        if named[index].replace(value).is_some() {
            return Err(format!(
                "Parameter -{} was given more than once.",
                PARAMS[index]
            ));
        }
    }
    let mut positional = positional.into_iter();
    for value in named.iter_mut().filter(|v| v.is_none()) {
        *value = positional.next();
    }
    if let Some(extra) = positional.next() {
        return Err(format!("Unexpected argument '{extra}'."));
    }
    let [action, target, port, slot] = named;
    let action = match action.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        None => Action::Start,
        Some(raw) => Action::parse(raw).ok_or_else(|| format!("Unknown action '{raw}'."))?,
    };
    let port = match port.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<u16>() {
            Ok(0) => None,
            Ok(port) => Some(port),
            Err(_) => return Err(format!("PORT must be between 0 and 65535, got '{raw}'.")),
        },
    };
    let slot = match slot.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Slot::DEFAULT,
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .and_then(|n| Slot::new(n).ok())
            .ok_or_else(|| format!("SLOT must be between 1 and {MAX_SLOT}, got '{raw}'."))?,
    };
    Ok(Command::Run(Args {
        action,
        target: target.unwrap_or_default().trim().to_owned(),
        port,
        slot,
        json,
    }))
}

/// Method and path-with-query of the request for `args`; `Err` is a usage message (exit 2).
fn request_for(args: &Args) -> Result<(&'static str, String), String> {
    let mut query = form_urlencoded::Serializer::new(String::new());
    let text = !args.json;
    let target = args.target.as_str();
    let slot = args.slot.to_string();
    let (method, path) = match args.action {
        Action::ProfilesHealth => {
            if target.is_empty() {
                return Err("Usage: vpnte-proxy profiles-health <groupId>".into());
            }
            if text {
                query.append_pair("format", "text");
            }
            query.append_pair("groupId", target);
            ("POST", "/profiles/healthcheck".to_owned())
        }
        Action::List => {
            if text {
                query.append_pair("format", "text");
            }
            if !target.is_empty() {
                query.append_pair("country", target);
            }
            ("GET", "/list".to_owned())
        }
        Action::Instances => {
            if text {
                query.append_pair("format", "text");
            }
            ("GET", "/instances".to_owned())
        }
        Action::Status | Action::Stop => {
            query.append_pair("slot", &slot);
            if text {
                query.append_pair("format", "text");
            }
            let method = if args.action == Action::Stop {
                "POST"
            } else {
                "GET"
            };
            (method, format!("/{}", args.action.name()))
        }
        Action::Start | Action::Rotate | Action::Connect | Action::Trigger => {
            let connect = matches!(args.action, Action::Connect | Action::Trigger);
            if connect && target.is_empty() {
                return Err(format!(
                    "Usage: vpnte-proxy {} <profileId>",
                    args.action.name()
                ));
            }
            query.append_pair("slot", &slot);
            if let Some(port) = args.port {
                query.append_pair("port", &port.to_string());
            }
            if text {
                query.append_pair("format", "text");
            }
            if !target.is_empty() {
                query.append_pair(if connect { "id" } else { "country" }, target);
            }
            ("POST", format!("/{}", args.action.name()))
        }
    };
    let query = query.finish();
    Ok(if query.is_empty() {
        (method, path)
    } else {
        (method, format!("{path}?{query}"))
    })
}

/// Where the API and its token are found.
struct Env {
    /// `VPNTE_CONTROL_URL` as set.
    url_override: Option<String>,
    /// `VPNTE_CONTROL_TOKEN` as set.
    token_override: Option<String>,
    /// The app's data root (endpoint and token files).
    data_dir: Option<PathBuf>,
    /// `VPN Tunnel Enforcer.exe` next to this exe, started when the API is down.
    app_exe: Option<PathBuf>,
}

impl Env {
    fn from_process() -> Self {
        let app_exe = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join("VPN Tunnel Enforcer.exe")))
            .filter(|exe| exe.is_file());
        Self {
            url_override: std::env::var(ENV_CONTROL_URL).ok(),
            token_override: std::env::var(ENV_CONTROL_TOKEN).ok(),
            data_dir: vpnte_core::paths::DataDirs::resolve().ok().map(|d| d.root),
            app_exe,
        }
    }

    /// `VPNTE_CONTROL_URL` if it is a loopback URL, else the endpoint file, else the default.
    /// The endpoint file is read every time: the app may just have bound an ephemeral port (B-6).
    fn control_url(&self, warn: bool) -> ControlUrl {
        if let Some(raw) = self
            .url_override
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
        {
            if let Some(url) = ControlUrl::parse(raw) {
                return url;
            }
            if warn {
                eprintln!(
                    "WARNING: {ENV_CONTROL_URL} is not a valid local loopback address: '{raw}'. Using default."
                );
            }
        }
        self.data_dir
            .as_ref()
            .and_then(|dir| discover(&dir.join(ENDPOINT_FILE)))
            .unwrap_or_else(ControlUrl::local_default)
    }

    /// The token and whether it came from the token file (which a restarted app rewrites).
    fn token(&self) -> (Option<String>, bool) {
        let env = self
            .token_override
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty());
        match env {
            Some(token) => (Some(token.to_owned()), false),
            None => (
                self.data_dir
                    .as_ref()
                    .and_then(|d| read_token(&d.join(TOKEN_FILE))),
                true,
            ),
        }
    }
}

/// Liveness probe timeout (old: 2 s).
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(2);
/// Timeout of the real request: a rotate probes the new route (up to ~20 s) before answering.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for a just-started app (old: 30 x 500 ms).
const LAUNCH_WAIT: Duration = Duration::from_secs(15);
const LAUNCH_POLL: Duration = Duration::from_millis(500);
const NOT_RUNNING: &str = "VPN Tunnel Enforcer is not running or external proxy API is unavailable";

/// Why the API could not be used.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    NoToken,
    /// The server answered 401 (the app runs, so it is never relaunched for this).
    Rejected {
        from_file: bool,
    },
    Down(String),
}

impl Failure {
    fn describe(&self) -> String {
        match self {
            Failure::NoToken => "External proxy control token was not found. \
                                 Start VPN Tunnel Enforcer and try again."
                .into(),
            Failure::Rejected { from_file: true } => "External proxy control token was rejected. \
                                                      Restart VPN Tunnel Enforcer and try again."
                .into(),
            Failure::Rejected { from_file: false } => {
                format!("External proxy control token was rejected. Check {ENV_CONTROL_TOKEN}.")
            }
            Failure::Down(reason) => format!("{NOT_RUNNING}: {reason}"),
        }
    }
}

/// One authenticated `GET /status` (the old CLIs probed without the token, always got 401 and
/// relaunched the app on every call, B-7).
fn attempt(env: &Env, warn: bool) -> Result<(ControlUrl, String), Failure> {
    let url = env.control_url(warn);
    let (token, from_file) = env.token();
    let token = token.ok_or(Failure::NoToken)?;
    match url.request("GET", "/status?format=text", Some(&token), LIVENESS_TIMEOUT) {
        Ok(reply) if reply.status == 200 => Ok((url, token)),
        Ok(reply) if reply.status == 401 => Err(Failure::Rejected { from_file }),
        Ok(reply) => Err(Failure::Down(format!("HTTP {} from {url}", reply.status))),
        Err(e) => Err(Failure::Down(format!("{e} ({url})"))),
    }
}

/// A live API and its token; starts the app (`launch`) when it is not running and waits for it.
fn ensure_api(
    env: &Env,
    launch: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
) -> Result<(ControlUrl, String), String> {
    let failure = match attempt(env, true) {
        Ok(found) => return Ok(found),
        // A restarted app may have rewritten the token file since it was read: one retry.
        Err(Failure::Rejected { from_file: true }) => match attempt(env, false) {
            Ok(found) => return Ok(found),
            Err(failure) => failure,
        },
        Err(failure) => failure,
    };
    let exe = match (&failure, env.app_exe.as_deref()) {
        (Failure::Rejected { .. }, _) | (_, None) => return Err(failure.describe()),
        (_, Some(exe)) => exe,
    };
    launch(exe).map_err(|e| format!("{NOT_RUNNING}: cannot start {}: {e}", exe.display()))?;
    let deadline = Instant::now() + LAUNCH_WAIT;
    let mut last = failure;
    while Instant::now() < deadline {
        std::thread::sleep(LAUNCH_POLL);
        match attempt(env, false) {
            Ok(found) => return Ok(found),
            Err(failure) => last = failure,
        }
    }
    Err(last.describe())
}

/// Starts the app; it elevates itself, this console process stays unelevated.
fn launch(exe: &std::path::Path) -> std::io::Result<()> {
    std::process::Command::new(exe).spawn().map(drop)
}

fn main() -> ExitCode {
    let argv = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned());
    let args = match parse_args(argv) {
        Ok(Command::Run(args)) => args,
        Ok(Command::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(msg) => {
            eprintln!("{msg}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (method, path) = match request_for(&args) {
        Ok(request) => request,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let (url, token) = match ensure_api(&Env::from_process(), launch) {
        Ok(found) => found,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(1);
        }
    };
    match url.request(method, &path, Some(&token), REQUEST_TIMEOUT) {
        Ok(reply) if (200..300).contains(&reply.status) => {
            println!("{}", reply.body.trim_end());
            ExitCode::SUCCESS
        }
        // The server's text-mode body is the error detail (curl -f / Invoke-WebRequest hid it).
        Ok(reply) => {
            eprintln!(
                "External proxy API request failed (HTTP {}): {}",
                reply.status,
                reply.body.trim()
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("{NOT_RUNNING}: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
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
}
