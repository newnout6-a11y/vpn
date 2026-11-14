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

/// Starts the app as the current user (it runs `asInvoker`; this console process stays as it is),
/// detached from our standard handles. `Command` always creates the child with handle
/// inheritance on, so a caller that captures our output through a pipe would otherwise see the
/// app hold that pipe open and wait for its EOF until the app exits (the old `Start-Process`
/// passed no handles).
fn launch(exe: &std::path::Path) -> std::io::Result<()> {
    keep_std_handles_private();
    std::process::Command::new(exe)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(drop)
}

/// Clears the inherit flag of this process's standard handles (inherited from our caller, so
/// still inheritable); `launch` is the only child this process starts.
fn keep_std_handles_private() {
    use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation};
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: no preconditions; a missing standard handle is an `Err`.
        let Ok(handle) = (unsafe { GetStdHandle(which) }) else {
            continue;
        };
        // SAFETY: changes only the inherit flag of a handle this process owns; a handle that
        // cannot take it (a console handle on old systems) fails harmlessly.
        let _ = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) };
    }
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
mod tests;
