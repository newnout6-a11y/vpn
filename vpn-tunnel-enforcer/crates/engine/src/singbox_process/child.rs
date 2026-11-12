//! One engine child process (sing-box or Xray): hidden spawn inside its own kill-on-close Job,
//! config written to stdin, line pumps into a ring + rotating log + subscribers, exit waiter.
//! Shared by `singbox_process` and `xray_process`; nothing here knows engine specifics beyond
//! the optional readiness marker.
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use regex::Regex;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Notify, broadcast, watch};
use tokio::task::JoinHandle;
use vpnte_core::logging::RotatingFile;
use vpnte_core::{net, redact};
use vpnte_winnet::process::{Job, app_job, spawn_hidden};

use crate::tags::{DNS_BOOTSTRAP, DNS_DIRECT, DNS_REMOTE, DNS_RESOLVER};

/// Raw output lines kept per process: fault window, exit tail, live view.
pub(crate) const RING_LINES: usize = 500;
/// Byte cap of the ring (the failure diagnostics read at most this much of a slot's log).
pub(crate) const RING_BYTES: usize = 256 * 1024;
/// Longer lines are cut: one huge line must not evict the whole ring.
const MAX_LINE_BYTES: usize = 8 * 1024;
/// How long the waiter lets the pumps drain after the exit before publishing it. The last
/// lines (sing-box `FATAL`, Xray `Failed to start:`) can trail the exit notification.
const DRAIN: Duration = Duration::from_millis(250);
/// Exit code of a process we terminate.
pub const KILL_CODE: i32 = 1;
/// Exit tail: last non-empty lines and its character cap (old `stderrTail`).
const TAIL_LINES: usize = 6;
const TAIL_CHARS: usize = 800;
/// Buffered raw lines per subscriber before it lags.
const SUBSCRIBER_BACKLOG: usize = 1024;
/// Secret values shorter than this are not scrubbed: they would mangle ordinary words.
const MIN_SECRET_LEN: usize = 6;

/// How an engine process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    /// When the exit was observed.
    pub at: SystemTime,
    /// Process exit code (`-1` = 0xFFFFFFFF); [`KILL_CODE`] when we terminated it.
    pub code: Option<i32>,
    /// Last 6 non-empty output lines, redacted, joined with `\n`, at most 800 chars.
    pub stderr_tail: String,
    /// The app asked for this exit (stop, compensation, drop): not a crash.
    pub user_initiated: bool,
    /// Loopback ports the engine reported it could not bind (`listen tcp 127.0.0.1:<p>: bind: …`).
    pub bind_failures: Vec<u16>,
    /// The English WSAEACCES text appeared without a parsable address.
    pub access_denied: bool,
}

impl ExitInfo {
    /// The engine died because one of `ports` could not be bound (or Windows refused a socket
    /// with WSAEACCES): the caller may retry once with fresh ports. Matches on Go's
    /// locale-independent `listen … bind:` prefix, so it also works on Russian Windows.
    pub fn binds_any(&self, ports: &[u16]) -> bool {
        self.access_denied || self.bind_failures.iter().any(|p| ports.contains(p))
    }
}

static BIND_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"listen (?:tcp|udp)[46]? 127\.0\.0\.1:(\d{1,5}): bind:").expect("static regex")
});
static WSAEACCES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)WSAEACCES|An attempt was made to access a socket in a way forbidden")
        .expect("static regex")
});

/// Ports from `listen … 127.0.0.1:<p>: bind:` lines, and whether the WSAEACCES text appeared.
pub(crate) fn bind_evidence<'a>(lines: impl Iterator<Item = &'a str>) -> (Vec<u16>, bool) {
    let mut ports = Vec::new();
    let mut denied = false;
    for line in lines {
        let mut bound = false;
        for cap in BIND_FAILURE.captures_iter(line) {
            bound = true;
            if let Ok(port) = cap[1].parse::<u16>()
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
        denied |= !bound && WSAEACCES.is_match(line);
    }
    (ports, denied)
}

/// Exact secret values taken from an engine config (and given by the caller), masked in every
/// line before it reaches a log, an error or the UI. Engine output is untrusted text: Xray echoes
/// config values in build errors (`invalid "password": <publicKey>`), and our own 32-hex slot
/// credentials are not caught by the generic redactor.
#[derive(Clone, Default)]
pub(crate) struct Scrubber {
    /// Longest first, so a secret containing another is replaced whole.
    secrets: Arc<[String]>,
}

impl Scrubber {
    /// Secrets of `config` (JSON values under `redact::is_secret_key` keys) and `extra`.
    pub(crate) fn new(config: &[u8], extra: &[&str]) -> Self {
        let mut found: Vec<String> = extra
            .iter()
            .filter(|s| worth_scrubbing(s))
            .map(|s| (*s).to_owned())
            .collect();
        if let Ok(doc) = serde_json::from_slice::<Value>(config) {
            collect_secrets(&doc, false, &mut found);
        }
        found.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        found.dedup();
        Self {
            secrets: found.into(),
        }
    }

    /// Exact secrets replaced by `<redacted>` (what goes into the log file, which redacts the rest).
    pub(crate) fn exact<'a>(&self, line: &'a str) -> Cow<'a, str> {
        let mut out = Cow::Borrowed(line);
        for secret in self.secrets.iter() {
            if out.contains(secret.as_str()) {
                out = Cow::Owned(out.replace(secret.as_str(), redact::REDACTED));
            }
        }
        out
    }

    /// Exact secrets, then the app-wide log redaction: safe for errors, tails and the UI.
    pub(crate) fn clean(&self, line: &str) -> String {
        redact::for_log(&self.exact(line)).into_owned()
    }

    /// The old `stderrTail` of non-empty `lines`: the last 6, cleaned, joined, ≤ 800 chars.
    pub(crate) fn tail<S: AsRef<str>>(&self, lines: &[S]) -> String {
        let last = &lines[lines.len().saturating_sub(TAIL_LINES)..];
        let cleaned: Vec<String> = last.iter().map(|l| self.clean(l.as_ref())).collect();
        cleaned.join("\n").chars().take(TAIL_CHARS).collect()
    }
}

fn collect_secrets(v: &Value, secret: bool, out: &mut Vec<String>) {
    match v {
        Value::String(s) if secret && worth_scrubbing(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|i| collect_secrets(i, secret, out)),
        Value::Object(map) => {
            for (key, value) in map {
                collect_secrets(value, redact::is_secret_key(key), out);
            }
        }
        _ => {}
    }
}

/// Our DNS server tags: what the secret-named `server` key holds in DNS rules and resolvers. A
/// reference, not a secret, and the name engine lines carry (`dns/https[dns-remote]`). The
/// bootstrap order's steps (`singbox_config::dns`, private there) are spelled out: a test
/// checks this list against every server tag a generated config carries.
const DNS_TAGS: [&str; 8] = [
    DNS_REMOTE,
    DNS_RESOLVER,
    DNS_BOOTSTRAP,
    DNS_DIRECT,
    "dns-bootstrap-quad9",
    "dns-bootstrap-google",
    "dns-bootstrap-tcp",
    "dns-bootstrap-isp",
];

/// Long enough, not one of our DNS tags, and not a private / loopback address (`127.0.0.1`, the
/// TUN `/30`): those carry no secret and must stay readable (`binds_any` evidence, adapter lines).
fn worth_scrubbing(s: &str) -> bool {
    if s.len() < MIN_SECRET_LEN || DNS_TAGS.contains(&s) {
        return false;
    }
    let host = s.split('/').next().unwrap_or(s);
    match host.parse::<IpAddr>() {
        Ok(ip) => net::is_public_ip(ip),
        Err(_) => true,
    }
}

/// Last raw lines of one process with the instant they were read.
#[derive(Default)]
struct Ring {
    lines: VecDeque<(Instant, Arc<str>)>,
    bytes: usize,
}

impl Ring {
    fn push(&mut self, at: Instant, line: Arc<str>) {
        self.bytes += line.len();
        self.lines.push_back((at, line));
        while self.lines.len() > RING_LINES || self.bytes > RING_BYTES {
            match self.lines.pop_front() {
                Some((_, old)) => self.bytes -= old.len(),
                None => break,
            }
        }
    }
}

/// What the pumps feed and the owner reads.
struct Output {
    ring: Mutex<Ring>,
    log: Option<RotatingFile>,
    log_failed: AtomicBool,
    scrub: Scrubber,
    lines: broadcast::Sender<Arc<str>>,
    marker: Option<&'static str>,
    ready: watch::Sender<bool>,
}

impl Output {
    fn on_line(&self, mut raw: String) {
        let trimmed = raw.trim_end_matches(['\r', '\n']).len();
        raw.truncate(trimmed);
        if raw.len() > MAX_LINE_BYTES {
            let mut cut = MAX_LINE_BYTES;
            while !raw.is_char_boundary(cut) {
                cut -= 1;
            }
            raw.truncate(cut);
        }
        if raw.trim().is_empty() {
            return;
        }
        let marks_ready = self.marker.is_some_and(|m| raw.contains(m));
        let raw: Arc<str> = raw.into();
        if let Some(log) = &self.log {
            // Small appends to an already open file: cheaper than a writer thread per pipe.
            match log.write_line(&self.scrub.exact(&raw)) {
                Ok(()) => self.log_failed.store(false, Ordering::Relaxed),
                Err(err) => {
                    if !self.log_failed.swap(true, Ordering::Relaxed) {
                        tracing::warn!(error = %err, "engine log write failed");
                    }
                }
            }
        }
        // No subscriber is the normal case.
        let _ = self.lines.send(raw.clone());
        self.ring.lock().push(Instant::now(), raw);
        // After the push: whoever wakes on readiness finds the line in the tail.
        if marks_ready {
            self.ready.send_replace(true);
        }
    }

    fn exit_info(&self, at: SystemTime, code: Option<i32>, user_initiated: bool) -> ExitInfo {
        let lines = self.snapshot(None);
        let (bind_failures, access_denied) = bind_evidence(lines.iter().map(|l| &**l));
        ExitInfo {
            at,
            code,
            stderr_tail: self.scrub.tail(&lines),
            user_initiated,
            bind_failures,
            access_denied,
        }
    }

    /// Raw lines read at or after `since` (all when `None`), oldest first. The lock covers only
    /// the copy: redaction is slow next to a pump's push, and the pumps wait for this lock.
    fn snapshot(&self, since: Option<Instant>) -> Vec<Arc<str>> {
        let ring = self.ring.lock();
        ring.lines
            .iter()
            .filter(|(at, _)| since.is_none_or(|s| *at >= s))
            .map(|(_, line)| line.clone())
            .collect()
    }
}

/// Reads one pipe line by line until EOF. Engines print UTF-8; anything else is kept lossily.
fn pump<R: AsyncRead + Unpin + Send + 'static>(pipe: R, out: Arc<Output>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(pipe);
        let mut buf = Vec::with_capacity(512);
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break,
                Ok(_) => out.on_line(String::from_utf8_lossy(&buf).into_owned()),
                Err(err) => {
                    tracing::debug!(error = %err, "engine pipe read ended");
                    break;
                }
            }
        }
    })
}

/// Opens `<dir>/<stem>.log` for a new engine session: the previous session's file becomes the
/// previous generation first (`<stem>.1.log`), so `<stem>.log` is always the current session.
fn open_session_log(dir: &Path, stem: &str) -> Option<RotatingFile> {
    let current = dir.join(format!("{stem}.log"));
    if std::fs::metadata(&current).is_ok_and(|m| m.len() > 0) {
        // A writer still alive from the previous session notices the move within a second and
        // reopens `<stem>.log`; until then its lines land in the previous generation.
        if let Err(err) = std::fs::rename(&current, dir.join(format!("{stem}.1.log"))) {
            tracing::warn!(error = %err, stem, "engine log rotation at start failed");
        }
    }
    RotatingFile::engine(dir, stem)
        .inspect_err(|err| tracing::warn!(error = %err, stem, "engine log unavailable"))
        .ok()
}

/// How to start one engine process.
pub(crate) struct Spec<'a> {
    pub exe: &'a Path,
    pub args: &'a [&'a str],
    /// Written to stdin, which is then closed (the engines read it to EOF).
    pub config: &'a [u8],
    /// Logs directory and file stem (`sing-box`, `xray-a`); `None` = no log file.
    pub log: Option<(&'a Path, &'a str)>,
    /// A line containing this marks the engine ready.
    pub marker: Option<&'static str>,
    pub scrub: Scrubber,
}

/// A running (or exited) engine process. Dropping it kills the process: the Job closes.
pub(crate) struct EngineChild {
    pid: u32,
    job: Job,
    out: Arc<Output>,
    exit: watch::Receiver<Option<ExitInfo>>,
    ready: watch::Receiver<bool>,
    user_initiated: Arc<AtomicBool>,
    kill: Arc<Notify>,
}

impl EngineChild {
    /// Spawns the engine (runtime). Errors only when the process cannot be created or put into
    /// its job; everything later (bad config, early exit) shows up on the exit watch.
    pub(crate) fn spawn(spec: Spec<'_>) -> io::Result<Self> {
        let job = Job::kill_on_close()?;
        let mut cmd = Command::new(spec.exe);
        cmd.args(spec.args);
        // The engines dir: wintun.dll / libcronet.dll sit next to the exe.
        if let Some(dir) = spec.exe.parent().filter(|d| !d.as_os_str().is_empty()) {
            cmd.current_dir(dir);
        }
        let mut child = spawn_hidden(&mut cmd, &job)?;
        let pid = child.id().unwrap_or_default();
        let (stdin, stdout, stderr) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let (ready_tx, ready) = watch::channel(false);
        let out = Arc::new(Output {
            ring: Mutex::default(),
            log: spec.log.and_then(|(dir, stem)| open_session_log(dir, stem)),
            log_failed: AtomicBool::new(false),
            scrub: spec.scrub,
            lines: broadcast::channel(SUBSCRIBER_BACKLOG).0,
            marker: spec.marker,
            ready: ready_tx,
        });
        if let Some(mut stdin) = stdin {
            let config = spec.config.to_vec();
            // A task, not an inline write: a child that never reads stdin must not block us.
            tokio::spawn(async move {
                if let Err(err) = stdin.write_all(&config).await {
                    tracing::debug!(error = %err, "engine config write ended early");
                }
                // Dropping the pipe closes it: the engine reads its config to EOF.
            });
        }
        let pumps = [
            stdout.map(|p| pump(p, out.clone())),
            stderr.map(|p| pump(p, out.clone())),
        ]
        .into_iter()
        .flatten()
        .collect();
        let (exit_tx, exit) = watch::channel(None);
        let user_initiated = Arc::new(AtomicBool::new(false));
        let kill = Arc::new(Notify::new());
        tokio::spawn(wait_exit(
            child,
            pumps,
            out.clone(),
            user_initiated.clone(),
            kill.clone(),
            exit_tx,
        ));
        Ok(Self {
            pid,
            job,
            out,
            exit,
            ready,
            user_initiated,
            kill,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// `Some` once the process has exited (the reaped handle is the proof).
    pub(crate) fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.exit.clone()
    }

    pub(crate) fn exited(&self) -> Option<ExitInfo> {
        self.exit.borrow().clone()
    }

    pub(crate) fn ready_watch(&self) -> watch::Receiver<bool> {
        self.ready.clone()
    }

    /// Raw lines for in-process consumers (traffic history, live log view). Not redacted.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.out.lines.subscribe()
    }

    /// The last `n` lines, redacted, oldest first.
    pub(crate) fn tail(&self, n: usize) -> Vec<String> {
        let lines = self.out.snapshot(None);
        lines[lines.len().saturating_sub(n)..]
            .iter()
            .map(|line| self.out.scrub.clean(line))
            .collect()
    }

    /// Raw lines read at or after `since` (all when `None`), oldest first: classifier input only.
    pub(crate) fn raw_lines(&self, since: Option<Instant>) -> Vec<Arc<str>> {
        self.out.snapshot(since)
    }

    /// The first line satisfying `pred`, redacted.
    pub(crate) fn find_line(&self, pred: impl Fn(&str) -> bool) -> Option<String> {
        let line = self.out.snapshot(None).into_iter().find(|l| pred(l))?;
        Some(self.out.scrub.clean(&line))
    }

    /// Requests termination (idempotent); the exit is reported as user-initiated.
    pub(crate) fn kill(&self) {
        self.user_initiated.store(true, Ordering::SeqCst);
        // Terminating our private job ends exactly this engine; the handle path is the fallback.
        if let Err(err) = self.job.terminate(KILL_CODE.unsigned_abs()) {
            tracing::warn!(error = %err, "engine job termination failed; killing the process");
            self.kill.notify_one();
        }
    }

    /// Test hook: ends the process the way a crash would (not user-initiated).
    #[cfg(test)]
    pub(crate) fn crash(&self) {
        let _ = self.job.terminate(77);
    }

    /// [`Self::kill`], then waits up to `within` for the exit. `None` = exit not confirmed
    /// ("killed" only means a signal was sent); the call can be repeated.
    pub(crate) async fn kill_and_wait(&self, within: Duration) -> Option<ExitInfo> {
        self.kill();
        let mut exit = self.exit.clone();
        tokio::time::timeout(within, exited(&mut exit))
            .await
            .ok()
            .flatten()
    }
}

/// Resolves with the exit published on `rx` (`None` only if its waiter task is gone).
pub(crate) async fn exited(rx: &mut watch::Receiver<Option<ExitInfo>>) -> Option<ExitInfo> {
    rx.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|info| info.clone())
}

impl Drop for EngineChild {
    fn drop(&mut self) {
        // The job closes right after this: its member dies, and that exit was our decision.
        self.user_initiated.store(true, Ordering::SeqCst);
    }
}

/// Owns the child until it exits, then publishes [`ExitInfo`] once the pumps drained.
async fn wait_exit(
    mut child: Child,
    pumps: Vec<JoinHandle<()>>,
    out: Arc<Output>,
    user_initiated: Arc<AtomicBool>,
    kill: Arc<Notify>,
    tx: watch::Sender<Option<ExitInfo>>,
) {
    let mut warned = false;
    let status = loop {
        tokio::select! {
            status = child.wait() => match status {
                Ok(status) => break status,
                // Never report an exit we did not observe: wait again (warn once, not 4x/s).
                Err(err) => {
                    if !std::mem::replace(&mut warned, true) {
                        tracing::warn!(error = %err, "waiting for the engine failed; retrying");
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            },
            () = kill.notified() => {
                if let Err(err) = child.start_kill() {
                    tracing::warn!(error = %err, "engine kill failed");
                }
            }
        }
    };
    // Read at the exit, not after the drain: a stop requested while a crash drains stays a crash.
    let (at, user) = (SystemTime::now(), user_initiated.load(Ordering::SeqCst));
    let _ = tokio::time::timeout(DRAIN, futures_util::future::join_all(pumps)).await;
    tx.send_replace(Some(out.exit_info(at, status.code(), user)));
}

/// Runs a one-shot engine command (`version`, config check) in the app job: optional stdin
/// (then closed), all output collected, killed when `within` passes.
pub(crate) async fn run_once(
    exe: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    within: Duration,
) -> io::Result<std::process::Output> {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    if let Some(dir) = exe.parent().filter(|d| !d.as_os_str().is_empty()) {
        cmd.current_dir(dir);
    }
    let mut child = spawn_hidden(&mut cmd, app_job()?)?;
    let pipe = child.stdin.take();
    let feed = async move {
        if let (Some(mut pipe), Some(bytes)) = (pipe, stdin)
            && let Err(err) = pipe.write_all(bytes).await
        {
            tracing::debug!(error = %err, "engine stdin write ended early");
        }
    };
    // Dropping the futures on timeout drops the child, and `kill_on_drop` ends it.
    let run = async { tokio::join!(feed, child.wait_with_output()).1 };
    tokio::time::timeout(within, run)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "engine command timed out"))?
}

#[cfg(test)]
mod tests;
