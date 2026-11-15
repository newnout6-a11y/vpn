//! mihomo supervision (WP-12 lab engine, feature `lab`): `mihomo -d <home> -f -` with the config
//! on stdin, in its own kill-on-close Job (the engine child shared with sing-box and Xray),
//! readiness = the authenticated SOCKS5 handshake on its listener, the keyed hop listening in
//! this process (mihomo keeps running without a listener it could not open, and a port race
//! could leave the hop port to another program) and the controller answering with the run's
//! secret, the same graceful CTRL_BREAK stop, logs through the same redaction.
//! Each run gets a home dir of its own (mihomo writes nothing there with our config, but `-d`
//! must point somewhere private), removed when the run ends and swept at start-up.
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, OutboundFault};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::socks5::{self, SocksError};
use vpnte_winnet::process::{Transport, listener_owner};

use crate::clash_api::{ClashApi, ClashEndpoint};
use crate::mihomo_config::Compiled;
use crate::singbox_process::child::{self, EngineChild, GRACEFUL_STOP, Scrubber, Spec, exited};
use crate::singbox_process::{ExitInfo, StopError, code_text, re, spawn_error};
use crate::slot::SlotEndpoint;

#[cfg(test)]
mod tests;

/// Log file stem under the logs dir: `mihomo.log` (this session), `mihomo.1.log` (previous).
pub const LOG_STEM: &str = "mihomo";
/// Readiness budget (mihomo is up in ~10 ms here; a cold antivirus scan of a 60 MB exe is not).
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Exit wait after the kill (a stop first waits up to [`GRACEFUL_STOP`] after CTRL_BREAK).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// Deadline of `-v` and `-t`.
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
/// Prefix of a per-run home dir under the runs root.
const HOME_PREFIX: &str = "mihomo-";
/// Pause between controller polls while it comes up.
const POLL: Duration = Duration::from_millis(100);

/// Why mihomo did not become ready, or could not start.
#[derive(Debug, thiserror::Error)]
pub enum MihomoError {
    #[error("mihomo exited before it was ready (code {:?})", .0.code)]
    Exited(ExitInfo),
    #[error("mihomo did not become ready in time")]
    Timeout,
    /// The hop port is held by another process: mihomo could not open its listener there
    /// (it keeps running without it).
    #[error("another process holds the mihomo hop port")]
    Listener,
    #[error("mihomo start cancelled")]
    Cancelled,
    #[error("mihomo could not be started")]
    Spawn(#[source] io::Error),
    /// The lab gate is closed (no lab record): nothing was started.
    #[error("the mihomo lab engine is not activated")]
    Inactive(crate::lab::LabGap),
}

impl From<MihomoError> for AppError {
    fn from(err: MihomoError) -> Self {
        let (kind, msg) = match &err {
            MihomoError::Cancelled => return AppError::cancelled(),
            MihomoError::Exited(info) => (
                ErrorKind::Internal,
                Msg::new("engine.lab.process.exited").arg("code", code_text(info.code)),
            ),
            MihomoError::Timeout => (ErrorKind::Timeout, Msg::new("engine.lab.process.notReady")),
            MihomoError::Listener => (ErrorKind::Internal, Msg::new("engine.lab.process.notReady")),
            MihomoError::Spawn(io) => spawn_error("mihomo", io),
            MihomoError::Inactive(gap) => (ErrorKind::Permission, gap.msg()),
        };
        AppError::msg(kind, msg).with_source(err)
    }
}

/// `mihomo -t` refused the config, or could not be run.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// Redacted engine output explaining the refusal.
    #[error("mihomo rejected the config: {0}")]
    Rejected(String),
    #[error("mihomo -t could not run")]
    Run(#[source] io::Error),
}

/// A private home dir for one run; removed on drop (best effort: the start-up sweep follows).
struct RunHome(PathBuf);

impl RunHome {
    fn create(root: &Path) -> io::Result<Self> {
        let name = format!("{HOME_PREFIX}{}", &crate::ports::secret()[..16]);
        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn arg(&self) -> io::Result<&str> {
        self.0
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "home dir is not Unicode"))
    }
}

impl Drop for RunHome {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0)
            && err.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(error = %err, "mihomo run dir not removed yet; the next start sweeps it");
        }
    }
}

/// Removes run dirs a crash or a kill left under `root` (call at start-up, before any run).
pub fn sweep_homes(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry.file_name().to_string_lossy().starts_with(HOME_PREFIX);
        if stale && entry.path().is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The arguments of a run. Every flag mihomo would otherwise take from a `CLASH_*` environment
/// variable is given explicitly: `CLASH_CONFIG_STRING` would win over stdin, `CLASH_POST_UP`
/// runs a shell command, `CLASH_OVERRIDE_*` would move the controller or replace its secret.
fn run_args(home: &str, test: bool) -> Vec<&str> {
    let mut args = vec!["-d", home, "-f", "-"];
    args.extend([
        "-config=",
        "-age-secret-key=",
        "-ext-ui=",
        "-ext-ctl=",
        "-ext-ctl-tls=",
        "-ext-ctl-unix=",
        "-ext-ctl-pipe=",
        "-ext-ctl-routing-mark=0",
        "-secret=",
        "-post-up=",
        "-post-down=",
    ]);
    if test {
        args.push("-t");
    }
    args
}

/// One mihomo run owned by handle. Dropping it kills the engine and removes its home dir.
pub struct MihomoProcess {
    child: EngineChild,
    socks: SlotEndpoint,
    /// Port of the keyed hop sing-box dials.
    hop: u16,
    controller: ClashEndpoint,
    // Dropped after the child (field order): the process is gone before its dir goes.
    _home: RunHome,
}

impl MihomoProcess {
    /// Starts `exe -d <runs>\mihomo-<id> -f -` with `config` on stdin (runtime). `socks` and
    /// `controller` are the endpoints the config was translated for. Refused without the lab
    /// record (AT-12-002) and, elevated, when the exe differs from its pin; a bad config shows up
    /// as an early exit.
    pub fn spawn(
        exe: &Path,
        runs: &Path,
        config: &Compiled,
        socks: SlotEndpoint,
        controller: ClashEndpoint,
        logs: Option<&Path>,
    ) -> Result<Self, MihomoError> {
        crate::lab::gate().map_err(MihomoError::Inactive)?;
        let home = RunHome::create(runs).map_err(MihomoError::Spawn)?;
        let secrets: Vec<&str> = config.secrets.iter().map(String::as_str).collect();
        let child = EngineChild::spawn(Spec {
            engine: Engine::Mihomo,
            exe,
            args: &run_args(home.arg().map_err(MihomoError::Spawn)?, false),
            config: config.text.as_bytes(),
            log: logs.map(|dir| (dir, LOG_STEM)),
            marker: None,
            scrub: Scrubber::new(&[], &secrets),
        })
        .map_err(MihomoError::Spawn)?;
        tracing::info!(pid = child.pid(), "mihomo spawned");
        Ok(Self {
            child,
            socks,
            hop: config.hop,
            controller,
            _home: home,
        })
    }

    /// Ready = our credentials pass the SOCKS5 handshake on the listener (a foreign listener on
    /// the port is never taken for ours), the hop listens in this process, the controller
    /// answers with the secret, raced with the exit. Does not kill on failure: the caller
    /// terminates (or drops) the process.
    pub async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), MihomoError> {
        let mut exit = self.child.exit_watch();
        let probe = async {
            let creds = self.socks.creds();
            match socks5::wait_ready(self.socks.port(), Some(creds), timeout, cancel).await {
                Ok(()) => {}
                Err(SocksError::Cancelled) => return Err(MihomoError::Cancelled),
                Err(_) => return Err(MihomoError::Timeout),
            }
            while !self.hop_listens()? {
                tokio::time::sleep(POLL).await;
            }
            let api = ClashApi::new(&self.controller).map_err(|_| MihomoError::Timeout)?;
            while api.version().await.is_err() {
                tokio::time::sleep(POLL).await;
            }
            Ok(())
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(MihomoError::Cancelled),
            Some(info) = exited(&mut exit) => Err(MihomoError::Exited(info)),
            res = tokio::time::timeout(timeout, probe) => match res {
                Ok(Ok(())) => self.child.exited().map_or(Ok(()), |i| Err(MihomoError::Exited(i))),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(MihomoError::Timeout),
            },
        }
    }

    /// `true` once this process listens on the hop port; another owner is a lost port race.
    fn hop_listens(&self) -> Result<bool, MihomoError> {
        let hosts = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ];
        match listener_owner(Transport::Tcp, self.hop, &hosts) {
            Ok(Some(owner)) if owner.pid == self.pid() => Ok(true),
            Ok(Some(_)) => Err(MihomoError::Listener),
            // Not listening yet (or the table is unreadable for a moment): poll again.
            Ok(None) | Err(_) => Ok(false),
        }
    }

    /// Stops the engine and waits for its exit (idempotent): CTRL_BREAK, up to [`GRACEFUL_STOP`]
    /// for its own exit (mihomo runs `executor.Shutdown` on SIGINT), else the kill and up to
    /// `within` more. The returned exit is the proof.
    pub async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError> {
        let info = self.child.stop_and_wait(GRACEFUL_STOP, within).await;
        info.ok_or(StopError::ExitNotConfirmed)
    }

    /// Process id (logs only; ownership is by handle).
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }

    /// `Some` once the process exited.
    pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.child.exit_watch()
    }

    /// The exit, if the process has ended.
    pub fn exit_info(&self) -> Option<ExitInfo> {
        self.child.exited()
    }

    /// The authenticated SOCKS5 listener of the app's own checks (sing-box dials the hop;
    /// diagnostics never show either).
    pub fn socks(&self) -> &SlotEndpoint {
        &self.socks
    }

    /// The controller of this run (Clash API: version, connections, traffic).
    pub fn controller(&self) -> &ClashEndpoint {
        &self.controller
    }

    /// The fault of the AmneziaWG hop in the output of the last [`FAULT_SPAN`], if any.
    pub fn recent_fault(&self) -> Option<OutboundFault> {
        let since = std::time::Instant::now().checked_sub(FAULT_SPAN);
        let lines = self.child.raw_lines(since);
        classify_fault(lines.iter().map(|l| &**l))
    }

    /// The last `n` output lines, redacted, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        self.child.tail(n)
    }
}

/// The WireGuard device could not send to the peer at all (`[WG](awg) … Failed to send …`, error
/// level): the peer is unreachable from here.
static PEER_UNREACHABLE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"level=error.*\[WG\]\(awg\).*Failed to send (handshake initiation|data packets)")
});
/// A dial through the hop that got nothing back (`[TCP] dial awg (…) <src> --> <dst> error: …
/// i/o timeout`, warning level), with its destination. A refused connection is not one: the
/// refusal itself came back through the tunnel.
static DIAL_TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)level=(?:warning|error).*\[(?:TCP|UDP)\] dial awg .*--> (\S+) error: .*(?:i/o timeout|context deadline exceeded)",
    )
});
/// How far back a fault is looked for (at warning level the ring spans hours).
const FAULT_SPAN: Duration = Duration::from_secs(120);
/// Failed sends to the peer that make a fault.
const FAULT_THRESHOLD: usize = 3;
/// Distinct destinations that got nothing back: mihomo retries one dead site up to ten times,
/// so one site is never the hop; several unrelated sites failing together are.
const DEAD_HOP_DESTINATIONS: usize = 3;

/// The fault of the AmneziaWG hop itself (audit mihomo-a3): the device failing to send to the
/// peer, or dials to several destinations getting no answer at all. Per-destination errors
/// inside a working tunnel (a refused port, an unreachable IPv6 network, one silent site) are
/// not the server's fault. AWG has no TLS or REALITY to fail.
pub fn classify_fault<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<OutboundFault> {
    let mut sends = 0;
    let mut silent = std::collections::HashSet::new();
    for line in lines {
        if PEER_UNREACHABLE.is_match(line) {
            sends += 1;
        } else if let Some(dst) = DIAL_TIMEOUT.captures(line).and_then(|c| c.get(1)) {
            silent.insert(dst.as_str());
        }
    }
    let dead = sends >= FAULT_THRESHOLD || silent.len() >= DEAD_HOP_DESTINATIONS;
    dead.then_some(OutboundFault::UpstreamUnreachable)
}

/// `exe -v` → `(major, minor, patch)`.
pub async fn engine_version(exe: &Path) -> io::Result<(u16, u16, u16)> {
    let out = child::run_once(Engine::Mihomo, exe, &["-v"], None, TOOL_TIMEOUT).await?;
    parse_version(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognised mihomo version output",
        )
    })
}

/// Parses `Mihomo Meta v1.19.34 windows amd64 with go1.26.11 …` (first line of `-v`).
pub fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let word = text.lines().next()?.split_whitespace().nth(2)?;
    let mut parts = word.strip_prefix('v')?.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// `exe -d <runs>\mihomo-<id> -f - -t`: parses the config and builds every proxy and listener
/// without starting them. For tests and diagnostics; a run relies on its own early exit.
pub async fn check_config(exe: &Path, runs: &Path, config: &Compiled) -> Result<(), CheckError> {
    let home = RunHome::create(runs).map_err(CheckError::Run)?;
    let args = run_args(home.arg().map_err(CheckError::Run)?, true);
    let out = child::run_once(
        Engine::Mihomo,
        exe,
        &args,
        Some(config.text.as_bytes()),
        TOOL_TIMEOUT,
    )
    .await
    .map_err(CheckError::Run)?;
    if out.status.success() {
        return Ok(());
    }
    // mihomo logs to stdout; Go runtime failures land on stderr.
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let secrets: Vec<&str> = config.secrets.iter().map(String::as_str).collect();
    Err(CheckError::Rejected(
        Scrubber::new(&[], &secrets).tail(&lines),
    ))
}
