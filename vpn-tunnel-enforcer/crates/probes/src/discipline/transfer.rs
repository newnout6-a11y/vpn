//! The transfer check: after the proxy connects, download more than the freeze threshold
//! through it. TCP to many foreign data centres freezes without RST after ~16–20 KB from the
//! server (~25 packets, fewer on mobile; net4people #490, Habr 1104872), so a check that reads a
//! short answer reports a frozen server as healthy. One connection = one handshake to the server.
//! Endpoint: `speed.cloudflare.com/__down?bytes=N` serves exactly N bytes (the speed-test API),
//! sets no per-client cap at our rate, is anycast next to the exit and is already a destination of
//! the live throughput stage; `/cdn-cgi/trace` on the same host gives the exit IP and country.
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppError;
use vpnte_base::types::Loopback;
use vpnte_profiles::countries::Iso2;

use crate::egress::rtt_ms;
use crate::key_health::parse_trace;
use crate::live::wire::{HeadError, Stream, Wire, exchange_head, io_text, read_body};

/// Host of the transfer and trace requests.
pub const TRANSFER_HOST: &str = "speed.cloudflare.com";
/// Body bytes the check must receive (more than any reported freeze threshold).
pub const TRANSFER_BYTES: u64 = 64 * 1024;
/// Raw bytes after which a stall is the freeze signature (what the proxy delivered, TLS records
/// included: the closest observable to what the server sent).
pub const FREEZE_BAND: RangeInclusive<u64> = 12 * 1024..=24 * 1024;

/// Timing of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Nothing at all from the server for this long: no data.
    pub first_byte: Duration,
    /// Silence after the first bytes for this long: a stall (a freeze sends no RST).
    pub gap: Duration,
    /// The whole check: connect, TLS, trace, transfer.
    pub deadline: Duration,
}

impl Limits {
    /// Production timing: a healthy path moves 64 KiB in a few round trips, a pause of 5 s
    /// after data flowed is a stall even on mobile.
    pub const STANDARD: Limits = Limits {
        first_byte: Duration::from_secs(10),
        gap: Duration::from_secs(5),
        deadline: Duration::from_secs(20),
    };
}

/// How the transfer went. `bytes` = raw bytes the proxy delivered from the server's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transfer {
    /// The whole body arrived.
    Complete { bytes: u64, ms: u32 },
    /// First bytes arrived, then the data stopped (no FIN, no RST) before the body was complete.
    Stalled { bytes: u64 },
    /// Nothing came back.
    NoData,
    /// The proxy refused, the stream closed early, TLS or HTTP failed.
    Failed { bytes: u64, error: String },
}

impl Transfer {
    /// The volume-freeze signature: a stall inside [`FREEZE_BAND`].
    pub fn frozen(&self) -> bool {
        matches!(self, Transfer::Stalled { bytes } if FREEZE_BAND.contains(bytes))
    }

    pub fn complete(&self) -> bool {
        matches!(self, Transfer::Complete { .. })
    }
}

/// Exit IP and its country from the trace.
pub type Trace = (Option<IpAddr>, Option<Iso2>);

/// What one transfer check saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReport {
    pub transfer: Transfer,
    /// Exit IP and country, when the trace was asked for and answered (kept even if the
    /// transfer then stalled).
    pub trace: Option<Trace>,
    /// From the start to the first response head through the server: the round trip of the
    /// key (connect, handshake, request).
    pub answer_ms: Option<u32>,
}

/// Why a step stopped.
enum Stop {
    Silent,
    Failed(String),
}

/// Runs the check through `proxy` on one connection: the trace first when asked (keep-alive),
/// then the transfer. `Err` only on cancellation.
pub(crate) async fn check(
    wire: &Wire,
    proxy: &Loopback,
    with_trace: bool,
    limits: Limits,
    cancel: &CancellationToken,
) -> Result<TransferReport, AppError> {
    let raw = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    // Set from inside the exchange and read after it, also when a stall cut it short.
    let answered = OnceLock::new();
    let traced = OnceLock::new();
    let head = || {
        answered.get_or_init(|| rtt_ms(started.elapsed()));
    };
    let run = async {
        let (mut stream, _) = wire
            .open_counted(proxy, TRANSFER_HOST, 443, TRANSFER_HOST, &raw)
            .await
            .map_err(|e| Stop::Failed(e.text()))?;
        if with_trace && let Some(found) = trace(&mut stream, &head).await? {
            let _ = traced.set(found);
        }
        download(&mut stream, &head).await
    };
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(AppError::cancelled()),
        outcome = run => outcome,
        () = silence(&raw, limits) => Err(Stop::Silent),
        () = tokio::time::sleep_until(started + limits.deadline) => Err(Stop::Silent),
    };
    let bytes = raw.load(Ordering::Relaxed);
    let transfer = match outcome {
        Ok(()) => Transfer::Complete {
            bytes,
            ms: rtt_ms(started.elapsed()),
        },
        Err(Stop::Silent) if bytes == 0 => Transfer::NoData,
        Err(Stop::Silent) => Transfer::Stalled { bytes },
        Err(Stop::Failed(error)) => Transfer::Failed { bytes, error },
    };
    Ok(TransferReport {
        transfer,
        trace: traced.get().copied(),
        answer_ms: answered.get().copied(),
    })
}

/// Completes once the server has been silent for too long: `first_byte` before anything came,
/// `gap` after.
async fn silence(raw: &AtomicU64, limits: Limits) {
    const TICK: Duration = Duration::from_millis(100);
    let mut seen = raw.load(Ordering::Relaxed);
    let mut since = Instant::now();
    loop {
        tokio::time::sleep(TICK).await;
        let now = raw.load(Ordering::Relaxed);
        if now != seen {
            (seen, since) = (now, Instant::now());
            continue;
        }
        let quiet = if seen == 0 {
            limits.first_byte
        } else {
            limits.gap
        };
        if since.elapsed() >= quiet {
            return;
        }
    }
}

/// Largest trace body read.
const TRACE_CAP: usize = 16 * 1024;

/// The trace on the open connection (kept alive for the transfer). A non-2xx answer or a body
/// without an address is just no trace: the transfer still decides.
async fn trace(stream: &mut Stream, on_head: &(dyn Fn() + Sync)) -> Result<Option<Trace>, Stop> {
    let (head, body) = exchange_head(stream, &request("/cdn-cgi/trace", "keep-alive"))
        .await
        .map_err(head_stop)?;
    on_head();
    let body = read_body(stream, &head, body, TRACE_CAP)
        .await
        .map_err(Stop::Failed)?;
    if !(200..300).contains(&head.status) {
        return Ok(None);
    }
    Ok(match parse_trace(&String::from_utf8_lossy(&body)) {
        (Some(ip), country) => Some((Some(ip), country)),
        (None, _) => None,
    })
}

/// The transfer: the body must reach [`TRANSFER_BYTES`] (chunk framing, if any, counts too:
/// the point is the volume, not the payload).
async fn download(stream: &mut Stream, on_head: &(dyn Fn() + Sync)) -> Result<(), Stop> {
    let path = format!("/__down?bytes={TRANSFER_BYTES}");
    let (head, body) = exchange_head(stream, &request(&path, "close"))
        .await
        .map_err(head_stop)?;
    on_head();
    if !(200..300).contains(&head.status) {
        return Err(Stop::Failed(format!("http status {}", head.status)));
    }
    let mut got = body.len() as u64;
    let mut buf = vec![0u8; 16 * 1024];
    while got < TRANSFER_BYTES {
        match stream.read(&mut buf).await {
            Ok(0) => return Err(Stop::Failed(format!("closed after {got} body bytes"))),
            Ok(n) => got += n as u64,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Stop::Failed(format!("closed after {got} body bytes")));
            }
            Err(e) => return Err(Stop::Failed(io_text(&e))),
        }
    }
    Ok(())
}

fn request(path: &str, connection: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {TRANSFER_HOST}\r\nUser-Agent: Mozilla/5.0\r\n\
         Accept: */*\r\nConnection: {connection}\r\n\r\n"
    )
}

fn head_stop(e: HeadError) -> Stop {
    Stop::Failed(e.text())
}
