//! Native real-time ETW consumer for VPN Tunnel Enforcer traffic forensics.
//!
//! Replaces the PowerShell Event-Log poller (`vpnte-etw-sidecar.ps1`) with a
//! genuine ETW real-time session built on `ferrisetw`. It enables the requested
//! providers (TCPIP, DNS-Client, WFP, Winsock-AFD, WebIO) and appends one
//! normalized NDJSON line per event to the file given by `--events`, following
//! the contract consumed by `src/main/trafficForensics.ts` and
//! `src/main/trafficForensicsSummary.ts`.
//!
//! Any line whose `category` is not `lifecycle` and not `health` is treated as a
//! "data event" by the Electron integration; emitting `tcp`/`dns`/`wfp` rows is
//! what clears the "sidecar is running but has no TCP/DNS/WFP data events"
//! warning.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, UserTrace};
use ferrisetw::EventRecord;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

mod classify;

const SIDECAR_NAME: &str = "vpnte-etw-sidecar.exe";
const TRACE_SESSION_NAME: &str = "VPNTE-ETW";
const HEARTBEAT_SECS: u64 = 30;
const DATA_EVENT_CAP: u64 = 250_000;

fn main() {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("vpnte-etw-sidecar: {err}");
            eprintln!("usage: vpnte-etw-sidecar --events <path> --session <id> --providers <csv>");
            std::process::exit(2);
        }
    };

    if let Some(parent) = std::path::Path::new(&args.events).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let sink = match Sink::open(&args.events, args.session.clone()) {
        Ok(sink) => Arc::new(Mutex::new(sink)),
        Err(err) => {
            eprintln!("vpnte-etw-sidecar: cannot open events file {}: {err}", args.events);
            std::process::exit(1);
        }
    };

    let provider_names: Vec<String> = args
        .providers
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    {
        let mut row = serde_json::Map::new();
        row.insert("provider".into(), "sidecar".into());
        row.insert("category".into(), "lifecycle".into());
        row.insert("event".into(), "started".into());
        row.insert("providers".into(), args.providers.clone().into());
        row.insert("eventsPath".into(), args.events.clone().into());
        row.insert("engine".into(), "ferrisetw-realtime".into());
        sink.lock().unwrap().write_row(row, None);
    }

    // Reclaim any orphaned kernel session left by a previous, abruptly-killed
    // sidecar (the Electron integration stops the sidecar with TerminateProcess,
    // so a graceful teardown is not guaranteed). A stable session name bounds
    // such orphans to at most one.
    let _ = stop_trace_by_name(TRACE_SESSION_NAME);

    let mut builder = UserTrace::new().named(TRACE_SESSION_NAME.to_string());
    let mut enabled: Vec<String> = Vec::new();
    for name in &provider_names {
        match build_provider(name, &sink) {
            Some(provider) => {
                builder = builder.enable(provider);
                enabled.push(name.clone());
            }
            None => {
                let mut row = serde_json::Map::new();
                row.insert("provider".into(), "sidecar".into());
                row.insert("category".into(), "health".into());
                row.insert("event".into(), "provider-unresolved".into());
                row.insert("providerName".into(), name.clone().into());
                row.insert(
                    "note".into(),
                    "provider could not be resolved by name or known GUID".into(),
                );
                sink.lock().unwrap().write_row(row, None);
            }
        }
    }

    if enabled.is_empty() {
        let mut row = serde_json::Map::new();
        row.insert("provider".into(), "sidecar".into());
        row.insert("category".into(), "lifecycle".into());
        row.insert("event".into(), "stopped".into());
        row.insert("reason".into(), "no providers could be enabled".into());
        sink.lock().unwrap().write_row(row, None);
        std::process::exit(1);
    }

    let trace = match builder.start_and_process() {
        Ok(trace) => trace,
        Err(err) => {
            let mut row = serde_json::Map::new();
            row.insert("provider".into(), "sidecar".into());
            row.insert("category".into(), "lifecycle".into());
            row.insert("event".into(), "stopped".into());
            row.insert("reason".into(), format!("failed to start ETW trace: {err:?}").into());
            sink.lock().unwrap().write_row(row, None);
            eprintln!("vpnte-etw-sidecar: failed to start ETW trace: {err:?}");
            std::process::exit(1);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    spawn_stdin_watcher(running.clone());

    let mut elapsed = 0u64;
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        elapsed += 500;
        if elapsed >= HEARTBEAT_SECS * 1000 {
            elapsed = 0;
            sink.lock().unwrap().write_heartbeat(&enabled);
        }
    }

    {
        let mut row = serde_json::Map::new();
        row.insert("provider".into(), "sidecar".into());
        row.insert("category".into(), "lifecycle".into());
        row.insert("event".into(), "stopped".into());
        row.insert("reason".into(), "stdin closed".into());
        sink.lock().unwrap().write_row(row, None);
    }

    // Dropping the trace stops the kernel ETW session.
    let _ = trace.stop();
}

/// Build a `Provider` for a canonical Microsoft provider name, resolving its
/// GUID by name (authoritative) and falling back to a known GUID table.
fn build_provider(name: &str, sink: &Arc<Mutex<Sink>>) -> Option<Provider> {
    let category = classify::provider_category(name);
    let label = classify::canonical_provider(name).to_string();

    let builder = match Provider::by_name(name) {
        Ok(builder) => builder,
        Err(_) => {
            let guid = classify::known_guid(name)?;
            Provider::by_guid(guid)
        }
    };

    let callback = make_callback(sink.clone(), label, category);
    Some(
        builder
            .any(0xFFFF_FFFF_FFFF_FFFF)
            .level(0xFF)
            .add_callback(callback)
            .build(),
    )
}

fn make_callback(
    sink: Arc<Mutex<Sink>>,
    provider_label: String,
    category: &'static str,
) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record: &EventRecord, locator: &SchemaLocator| {
        let ts = record.timestamp().format(&Rfc3339).ok();
        let event_id = record.event_id();
        let process_id = record.process_id();

        let mut fields = serde_json::Map::new();
        let mut task = String::new();
        let mut opcode = String::new();

        if let Ok(schema) = locator.event_schema(record) {
            task = schema.task_name();
            opcode = schema.opcode_name();
            let parser = Parser::create(record, &schema);
            extract_fields(&parser, category, &mut fields);
        }

        let kind = format!("{provider_label} {task} {opcode}").to_lowercase();
        let (event, reason) = classify::derive_event_and_reason(category, &kind, &opcode);

        let mut row = serde_json::Map::new();
        row.insert("provider".into(), provider_label.clone().into());
        row.insert("category".into(), category.into());
        row.insert("event".into(), event.into());
        row.insert(
            "reason".into(),
            reason.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
        );
        // Always present (null if unknown) so the Electron probe and summary see
        // a stable shape, mirroring the PowerShell sidecar.
        if !fields.contains_key("remoteAddress") {
            row.insert("remoteAddress".into(), serde_json::Value::Null);
        }
        if !fields.contains_key("queryName") {
            row.insert("queryName".into(), serde_json::Value::Null);
        }
        for (k, v) in fields {
            row.insert(k, v);
        }
        row.insert("eventId".into(), event_id.into());
        row.insert("level".into(), record.level().into());
        if process_id != 0 {
            row.insert("processId".into(), process_id.into());
        }
        if !task.is_empty() {
            row.insert("taskName".into(), task.into());
        }
        if !opcode.is_empty() {
            row.insert("opcodeName".into(), opcode.into());
        }

        sink.lock().unwrap().write_data_row(row, ts);
    }
}

/// Best-effort extraction of normalized fields from a parsed event. Unknown or
/// mistyped properties are simply skipped; the goal is metadata (5-tuple,
/// domain, resolver), never packet payloads.
fn extract_fields(parser: &Parser, category: &str, fields: &mut serde_json::Map<String, serde_json::Value>) {
    match category {
        "dns" => {
            if let Some(q) = try_string(parser, "QueryName") {
                fields.insert("queryName".into(), q.into());
            }
            if let Some(results) = try_string(parser, "QueryResults") {
                if let Some(ip) = first_ip(&results) {
                    fields.insert("remoteAddress".into(), ip.into());
                }
                if !results.is_empty() {
                    fields.insert("queryResults".into(), truncate(&results, 500).into());
                }
            }
            for name in ["DnsServerIpAddress", "DnsServer", "ServerList", "Address"] {
                if let Some(resolver) = try_ip(parser, name).or_else(|| try_string(parser, name)) {
                    if let Some(ip) = first_ip(&resolver).or(Some(resolver.clone())) {
                        if !ip.is_empty() {
                            fields.insert("resolver".into(), ip.into());
                            break;
                        }
                    }
                }
            }
            if let Some(status) = try_u(parser, "QueryStatus") {
                fields.insert("queryStatus".into(), status.into());
            }
        }
        _ => {
            if let Some((addr, port)) =
                resolve_addr(parser, &["RemoteAddress", "DestinationAddress", "DestAddress", "Address"])
            {
                fields.insert("remoteAddress".into(), addr.into());
                if let Some(p) = port {
                    fields.insert("remotePort".into(), p.into());
                }
            }
            if let Some((addr, port)) =
                resolve_addr(parser, &["LocalAddress", "SourceAddress", "SourceAddr"])
            {
                fields.insert("localAddress".into(), addr.into());
                if let Some(p) = port {
                    fields.insert("localPort".into(), p.into());
                }
            }
            if !fields.contains_key("remotePort") {
                for name in ["RemotePort", "DestinationPort", "DestPort"] {
                    if let Some(port) = try_u(parser, name) {
                        fields.insert("remotePort".into(), port.into());
                        break;
                    }
                }
            }
            if !fields.contains_key("localPort") {
                for name in ["LocalPort", "SourcePort"] {
                    if let Some(port) = try_u(parser, name) {
                        fields.insert("localPort".into(), port.into());
                        break;
                    }
                }
            }
            if category == "tcp" {
                fields.insert("protocol".into(), "tcp".into());
            }
        }
    }
}

/// Resolve an address (and optional port) from the first matching property,
/// trying a typed `IpAddr`, then a raw `sockaddr`/`IN_ADDR` blob, then a string.
fn resolve_addr(parser: &Parser, names: &[&str]) -> Option<(String, Option<u16>)> {
    for name in names {
        if let Some(ip) = try_ip(parser, name) {
            return Some((ip, None));
        }
        if let Some(bytes) = try_bytes(parser, name) {
            if let Some(parsed) = parse_sockaddr(&bytes) {
                return Some(parsed);
            }
        }
        if let Some(s) = try_string(parser, name) {
            if let Some(ip) = first_ip(&s) {
                return Some((ip, None));
            }
        }
    }
    None
}

fn try_bytes(parser: &Parser, name: &str) -> Option<Vec<u8>> {
    parser.try_parse::<Vec<u8>>(name).ok().filter(|b| !b.is_empty())
}

/// Parse a Windows `SOCKADDR`/`SOCKADDR_IN(6)` or raw `IN_ADDR`/`IN6_ADDR` blob.
fn parse_sockaddr(bytes: &[u8]) -> Option<(String, Option<u16>)> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if bytes.len() >= 8 {
        let family = u16::from_le_bytes([bytes[0], bytes[1]]);
        // AF_INET
        if family == 2 {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            return Some((ip.to_string(), nonzero_port(port)));
        }
        // AF_INET6
        if family == 23 && bytes.len() >= 24 {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            return Some((Ipv6Addr::from(addr).to_string(), nonzero_port(port)));
        }
    }
    match bytes.len() {
        4 => {
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Some((ip.to_string(), None))
        }
        16 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(bytes);
            Some((Ipv6Addr::from(addr).to_string(), None))
        }
        _ => None,
    }
}

fn nonzero_port(port: u16) -> Option<u16> {
    if port == 0 {
        None
    } else {
        Some(port)
    }
}

fn try_string(parser: &Parser, name: &str) -> Option<String> {
    parser.try_parse::<String>(name).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn try_ip(parser: &Parser, name: &str) -> Option<String> {
    parser.try_parse::<IpAddr>(name).ok().map(|ip| ip.to_string())
}

fn try_u(parser: &Parser, name: &str) -> Option<u64> {
    if let Ok(v) = parser.try_parse::<u16>(name) {
        return Some(v as u64);
    }
    if let Ok(v) = parser.try_parse::<u32>(name) {
        return Some(v as u64);
    }
    parser.try_parse::<u64>(name).ok()
}

fn first_ip(text: &str) -> Option<String> {
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':')) {
        if token.is_empty() {
            continue;
        }
        if token.parse::<IpAddr>().is_ok() {
            return Some(token.to_string());
        }
    }
    None
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect()
    }
}

fn spawn_stdin_watcher(running: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 256];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        running.store(false, Ordering::Relaxed);
    });
}

struct Sink {
    file: std::fs::File,
    session: String,
    total: AtomicU64,
    data: AtomicU64,
    cap_reported: bool,
}

impl Sink {
    fn open(path: &str, session: String) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            session,
            total: AtomicU64::new(0),
            data: AtomicU64::new(0),
            cap_reported: false,
        })
    }

    fn write_row(&mut self, mut row: serde_json::Map<String, serde_json::Value>, ts: Option<String>) {
        row.insert("session".into(), self.session.clone().into());
        row.insert("sidecar".into(), SIDECAR_NAME.into());
        let ts = ts.unwrap_or_else(|| OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default());
        row.insert("ts".into(), ts.into());
        if let Ok(line) = serde_json::to_string(&serde_json::Value::Object(row)) {
            let _ = self.file.write_all(line.as_bytes());
            let _ = self.file.write_all(b"\n");
            let _ = self.file.flush();
            self.total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn write_data_row(&mut self, row: serde_json::Map<String, serde_json::Value>, ts: Option<String>) {
        if self.data.load(Ordering::Relaxed) >= DATA_EVENT_CAP {
            if !self.cap_reported {
                self.cap_reported = true;
                let mut cap = serde_json::Map::new();
                cap.insert("provider".into(), "sidecar".into());
                cap.insert("category".into(), "health".into());
                cap.insert("event".into(), "event-cap-reached".into());
                cap.insert("bufferPressure".into(), 1.into());
                cap.insert("dataEvents".into(), DATA_EVENT_CAP.into());
                self.write_row(cap, None);
            }
            return;
        }
        self.data.fetch_add(1, Ordering::Relaxed);
        self.write_row(row, ts);
    }

    fn write_heartbeat(&mut self, providers: &[String]) {
        let mut row = serde_json::Map::new();
        row.insert("provider".into(), "sidecar".into());
        row.insert("category".into(), "health".into());
        row.insert("event".into(), "heartbeat".into());
        row.insert("observedEvents".into(), self.total.load(Ordering::Relaxed).into());
        row.insert("dataEvents".into(), self.data.load(Ordering::Relaxed).into());
        row.insert("enabledProviders".into(), providers.join(",").into());
        row.insert(
            "note".into(),
            "native ferrisetw real-time ETW consumer; pktmon remains the primary packet capture source.".into(),
        );
        self.write_row(row, None);
    }
}

struct Args {
    events: String,
    session: String,
    providers: String,
}

impl Args {
    fn parse(iter: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut events = None;
        let mut session = None;
        let mut providers = None;
        let mut args: Vec<String> = iter.collect();
        let mut i = 0;
        while i < args.len() {
            let flag = std::mem::take(&mut args[i]);
            let key = flag.trim_start_matches('-').trim_start_matches('/').to_ascii_lowercase();
            let value = args.get(i + 1).cloned();
            match key.as_str() {
                "events" | "session" | "providers" => {
                    let value = value.ok_or_else(|| format!("missing value for --{key}"))?;
                    match key.as_str() {
                        "events" => events = Some(value),
                        "session" => session = Some(value),
                        "providers" => providers = Some(value),
                        _ => unreachable!(),
                    }
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
        Ok(Self {
            events: events.ok_or("missing --events")?,
            session: session.ok_or("missing --session")?,
            providers: providers.ok_or("missing --providers")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sockaddr_in_ipv4_with_port() {
        // AF_INET (2), port 443 (0x01BB big-endian), 142.250.1.2
        let bytes = [2u8, 0, 0x01, 0xBB, 142, 250, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        let (ip, port) = parse_sockaddr(&bytes).unwrap();
        assert_eq!(ip, "142.250.1.2");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parses_sockaddr_in6_with_port() {
        let mut bytes = vec![23u8, 0, 0x01, 0xBB, 0, 0, 0, 0];
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let (ip, port) = parse_sockaddr(&bytes).unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parses_raw_in_addr_ipv4() {
        let (ip, port) = parse_sockaddr(&[8, 8, 4, 4]).unwrap();
        assert_eq!(ip, "8.8.4.4");
        assert_eq!(port, None);
    }

    #[test]
    fn extracts_first_ip_from_dns_results() {
        assert_eq!(first_ip("172.16.2.2;10.0.0.1;").as_deref(), Some("172.16.2.2"));
        assert_eq!(first_ip("no-ip-here"), None);
    }

    #[test]
    fn args_parse_long_flags() {
        let args = Args::parse(
            [
                "--events", "C:/x/events.ndjson", "--session", "abc", "--providers", "A,B",
            ]
            .iter()
            .map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(args.events, "C:/x/events.ndjson");
        assert_eq!(args.session, "abc");
        assert_eq!(args.providers, "A,B");
    }
}
