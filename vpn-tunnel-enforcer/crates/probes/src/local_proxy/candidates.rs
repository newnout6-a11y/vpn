//! Where a local upstream proxy may listen: config files of known clients, the system proxy
//! settings, loopback listeners and the ports popular clients use by default. Pure parsing here;
//! the OS reads live in `system.rs`.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use vpnte_base::types::ProxyKind;

/// Where a candidate address came from (shown to the user and logged; never a secret).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", content = "detail", rename_all = "kebab-case")]
pub enum Source {
    /// A config file of a known client (file name only).
    Config(String),
    /// System proxy settings: `wininet`, `winhttp` or `env:<NAME>`.
    System(String),
    /// A loopback listener; the owning process image name is only a hint.
    Listener(String),
    /// One of the ports popular clients use by default.
    TypicalPort,
}

/// One address to classify, in priority order of the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    /// Protocol the source suggests; tried first.
    pub hint: Option<ProxyKind>,
    pub source: Source,
}

/// Ports Happ, v2rayN, Clash, NekoRay, Hiddify and others listen on by default. The old array
/// held duplicates (1080 three times); this is its unique set in first-occurrence order.
pub const TYPICAL_PORTS: [u16; 20] = [
    443, 10808, 10809, 1080, 1081, 1087, 7890, 7891, 7892, 7893, 2080, 2081, 6450, 6451, 8080,
    9090, 20170, 20171, 8388, 7897,
];

/// Client directories under `%APPDATA%` and `%LOCALAPPDATA%` (Windows paths are case-insensitive,
/// so the old `Happ`/`happ` and `nekoray`/`NekoRay` pairs are one entry each).
pub const CONFIG_DIRS: [&str; 14] = [
    "Happ",
    "Happ VPN",
    "v2rayN",
    "HiddifyN",
    "io.github.clash-verge-rev.clash-verge-rev",
    "clash-verge",
    "FlClash",
    "nekoray",
    "nekobox",
    "Hiddify",
    "Karing",
    "mihomo-party",
    "sing-box",
    "Streisand",
];

/// Config file extensions that are read (top level of a client directory only).
pub const CONFIG_EXTENSIONS: [&str; 6] = ["json", "yaml", "yml", "conf", "ini", "toml"];

/// Bigger files are skipped: client configs are small, rule databases are not.
pub const CONFIG_MAX_BYTES: u64 = 1024 * 1024;

static PORT_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)^\s*["']?(mixed-port|socks-port|http-port|redir-port|tproxy-port|local[-_]port|listen[-_]port|port)["']?\s*[:=]\s*["']?(\d{2,5})\b"#,
    )
    .expect("static regex")
});

static LISTEN_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)^\s*["']?(listen|bind)["']?\s*[:=]\s*["']?(?:([a-z][\w+.-]*)://)?(?:\[[^\]]+\]|localhost|127\.0\.0\.1|0\.0\.0\.0|::1|::)?:(\d{2,5})\b"#,
    )
    .expect("static regex")
});

static HOST_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:(https?|socks5h?|socks4a?|socks)://)?(\[[0-9a-f:.]+\]|localhost|(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+):(\d{2,5})",
    )
    .expect("static regex")
});

/// Cuts a trailing comment (`#`, `;`, `//`) outside quotes. `//` counts only at the line start or
/// after whitespace: the old cut at any `//` made `listen: socks5://127.0.0.1:1080` unreadable.
pub fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'#' | b';' => return &line[..i],
                b'/' if bytes.get(i + 1) == Some(&b'/')
                    && (i == 0 || bytes[i - 1].is_ascii_whitespace()) =>
                {
                    return &line[..i];
                }
                _ => {}
            },
        }
    }
    line
}

fn hint_from(word: &str) -> Option<ProxyKind> {
    let word = word.to_ascii_lowercase();
    if word.contains("socks") {
        Some(ProxyKind::Socks5)
    } else if word.contains("http") {
        Some(ProxyKind::Http)
    } else {
        None
    }
}

fn port_of(digits: &str) -> Option<u16> {
    digits.parse::<u16>().ok().filter(|p| *p > 0)
}

/// Proxy ports declared in a client config (`mixed-port: 7890`, `"listen": "127.0.0.1:2080"`),
/// always on `127.0.0.1`; a `socks`/`http` key or scheme sets the hint.
pub fn config_candidates(content: &str, file: &str) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for raw in content.lines() {
        let line = strip_comment(raw);
        let found = if let Some(c) = PORT_KEY.captures(line) {
            port_of(&c[2]).map(|p| (p, hint_from(&c[1])))
        } else if let Some(c) = LISTEN_KEY.captures(line) {
            let hint = c.get(2).and_then(|s| hint_from(s.as_str()));
            port_of(&c[3]).map(|p| (p, hint))
        } else {
            None
        };
        if let Some((port, hint)) = found {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            if !out.iter().any(|c| c.addr == addr) {
                out.push(Candidate {
                    addr,
                    hint,
                    source: Source::Config(file.to_owned()),
                });
            }
        }
    }
    out
}

fn loopback_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<IpAddr>().ok()?
    };
    let ip = match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    ip.is_loopback().then_some(SocketAddr::new(ip, port))
}

/// Loopback `host:port` pairs inside a free-form proxy setting (env URL, WinINet / WinHTTP value,
/// PAC URL); the scheme sets the hint. Remote proxies are ignored: only a local client can be
/// the upstream of the TUN.
pub fn text_candidates(text: &str, source: &Source) -> Vec<Candidate> {
    HOST_PORT
        .captures_iter(text)
        .filter_map(|c| {
            let addr = loopback_addr(&c[2], port_of(&c[3])?)?;
            let hint = c.get(1).and_then(|s| hint_from(s.as_str()));
            Some(Candidate {
                addr,
                hint,
                source: source.clone(),
            })
        })
        .collect()
}

/// A WinINet / WinHTTP proxy value: `host:port` or `http=host:port;https=…;socks=host:port`.
/// The per-protocol form sets the hint (the old text scan lost it).
pub fn proxy_server_candidates(value: &str, source: &Source) -> Vec<Candidate> {
    let mut out = Vec::new();
    for part in value
        .split([';', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let (hint, rest) = match part.split_once('=') {
            Some((scheme, rest)) => (hint_from(scheme), rest),
            None => (None, part),
        };
        for mut c in text_candidates(rest, source) {
            c.hint = c.hint.or(hint);
            out.push(c);
        }
    }
    out
}

/// A TCP listener as read from the socket table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerRow {
    pub local: SocketAddr,
    pub pid: u32,
    /// Image file name (`xray.exe`), when readable.
    pub process: Option<String>,
}

/// Well-known ports of OS services, databases and dev servers: never a client's proxy.
const EXCLUDED_PORTS: [u16; 27] = [
    135, 139, 445, 3389, 5985, 5986, 5040, 5357, 49664, 49665, 49666, 49667, 49668, 49669, 49670,
    49671, 49672, 49673, 80, 3306, 5432, 6379, 27017, 11211, 8443, 8888, 9000,
];

static SYSTEM_PROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(svchost|System|wininit|services|lsass|csrss|smss|winlogon|spoolsv|RuntimeBroker|SearchHost|SearchApp|StartMenuExperienceHost|TextInputHost|ShellExperienceHost|ApplicationFrameHost|Explorer|Taskmgr|dllhost|conhost|fontdrvhost|sihost|ctfmon|dwm|audiodg)(\.exe)?$",
    )
    .expect("static regex")
});

/// Loopback / wildcard listeners that could be a client's proxy, one per port, probed where
/// they accept: `0.0.0.0` / `::` at `127.0.0.1`, a `::1`-only socket at `[::1]` (the old code
/// always dialled `127.0.0.1` and missed it). `skip` holds the app's own pids and ports.
pub fn listener_candidates(
    rows: &[ListenerRow],
    skip_pids: &[u32],
    skip_ports: &[u16],
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for row in rows {
        let port = row.local.port();
        if (port < 1024 && port != 443)
            || EXCLUDED_PORTS.contains(&port)
            || skip_ports.contains(&port)
            || skip_pids.contains(&row.pid)
            || row
                .process
                .as_deref()
                .is_some_and(|p| SYSTEM_PROCESS.is_match(p))
        {
            continue;
        }
        let Some(addr) = loopback_addr(&row.local.ip().to_string(), port) else {
            continue;
        };
        match out.iter_mut().find(|c| c.addr.port() == port) {
            // Prefer the IPv4 address when the same port listens on both stacks.
            Some(c) if c.addr.is_ipv6() && addr.is_ipv4() => c.addr = addr,
            Some(_) => {}
            None => out.push(Candidate {
                addr,
                hint: None,
                source: Source::Listener(row.process.clone().unwrap_or_default()),
            }),
        }
    }
    out
}

/// The fallback list on `127.0.0.1`.
pub fn typical_candidates() -> Vec<Candidate> {
    TYPICAL_PORTS
        .iter()
        .map(|&port| Candidate {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            hint: None,
            source: Source::TypicalPort,
        })
        .collect()
}

/// Concatenates the groups in priority order and keeps the first occurrence of each address
/// (its source and hint win; a later hint fills a missing one).
pub fn merge(groups: impl IntoIterator<Item = Vec<Candidate>>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for c in groups.into_iter().flatten() {
        match out.iter_mut().find(|o| o.addr == c.addr) {
            Some(o) => o.hint = o.hint.or(c.hint),
            None => out.push(c),
        }
    }
    out
}
