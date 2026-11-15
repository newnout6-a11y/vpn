//! Strict host and `host:port` parsing (tunnel-core B-01 / AT-02-007): garbage such as
//! `127.0.0.1:10808abc`, `127.0.0.1:1e3` or shell metacharacters never reaches probes or configs.
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use vpnte_base::{AppError, Msg};

/// Why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    #[error("empty address")]
    Empty,
    #[error("address has no port")]
    MissingPort,
    #[error("port is not a number in 1..=65535")]
    BadPort,
    #[error("host is neither an IP literal nor a DNS name")]
    BadHost,
}

impl From<AddrError> for AppError {
    fn from(err: AddrError) -> Self {
        AppError::validation(Msg::new("core.net.addressInvalid")).with_source(err)
    }
}

/// A host as written in an address: an IP literal or a DNS name (stored lowercase, no trailing dot).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    /// Parses a bare host (trimmed): an IPv4/IPv6 literal, `[v6]`, or a DNS name.
    pub fn parse(s: &str) -> Result<Host, AddrError> {
        let s = s.trim();
        match s.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            Some(inner) => parse_v6(inner),
            None => parse_unbracketed(s),
        }
    }

    /// The address when the host is an IP literal.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Host::Ip(ip) => Some(*ip),
            Host::Name(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ip(ip) => ip.fmt(f),
            Host::Name(name) => f.write_str(name),
        }
    }
}

impl FromStr for Host {
    type Err = AddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Host::parse(s)
    }
}

/// A validated `host:port` (port 1..=65535); displays as `host:port` or `[v6]:port`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPort {
    host: Host,
    port: u16,
}

impl HostPort {
    /// Strict parse of `host:port` / `[v6]:port` (surrounding whitespace ignored).
    pub fn parse(s: &str) -> Result<HostPort, AddrError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(AddrError::Empty);
        }
        let (host, port) = match s.strip_prefix('[') {
            Some(rest) => {
                let (inner, after) = rest.split_once(']').ok_or(AddrError::BadHost)?;
                let port = after.strip_prefix(':').ok_or(AddrError::MissingPort)?;
                (parse_v6(inner)?, port)
            }
            None => {
                let (host, port) = s.rsplit_once(':').ok_or(AddrError::MissingPort)?;
                // An unbracketed IPv6 literal cannot be told apart from its port.
                if host.contains(':') {
                    return Err(AddrError::BadHost);
                }
                (parse_unbracketed(host)?, port)
            }
        };
        Ok(HostPort {
            host,
            port: parse_port(port)?,
        })
    }

    /// Builds from a bare host (as [`Host::parse`]) and a port.
    pub fn new(host: &str, port: u16) -> Result<HostPort, AddrError> {
        if port == 0 {
            return Err(AddrError::BadPort);
        }
        Ok(HostPort {
            host: Host::parse(host)?,
            port,
        })
    }

    /// The host part.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port (never 0).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The socket address when the host is an IP literal.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.host.ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            host => write!(f, "{host}:{}", self.port),
        }
    }
}

impl FromStr for HostPort {
    type Err = AddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HostPort::parse(s)
    }
}

impl TryFrom<SocketAddr> for HostPort {
    type Error = AddrError;
    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        if addr.port() == 0 {
            return Err(AddrError::BadPort);
        }
        Ok(HostPort {
            host: Host::Ip(addr.ip()),
            port: addr.port(),
        })
    }
}

fn parse_v6(s: &str) -> Result<Host, AddrError> {
    s.parse::<Ipv6Addr>()
        .map(|ip| Host::Ip(IpAddr::V6(ip)))
        .map_err(|_| AddrError::BadHost)
}

fn parse_unbracketed(s: &str) -> Result<Host, AddrError> {
    if s.is_empty() {
        return Err(AddrError::Empty);
    }
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(Host::Ip(ip)),
        Err(_) => parse_name(s).map(Host::Name),
    }
}

/// RFC 1123 host name; `_` is accepted too because Go's resolver (used by both engines) does.
fn parse_name(s: &str) -> Result<String, AddrError> {
    let name = s.strip_suffix('.').unwrap_or(s);
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) || ends_in_number(name)
    {
        return Err(AddrError::BadHost);
    }
    let name = name.to_ascii_lowercase();
    // A punycode label that does not decode (`xn--zz`) names nothing, and the URL parser refuses
    // it: proxy and request URLs are built from these names and must always parse.
    if url::Host::parse(&name).is_err() {
        return Err(AddrError::BadHost);
    }
    Ok(name)
}

/// WHATWG "ends in a number": `999.1.1.1`, `127.1` or `0x7f.1` are malformed IPv4 literals that
/// some resolvers still turn into addresses (`inet_aton` forms), so they are not names.
fn ends_in_number(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    let hex = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"));
    last.bytes().all(|b| b.is_ascii_digit())
        || hex.is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn parse_port(s: &str) -> Result<u16, AddrError> {
    if s.is_empty() {
        return Err(AddrError::MissingPort);
    }
    if s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AddrError::BadPort);
    }
    match s.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(AddrError::BadPort),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hp(s: &str) -> (String, u16) {
        let parsed = HostPort::parse(s).unwrap();
        (parsed.host().to_string(), parsed.port())
    }

    /// AT-02-007 (tunnel-core §7.1, normative §7.3): strict proxy address parsing.
    #[test]
    fn proxy_address_table() {
        assert_eq!(hp("127.0.0.1:10808"), ("127.0.0.1".into(), 10808));
        assert_eq!(hp("[::1]:1080"), ("::1".into(), 1080));
        assert_eq!(hp(" 127.0.0.1:10808 "), ("127.0.0.1".into(), 10808));
        assert_eq!(hp("localhost:1080"), ("localhost".into(), 1080));
        for bad in [
            "127.0.0.1",
            "127.0.0.1:70000",
            ":1080",
            "127.0.0.1:10808abc",
            "127.0.0.1:1e3",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:+80",
            "127.0.0.1:0x50",
            "[::1]:",
        ] {
            assert!(HostPort::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// AT-02-007: `parse(format(parse(x))) == parse(x)` for every accepted input.
    #[test]
    fn display_round_trips() {
        for s in [
            "127.0.0.1:10808",
            "[::1]:1080",
            " 127.0.0.1:10808 ",
            "[2001:DB8:0:0:0:0:0:1]:443",
            "[::ffff:1.2.3.4]:80",
            "Proxy.Example.COM.:0080",
            "localhost:8080",
            "a_b.example:65535",
        ] {
            let once = HostPort::parse(s).unwrap();
            let twice = HostPort::parse(&once.to_string()).unwrap();
            assert_eq!(once, twice, "{s:?}");
        }
        assert_eq!(
            HostPort::parse("[::1]:1080").unwrap().to_string(),
            "[::1]:1080"
        );
        assert_eq!(
            HostPort::parse("Proxy.Example.COM.:0080")
                .unwrap()
                .to_string(),
            "proxy.example.com:80"
        );
    }

    #[test]
    fn refuses_ambiguous_and_malformed_hosts() {
        use AddrError::*;
        let cases = [
            ("2001:db8::1:80", BadHost),
            ("[1.2.3.4]:80", BadHost),
            ("[::1:80", BadHost),
            ("[::1]", MissingPort),
            ("[::1]80", MissingPort),
            ("999.1.1.1:80", BadHost),
            ("127.1:80", BadHost),
            ("0x7f.1:80", BadHost),
            ("-a.example:80", BadHost),
            ("a..b:80", BadHost),
            ("host/path:80", BadHost),
            ("xn--zz.example:80", BadHost),
            ("host:0", BadPort),
            ("host:+80", BadPort),
            ("host:", MissingPort),
            ("", Empty),
        ];
        for (input, err) in cases {
            assert_eq!(HostPort::parse(input), Err(err), "{input:?}");
        }
    }

    /// Ping host gate (servers §7 #21) and server-info host parsing (S-46).
    #[test]
    fn host_gate() {
        for ok in [
            "8.8.8.8",
            "192.168.0.1",
            "sub.feodorn.com",
            "a-b.example.org",
            "xn--d1acufc.xn--p1ai",
            "2001:db8::1",
            "::1",
            "8.8.8.8 ",
            "[2001:db8::1]",
        ] {
            assert!(Host::parse(ok).is_ok(), "{ok:?} must be accepted");
        }
        let long = "a".repeat(300);
        for bad in [
            "8.8.8.8 & calc",
            "8.8.8.8 && shutdown /s",
            "8.8.8.8 | whoami",
            "$(calc)",
            "`calc`",
            "a.com; rm -rf /",
            "a.com\nb.com",
            "",
            "  ",
            "8 8",
            long.as_str(),
        ] {
            assert!(Host::parse(bad).is_err(), "{bad:?} must be refused");
        }
        let full_form = Host::parse("2001:db8:0:0:0:0:0:1").unwrap();
        assert_eq!(full_form, Host::Ip("2001:db8::1".parse().unwrap()));
        let bracketed = HostPort::parse("[2606:4700:4700::1111]:8443").unwrap();
        assert_eq!(bracketed.host().to_string(), "2606:4700:4700::1111");
        assert_eq!(
            Host::parse("WWW.Example.com.").unwrap(),
            Host::Name("www.example.com".into())
        );
    }

    #[test]
    fn constructors() {
        let v6: SocketAddr = "[::1]:53".parse().unwrap();
        let addr = HostPort::try_from(v6).unwrap();
        assert_eq!(addr.to_string(), "[::1]:53");
        assert_eq!(addr.socket_addr(), Some(v6));
        assert_eq!(
            HostPort::try_from("1.2.3.4:0".parse::<SocketAddr>().unwrap()),
            Err(AddrError::BadPort)
        );
        assert_eq!(
            HostPort::new("Example.org", 443).unwrap().to_string(),
            "example.org:443"
        );
        assert_eq!(HostPort::new("[::1]", 1).unwrap().to_string(), "[::1]:1");
        assert_eq!(HostPort::new("example.org", 0), Err(AddrError::BadPort));
        assert_eq!(HostPort::new("example.org", 1).unwrap().socket_addr(), None);
        let err: AppError = AddrError::BadPort.into();
        assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    }
}
