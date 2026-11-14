//! Just enough DER to describe a server certificate (subject, issuer, validity, SAN) and Node's
//! hostname-check rules. A full X.509 crate would add a dozen dependencies for four fields.
use std::net::IpAddr;

/// Fields of a leaf certificate shown in the live check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertSummary {
    pub subject: Vec<(String, String)>,
    pub issuer: Vec<(String, String)>,
    pub not_before: AsnTime,
    pub not_after: AsnTime,
    pub dns_names: Vec<String>,
    pub ips: Vec<IpAddr>,
}

/// A UTC calendar time from a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AsnTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl AsnTime {
    /// Seconds since the Unix epoch.
    pub fn unix_secs(&self) -> i64 {
        let days = days_from_civil(self.year, self.month, self.day);
        days * 86_400 + i64::from(self.hour * 3600 + self.minute * 60 + self.second)
    }

    /// OpenSSL text (`Jan  1 00:00:00 2027 GMT`): Node's `valid_to`, kept for history compatibility.
    pub fn openssl_text(&self) -> String {
        let month = MONTHS[(self.month.clamp(1, 12) - 1) as usize];
        format!(
            "{month} {:>2} {:02}:{:02}:{:02} {} GMT",
            self.day, self.hour, self.minute, self.second, self.year
        )
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// One TLV: (tag, value, rest).
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        rest = &rest[n..];
        len
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Reads one element that must carry `tag`.
fn expect(buf: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, value, rest) = tlv(buf)?;
    (t == tag).then_some((value, rest))
}

const SEQ: u8 = 0x30;
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// Parses a DER certificate; `None` when it is not one.
pub(crate) fn parse(der: &[u8]) -> Option<CertSummary> {
    let (cert, _) = expect(der, SEQ)?;
    let (tbs, _) = expect(cert, SEQ)?;
    let mut rest = tbs;
    if let Some((0xa0, _, after)) = tlv(rest) {
        rest = after; // explicit version
    }
    let (_serial, rest) = expect(rest, 0x02)?;
    let (_sig_alg, rest) = expect(rest, SEQ)?;
    let (issuer, rest) = expect(rest, SEQ)?;
    let (validity, rest) = expect(rest, SEQ)?;
    let (subject, rest) = expect(rest, SEQ)?;
    let (_spki, mut rest) = expect(rest, SEQ)?;
    let (not_before, after) = time(validity)?;
    let (not_after, _) = time(after)?;
    let (mut dns_names, mut ips) = (Vec::new(), Vec::new());
    while let Some((tag, value, after)) = tlv(rest) {
        rest = after;
        if tag == 0xa3 {
            san(value, &mut dns_names, &mut ips)?;
        }
    }
    Some(CertSummary {
        subject: name(subject)?,
        issuer: name(issuer)?,
        not_before,
        not_after,
        dns_names,
        ips,
    })
}

fn time(buf: &[u8]) -> Option<(AsnTime, &[u8])> {
    let (tag, value, rest) = tlv(buf)?;
    let text = std::str::from_utf8(value).ok()?;
    let digits = |s: &str| s.parse::<u32>().ok();
    let (year, tail) = match tag {
        0x17 => {
            let yy = i64::from(digits(text.get(..2)?)?);
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, text.get(2..)?)
        }
        0x18 => (i64::from(digits(text.get(..4)?)?), text.get(4..)?),
        _ => return None,
    };
    let field = |i: usize| digits(tail.get(i..i + 2)?);
    let t = AsnTime {
        year,
        month: field(0)?,
        day: field(2)?,
        hour: field(4)?,
        minute: field(6)?,
        second: field(8).unwrap_or(0),
    };
    Some((t, rest))
}

/// `[3] Extensions`: picks dNSName / iPAddress entries of subjectAltName.
fn san(explicit: &[u8], dns: &mut Vec<String>, ips: &mut Vec<IpAddr>) -> Option<()> {
    let (mut exts, _) = expect(explicit, SEQ)?;
    while let Some((ext, after)) = expect(exts, SEQ) {
        exts = after;
        let (oid, mut rest) = expect(ext, 0x06)?;
        if let Some((0x01, _, after)) = tlv(rest) {
            rest = after; // critical flag
        }
        let (value, _) = expect(rest, 0x04)?;
        if oid != OID_SAN {
            continue;
        }
        let (mut names, _) = expect(value, SEQ)?;
        while let Some((tag, value, after)) = tlv(names) {
            names = after;
            match (tag, value.len()) {
                (0x82, _) => dns.push(String::from_utf8_lossy(value).into_owned()),
                (0x87, 4) => ips.push(IpAddr::from(<[u8; 4]>::try_from(value).ok()?)),
                (0x87, 16) => ips.push(IpAddr::from(<[u8; 16]>::try_from(value).ok()?)),
                _ => {}
            }
        }
    }
    Some(())
}

/// A distinguished name as (short label, value) pairs in certificate order.
fn name(buf: &[u8]) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut rdns = buf;
    while let Some((set, after)) = expect(rdns, 0x31) {
        rdns = after;
        let mut atvs = set;
        while let Some((atv, after)) = expect(atvs, SEQ) {
            atvs = after;
            let (oid, rest) = expect(atv, 0x06)?;
            let (tag, value, _) = tlv(rest)?;
            out.push((oid_label(oid), string(tag, value)));
        }
    }
    Some(out)
}

fn oid_label(oid: &[u8]) -> String {
    let short = match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        _ => return dotted(oid),
    };
    short.to_owned()
}

fn dotted(oid: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut acc = 0u64;
    for b in oid {
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (acc / 40).min(2);
                parts.extend([first, acc - first * 40]);
            } else {
                parts.push(acc);
            }
            acc = 0;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn string(tag: u8, value: &[u8]) -> String {
    match tag {
        // BMPString: UTF-16BE.
        0x1e => {
            let units: Vec<u16> = value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        // TeletexString: treated as Latin-1, like OpenSSL does in practice.
        0x14 => value.iter().map(|b| char::from(*b)).collect(),
        _ => String::from_utf8_lossy(value).into_owned(),
    }
}

fn values<'a>(dn: &'a [(String, String)], label: &str) -> Vec<&'a str> {
    dn.iter()
        .filter(|(k, _)| k == label)
        .map(|(_, v)| v.as_str())
        .collect()
}

fn dn_text(dn: &[(String, String)]) -> String {
    dn.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl CertSummary {
    /// Subject CN (several joined with `, `), else the whole name.
    pub fn subject_text(&self) -> String {
        let cn = values(&self.subject, "CN");
        if cn.is_empty() {
            dn_text(&self.subject)
        } else {
            cn.join(", ")
        }
    }

    /// Issuer O, else CN, else the whole name.
    pub fn issuer_text(&self) -> String {
        let pick = |label| values(&self.issuer, label).join(", ");
        [pick("O"), pick("CN")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_else(|| dn_text(&self.issuer))
    }

    /// SAN entries as strings: DNS names, then IPs.
    pub fn sans(&self) -> Vec<String> {
        let ips = self.ips.iter().map(IpAddr::to_string);
        self.dns_names.iter().cloned().chain(ips).collect()
    }

    /// Node's `checkServerIdentity`: an IP must be an IP SAN; a name matches a DNS SAN (one
    /// left-most wildcard, never `*.tld`) or, when there is none, the subject CN.
    pub fn matches_identity(&self, identity: &str) -> bool {
        let host = identity.trim_end_matches('.').to_ascii_lowercase();
        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            return self.ips.contains(&ip);
        }
        let host_parts: Vec<&str> = host.split('.').collect();
        if !self.dns_names.is_empty() {
            return self
                .dns_names
                .iter()
                .any(|p| wildcard_match(&host_parts, p));
        }
        values(&self.subject, "CN")
            .iter()
            .any(|p| wildcard_match(&host_parts, p))
    }
}

fn wildcard_match(host: &[&str], pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = pattern.split('.').collect();
    if pattern.is_empty() || parts.len() != host.len() || parts.contains(&"") {
        return false;
    }
    if parts
        .iter()
        .any(|p| p.bytes().any(|b| !(0x21..=0x7f).contains(&b)))
    {
        return false;
    }
    if parts[1..] != host[1..] {
        return false;
    }
    let (first, label) = (parts[0], host[0]);
    let pieces: Vec<&str> = first.split('*').collect();
    if pieces.len() == 1 || first.contains("xn--") {
        return label == first;
    }
    if pieces.len() > 2 || parts.len() <= 2 {
        return false;
    }
    let (prefix, suffix) = (pieces[0], pieces[1]);
    prefix.len() + suffix.len() <= label.len()
        && label.starts_with(prefix)
        && label.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake self-signed EC certificate: CN=unrelated.example, O=Test Org; SAN unrelated.example,
    /// *.wild.example, 192.0.2.1, 2001:db8::1; valid 2026-11-11 .. 2126-10-18.
    pub(crate) const CERT: &[u8] = include_bytes!("testdata/self-signed.der");

    #[test]
    fn parses_the_fixture() {
        let c = parse(CERT).unwrap();
        assert_eq!(c.subject_text(), "unrelated.example");
        assert_eq!(c.issuer_text(), "Test Org");
        assert_eq!(c.not_before.openssl_text(), "Nov 11 04:12:44 2026 GMT");
        assert_eq!(c.not_after.openssl_text(), "Oct 18 04:12:44 2126 GMT");
        assert_eq!(
            c.sans(),
            [
                "unrelated.example",
                "*.wild.example",
                "192.0.2.1",
                "2001:db8::1"
            ]
        );
        assert!(c.not_after.unix_secs() > c.not_before.unix_secs());
        assert!(parse(&CERT[..100]).is_none());
        assert!(parse(b"not a certificate").is_none());
    }

    /// AT-05-001 (audit defect 4): identity checks follow Node's checkServerIdentity.
    #[test]
    fn identity_rules() {
        let c = parse(CERT).unwrap();
        assert!(c.matches_identity("unrelated.example"));
        assert!(c.matches_identity("UNRELATED.example."));
        assert!(c.matches_identity("a.wild.example"));
        assert!(!c.matches_identity("a.b.wild.example"));
        assert!(!c.matches_identity("wild.example"));
        assert!(c.matches_identity("192.0.2.1"));
        assert!(c.matches_identity("2001:db8::1"));
        assert!(!c.matches_identity("127.0.0.1"));
        assert!(!c.matches_identity("vpn.example.com"));
    }

    #[test]
    fn wildcards() {
        let host = |h: &'static str| h.split('.').collect::<Vec<_>>();
        assert!(wildcard_match(&host("www.example.com"), "w*.example.com"));
        assert!(wildcard_match(&host("www.example.com"), "*w.example.com"));
        assert!(!wildcard_match(&host("example.com"), "*.com"));
        assert!(!wildcard_match(&host("a.example.com"), "*.*.com"));
        assert!(!wildcard_match(
            &host("xn--a.example.com"),
            "xn--*.example.com"
        ));
        assert!(!wildcard_match(&host("a.example.com"), "a..com"));
    }

    #[test]
    fn calendar() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        let t = AsnTime {
            year: 2027,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(t.openssl_text(), "Jan  1 00:00:00 2027 GMT");
        assert_eq!(t.unix_secs(), 1_798_761_600);
    }

    #[test]
    fn dotted_oids() {
        assert_eq!(dotted(&[0x55, 0x04, 0x05]), "2.5.4.5");
        assert_eq!(
            dotted(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]),
            "1.2.840.113549.1.9.1"
        );
    }
}
