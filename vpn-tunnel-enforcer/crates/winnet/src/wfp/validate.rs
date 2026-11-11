//! Kill-switch exception validation: firewall-recovery §3.4 and owner-decisions §2.7, ported
//! exactly, plus the decided fixes (IPs parsed, so `2001:DB8::1` and `2001:0db8::1` dedupe and
//! `::ffff:0.0.0.0` counts as unspecified; the 256 limit is enforced when the list changes).
use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use vpnte_base::Msg;

use super::MAX_EXCEPTIONS;
use super::model::{ExceptionKind, ExceptionTarget, KillSwitchException};

const LABEL_MAX: usize = 200;
const VALUE_MAX: usize = 2048;

/// Why an exception was rejected (before anything is applied or stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("exception.label must contain 1-200 characters")]
    LabelLength,
    #[error("exception.value must contain 1-2048 characters")]
    ValueLength,
    #[error(
        "exception.value must be a valid IP/CIDR; wildcard /0 and unspecified addresses are forbidden"
    )]
    InvalidIp,
    #[error("exception.value must be an executable path")]
    NotExecutable,
    #[error("exception.value must be a local absolute Windows path")]
    NotLocalPath,
    #[error("exception.value must be a local readable .exe file")]
    Unreadable,
    #[error("an equivalent kill-switch exception already exists")]
    Duplicate,
    #[error("more than {MAX_EXCEPTIONS} kill-switch exceptions")]
    TooMany,
    #[error("kill-switch exception not found")]
    NotFound,
}

impl ValidationError {
    /// The user-facing message.
    pub fn msg(self) -> Msg {
        let key = match self {
            ValidationError::LabelLength => "winnet.wfp.exception.labelLength",
            ValidationError::ValueLength => "winnet.wfp.exception.valueLength",
            ValidationError::InvalidIp => "winnet.wfp.exception.invalidIp",
            ValidationError::NotExecutable => "winnet.wfp.exception.notExecutable",
            ValidationError::NotLocalPath => "winnet.wfp.exception.notLocalPath",
            ValidationError::Unreadable => "winnet.wfp.exception.unreadable",
            ValidationError::Duplicate => "winnet.wfp.exception.duplicate",
            ValidationError::NotFound => "winnet.wfp.exception.notFound",
            ValidationError::TooMany => {
                return Msg::new("winnet.wfp.exception.tooMany").arg("max", MAX_EXCEPTIONS);
            }
        };
        Msg::new(key)
    }
}

/// JavaScript `String.prototype.trim` (also strips U+FEFF, which `str::trim` keeps).
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// Length in UTF-16 units, as the old limits were measured.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The trimmed label, 1..=200 characters.
pub(crate) fn check_label(raw: &str) -> Result<&str, ValidationError> {
    let label = js_trim(raw);
    match label.is_empty() || js_len(label) > LABEL_MAX {
        true => Err(ValidationError::LabelLength),
        false => Ok(label),
    }
}

/// Validates a user exception; returns the target and the trimmed label.
pub fn validate_exception(
    kind: ExceptionKind,
    value: &str,
    label: &str,
) -> Result<(ExceptionTarget, String), ValidationError> {
    let label = check_label(label)?;
    let value = js_trim(value);
    if value.is_empty() || js_len(value) > VALUE_MAX {
        return Err(ValidationError::ValueLength);
    }
    let target = match kind {
        ExceptionKind::Ip => ExceptionTarget::Ip(parse_ip_or_cidr(value)?),
        ExceptionKind::App => ExceptionTarget::App(canonical_exe(value)?),
    };
    Ok((target, label.to_owned()))
}

/// Parses `addr` or `addr/prefix`: one optional `/`, a decimal prefix (leading zeros allowed,
/// `+24`, `0x10`, `1e1`, ` 24` are not), no unspecified address, no `/0`, no zone id. Host bits
/// are kept; they are masked when the filter is installed.
pub fn parse_ip_or_cidr(s: &str) -> Result<IpNet, ValidationError> {
    let v = js_trim(s);
    let (addr, prefix) = match v.split_once('/') {
        None => (v, None),
        Some((_, p)) if p.contains('/') => return Err(ValidationError::InvalidIp),
        Some((a, p)) => (a, Some(p)),
    };
    let ip: IpAddr = addr.parse().map_err(|_| ValidationError::InvalidIp)?;
    let unspecified = match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|m| m.is_unspecified())
        }
    };
    if unspecified {
        return Err(ValidationError::InvalidIp);
    }
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match prefix {
        None => max,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p
            .parse::<u8>()
            .ok()
            .filter(|n| (1..=max).contains(n))
            .ok_or(ValidationError::InvalidIp)?,
        Some(_) => return Err(ValidationError::InvalidIp),
    };
    IpNet::new(ip, len).map_err(|_| ValidationError::InvalidIp)
}

/// Canonical form of an app exception: a readable local `.exe` on a drive-letter path, with
/// 8.3 names, symlinks and junctions resolved (the same spelling WFP app IDs are built from).
pub fn canonical_exe(raw: &str) -> Result<PathBuf, ValidationError> {
    let is_exe = |s: &str| {
        s.len() >= 4
            && s.is_char_boundary(s.len() - 4)
            && s[s.len() - 4..].eq_ignore_ascii_case(".exe")
    };
    if raw.is_empty()
        || js_len(raw) > VALUE_MAX
        || raw.chars().any(|c| (c as u32) < 0x20)
        || !is_exe(raw)
    {
        return Err(ValidationError::NotExecutable);
    }
    if !drive_rooted(raw) || raw[2..].contains(':') || raw.split(['\\', '/']).any(|seg| seg == "..")
    {
        return Err(ValidationError::NotLocalPath);
    }
    std::fs::File::open(raw).map_err(|_| ValidationError::Unreadable)?;
    let real = std::fs::canonicalize(raw).map_err(|_| ValidationError::Unreadable)?;
    let real = real.to_str().ok_or(ValidationError::Unreadable)?;
    // canonicalize returns `\\?\C:\...`; a share comes back as `\\?\UNC\...` and is refused.
    let plain = real.strip_prefix(r"\\?\").unwrap_or(real);
    if !drive_rooted(plain)
        || !is_exe(plain)
        || !std::fs::metadata(plain).is_ok_and(|m| m.is_file())
    {
        return Err(ValidationError::Unreadable);
    }
    Ok(PathBuf::from(plain))
}

/// `^[a-z]:\\` (case-insensitive), the old local-path gate.
fn drive_rooted(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// Rejects a list with equivalent entries or more than [`MAX_EXCEPTIONS`] entries.
pub fn check_list(list: &[KillSwitchException]) -> Result<(), ValidationError> {
    if list.len() > MAX_EXCEPTIONS {
        return Err(ValidationError::TooMany);
    }
    let mut seen = std::collections::HashSet::new();
    match list.iter().all(|e| seen.insert(e.target.identity())) {
        true => Ok(()),
        false => Err(ValidationError::Duplicate),
    }
}

/// A warning (never a refusal) for very broad exceptions: IPv4 prefix < 8, IPv6 prefix < 16.
pub fn broad_warning(target: &ExceptionTarget) -> Option<Msg> {
    let broad = match target {
        ExceptionTarget::Ip(IpNet::V4(n)) => n.prefix_len() < 8,
        ExceptionTarget::Ip(IpNet::V6(n)) => n.prefix_len() < 16,
        ExceptionTarget::App(_) => false,
    };
    broad.then(|| Msg::new("winnet.wfp.exception.broad"))
}

#[cfg(test)]
mod tests;
