//! Answers of the public "what is my IP" services (Cloudflare trace, ipify, icanhazip, myip): one
//! parser for the public-IP reads (`public_ip`) and the SOCKS egress probe (`egress`).
use std::net::IpAddr;

/// Extracts the address from a provider answer: a JSON object's `ip` (or `query`), a
/// Cloudflare trace `ip=` line, or a bare address. Range and family checks are the caller's.
pub fn parse_provider_body(body: &str) -> Option<IpAddr> {
    let text = body.trim();
    let candidate = if text.starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        ["ip", "query"].iter().find_map(|key| {
            json.get(key)?
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
        })?
    } else if let Some(ip) = text.lines().find_map(|line| line.strip_prefix("ip=")) {
        ip.to_owned()
    } else {
        text.to_owned()
    };
    candidate.trim().parse().ok()
}
