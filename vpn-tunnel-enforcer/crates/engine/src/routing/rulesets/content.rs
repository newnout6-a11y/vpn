//! Content bounds of a downloaded Smart RU rule set (psmart-b3): canaries alone pass a crafted
//! set (an inverted rule, or every address but the probes), so the pinned sing-box decompiles
//! each file and the sets that send traffic DIRECT are bounded against the release's own copy:
//! plain rules only, no prefix shorter than /8 (IPv4) or /16 (IPv6), at most twice the
//! release's address space, no well-known foreign address, gov names only under the Russian
//! zones (or named by the release's copy), and every file within a size window of its copy.
//! The sets that send traffic through the VPN only get the size window: a wrong one costs
//! availability, never privacy.
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};
use vpnte_base::types::Engine;

use crate::routing::smart_ru::{GEOIP_RU, GOV_RU};
use crate::singbox_process::child::run_once;

/// Budget of one `sing-box rule-set decompile` run (the blocked list takes about 0.3 s).
const DECOMPILE_TIMEOUT: Duration = Duration::from_secs(20);
/// A file is a quarter to four times the size of the release's copy.
const SIZE_FACTOR: u64 = 4;
/// The direct address set covers at most twice the release's address space (November 2026:
/// 1.05 % of IPv4, 2.5e-6 of IPv6, shortest prefixes /13 and /29).
const COVERAGE_FACTOR: f64 = 2.0;
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 16;
/// Addresses no direct set may hold: public resolvers, Google, Meta, Telegram, Cloudflare,
/// Amazon CloudFront.
const FOREIGN: [&str; 10] = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "142.250.185.78",
    "157.240.0.35",
    "149.154.167.50",
    "104.16.0.1",
    "13.32.0.1",
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
];
/// The zones a gov name may lie in; the release's own names outside them (`emias.info`) stay.
const RU_ZONES: [&str; 3] = ["ru", "su", "xn--p1ai"];

/// Why a file is out of bounds (logged; the user sees «the file failed its check»).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
enum OutOfBounds {
    #[error("size {0} B is far from the release's copy")]
    Size(u64),
    #[error("not a plain rule set of its kind")]
    Shape,
    #[error("prefix too short: {0}")]
    Prefix(String),
    #[error("covers more address space than allowed")]
    Coverage,
    #[error("holds the foreign address {0}")]
    Foreign(&'static str),
    #[error("names a site outside the Russian zones: {0}")]
    Zone(String),
}

/// Checks `file` (a set of `tag`) against the copy of the same name in `reference`; `None` =
/// the engine could not run or the reference is unreadable (nothing can be judged).
pub(super) async fn check(engine: &Path, file: &Path, tag: &str, reference: &Path) -> Option<bool> {
    let name = file.file_name()?;
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len());
    let (got, release) = (size(file).ok()?, size(&reference.join(name)).ok()?);
    let mut verdict = size_ok(got, release)
        .then_some(())
        .ok_or(OutOfBounds::Size(got));
    if verdict.is_ok() && [GEOIP_RU, GOV_RU].contains(&tag) {
        let json = decompile(engine, file).await.ok();
        let release = decompile(engine, &reference.join(name)).await.ok()?;
        verdict = match (json, tag == GEOIP_RU) {
            (None, _) => Err(OutOfBounds::Shape),
            (Some(json), true) => address_bounds(&json, &release),
            (Some(json), false) => name_bounds(&json, &release),
        };
    }
    if let Err(why) = &verdict {
        tracing::warn!(%why, file = %file.display(), "rule set out of bounds");
    }
    Some(verdict.is_ok())
}

fn size_ok(got: u64, release: u64) -> bool {
    got.saturating_mul(SIZE_FACTOR) >= release && got <= release.saturating_mul(SIZE_FACTOR)
}

/// The direct address set: plain `ip_cidr` rules within the prefix, coverage and foreign bounds.
fn address_bounds(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let nets = cidrs(json)?;
    let limit = coverage(&cidrs(release)?);
    let cover = coverage(&nets);
    for (ip, len) in &nets {
        let min = if ip.is_ipv4() {
            MIN_V4_PREFIX
        } else {
            MIN_V6_PREFIX
        };
        if *len < min {
            return Err(OutOfBounds::Prefix(format!("{ip}/{len}")));
        }
    }
    if cover.0 > limit.0 * COVERAGE_FACTOR || cover.1 > limit.1 * COVERAGE_FACTOR {
        return Err(OutOfBounds::Coverage);
    }
    for probe in FOREIGN {
        let addr: IpAddr = probe.parse().map_err(|_| OutOfBounds::Shape)?;
        if nets.iter().any(|(net, len)| contains(*net, *len, addr)) {
            return Err(OutOfBounds::Foreign(probe));
        }
    }
    Ok(())
}

/// The gov list: plain `domain` / `domain_suffix` rules, every name a site under a Russian
/// zone (never the zone itself) or named by the release's copy.
fn name_bounds(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let known = names(release)?;
    for name in names(json)? {
        let in_zone = RU_ZONES.iter().any(|z| name.ends_with(&format!(".{z}")));
        if !in_zone && !known.contains(&name) {
            return Err(OutOfBounds::Zone(name));
        }
    }
    Ok(())
}

/// The rules of a decompiled set; any logical, inverted or otherwise conditioned rule is
/// out of shape (each rule may hold the `keys` only).
fn rules<'a>(json: &'a Value, keys: &[&str]) -> Result<&'a [Value], OutOfBounds> {
    let rules = json
        .get("rules")
        .and_then(Value::as_array)
        .ok_or(OutOfBounds::Shape)?;
    let plain = |r: &Value| {
        r.as_object()
            .is_some_and(|o: &Map<String, Value>| o.keys().all(|k| keys.contains(&k.as_str())))
    };
    if rules.iter().all(plain) {
        Ok(rules)
    } else {
        Err(OutOfBounds::Shape)
    }
}

/// The strings of `key` in every rule.
fn strings<'a>(rules: &'a [Value], key: &'a str) -> impl Iterator<Item = &'a Value> {
    rules
        .iter()
        .filter_map(move |r| r.get(key))
        .flat_map(|v| match v {
            Value::Array(items) => items.iter().collect::<Vec<_>>(),
            one => vec![one],
        })
}

fn parse(json: &str) -> Result<Value, OutOfBounds> {
    serde_json::from_str(json).map_err(|_| OutOfBounds::Shape)
}

/// Every network of a plain address set.
fn cidrs(json: &str) -> Result<Vec<(IpAddr, u8)>, OutOfBounds> {
    let json = parse(json)?;
    let rules = rules(&json, &["ip_cidr"])?;
    strings(rules, "ip_cidr")
        .map(|v| {
            let text = v.as_str().ok_or(OutOfBounds::Shape)?;
            let (ip, len) = text.split_once('/').unwrap_or((text, ""));
            let ip: IpAddr = ip.parse().map_err(|_| OutOfBounds::Shape)?;
            let full = if ip.is_ipv4() { 32 } else { 128 };
            let len = if len.is_empty() {
                Ok(full)
            } else {
                len.parse()
            };
            match len {
                Ok(len) if len <= full => Ok((ip, len)),
                _ => Err(OutOfBounds::Shape),
            }
        })
        .collect()
}

/// Shares of the IPv4 and IPv6 space (overlaps count twice: the bound only gets stricter).
fn coverage(nets: &[(IpAddr, u8)]) -> (f64, f64) {
    nets.iter().fold((0.0, 0.0), |(v4, v6), (ip, len)| {
        let share = 2f64.powi(-i32::from(*len));
        if ip.is_ipv4() {
            (v4 + share, v6)
        } else {
            (v4, v6 + share)
        }
    })
}

fn contains(net: IpAddr, len: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// Every name of a plain name set, lower case without the leading dot.
fn names(json: &str) -> Result<Vec<String>, OutOfBounds> {
    let json = parse(json)?;
    let rules = rules(&json, &["domain", "domain_suffix"])?;
    strings(rules, "domain")
        .chain(strings(rules, "domain_suffix"))
        .map(|v| {
            let name = v.as_str().ok_or(OutOfBounds::Shape)?;
            Ok(name.trim_start_matches('.').to_ascii_lowercase())
        })
        .collect()
}

/// `sing-box rule-set decompile <file> -o <temp>`: the command writes a file only (`stdout` is
/// taken as a file name), so the JSON goes through a temp file removed right after.
pub(crate) async fn decompile(exe: &Path, file: &Path) -> io::Result<String> {
    // The engine runs in its own folder: relative paths would point there.
    let file = std::path::absolute(file)?;
    static RUN: AtomicU64 = AtomicU64::new(0);
    let out = std::env::temp_dir().join(format!(
        "vpnte-ruleset-{}-{}.json",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    let args = [
        "rule-set".as_ref(),
        "decompile".as_ref(),
        file.as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
    ];
    let run = run_once(Engine::SingBox, exe, &args, None, DECOMPILE_TIMEOUT).await;
    let text = match run {
        Ok(o) if o.status.success() => tokio::fs::read_to_string(&out).await,
        Ok(o) => Err(io::Error::other(format!(
            "decompile exited with {}",
            o.status
        ))),
        Err(err) => Err(err),
    };
    let _ = tokio::fs::remove_file(&out).await;
    text
}

#[cfg(test)]
mod tests;
