//! Content bounds of a downloaded Smart RU rule set (psmart-b3): canaries alone pass a crafted
//! set (an inverted rule, or every address but the probes), so the pinned sing-box decompiles
//! each file and bounds it against the release's own copy, besides a size window.
//! The sets that send traffic DIRECT may add little: the address set at most a tenth of the
//! copy's space and none of it inside a well-known foreign provider (fixlists-b1: a crafted
//! set must not pull chosen services out of the tunnel); the gov list sites under the Russian
//! zones, the copy's own names, and a few other names that are logged (lab F-10: upstream
//! lists regional sites such as `edu22.info`). The sets that send traffic through the VPN keep
//! most of the copy (fixlists-b5): a shrunk blocked list sends blocked Russian sites to the
//! ISP's resolver and out directly.
//! Only the files' content is judged: an engine that cannot run is not a bad file (a6).
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};
use vpnte_base::types::Engine;

use crate::routing::smart_ru::{GEOIP_RU, GOV_RU, RU_BLOCKED_IPS, RU_BLOCKED_SITES};
use crate::singbox_process::child::run_once;
use foreign::{FOREIGN, FOREIGN_SITES};
use space::{Ranges, Space};

mod foreign;
mod space;

/// Budget of one `sing-box rule-set decompile` run (the blocked list takes about 0.3 s).
const DECOMPILE_TIMEOUT: Duration = Duration::from_secs(20);
/// A file is a quarter to four times the size of the release's copy.
const SIZE_FACTOR: u64 = 4;
/// New direct address space (outside the copy) per family, as a share of the copy's space.
/// Upstream drifts slowly: 0.42 % of IPv4 in the 5.5 months after the copy of 31.05.2026.
const NEW_SPACE_SHARE: f64 = 0.1;
/// Share of the copy's names or addresses a blocked set keeps (registry churn stays far
/// below; a crafted shrink does not).
const KEPT_SHARE: f64 = 0.5;
/// New gov names outside the Russian zones that pass (logged); upstream added three in 2026.
const MAX_NEW_FOREIGN_NAMES: usize = 8;
/// The zones a gov name may lie in without counting as foreign.
const RU_ZONES: [&str; 3] = ["ru", "su", "xn--p1ai"];

/// Why a file is out of bounds (logged; the user sees «the file failed its check»).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
enum OutOfBounds {
    #[error("size {0} B is far from the release's copy")]
    Size(u64),
    #[error("not a plain rule set of its kind")]
    Shape,
    #[error("adds more address space than allowed")]
    Coverage,
    #[error("adds addresses of the foreign network {0}")]
    Foreign(&'static str),
    #[error("names a well-known foreign site or a whole zone: {0}")]
    Zone(String),
    #[error("{0} new names outside the Russian zones")]
    ForeignNames(usize),
    #[error("keeps too little of the release's copy")]
    Shrunk,
}

/// Checks `file` (a set of `tag`, already parsed by the engine) against the copy of the same
/// name in `reference`; `None` = the engine could not run or a file could not be read
/// (nothing can be judged).
pub(super) async fn check(engine: &Path, file: &Path, tag: &str, reference: &Path) -> Option<bool> {
    let name = file.file_name()?;
    let copy = reference.join(name);
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len());
    let (got, release) = (size(file).ok()?, size(&copy).ok()?);
    let verdict = if size_ok(got, release) {
        let read = async |p: &Path| {
            decompile(engine, p)
                .await
                .map_err(|err| tracing::warn!(%err, file = %p.display(), "rule set not decompiled"))
                .ok()
        };
        // Two engine runs side by side (lab live-9 L9-2: the checks sat in the first connect).
        let (json, release) = tokio::join!(read(file), read(&copy));
        let (json, release) = (json?, release?);
        bounds(tag, &json, &release)
    } else {
        Err(OutOfBounds::Size(got))
    };
    if let Err(why) = &verdict {
        tracing::warn!(%why, file = %file.display(), "rule set out of bounds");
    }
    Some(verdict.is_ok())
}

fn bounds(tag: &str, json: &str, release: &str) -> Result<(), OutOfBounds> {
    match tag {
        GEOIP_RU => address_bounds(json, release),
        GOV_RU => name_bounds(json, release),
        RU_BLOCKED_SITES => kept_names(json, release),
        RU_BLOCKED_IPS => kept_space(json, release),
        _ => Err(OutOfBounds::Shape),
    }
}

fn size_ok(got: u64, release: u64) -> bool {
    got.saturating_mul(SIZE_FACTOR) >= release && got <= release.saturating_mul(SIZE_FACTOR)
}

/// The direct address set: plain `ip_cidr` rules; what it adds to the copy stays small and
/// outside every foreign provider.
fn address_bounds(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let got = Space::of(&cidrs(strict(json, "ip_cidr")?)?);
    let copy = Space::of(&cidrs(strict(release, "ip_cidr")?)?);
    for (got, copy, v6) in [(&got.v4, &copy.v4, false), (&got.v6, &copy.v6, true)] {
        let new = got.minus(copy);
        if new.size() > copy.size() * NEW_SPACE_SHARE {
            return Err(OutOfBounds::Coverage);
        }
        let mut foreign = FOREIGN.into_iter().filter(|net| net.contains(':') == v6);
        if let Some(net) = foreign.find(|net| new.overlaps(&ranges_of(net))) {
            return Err(OutOfBounds::Foreign(net));
        }
    }
    Ok(())
}

/// One entry of [`FOREIGN`] as ranges of its family.
fn ranges_of(net: &str) -> Ranges {
    let space = cidr(net).map(|n| Space::of(&[n])).unwrap_or_default();
    if net.contains(':') {
        space.v6
    } else {
        space.v4
    }
}

/// The gov list: plain `domain` / `domain_suffix` rules naming sites under the Russian zones,
/// the copy's own names, or a few other sites (logged), never a zone or a foreign service.
fn name_bounds(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let known: HashSet<String> = names(strict(release, "domain_suffix")?)?
        .into_iter()
        .collect();
    let mut new = Vec::new();
    for name in names(strict(json, "domain_suffix")?)? {
        let in_zone = RU_ZONES.iter().any(|z| name.ends_with(&format!(".{z}")));
        if known.contains(&name) || in_zone {
            continue;
        }
        let related = |site: &str| {
            site == name
                || site.ends_with(&format!(".{name}"))
                || name.ends_with(&format!(".{site}"))
        };
        if !name.contains('.') || FOREIGN_SITES.into_iter().any(related) {
            return Err(OutOfBounds::Zone(name));
        }
        new.push(name);
    }
    if new.len() > MAX_NEW_FOREIGN_NAMES {
        return Err(OutOfBounds::ForeignNames(new.len()));
    }
    if !new.is_empty() {
        tracing::info!(names = ?new, "the gov list names sites outside the Russian zones");
    }
    Ok(())
}

/// The blocked sites: at least [`KEPT_SHARE`] of the copy's names are still there, in rules
/// that match by the name alone.
fn kept_names(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let got: HashSet<String> = names(unconditioned(lenient(json)?))?.into_iter().collect();
    let copy = names(lenient(release)?)?;
    let kept = copy.iter().filter(|n| got.contains(*n)).count();
    if (kept as f64) < copy.len() as f64 * KEPT_SHARE {
        return Err(OutOfBounds::Shrunk);
    }
    Ok(())
}

/// The blocked addresses: at least [`KEPT_SHARE`] of the copy's space is still covered, by
/// rules that match by the address alone.
fn kept_space(json: &str, release: &str) -> Result<(), OutOfBounds> {
    let got = Space::of(&cidrs(unconditioned(lenient(json)?))?);
    let copy = Space::of(&cidrs(lenient(release)?)?);
    for (got, copy) in [(&got.v4, &copy.v4), (&got.v6, &copy.v6)] {
        let kept = copy.size() - copy.minus(got).size();
        if kept < copy.size() * KEPT_SHARE {
            return Err(OutOfBounds::Shrunk);
        }
    }
    Ok(())
}

/// The rules of a decompiled set that sends traffic direct: any logical, inverted or otherwise
/// conditioned rule is out of shape (each rule may hold `key`, and `domain` beside a suffix).
fn strict(json: &str, key: &str) -> Result<Vec<Value>, OutOfBounds> {
    let rules = lenient(json)?;
    let allowed = |k: &str| k == key || (key == "domain_suffix" && k == "domain");
    let plain = |r: &Value| {
        r.as_object()
            .is_some_and(|o: &Map<String, Value>| o.keys().all(|k| allowed(k)))
    };
    if rules.iter().all(plain) {
        Ok(rules)
    } else {
        Err(OutOfBounds::Shape)
    }
}

/// The rules that match by their names or networks alone. Review live2-a4: a rule with any
/// other condition (a port, a network, `invert`, a logical type) may never match in use, so
/// what it lists does not count as kept.
fn unconditioned(rules: Vec<Value>) -> Vec<Value> {
    const MATCHERS: [&str; 5] = [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
    ];
    let plain = |r: &Value| {
        r.as_object()
            .is_some_and(|o| o.keys().all(|k| MATCHERS.contains(&k.as_str())))
    };
    rules.into_iter().filter(plain).collect()
}

/// Every rule of a decompiled set, whatever it holds.
fn lenient(json: &str) -> Result<Vec<Value>, OutOfBounds> {
    let mut json: Value = serde_json::from_str(json).map_err(|_| OutOfBounds::Shape)?;
    match json.get_mut("rules").map(Value::take) {
        Some(Value::Array(rules)) => Ok(rules),
        _ => Err(OutOfBounds::Shape),
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

/// Every network of the rules' `ip_cidr` lists.
fn cidrs(rules: Vec<Value>) -> Result<Vec<(IpAddr, u8)>, OutOfBounds> {
    strings(&rules, "ip_cidr")
        .map(|v| v.as_str().and_then(cidr).ok_or(OutOfBounds::Shape))
        .collect()
}

/// `a.b.c.d/len`, `x::/len` or a single address.
fn cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = text.split_once('/').unwrap_or((text, ""));
    let ip: IpAddr = ip.parse().ok()?;
    let full = if ip.is_ipv4() { 32 } else { 128 };
    let len = if len.is_empty() {
        full
    } else {
        len.parse().ok()?
    };
    (len <= full).then_some((ip, len))
}

/// Every name of the rules' `domain` / `domain_suffix` lists, lower case without the dot.
fn names(rules: Vec<Value>) -> Result<Vec<String>, OutOfBounds> {
    strings(&rules, "domain")
        .chain(strings(&rules, "domain_suffix"))
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
