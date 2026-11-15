//! The pure history state: Clash snapshot merge and the engine's DNS answer observer.
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::types::UnixMs;

use super::{DomainRecord, DomainsDoc, MAX_DOMAINS, normalize_host, should_record};
use crate::connections::ClashSnapshot;

/// Bound of the CNAME alias map and of the IP → name map.
const NAME_MAP_CAP: usize = 4096;
/// Bound of the (DNS exchange, host) dedupe set.
const RECENT_CAP: usize = 1024;

/// Bounded map with O(1) operations that forgets the least recently used entries in halves:
/// two generations, the young one becomes the old one when it reaches half the capacity.
pub(super) struct Recent<K, V> {
    half: usize,
    pub(super) young: HashMap<K, V>,
    pub(super) old: HashMap<K, V>,
}

impl<K: Eq + Hash, V: Clone> Recent<K, V> {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            half: (cap / 2).max(1),
            young: HashMap::new(),
            old: HashMap::new(),
        }
    }

    pub(super) fn get(&mut self, key: &K) -> Option<V> {
        if let Some(v) = self.young.get(key) {
            return Some(v.clone());
        }
        let (key, v) = self.old.remove_entry(key)?;
        self.insert(key, v.clone());
        Some(v)
    }

    /// Inserts or refreshes; true when the key was not present.
    pub(super) fn insert(&mut self, key: K, value: V) -> bool {
        let was_old = self.old.remove(&key).is_some();
        let fresh = self.young.insert(key, value).is_none() && !was_old;
        if self.young.len() >= self.half {
            self.old = std::mem::take(&mut self.young);
        }
        fresh
    }

    fn clear(&mut self) {
        self.young.clear();
        self.old.clear();
    }
}

static ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").expect("valid regex"));

/// A per-record INFO answer line of sing-box 1.14 (`dns/client_log.go`), e.g.
/// `+0300 2026-09-25 17:17:06 INFO [1657141230 946ms] dns: exchanged A x.org. 13 IN A 203.0.113.4`.
/// `rejected` (blocked by a rule) and `refreshed` (background cache refresh) are not visits.
static ANSWER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:\[(\d+)[^\]]*\]\s+)?\bdns: (?:exchanged|cached|optimistic) ",
        r"([A-Z0-9]+) (\S+) \d+ IN [A-Z0-9]+ (.+)$"
    ))
    .expect("valid regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType {
    Address,
    Cname,
    /// HTTPS / SVCB: a lookup of the owner, without an address to map.
    Service,
}

/// One DNS answer record the history cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAnswer {
    /// sing-box log context id: the same for every record of one exchange.
    context: String,
    kind: RecordType,
    owner: String,
    data: String,
}

/// Parses an engine log line. Only A, AAAA, CNAME, HTTPS and SVCB records count: the answer log
/// also prints the authority and additional sections (an SOA line would credit the zone apex).
fn parse_answer(line: &str) -> Option<DnsAnswer> {
    // Colours are off for pipe output (`disable_color`), stripped anyway in case they are not.
    let line = ANSI.replace_all(line, "");
    if !line.contains("dns: ") {
        return None;
    }
    let caps = ANSWER.captures(&line)?;
    let kind = match &caps[2] {
        "A" | "AAAA" => RecordType::Address,
        "CNAME" => RecordType::Cname,
        "HTTPS" | "SVCB" => RecordType::Service,
        _ => return None,
    };
    Some(DnsAnswer {
        context: caps.get(1).map_or("", |m| m.as_str()).to_owned(),
        kind,
        owner: normalize_host(&caps[3])?,
        data: caps[4].trim().to_owned(),
    })
}

/// A live connection already counted: the host it was credited to and the bytes credited so far.
/// The host is fixed at first sight: re-resolving an address-only flow through the bounded
/// IP → name map would move its bytes to another name sharing a CDN address, or count it again
/// (full bytes included) after the map forgot and relearned the address.
pub(super) struct Seen {
    host: String,
    up: u64,
    down: u64,
}

/// In-memory history state: the records plus what the merge needs between snapshots.
pub struct History {
    records: HashMap<String, DomainRecord>,
    /// Clash connection id → what it was credited with.
    pub(super) seen: HashMap<String, Seen>,
    /// CNAME target → the name the user asked for.
    aliases: Recent<String, String>,
    /// Answered address → the name the user asked for.
    ip_names: Recent<IpAddr, String>,
    /// (exchange context, host) already counted as a lookup.
    recent: Recent<(String, String), ()>,
    /// Normalised hosts of the configured servers.
    infra: HashSet<String>,
    pub(super) dirty: bool,
}

impl History {
    /// State loaded from the stored document.
    pub fn new(doc: DomainsDoc) -> Self {
        Self {
            records: doc.domains.into_iter().collect(),
            seen: HashMap::new(),
            aliases: Recent::new(NAME_MAP_CAP),
            ip_names: Recent::new(NAME_MAP_CAP),
            recent: Recent::new(RECENT_CAP),
            infra: HashSet::new(),
            dirty: false,
        }
    }

    /// Replaces the configured server hosts; a host that becomes a server later is hidden from
    /// [`History::list`], not deleted.
    pub fn set_infra<S: AsRef<str>>(&mut self, server_hosts: impl IntoIterator<Item = S>) {
        self.infra = server_hosts
            .into_iter()
            .filter_map(|h| normalize_host(h.as_ref()))
            .collect();
    }

    /// The host a connection is credited to: its sniffed `host`, else the name its destination
    /// address was answered for.
    fn connection_host(&mut self, host: &str, destination_ip: &str) -> Option<String> {
        if !host.is_empty() {
            return should_record(host, &self.infra);
        }
        let ip = destination_ip.parse::<IpAddr>().ok()?.to_canonical();
        let name = self.ip_names.get(&ip)?;
        should_record(&name, &self.infra)
    }

    /// Folds one `/connections` snapshot in. A connection id seen for the first time is one
    /// visit; later sightings add only the byte delta (to the same host); ids that left the
    /// snapshot are forgotten. Hosts of new connections are appended to `new_hosts`. True when
    /// changed.
    pub fn merge_snapshot(
        &mut self,
        snapshot: &ClashSnapshot,
        now: UnixMs,
        new_hosts: &mut Vec<String>,
    ) -> bool {
        let mut changed = false;
        let mut live: HashSet<&str> = HashSet::new();
        for c in &snapshot.connections {
            if c.id.is_empty() {
                continue;
            }
            let known = self.seen.get(&c.id).map(|s| s.host.clone());
            let Some(host) = known
                .or_else(|| self.connection_host(&c.metadata.host, &c.metadata.destination_ip))
            else {
                continue;
            };
            live.insert(&c.id);
            let rec = self
                .records
                .entry(host.clone())
                .or_insert_with(|| DomainRecord::new(&host, now));
            match self.seen.get_mut(&c.id) {
                Some(prev) => {
                    let up = c.upload.saturating_sub(prev.up);
                    let down = c.download.saturating_sub(prev.down);
                    if up > 0 || down > 0 {
                        rec.bytes_up = rec.bytes_up.saturating_add(up);
                        rec.bytes_down = rec.bytes_down.saturating_add(down);
                        rec.last_seen = now;
                        (prev.up, prev.down) = (c.upload, c.download);
                        changed = true;
                    }
                }
                None => {
                    rec.connections = rec.connections.saturating_add(1);
                    rec.first_seen = rec.first_seen.min(now);
                    rec.last_seen = now;
                    rec.bytes_up = rec.bytes_up.saturating_add(c.upload);
                    rec.bytes_down = rec.bytes_down.saturating_add(c.download);
                    let seen = Seen {
                        host: host.clone(),
                        up: c.upload,
                        down: c.download,
                    };
                    self.seen.insert(c.id.clone(), seen);
                    new_hosts.push(host.clone());
                    changed = true;
                }
            }
            if let Some(outbound) = c.chains.last()
                && rec.outbound.as_ref() != Some(outbound)
            {
                rec.outbound = Some(outbound.clone());
                changed = true;
            }
        }
        self.seen.retain(|id, _| live.contains(id.as_str()));
        self.dirty |= changed;
        changed
    }

    /// Feeds one engine log line (received now). Answers credit the name the user asked for:
    /// a CNAME target maps back to it, and an address maps to it for flows without a `host`.
    /// One exchange counts as one lookup. True when a record changed.
    pub fn observe_log_line(&mut self, line: &str, now: UnixMs) -> bool {
        let Some(answer) = parse_answer(line) else {
            return false;
        };
        let origin = self.aliases.get(&answer.owner).unwrap_or(answer.owner);
        match answer.kind {
            RecordType::Cname => {
                if let Some(target) = normalize_host(&answer.data) {
                    self.aliases.insert(target, origin);
                }
                return false;
            }
            RecordType::Address => {
                if let Ok(ip) = answer.data.parse::<IpAddr>() {
                    self.ip_names.insert(ip.to_canonical(), origin.clone());
                }
            }
            RecordType::Service => {}
        }
        let Some(host) = should_record(&origin, &self.infra) else {
            return false;
        };
        if !self.recent.insert((answer.context, host.clone()), ()) {
            return false;
        }
        let rec = self
            .records
            .entry(host.clone())
            .or_insert_with(|| DomainRecord::new(&host, now));
        rec.lookups = rec.lookups.saturating_add(1);
        rec.first_seen = rec.first_seen.min(now);
        rec.last_seen = now;
        self.dirty = true;
        true
    }

    /// Records newest first, without hosts that are infrastructure under the current servers.
    pub fn list(&self) -> Vec<DomainRecord> {
        let mut out: Vec<DomainRecord> = self
            .records
            .values()
            .filter(|r| should_record(&r.domain, &self.infra).is_some())
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.domain.cmp(&b.domain))
        });
        out
    }

    /// Forgets everything (records, live ids, name maps). Engine logs are not touched (B-22).
    pub fn clear(&mut self) {
        self.records.clear();
        self.seen.clear();
        self.aliases.clear();
        self.ip_names.clear();
        self.recent.clear();
        self.dirty = true;
    }

    /// The document to persist when something changed since the last call (pruned first).
    pub fn take_doc(&mut self) -> Option<DomainsDoc> {
        if !std::mem::take(&mut self.dirty) {
            return None;
        }
        self.prune(MAX_DOMAINS);
        let domains = self
            .records
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Some(DomainsDoc { domains })
    }

    /// Keeps the `max` most recently seen records.
    pub(super) fn prune(&mut self, max: usize) {
        if self.records.len() <= max {
            return;
        }
        let mut by_age: Vec<(UnixMs, String)> = self
            .records
            .values()
            .map(|r| (r.last_seen, r.domain.clone()))
            .collect();
        by_age.sort();
        let excess = self.records.len() - max;
        for (_, domain) in by_age.into_iter().take(excess) {
            self.records.remove(&domain);
        }
    }
}
