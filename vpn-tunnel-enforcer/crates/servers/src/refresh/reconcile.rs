//! Matching a fresh subscription list against the stored feed rows of its group (servers §3.3).
//! Pass-major cascade; each stored row and each fresh entry is matched at most once; every pass
//! but the exact-line one pairs a key only when it is unambiguous, because several locations
//! behind one bridge often share host, port and even the UUID, and "first unmatched row" would
//! silently re-point the user's selection to another location (S-01, S-02, S-04).
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use vpnte_base::AppResult;
use vpnte_base::types::UnixMs;
use vpnte_profiles::model::{Kind, Profile, Source};

use crate::model::{ArchiveReason, Archived, Origin, ProfileId, ServerGroup, ServerRow};

/// How long a key may be missing from complete answers before it is archived: the shortest
/// provider interval, so one bad answer never archives while a real removal is archived on the
/// next scheduled refresh.
pub const MISSING_GRACE_MS: UnixMs = 15 * 60 * 1000;

/// What a refresh changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshReport {
    pub added: Vec<ProfileId>,
    /// Stored rows matched by a fresh entry (key and remark refreshed).
    pub updated: usize,
    /// Rows archived because the provider had dropped them, now listed again.
    pub restored: usize,
    /// Rows archived now (missing for at least [`MISSING_GRACE_MS`]).
    pub archived: usize,
    /// Rows missing from this answer, still inside their grace period.
    pub pending_absent: usize,
    /// The parser skipped entries, so missing rows were left alone.
    pub partial: bool,
}

/// The keys one row or fresh entry is matched by.
struct Keys {
    /// The exact share-link line (`Source::Uri`; the feed URL is never stored in Rust, §2.1).
    line: Option<String>,
    protocol: String,
    server: String,
    port: u16,
    name: String,
    credential: Option<String>,
    identity: Option<[u8; 16]>,
}

impl Keys {
    fn of_profile(p: &Profile) -> Self {
        Self {
            line: match &p.source {
                Source::Uri(line) => Some(line.trim().to_owned()),
                _ => None,
            },
            protocol: p.kind.label().to_owned(),
            server: p.server.to_string().to_ascii_lowercase(),
            port: p.port,
            name: p.name.trim().to_owned(),
            credential: credential(&p.kind),
            identity: Some(p.identity()),
        }
    }

    /// A row's keys from its opened `profile`; a row whose key cannot be decrypted here still
    /// matches by its plain copies (name, protocol, host, port), and the fresh key then replaces
    /// the locked one.
    fn of_row(row: &ServerRow, profile: Option<&Profile>) -> Self {
        match profile {
            Some(p) => Self::of_profile(p),
            None => Self {
                line: None,
                protocol: row.protocol.clone(),
                server: row.server.to_ascii_lowercase(),
                port: row.port,
                name: row.name.trim().to_owned(),
                credential: None,
                identity: None,
            },
        }
    }
}

/// The secret that identifies an account on a server: uuid | password | private key |
/// username + password (servers §3.3); `None` never matches.
fn credential(kind: &Kind) -> Option<String> {
    let value = match kind {
        Kind::Vless { uuid, .. } | Kind::Vmess { uuid, .. } | Kind::Tuic { uuid, .. } => {
            uuid.clone()
        }
        Kind::Trojan { password }
        | Kind::Shadowsocks { password, .. }
        | Kind::Hysteria2 { password, .. }
        | Kind::Anytls { password, .. } => password.clone(),
        Kind::Wireguard(wg) => wg.private_key.clone(),
        Kind::Naive {
            username, password, ..
        } => format!("{username}\u{0}{password}"),
        Kind::Socks { username, password } | Kind::Http { username, password } => {
            if username.is_none() && password.is_none() {
                return None;
            }
            let (user, pass) = (username.as_deref(), password.as_deref());
            format!(
                "{}\u{0}{}",
                user.unwrap_or_default(),
                pass.unwrap_or_default()
            )
        }
    };
    (!value.is_empty() && value != "\u{0}").then_some(value)
}

/// Which stored row each fresh entry got.
struct Matching {
    row_taken: Vec<bool>,
    fresh_row: Vec<Option<usize>>,
}

impl Matching {
    /// One pass: pairs still-unmatched rows and fresh entries with equal `key`, in fresh order.
    /// `unique`: only keys present exactly once on each side.
    fn pass<K: Eq + Hash>(
        &mut self,
        rows: &[Keys],
        fresh: &[Keys],
        unique: bool,
        key: impl Fn(&Keys) -> Option<K>,
    ) {
        let mut slots: HashMap<K, VecDeque<usize>> = HashMap::new();
        for (i, keys) in rows.iter().enumerate() {
            if !self.row_taken[i]
                && let Some(k) = key(keys)
            {
                slots.entry(k).or_default().push_back(i);
            }
        }
        let mut wanted: HashMap<K, usize> = HashMap::new();
        for (j, keys) in fresh.iter().enumerate() {
            if self.fresh_row[j].is_none()
                && let Some(k) = key(keys)
            {
                *wanted.entry(k).or_default() += 1;
            }
        }
        for (j, keys) in fresh.iter().enumerate() {
            if self.fresh_row[j].is_some() {
                continue;
            }
            let Some(k) = key(keys) else { continue };
            let ambiguous = wanted.get(&k).is_some_and(|&n| n != 1);
            let Some(free) = slots.get_mut(&k) else {
                continue;
            };
            if unique && (ambiguous || free.len() != 1) {
                continue;
            }
            if let Some(i) = free.pop_front() {
                self.row_taken[i] = true;
                self.fresh_row[j] = Some(i);
            }
        }
    }
}

/// Merges `fresh` (one parsed answer of `group`'s subscription) into `rows` (the whole list):
/// only `origin = feed` rows of `group` take part, manual rows are never touched (S-22).
///
/// Passes: exact line → (protocol, host, port, name) → key identity → (protocol, host, port,
/// credential) → (protocol, credential, name). Matched rows take the fresh key and name, lose
/// their `missing_since`, come back from a provider archive (a user archive stays) and lose their
/// health and classifier verdicts when host, port or credential changed. Unmatched fresh entries
/// become rows, unless the group already holds that key as a manual row.
/// Missing rows: untouched when `complete` is false (skipped lines prove nothing); otherwise
/// marked missing, then archived for the provider once missing for [`MISSING_GRACE_MS`]. The
/// selection is never changed here.
pub fn reconcile(
    group: &ServerGroup,
    rows: &mut Vec<ServerRow>,
    fresh: Vec<Profile>,
    complete: bool,
    now: UnixMs,
) -> AppResult<RefreshReport> {
    let device = group.device().unwrap_or_default();
    let feed: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.group_id == group.id && r.origin == Origin::Feed)
        .map(|(i, _)| i)
        .collect();
    // Opened once: DPAPI is the cost of a refresh, and the matched rows are compared below.
    let stored: Vec<Option<Profile>> = feed.iter().map(|&i| rows[i].profile().ok()).collect();
    let row_keys: Vec<Keys> = feed
        .iter()
        .zip(&stored)
        .map(|(&i, p)| Keys::of_row(&rows[i], p.as_ref()))
        .collect();
    let fresh_keys: Vec<Keys> = fresh.iter().map(Keys::of_profile).collect();
    // Keys the user holds in this group as manual rows (pasted in, or a provider-archived key
    // pasted back) are not added again as feed copies: one key per group, as `Servers::add`
    // keeps it.
    let manual: HashSet<[u8; 16]> = rows
        .iter()
        .filter(|r| r.group_id == group.id && r.origin == Origin::Manual)
        .filter_map(ServerRow::identity)
        .collect();
    let mut m = Matching {
        row_taken: vec![false; feed.len()],
        fresh_row: vec![None; fresh.len()],
    };
    // The same line twice is the same key: pairing in order is safe even when repeated.
    m.pass(&row_keys, &fresh_keys, false, |k| k.line.clone());
    // Names before credentials: names tell the locations behind a shared bridge apart.
    m.pass(&row_keys, &fresh_keys, true, |k| {
        Some((k.protocol.clone(), k.server.clone(), k.port, k.name.clone()))
    });
    m.pass(&row_keys, &fresh_keys, true, |k| k.identity);
    m.pass(&row_keys, &fresh_keys, true, |k| {
        let cred = k.credential.clone()?;
        Some((k.protocol.clone(), k.server.clone(), k.port, cred))
    });
    m.pass(&row_keys, &fresh_keys, true, |k| {
        let cred = k.credential.clone()?;
        Some((k.protocol.clone(), cred, k.name.clone()))
    });

    let mut report = RefreshReport {
        partial: !complete,
        ..RefreshReport::default()
    };
    for (j, profile) in fresh.iter().enumerate() {
        let Some(k) = m.fresh_row[j] else {
            if fresh_keys[j]
                .identity
                .is_some_and(|id| manual.contains(&id))
            {
                continue;
            }
            let mut row = ServerRow::new(profile, group.id.clone(), Origin::Feed, device, now)?;
            row.last_seen_at = Some(now);
            report.added.push(row.id.clone());
            rows.push(row);
            continue;
        };
        let (old, new) = (&row_keys[k], &fresh_keys[j]);
        let row = &mut rows[feed[k]];
        // Re-sealing an unchanged key would cost a DPAPI call per row and refresh.
        if stored[k].as_ref() != Some(profile) {
            row.set_profile(profile)?;
        }
        if old.credential != new.credential || old.server != new.server || old.port != new.port {
            // Both verdicts were about the old endpoint or account.
            row.health = None;
            row.verdict = None;
        }
        row.last_seen_at = Some(now);
        row.missing_since = None;
        if row.archived_for(ArchiveReason::Provider) {
            row.archived = None;
            report.restored += 1;
        } else {
            report.updated += 1;
        }
    }
    for (k, &i) in feed.iter().enumerate() {
        let row = &mut rows[i];
        if m.row_taken[k] || row.archived.is_some() || !complete {
            continue;
        }
        match row.missing_since {
            // Saturating: the timestamp comes from a file and may be anything.
            Some(since) if now.saturating_sub(since) >= MISSING_GRACE_MS => {
                row.archived = Some(Archived {
                    at: now,
                    reason: ArchiveReason::Provider,
                });
                report.archived += 1;
            }
            Some(_) => report.pending_absent += 1,
            None => {
                row.missing_since = Some(now);
                report.pending_absent += 1;
            }
        }
    }
    Ok(report)
}
