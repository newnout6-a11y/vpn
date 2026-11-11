//! One server of the list: where it came from, its archive state, verified country and key
//! health, and the sealed typed profile with its plain copies.
use std::cmp::Ordering;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::secret::{Secret, SecretError};
use vpnte_profiles::countries::{self, Iso2};
use vpnte_profiles::model::Profile;

use super::{ARCHIVE_TTL_MS, GroupId, ProfileId};

/// Age after which weaker country evidence may replace stronger evidence.
const COUNTRY_STALE_MS: UnixMs = 30 * 24 * 60 * 60 * 1000;

/// Where a row came from. Only `Feed` rows are reconciled by a subscription refresh; keys the user
/// pasted into a subscription group are `Manual` and never archived by it (S-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Feed,
    Manual,
}

/// Why a row is archived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveReason {
    /// The provider stopped publishing the key; the user can still select it (with a warning).
    Provider,
    /// The user removed it (soft delete): not selectable until restored.
    User,
}

/// Archive state of a row; it is purged [`ARCHIVE_TTL_MS`] after `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Archived {
    pub at: UnixMs,
    pub reason: ArchiveReason,
}

/// How a country was verified (S-11 / S-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CountrySource {
    /// Geo lookup of the exit IP seen through the tunnel.
    ExitIp,
    /// The key-health probe's trace (exit IP and its country).
    HealthTrace,
    /// Geo lookup of the server's own address: wrong for bridges, so never replaces exit data.
    EntryIp,
    /// Imported from the Electron app: low confidence, any new verification replaces it.
    Legacy,
}

impl CountrySource {
    /// Higher rank wins; equal ranks: the newer record wins.
    fn rank(self) -> u8 {
        match self {
            CountrySource::Legacy => 0,
            CountrySource::EntryIp => 1,
            CountrySource::ExitIp | CountrySource::HealthTrace => 2,
        }
    }
}

/// A verified country of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedCountry {
    pub iso2: Iso2,
    pub at: UnixMs,
    /// The address that was looked up (absent for some imported records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    pub source: CountrySource,
}

impl VerifiedCountry {
    /// True when `self` should replace `old`: stronger evidence, or the same kind and newer. Weaker
    /// evidence (an entry-IP lookup after exit data) wins only once `old` is 30 days older than it
    /// (servers §3.9): a server can move, and nothing else would ever correct the stale record.
    pub fn supersedes(&self, old: &VerifiedCountry) -> bool {
        match self.source.rank().cmp(&old.source.rank()) {
            Ordering::Greater => true,
            Ordering::Equal => self.at >= old.at,
            Ordering::Less => self.at.saturating_sub(old.at) >= COUNTRY_STALE_MS,
        }
    }
}

/// Last key-health verdict of a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthRecord {
    pub online: bool,
    pub at: UnixMs,
    /// From "SOCKS ready" to the first 2xx (S-14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<HealthReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<IpAddr>,
}

/// Why a key failed its health probe (the old `healthReason` strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthReason {
    NoOutbound,
    ConfigFailed,
    TlsFailed,
    AuthFailed,
    Timeout,
    HandshakeFailed,
    Hy2ConfigFailed,
    Hy2AuthFailed,
    Hy2UdpBlocked,
    Hy2TlsFailed,
    Hy2HandshakeFailed,
}

/// One server of the list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRow {
    pub id: ProfileId,
    pub group_id: GroupId,
    pub origin: Origin,
    /// Plain copies of the profile's name, protocol label, host and port (lists, pings).
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    /// Client device: a feed row follows its group, a manual row has its own (uTLS default, S-12b).
    #[serde(default)]
    pub device: ClientDevice,
    /// The typed [`Profile`] as JSON, DPAPI-sealed on disk.
    pub profile: Secret,
    pub imported_at: UnixMs,
    /// Last refresh that still listed this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<UnixMs>,
    /// First complete refresh that no longer listed it (the 15-minute grace before archiving).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_since: Option<UnixMs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived: Option<Archived>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<VerifiedCountry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthRecord>,
}

impl ServerRow {
    /// A new row for `profile` (the secret is sealed when the document is written).
    pub fn new(
        profile: &Profile,
        group_id: GroupId,
        origin: Origin,
        device: ClientDevice,
        now: UnixMs,
    ) -> AppResult<Self> {
        let mut row = Self {
            id: ProfileId::random(),
            group_id,
            origin,
            name: String::new(),
            protocol: String::new(),
            server: String::new(),
            port: 0,
            device,
            profile: Secret::new(String::new()),
            imported_at: now,
            last_seen_at: None,
            missing_since: None,
            archived: None,
            country: None,
            health: None,
        };
        row.set_profile(profile)?;
        Ok(row)
    }

    /// The typed profile. Fails when the key cannot be decrypted under this Windows account.
    pub fn profile(&self) -> AppResult<Profile> {
        self.profile.expose_json().map_err(profile_error)
    }

    /// Replaces the stored profile and refreshes the plain copies.
    pub fn set_profile(&mut self, profile: &Profile) -> AppResult<()> {
        self.profile = Secret::from_json(profile).map_err(AppError::internal)?;
        self.name = profile.name.clone();
        self.protocol = profile.kind.label().to_owned();
        self.server = profile.server.to_string();
        self.port = profile.port;
        Ok(())
    }

    /// Key identity (`Profile::identity`); `None` when the profile cannot be opened.
    pub fn identity(&self) -> Option<[u8; 16]> {
        self.profile().ok().map(|p| p.identity())
    }

    /// True when the stored key cannot be decrypted (copied from another PC or account).
    pub fn is_locked(&self) -> bool {
        self.profile.is_locked()
    }

    /// True when archived for `reason`.
    pub fn archived_for(&self, reason: ArchiveReason) -> bool {
        self.archived.is_some_and(|a| a.reason == reason)
    }

    /// Country the provider claims in the name (derived, never stored).
    pub fn claimed_country(&self) -> Option<Iso2> {
        countries::infer(&self.name)
    }

    /// Country to show: the verified one, else the claimed one.
    pub fn display_country(&self) -> Option<Iso2> {
        self.country
            .map(|c| c.iso2)
            .or_else(|| self.claimed_country())
    }

    /// When an archived row is purged.
    pub fn purge_at(&self) -> Option<UnixMs> {
        self.archived.map(|a| a.at.saturating_add(ARCHIVE_TTL_MS))
    }
}

fn profile_error(err: SecretError) -> AppError {
    match err {
        SecretError::Locked => AppError::msg(ErrorKind::Conflict, Msg::new("servers.locked")),
        other => {
            AppError::msg(ErrorKind::Internal, Msg::new("servers.unreadable")).with_source(other)
        }
    }
}
