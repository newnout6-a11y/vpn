//! What this build trusts: the feed keys, the feed addresses, the engine versions its configs
//! work with, and how old a feed may be. Compiled in on purpose: the elevated pin check and the
//! helper service must not take any of it from a file the user can write.
use std::sync::LazyLock;
use std::time::Duration;

use minisign_verify::PublicKey;

use crate::version::{Range, Version};

/// The owner's two minisign public keys (the base64 line `RW…` of `minisign -G`): the current
/// one and the offline backup for a rotation. Empty until the owner creates them
/// (`ВОПРОСЫ-ВЛАДЕЛЬЦУ.md`, «Обновления: что сделать один раз»); while both are empty nothing
/// is checked and Settings says the channel is not set up yet.
const CURRENT_KEY: &str = "";
const BACKUP_KEY: &str = "";

static KEYS: LazyLock<Vec<PublicKey>> = LazyLock::new(|| {
    [CURRENT_KEY, BACKUP_KEY]
        .into_iter()
        .filter_map(|k| PublicKey::from_base64(k.trim()).ok())
        .collect()
});

/// The compiled feed keys that parse (none while they are placeholders).
pub fn trusted_keys() -> &'static [PublicKey] {
    &KEYS
}

/// `true` once the owner's keys are compiled in: only then does the app check for updates.
pub fn keys_ready() -> bool {
    !trusted_keys().is_empty()
}

/// Feed addresses in the order they are tried: the `update-feed` branch, then GitHub Pages and
/// jsDelivr (cached up to ~12 h). Never `api.github.com` (60 requests an hour per address,
/// shared behind CGNAT). The feed is signed, so a mirror can only be silent or stale.
pub const FEED_BASES: [&str; 3] = [
    "https://raw.githubusercontent.com/newnout6-a11y/vpn/update-feed/",
    "https://newnout6-a11y.github.io/vpn/",
    "https://cdn.jsdelivr.net/gh/newnout6-a11y/vpn@update-feed/",
];

/// A feed older than this is "stale": the app says so instead of "up to date".
pub const MAX_FEED_AGE: Duration = Duration::from_secs(90 * 24 * 3600);

/// Engine ids the feed may list (the folder names of the engine store).
pub const SINGBOX: &str = "sing-box";
pub const XRAY: &str = "xray";

/// The engine versions this build's configs are written for. sing-box changes its config schema
/// between minor versions (deprecated in N, removed in N+2), and the generated config uses
/// 1.14-only fields, so only 1.14.x from the bundled release on; Xray keeps its config stable
/// across releases, so any version from the bundled one on. The lower bounds are also the floor
/// of the elevated pin check: an old signed feed cannot bring back an older engine. A feed entry
/// can narrow this, never widen it.
pub fn engine_range(id: &str) -> Option<Range> {
    let text = match id {
        SINGBOX => ">=1.14.4 <1.15.0",
        XRAY => ">=26.11.9",
        _ => return None,
    };
    text.parse().ok()
}

/// `true` when engine `id` at `version` fits this build's range.
pub fn engine_allowed(id: &str, version: Version) -> bool {
    engine_range(id).is_some_and(|r| r.contains(version))
}

/// The release's pin manifest: the bundled engine versions.
const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/engines.toml"
));

/// The version of engine `id` this build bundles (`resources/engines.toml`): a downloaded copy
/// is used only when it is newer.
pub fn bundled_version(id: &str) -> Option<Version> {
    let mut lines = MANIFEST.lines().map(str::trim);
    lines.find(|l| *l == format!("id = \"{id}\""))?;
    let line = lines.find(|l| l.starts_with("version = "))?;
    line.strip_prefix("version = \"")?
        .strip_suffix('"')?
        .parse()
        .ok()
}

/// This build's own version.
pub fn app_version() -> Version {
    env!("CARGO_PKG_VERSION")
        .parse()
        .unwrap_or(Version(0, 0, 0))
}

#[cfg(test)]
mod tests;
