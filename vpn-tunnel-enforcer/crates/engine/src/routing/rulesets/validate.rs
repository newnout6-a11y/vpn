//! Engine validation of a downloaded rule set: the bundled sing-box must parse it and classify
//! known canaries the right way, and its content must stay within the bounds of the release's
//! copy ([`super::content`]).
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use vpnte_base::types::Engine;

use crate::routing::smart_ru::{GEOIP_RU, GOV_RU, RU_BLOCKED_IPS, RU_BLOCKED_SITES};
use crate::singbox_process::child::run_once;

/// Budget of one `sing-box rule-set match` run.
const MATCH_TIMEOUT: Duration = Duration::from_secs(20);

/// `(tag, [(probe, member)])`: one member and two outsiders, or two members and one outsider.
/// Picked to stay true for years: Yandex DNS is Russian and never blocked, Meta's and
/// rutracker's / LinkedIn's blocks date from 2022 and 2016. 1.1.1.1 is NOT a safe outsider of
/// the blocked addresses: whole Cloudflare ranges are in that list.
const CANARIES: [(&str, [(&str, bool); 3]); 4] = [
    (
        GEOIP_RU,
        [("77.88.8.8", true), ("8.8.8.8", false), ("1.1.1.1", false)],
    ),
    (
        GOV_RU,
        [
            ("gosuslugi.ru", true),
            ("google.com", false),
            ("youtube.com", false),
        ],
    ),
    (
        RU_BLOCKED_SITES,
        [
            ("rutracker.org", true),
            ("linkedin.com", true),
            ("gosuslugi.ru", false),
        ],
    ),
    (
        RU_BLOCKED_IPS,
        [
            ("157.240.0.35", true),
            ("31.13.72.36", true),
            ("77.88.8.8", false),
        ],
    ),
];

/// Canaries per set: the file must parse in the bundled engine AND classify known names and
/// addresses the right way (a truncated, HTML or hostile file fails here, not at connect
/// time), then keep within the bounds of `reference`'s copy of the same file.
/// `Some(true)` = valid, `Some(false)` = invalid, `None` = the engine could not run.
pub(super) async fn validate(
    engine: &Path,
    file: &Path,
    tag: &str,
    reference: &Path,
) -> Option<bool> {
    let Some((_, canaries)) = CANARIES.iter().find(|(t, _)| *t == tag) else {
        return Some(false);
    };
    for &(probe, want) in canaries {
        if rule_set_match(engine, file, probe).await? != Some(want) {
            return Some(false);
        }
    }
    super::content::check(engine, file, tag, reference).await
}

/// `sing-box rule-set match -f binary <file> <probe>`: matches are printed to stderr as
/// `match rules.[i]: …`; an unreadable file exits non-zero. Outer `None` = the engine could
/// not run; inner `None` = the engine rejected the file.
async fn rule_set_match(engine: &Path, file: &Path, probe: &str) -> Option<Option<bool>> {
    // The engine runs in its own folder: a relative file name would point there.
    let file = std::path::absolute(file).ok()?;
    let args = ["rule-set", "match", "--disable-color", "-f", "binary"]
        .map(OsStr::new)
        .into_iter()
        .chain([file.as_os_str(), OsStr::new(probe)])
        .collect::<Vec<_>>();
    let out = run_once(Engine::SingBox, engine, &args, None, MATCH_TIMEOUT)
        .await
        .map_err(|err| tracing::warn!(%err, "sing-box rule-set match did not run"))
        .ok()?;
    Some(
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stderr).contains("match rules.[")),
    )
}
