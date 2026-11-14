//! `cargo xtask feed`: the signed update feed (research/updates.md §4.2-4.3). `update.json` lists
//! the app's installer of a release (`target/dist` + its `checksums.txt`), the engines of a pin
//! manifest (`resources/engines.toml`: the same `[[archive]]` entries in JSON) and, when the
//! release ships it, the helper service's executable; `update.json.minisig` is a prehashed
//! minisign signature made with the key in `UPDATE_SIGNING_KEY` (+ `UPDATE_SIGNING_PASSWORD`).
//! `--base <update.json>` keeps the app and service parts of a published feed and lists the
//! engines of `--engines` (an engine update between app releases). `--verify` checks a feed
//! against the keys compiled into the app (`crates/update/src/policy.rs`) or `--pubkey`.
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use crate::dist::{installer_name, service_name, workspace_version};
use crate::fetch;
use crate::manifest::{Manifest, Sha256Hex};

const REPO: &str = "https://github.com/newnout6-a11y/vpn";
/// The feed layout the app reads (`vpnte_update::feed::SCHEMA`).
const SCHEMA: u64 = 1;
/// Engines the app can update; others in the manifest (Wintun, lab engines) never are.
const ENGINE_IDS: [&str; 2] = ["sing-box", "xray"];
const FEED: &str = "update.json";
const SIG: &str = "update.json.minisig";

/// `cargo xtask feed [...]`; `args` are the words after `feed`.
pub fn run(root: &Path, args: &[String]) -> Result<()> {
    let value = |name: &str| -> Option<&str> {
        let at = args.iter().position(|a| a == name)?;
        args.get(at + 1).map(String::as_str)
    };
    let path =
        |name: &str, default: &str| value(name).map_or_else(|| root.join(default), PathBuf::from);
    let out = path("--out", "target/feed");
    if args.iter().any(|a| a == "--verify") {
        return verify(root, &out, value("--pubkey"));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let seq = match value("--seq") {
        Some(text) => text.parse().context("--seq must be a whole number")?,
        // Seconds since 1970 only grow: every publication gets a higher seq than the last.
        None => now,
    };
    let (app, service, app_version) = match value("--base") {
        Some(base) => from_base(Path::new(base))?,
        None => from_dist(root, &path("--dist", "target/dist"), args)?,
    };
    let engines = engine_entries(
        root,
        &path("--engines", "resources/engines.toml"),
        &app_version,
        now,
    )?;
    let mut feed = json!({
        "schema": SCHEMA,
        "seq": seq,
        "issued": rfc3339(now),
        "app": app,
        "engines": engines,
    });
    if let Some(service) = service {
        feed["service"] = service;
    }
    let mut bytes = serde_json::to_vec_pretty(&feed)?;
    bytes.push(b'\n');
    fs::create_dir_all(&out)?;
    fs::write(out.join(FEED), &bytes)?;
    let sig = sign(&bytes, seq)?;
    fs::write(out.join(SIG), sig)?;
    println!("  feed     {} (seq {seq})", out.join(FEED).display());
    verify(root, &out, value("--pubkey"))
}

/// App and service parts of an already published feed, and the app version it offers.
fn from_base(base: &Path) -> Result<(Value, Option<Value>, String)> {
    let feed: Value = serde_json::from_slice(
        &fs::read(base).with_context(|| format!("read {}", base.display()))?,
    )?;
    ensure!(
        feed["schema"] == SCHEMA,
        "{}: not a schema {SCHEMA} feed",
        base.display()
    );
    let version = feed["app"]["stable"]["version"]
        .as_str()
        .context("the base feed has no stable app version")?
        .to_owned();
    let service = feed.get("service").filter(|s| !s.is_null()).cloned();
    Ok((feed["app"].clone(), service, version))
}

/// The app part from a release's artifacts: the installer named in `checksums.txt`, its size and
/// a hash that matches the file; optional notes, severity, `warn_below` and rollback target.
fn from_dist(root: &Path, dist: &Path, args: &[String]) -> Result<(Value, Option<Value>, String)> {
    let value = |name: &str| -> Option<&str> {
        let at = args.iter().position(|a| a == name)?;
        args.get(at + 1).map(String::as_str)
    };
    let version = workspace_version(root)?;
    let sums = checksums(&dist.join("checksums.txt"))?;
    let file = release_file(dist, &sums, &installer_name(&version), &version)?;
    let mut notes = serde_json::Map::new();
    for (lang, flag) in [("ru", "--notes-ru"), ("en", "--notes-en")] {
        if let Some(path) = value(flag) {
            notes.insert(lang.into(), fs::read_to_string(path)?.trim().into());
        }
    }
    let severity = value("--severity").unwrap_or("normal");
    ensure!(
        ["normal", "security", "critical"].contains(&severity),
        "--severity must be normal, security or critical"
    );
    let mut stable =
        json!({ "version": version, "severity": severity, "notes": notes, "file": file });
    if let (Some(to), Some(sums_path)) = (value("--rollback-to"), value("--rollback-checksums")) {
        let size: u64 = value("--rollback-size")
            .context("--rollback-to needs --rollback-size (bytes of that installer)")?
            .parse()?;
        let old = checksums(Path::new(sums_path))?;
        let name = installer_name(to);
        let sha = old
            .get(&name)
            .with_context(|| format!("{sums_path} does not list {name}"))?;
        stable["rollback_to"] = to.into();
        stable["rollback_file"] = json!({ "name": name, "size": size, "sha256": sha,
            "urls": [format!("{REPO}/releases/download/v{to}/{name}")] });
    }
    let app = json!({ "stable": stable, "beta": null, "warn_below": value("--warn-below") });
    let service_file = service_name(&version);
    let service = match sums.contains_key(&service_file) {
        true => {
            let file = release_file(dist, &sums, &service_file, &version)?;
            Some(
                json!({ "version": version, "size": file["size"], "sha256": file["sha256"], "urls": file["urls"] }),
            )
        }
        false => None,
    };
    Ok((app, service, version))
}

/// `{name, size, sha256, urls}` of a release artifact whose bytes match `checksums.txt`.
fn release_file(
    dist: &Path,
    sums: &BTreeMap<String, String>,
    name: &str,
    version: &str,
) -> Result<Value> {
    let sha = sums
        .get(name)
        .with_context(|| format!("checksums.txt does not list {name}"))?;
    let bytes = fs::read(dist.join(name)).with_context(|| format!("read {name}"))?;
    ensure!(
        Sha256Hex::of(&bytes).to_string() == *sha,
        "{name} does not match checksums.txt"
    );
    Ok(json!({ "name": name, "size": bytes.len(), "sha256": sha,
        "urls": [format!("{REPO}/releases/download/v{version}/{name}")] }))
}

/// `<sha256>  <name>` lines (the format `cargo xtask dist` writes).
fn checksums(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let (sha, name) = line
                .split_once("  ")
                .with_context(|| format!("bad line `{line}`"))?;
            Sha256Hex::try_from(sha.to_owned()).map_err(anyhow::Error::msg)?;
            Ok((name.trim().to_owned(), sha.to_owned()))
        })
        .collect()
}

/// The manifest's sing-box and Xray archives as feed entries, meant for the app's minor series.
/// The archive sizes come from the verified download cache (`cargo xtask engines` fills it).
fn engine_entries(root: &Path, manifest: &Path, app_version: &str, now: u64) -> Result<Vec<Value>> {
    let text =
        fs::read_to_string(manifest).with_context(|| format!("read {}", manifest.display()))?;
    let manifest = Manifest::parse(&text)?;
    let app_range = minor_range(app_version)?;
    let tested = std::env::var("GITHUB_RUN_ID").ok().map(|run| {
        let repo =
            std::env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "newnout6-a11y/vpn".into());
        format!("https://github.com/{repo}/actions/runs/{run}")
    });
    let mut out = Vec::new();
    let engines = manifest
        .archive
        .iter()
        .filter(|a| !a.lab && ENGINE_IDS.contains(&a.id.as_str()));
    for archive in engines {
        let bytes = fetch::cached(root, &archive.id, &archive.url, &archive.sha256, false)?;
        let files: Vec<Value> = archive
            .files
            .iter()
            .filter_map(|f| {
                let name = f.install.as_str().strip_prefix("resources/")?;
                Some(json!({ "path": f.path.as_str(), "name": name, "sha256": f.sha256.to_string() }))
            })
            .collect();
        out.push(json!({
            "id": archive.id, "version": archive.version, "app": app_range, "severity": "normal",
            "tested_on": &rfc3339(now)[..10], "tested": tested,
            "archive": { "url": archive.url, "size": bytes.len(), "sha256": archive.sha256.to_string() },
            "files": files,
        }));
    }
    ensure!(
        out.len() == ENGINE_IDS.len(),
        "the manifest must pin both sing-box and xray"
    );
    Ok(out)
}

/// `2.0.3` -> `>=2.0.0 <2.1.0`: engine entries are meant for the app's minor series.
fn minor_range(version: &str) -> Result<String> {
    let mut parts = version.split('.').map(str::parse::<u32>);
    let (Some(Ok(major)), Some(Ok(minor))) = (parts.next(), parts.next()) else {
        bail!("app version `{version}` is not X.Y.Z");
    };
    Ok(format!(">={major}.{minor}.0 <{major}.{}.0", minor + 1))
}

/// A prehashed minisign signature with the key from the environment (never a prompt: a key with
/// a password needs `UPDATE_SIGNING_PASSWORD`).
fn sign(bytes: &[u8], seq: u64) -> Result<String> {
    let key = std::env::var("UPDATE_SIGNING_KEY")
        .context("UPDATE_SIGNING_KEY is not set (the content of the minisign secret key file)")?;
    let boxed = minisign::SecretKeyBox::from_string(key.trim())?;
    let secret = match std::env::var("UPDATE_SIGNING_PASSWORD") {
        Ok(password) => boxed.into_secret_key(Some(password))?,
        Err(_) => boxed.into_unencrypted_secret_key()?,
    };
    let comment = format!("vpnte update feed seq {seq}");
    let signature = minisign::sign(None, &secret, Cursor::new(bytes), Some(&comment), None)?;
    Ok(signature.into_string())
}

/// Checks `dir/update.json` against its signature with `pubkey` or the app's compiled keys, and
/// the parts the app relies on.
fn verify(root: &Path, dir: &Path, pubkey: Option<&str>) -> Result<()> {
    let bytes =
        fs::read(dir.join(FEED)).with_context(|| format!("read {}", dir.join(FEED).display()))?;
    let sig = fs::read_to_string(dir.join(SIG))?;
    let keys = match pubkey {
        Some(key) => vec![key.trim().to_owned()],
        None => compiled_keys(root)?,
    };
    ensure!(
        !keys.is_empty(),
        "no public key: pass --pubkey RW... or compile the owner's keys into the app"
    );
    let signature = minisign::SignatureBox::from_string(&sig)?;
    let verified = keys.iter().any(|key| {
        minisign::PublicKey::from_base64(key)
            .and_then(|pk| {
                minisign::verify(&pk, &signature, Cursor::new(&bytes), true, false, false)
            })
            .is_ok()
    });
    ensure!(
        verified,
        "the signature of {} does not verify",
        dir.join(FEED).display()
    );
    let feed: Value = serde_json::from_slice(&bytes)?;
    ensure!(feed["schema"] == SCHEMA, "unknown schema");
    let seq = feed["seq"].as_u64().context("no seq")?;
    let app = feed["app"]["stable"]["version"].as_str().unwrap_or("-");
    let engines: Vec<String> = feed["engines"]
        .as_array()
        .context("no engines")?
        .iter()
        .map(|e| {
            let field = |k: &str| e[k].as_str().unwrap_or("?").to_owned();
            format!("{} {}", field("id"), field("version"))
        })
        .collect();
    println!(
        "  verified seq {seq}, app {app}, engines {}",
        engines.join(", ")
    );
    Ok(())
}

/// `CURRENT_KEY` / `BACKUP_KEY` of `crates/update/src/policy.rs` (empty = not set yet).
fn compiled_keys(root: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(root.join("crates/update/src/policy.rs"))?;
    Ok(text
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l
                .strip_prefix("const CURRENT_KEY: &str = \"")
                .or_else(|| l.strip_prefix("const BACKUP_KEY: &str = \""))?;
            Some(rest.strip_suffix("\";")?.to_owned())
        })
        .filter(|k| !k.is_empty())
        .collect())
}

/// Unix seconds -> `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, H. Hinnant).
fn rfc3339(secs: u64) -> String {
    let (days, rest) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (rest / 3600, rest % 3600 / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_ranges_and_checksums() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_794_484_800), "2026-11-12T12:00:00Z");
        assert_eq!(minor_range("2.0.3").unwrap(), ">=2.0.0 <2.1.0");
        assert!(minor_range("2").is_err());
        let dir = std::env::temp_dir().join(format!("xtask-feed-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let sha = Sha256Hex::of(b"x").to_string();
        fs::write(dir.join("checksums.txt"), format!("{sha}  a.exe\n")).unwrap();
        let sums = checksums(&dir.join("checksums.txt")).unwrap();
        assert_eq!(sums["a.exe"], sha);
        fs::write(dir.join("a.exe"), b"x").unwrap();
        assert_eq!(
            release_file(&dir, &sums, "a.exe", "2.0.1").unwrap()["size"],
            1
        );
        fs::write(dir.join("a.exe"), b"y").unwrap();
        assert!(release_file(&dir, &sums, "a.exe", "2.0.1").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A feed signed here verifies with the matching public key only (the app runs the same
    /// prehashed check through minisign-verify).
    #[test]
    fn a_signed_feed_verifies() {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let dir = std::env::temp_dir().join(format!("xtask-feed-sig-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let feed = json!({ "schema": 1, "seq": 9, "issued": rfc3339(0),
            "app": { "stable": null }, "engines": [] });
        let bytes = serde_json::to_vec(&feed).unwrap();
        fs::write(dir.join(FEED), &bytes).unwrap();
        let sig = minisign::sign(None, &pair.sk, Cursor::new(&bytes), Some("t"), None).unwrap();
        fs::write(dir.join(SIG), sig.into_string()).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert!(verify(root, &dir, Some(&pair.pk.to_base64())).is_ok());
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        assert!(verify(root, &dir, Some(&other.pk.to_base64())).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
