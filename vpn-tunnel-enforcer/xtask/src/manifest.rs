//! The pin manifest `resources/engines.toml`: every third-party binary, licence text and repo file that ships,
//! each with its SHA-256, plus the build tools. Parsing, validation and the stage file-set check live here, so
//! one module decides what "the pinned composition" is.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Location of the manifest relative to the workspace root.
pub const PATH: &str = "resources/engines.toml";
/// Install paths under this prefix are also the development drop in the workspace `resources/`.
pub const DEV_DROP_PREFIX: &str = "resources/";
const SCHEMA: u32 = 2;

/// The whole manifest (`schema = 2`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    #[serde(default)]
    pub archive: Vec<Archive>,
    #[serde(default)]
    pub download: Vec<Download>,
    #[serde(default)]
    pub local: Vec<LocalFile>,
    #[serde(default)]
    pub tool: Vec<Tool>,
}

/// A single file fetched as-is (no archive), such as Microsoft's WebView2 bootstrapper.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Download {
    pub id: String,
    pub version: String,
    pub url: String,
    pub sha256: Sha256Hex,
    /// Exact length in bytes: a wrong file is refused before it is hashed (and the read is bounded by it).
    pub size: u64,
    pub license: String,
    /// Where the file is published (the link to re-pin from).
    pub source: Option<String>,
    pub install: RelPath,
}

/// A downloaded zip archive and the files taken from it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub id: String,
    pub version: String,
    pub url: String,
    pub sha256: Sha256Hex,
    pub license: String,
    pub source: Option<String>,
    /// A WP-12 lab engine: in the dev drop (tests), staged only by `dist --lab`, never in a release.
    #[serde(default)]
    pub lab: bool,
    pub files: Vec<ArchiveFile>,
}

/// One member of an archive: where it is in the zip and where it is installed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveFile {
    pub path: RelPath,
    pub install: RelPath,
    pub sha256: Sha256Hex,
}

/// A file tracked in this repository (path relative to the workspace root).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFile {
    pub repo: RelPath,
    pub install: RelPath,
    /// For `text = true` the hash covers the LF-normalised text; the file is staged with CRLF line endings.
    pub sha256: Sha256Hex,
    #[serde(default)]
    pub text: bool,
}

/// A build-time tool (never shipped), unpacked to `target/tools/<id>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    pub version: String,
    pub url: String,
    pub sha256: Sha256Hex,
    /// Top-level folder of the archive, stripped when unpacking.
    pub root: String,
    /// The executable that must exist after unpacking, relative to the unpacked directory.
    pub exe: RelPath,
}

/// A SHA-256 digest; parsed only from exactly 64 lowercase hex characters (one canonical form).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Sha256Hex([u8; 32]);

impl Sha256Hex {
    /// Digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl TryFrom<String> for Sha256Hex {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let canonical = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let mut out = [0u8; 32];
        match canonical && hex::decode_to_slice(&s, &mut out).is_ok() {
            true => Ok(Self(out)),
            false => Err(format!("`{s}` is not 64 lowercase hex characters")),
        }
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A relative path with forward slashes: no `..` or `.` segment, no leading `/`, no drive, no backslash.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct RelPath(String);

impl RelPath {
    /// The path as written in the manifest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RelPath {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let bad_segment = s
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..");
        match s.is_empty() || s.contains(['\\', ':']) || bad_segment {
            true => Err(format!("`{s}` is not a relative path with forward slashes")),
            false => Ok(Self(s)),
        }
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Manifest {
    /// Reads and validates `resources/engines.toml` under the workspace root.
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(PATH);
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid {PATH}"))
    }

    /// Parses and validates manifest text.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Manifest = toml::from_str(text)?;
        ensure!(
            manifest.schema == SCHEMA,
            "unsupported schema {} (expected {SCHEMA})",
            manifest.schema
        );
        let mut ids = BTreeSet::new();
        for (id, url) in manifest
            .archive
            .iter()
            .map(|a| (&a.id, &a.url))
            .chain(manifest.download.iter().map(|d| (&d.id, &d.url)))
            .chain(manifest.tool.iter().map(|t| (&t.id, &t.url)))
        {
            ensure!(ids.insert(id.as_str()), "duplicate id `{id}`");
            ensure!(url.starts_with("https://"), "{id}: url must use https");
        }
        for archive in &manifest.archive {
            ensure!(!archive.files.is_empty(), "{}: lists no files", archive.id);
        }
        for download in &manifest.download {
            ensure!(download.size > 0, "{}: size must be set", download.id);
        }
        // Windows paths are case-insensitive: two entries differing only in case would overwrite each other.
        let mut installs = BTreeSet::new();
        for install in manifest.installs().map(|(path, _)| path) {
            ensure!(
                installs.insert(install.as_str().to_ascii_lowercase()),
                "duplicate install path `{install}`"
            );
        }
        Ok(manifest)
    }

    /// What one package ships: a production package (`lab = false`) drops every lab archive, so the
    /// stage check, the notices and the installer never see them.
    pub fn composition(mut self, lab: bool) -> Self {
        self.archive.retain(|a| lab || !a.lab);
        self
    }

    /// Every pinned install path with what the stage must hold there (archive members, downloads, then repo
    /// files).
    pub fn installs(&self) -> impl Iterator<Item = (&RelPath, Expect)> {
        let archived = self
            .archive
            .iter()
            .flat_map(|a| &a.files)
            .map(|f| (&f.install, Expect::Bytes(f.sha256.clone())));
        let downloaded = self
            .download
            .iter()
            .map(|d| (&d.install, Expect::Bytes(d.sha256.clone())));
        archived.chain(downloaded).chain(self.local.iter().map(|l| {
            let pin = l.sha256.clone();
            (
                &l.install,
                if l.text {
                    Expect::Text(pin)
                } else {
                    Expect::Bytes(pin)
                },
            )
        }))
    }

    /// The build tool with this id.
    pub fn tool(&self, id: &str) -> Result<&Tool> {
        self.tool
            .iter()
            .find(|t| t.id == id)
            .with_context(|| format!("no [[tool]] `{id}` in {PATH}"))
    }

    /// The exact stage content: every pinned file plus the `built` files (presence only).
    pub fn expected_stage(&self, built: &[&str]) -> Result<BTreeMap<String, Expect>> {
        let mut expected: BTreeMap<String, Expect> = self
            .installs()
            .map(|(path, expect)| (path.as_str().to_owned(), expect))
            .collect();
        for name in built {
            let path = RelPath::try_from((*name).to_owned()).map_err(anyhow::Error::msg)?;
            let clash = expected
                .keys()
                .any(|k| k.eq_ignore_ascii_case(path.as_str()));
            ensure!(
                !clash,
                "built file `{path}` collides with a pinned install path"
            );
            expected.insert(path.0, Expect::Built);
        }
        Ok(expected)
    }
}

/// What the stage check expects at one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Raw bytes with this hash.
    Bytes(Sha256Hex),
    /// Text whose LF-normalised content has this hash (staged with CRLF line endings).
    Text(Sha256Hex),
    /// A build output: presence only.
    Built,
}

/// Fails unless `stage` holds exactly the `expected` files with their pinned content; names every offender.
pub fn verify_stage(stage: &Path, expected: &BTreeMap<String, Expect>) -> Result<()> {
    let mut found = BTreeMap::new();
    let mut problems = Vec::new();
    walk(stage, "", &mut found, &mut problems)?;
    for (path, expect) in expected {
        let Some(raw) = found.remove(path) else {
            problems.push(format!("missing: {path}"));
            continue;
        };
        let (pin, actual) = match expect {
            Expect::Built => continue,
            Expect::Bytes(pin) => (pin, raw),
            Expect::Text(pin) => (
                pin,
                Sha256Hex::of(&normalize_text(&fs::read(stage.join(path))?)),
            ),
        };
        if actual != *pin {
            problems.push(format!(
                "hash differs: {path} (pinned {pin}, staged {actual})"
            ));
        }
    }
    problems.extend(found.into_keys().map(|path| format!("unexpected: {path}")));
    if !problems.is_empty() {
        bail!(
            "{} does not match the expected file set:\n  {}",
            stage.display(),
            problems.join("\n  ")
        );
    }
    Ok(())
}

/// SHA-256 of every file under `dir`, keyed by relative path with forward slashes.
pub fn tree_hashes(dir: &Path) -> Result<BTreeMap<String, Sha256Hex>> {
    let mut found = BTreeMap::new();
    let mut problems = Vec::new();
    walk(dir, "", &mut found, &mut problems)?;
    ensure!(
        problems.is_empty(),
        "{}: {}",
        dir.display(),
        problems.join("; ")
    );
    Ok(found)
}

fn walk(
    dir: &Path,
    prefix: &str,
    found: &mut BTreeMap<String, Sha256Hex>,
    problems: &mut Vec<String>,
) -> Result<()> {
    let mut empty = true;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        empty = false;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type()?.is_dir() {
            walk(&entry.path(), &rel, found, problems)?;
        } else {
            let bytes = fs::read(entry.path())
                .with_context(|| format!("read {}", entry.path().display()))?;
            found.insert(rel, Sha256Hex::of(&bytes));
        }
    }
    if empty && !prefix.is_empty() {
        problems.push(format!("unexpected empty directory: {prefix}"));
    }
    Ok(())
}

/// Text as pinned: CRLF line endings replaced by LF.
pub fn normalize_text(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for (i, &b) in bytes.iter().enumerate() {
        if !(b == b'\r' && bytes.get(i + 1) == Some(&b'\n')) {
            out.push(b);
        }
    }
    out
}

/// LF-normalised text with Windows line endings, as staged for installation.
pub fn to_crlf(normalized: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(normalized.len() + normalized.len() / 32);
    for &b in normalized {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const HASH_A: &str = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df";

    fn manifest(body: &str) -> Result<Manifest> {
        Manifest::parse(&format!("schema = 2\n{body}"))
    }

    fn archive(install: &str) -> String {
        format!(
            "[[archive]]\nid = \"a\"\nversion = \"1\"\nurl = \"https://example.invalid/a.zip\"\nsha256 = \"{HASH_A}\"\n\
             license = \"MIT\"\nfiles = [{{ path = \"a/a.exe\", install = \"{install}\", sha256 = \"{HASH_A}\" }}]\n"
        )
    }

    /// Scratch directory inside the xtask target dir (the only place tests may write).
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/xtask/test-scratch")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// AT-11-004: one canonical digest form.
    #[test]
    fn sha256_hex_accepts_only_64_lowercase_hex() {
        assert!(Sha256Hex::try_from(HASH_A.to_owned()).is_ok());
        for bad in [
            &HASH_A[..63],
            &format!("{HASH_A}0"),
            &HASH_A.to_uppercase(),
            &format!("{}g", &HASH_A[..63]),
            "",
        ] {
            assert!(
                Sha256Hex::try_from(bad.to_owned()).is_err(),
                "accepted {bad}"
            );
        }
        assert_eq!(
            Sha256Hex::try_from(HASH_A.to_owned()).unwrap().to_string(),
            HASH_A
        );
    }

    /// AT-11-004: install paths cannot escape the install directory.
    #[test]
    fn rel_path_rejects_escapes_and_backslashes() {
        assert!(RelPath::try_from("resources/sing-box.exe".to_owned()).is_ok());
        for bad in [
            "../x",
            "/x",
            "C:/x",
            r"resources\x",
            "",
            "a//b",
            "a/./b",
            "a/",
        ] {
            assert!(RelPath::try_from(bad.to_owned()).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn manifest_validation_rejects_bad_documents() {
        assert!(manifest(&archive("resources/a.exe")).is_ok());
        let wrong_schema = Manifest::parse(&format!("schema = 1\n{}", archive("resources/a.exe")));
        assert!(wrong_schema.is_err());
        assert!(manifest(&archive("resources/../a.exe")).is_err());
        assert!(manifest(&archive("resources/a.exe").replace("https://", "http://")).is_err());
        assert!(manifest(&format!("{}unknown = 1\n", archive("resources/a.exe"))).is_err());
        let local = format!(
            "[[local]]\nrepo = \"x/A.EXE\"\ninstall = \"RESOURCES/A.EXE\"\nsha256 = \"{HASH_A}\"\n"
        );
        let duplicate = manifest(&format!("{}{local}", archive("resources/a.exe"))).unwrap_err();
        assert!(
            format!("{duplicate:#}").contains("duplicate install path"),
            "{duplicate:#}"
        );
        let twice = format!(
            "{}{}",
            archive("resources/a.exe"),
            archive("resources/b.exe")
        );
        assert!(format!("{:#}", manifest(&twice).unwrap_err()).contains("duplicate id"));
    }

    /// The real manifest parses and carries the pins the product is built against.
    #[test]
    fn workspace_manifest_is_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let m = Manifest::load(root).unwrap();
        let versions: Vec<_> = m
            .archive
            .iter()
            .map(|a| format!("{} {}", a.id, a.version))
            .collect();
        assert_eq!(
            versions,
            [
                "sing-box 1.14.4",
                "xray 26.11.9",
                "wintun 0.14.1",
                "mihomo 1.19.34"
            ]
        );
        assert_eq!(m.tool("nsis").unwrap().version, "3.13");
        // The WebView2 bootstrapper: Microsoft's file, pinned by URL, hash and size, shipped in resources/.
        let [wv2] = m.download.as_slice() else {
            panic!("expected exactly one [[download]], found {:?}", m.download);
        };
        assert_eq!(wv2.id, "webview2-bootstrapper");
        assert_eq!(
            wv2.install.as_str(),
            "resources/MicrosoftEdgeWebview2Setup.exe"
        );
        assert!(
            wv2.url
                .starts_with("https://msedge.sf.dl.delivery.mp.microsoft.com/")
        );
        assert!(wv2.url.ends_with("/MicrosoftEdgeWebview2Setup.exe"));
        assert_eq!(
            wv2.source.as_deref(),
            Some("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
        );
        assert_eq!(wv2.size, 1_897_688);
        assert!(
            wv2.license
                .starts_with("Microsoft Edge WebView2 Runtime License")
        );
        assert!(
            m.installs()
                .any(|(p, e)| p == &wv2.install && e == Expect::Bytes(wv2.sha256.clone()))
        );
        for engine in [
            "sing-box.exe",
            "libcronet.dll",
            "xray.exe",
            "wintun.dll",
            "mihomo.exe",
        ] {
            assert!(
                m.installs()
                    .any(|(p, _)| p.as_str() == format!("resources/{engine}")),
                "{engine}"
            );
        }
    }

    /// AT-12-002: the lab engine is in the dev drop, never in a production package.
    #[test]
    fn production_composition_drops_lab_archives() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let lab: Vec<String> = Manifest::load(root)
            .unwrap()
            .archive
            .iter()
            .filter(|a| a.lab)
            .map(|a| a.id.clone())
            .collect();
        assert_eq!(lab, ["mihomo"]);
        let release = Manifest::load(root).unwrap().composition(false);
        assert!(release.archive.iter().all(|a| !a.lab));
        let stage = release.expected_stage(&[]).unwrap();
        assert!(!stage.contains_key("resources/mihomo.exe"));
        assert!(stage.contains_key("resources/sing-box.exe"));
        let lab_stage = Manifest::load(root)
            .unwrap()
            .composition(true)
            .expected_stage(&[])
            .unwrap();
        assert!(lab_stage.contains_key("resources/mihomo.exe"));
        // An archive without the key is a production archive.
        assert!(!manifest(&archive("resources/a.exe")).unwrap().archive[0].lab);
    }

    /// AT-11-006: the stage must hold exactly the pinned set; every offender is named.
    #[test]
    fn verify_stage_names_missing_extra_and_changed_files() {
        let stage = scratch("verify-stage");
        let m = manifest(&archive("resources/a.exe")).unwrap();
        let expected = m.expected_stage(&["App.exe"]).unwrap();
        fs::create_dir_all(stage.join("resources")).unwrap();
        fs::write(stage.join("App.exe"), b"built").unwrap();
        let missing = format!("{:#}", verify_stage(&stage, &expected).unwrap_err());
        assert!(missing.contains("missing: resources/a.exe"), "{missing}");

        fs::write(stage.join("resources/a.exe"), b"not the pinned bytes").unwrap();
        fs::write(stage.join("resources/sing-box-old.exe"), b"stale").unwrap();
        let err = format!("{:#}", verify_stage(&stage, &expected).unwrap_err());
        assert!(err.contains("hash differs: resources/a.exe"), "{err}");
        assert!(
            err.contains("unexpected: resources/sing-box-old.exe"),
            "{err}"
        );

        let exact = manifest(
            &archive("resources/a.exe").replace(HASH_A, &Sha256Hex::of(b"pinned").to_string()),
        );
        let exact = exact.unwrap().expected_stage(&["App.exe"]).unwrap();
        fs::write(stage.join("resources/a.exe"), b"pinned").unwrap();
        fs::remove_file(stage.join("resources/sing-box-old.exe")).unwrap();
        verify_stage(&stage, &exact).unwrap();
        fs::create_dir_all(stage.join("empty")).unwrap();
        let err = format!("{:#}", verify_stage(&stage, &exact).unwrap_err());
        assert!(err.contains("unexpected empty directory: empty"), "{err}");
        fs::remove_dir_all(&stage).unwrap();
    }

    fn download(id: &str, install: &str, size: u64) -> String {
        format!(
            "[[download]]\nid = \"{id}\"\nversion = \"1\"\nurl = \"https://example.invalid/{id}.exe\"\n\
             sha256 = \"{HASH_A}\"\nsize = {size}\nlicense = \"Proprietary\"\ninstall = \"{install}\"\n"
        )
    }

    /// A `[[download]]` is one pinned file: validated like an archive and staged at its install path.
    #[test]
    fn download_entries_are_validated_and_staged() {
        let m = manifest(&download("d", "resources/d.exe", 10)).unwrap();
        let stage = m.expected_stage(&[]).unwrap();
        assert_eq!(
            stage.get("resources/d.exe"),
            Some(&Expect::Bytes(
                Sha256Hex::try_from(HASH_A.to_owned()).unwrap()
            ))
        );
        assert!(
            manifest(&download("d", "resources/d.exe", 0)).is_err(),
            "size 0"
        );
        assert!(manifest(&download("d", "../d.exe", 10)).is_err());
        let plain = download("d", "resources/d.exe", 10).replace("https://", "http://");
        assert!(manifest(&plain).is_err());
        let missing_size = download("d", "resources/d.exe", 10).replace("size = 10\n", "");
        assert!(manifest(&missing_size).is_err());
        let same_id = format!(
            "{}{}",
            archive("resources/a.exe"),
            download("a", "resources/d.exe", 1)
        );
        assert!(format!("{:#}", manifest(&same_id).unwrap_err()).contains("duplicate id"));
        let same_path = format!(
            "{}{}",
            archive("resources/a.exe"),
            download("d", "resources/A.exe", 1)
        );
        let err = format!("{:#}", manifest(&same_path).unwrap_err());
        assert!(err.contains("duplicate install path"), "{err}");
    }

    #[test]
    fn built_files_may_not_shadow_pins() {
        let m = manifest(&archive("resources/a.exe")).unwrap();
        assert!(m.expected_stage(&["Resources/A.exe"]).is_err());
        assert!(m.expected_stage(&["../x.exe"]).is_err());
    }

    #[test]
    fn text_pins_ignore_checkout_line_endings() {
        assert_eq!(normalize_text(b"a\r\nb\nc\r"), b"a\nb\nc\r");
        assert_eq!(to_crlf(b"a\nb\n"), b"a\r\nb\r\n");
        assert_eq!(normalize_text(&to_crlf(b"x\ny")), b"x\ny");

        let pin = Sha256Hex::of(b"line\n");
        let m = manifest(&format!(
            "[[local]]\nrepo = \"x/n.txt\"\ninstall = \"licenses/n.txt\"\nsha256 = \"{pin}\"\ntext = true\n"
        ))
        .unwrap();
        let expected = m.expected_stage(&[]).unwrap();
        let stage = scratch("text-pin");
        fs::create_dir_all(stage.join("licenses")).unwrap();
        fs::write(stage.join("licenses/n.txt"), b"line\r\n").unwrap();
        verify_stage(&stage, &expected).unwrap();
        fs::write(stage.join("licenses/n.txt"), b"edited\r\n").unwrap();
        assert!(verify_stage(&stage, &expected).is_err());
        fs::remove_dir_all(&stage).unwrap();
    }
}
