//! Installed-application discovery for the split-tunnel picker: the registry Uninstall keys
//! (HKLM 64-bit view, HKLM 32-bit view, HKCU) read directly through `vpnte_winnet::registry`,
//! plus `%LOCALAPPDATA%\Programs` for per-user apps that never write an Uninstall key (Codex
//! CLI, VS Code Insiders, portable Electron apps). Blocking: run it on the blocking pool.
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::routing::process::AppPath;

/// A discovered application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    /// Display name, sanitised.
    pub name: String,
    pub path: AppPath,
}

/// Vendor directories of `%LOCALAPPDATA%\Programs` inspected at most.
const MAX_PRODUCTS: usize = 250;
/// Subdirectories followed per level inside a vendor directory.
const MAX_SUBDIRS: usize = 8;

static MOJIBAKE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\x{3400}-\x{9fff}\x{f900}-\x{faff}\x{ac00}-\x{d7af}\x{0800}-\x{08ff}]+")
        .expect("static regex")
});
static VERSION_GROUP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(\s*\d+\s*[-–][^)]*\)").expect("static regex"));
/// `, 2` → ` 2` (the old `,\s*(?=\d)`; the digit is captured instead of a lookahead).
static COMMA_DIGIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r",\s*(\d)").expect("static regex"));
static HELPER_EXE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(unins|uninstall|setup|update|inno|crash|crashpad|report|notifier|elevate|elevator|squirrel|service|helper|daemon|broker)")
        .expect("static regex")
});
static GENERIC_CONTAINER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(application|app|bin|bin64|x64|x86|win64|win32|program files|program files \(x86\)|common files|current)$")
        .expect("static regex")
});

fn is_mojibake(c: char) -> bool {
    matches!(c, '\u{3400}'..='\u{9fff}' | '\u{f900}'..='\u{faff}' | '\u{ac00}'..='\u{d7af}' | '\u{0800}'..='\u{08ff}')
}

/// Registry `DisplayName`s are often mojibake (UTF-16LE bytes read as UTF-8 or the other way
/// round): runs of CJK / Hangul / high-range letters mixed into Latin or Cyrillic text. Real
/// CJK / Hangul names carry no Latin / Cyrillic and are never flagged. Ported exactly,
/// including the old counting quirks (letters = ASCII only; Ё / ё not counted).
pub fn looks_corrupt(name: &str) -> bool {
    if name.contains('\u{fffd}') {
        return true;
    }
    let moj = name.chars().filter(|c| is_mojibake(*c)).count() as f64;
    let ascii_letters = name.chars().filter(char::is_ascii_alphabetic).count() as f64;
    let cyr = |c: char| ('\u{0410}'..='\u{044f}').contains(&c);
    let known = name.chars().any(|c| c.is_ascii_alphanumeric() || cyr(c));
    let latin_cyr = name
        .chars()
        .filter(|c| c.is_ascii_alphabetic() || cyr(*c))
        .count();
    known && latin_cyr > 0 && moj >= 3.0 && moj > (ascii_letters - moj) / 2.0
}

/// `cleanDisplayName`: replacement-char runs and (for corrupt names) mojibake runs become
/// spaces, `(64-…)` groups go, spacing around punctuation is tidied.
fn clean(name: &str) -> String {
    let mut s = name.split('\u{fffd}').collect::<Vec<_>>().join(" ");
    if looks_corrupt(name) {
        s = MOJIBAKE.replace_all(&s, " ").into_owned();
    }
    let s = VERSION_GROUP.replace_all(&s, " ");
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let s = [
        (" ,", ","),
        (" .", "."),
        (" )", ")"),
        (" ]", "]"),
        ("( ", "("),
    ]
    .into_iter()
    .fold(s, |s, (from, to)| s.replace(from, to));
    let s = COMMA_DIGIT.replace_all(&s, " $1");
    let s = s.trim_end();
    s.strip_suffix(',').unwrap_or(s).trim().to_owned()
}

fn mostly_numeric(v: &str) -> bool {
    let compact: String = v.chars().filter(|c| !c.is_whitespace()).collect();
    !compact.is_empty()
        && compact
            .chars()
            .all(|c| c.is_ascii_digit() || ".+-()".contains(c))
}

fn generic_container(v: &str) -> bool {
    GENERIC_CONTAINER.is_match(v.trim())
}

/// `fallbackAppNameFromPath`: the parent folder or the file stem, whichever reads as a name.
pub fn fallback_name(path: &str) -> String {
    let p = Path::new(path);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().trim().to_owned())
        .unwrap_or_default();
    let parent = p
        .parent()
        .and_then(Path::file_name)
        .map(|s| s.to_string_lossy().trim().to_owned())
        .unwrap_or_default();
    let picked = [&parent, &stem]
        .into_iter()
        .find(|c| !c.is_empty() && !looks_corrupt(c) && !mostly_numeric(c) && !generic_container(c))
        .cloned();
    match picked {
        Some(name) => name,
        None if stem.is_empty() => path.to_owned(),
        None => stem,
    }
}

/// `sanitizeAppDisplayName`: the cleaned registry name when it reads as one, else a name
/// derived from the path.
pub fn sanitize_name(name: &str, path: &str) -> String {
    let trimmed = name.trim();
    let cleaned = clean(trimmed);
    if !looks_corrupt(trimmed) && !cleaned.is_empty() && !mostly_numeric(&cleaned) {
        return cleaned;
    }
    let letter = |c: char| c.is_ascii_alphabetic() || ('\u{0410}'..='\u{044f}').contains(&c);
    if cleaned.chars().count() >= 3 && cleaned.chars().any(letter) && !mostly_numeric(&cleaned) {
        return cleaned;
    }
    fallback_name(path)
}

fn is_helper(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| HELPER_EXE.is_match(&n.to_string_lossy()))
}

fn leaf_len(p: &Path) -> usize {
    p.file_name().map_or(0, |n| n.len())
}

/// `pickMainExe`: helpers (uninstallers, updaters, crash reporters…) out, then the shortest
/// exe whose stem matches a word of the product name ("OpenAI Codex" → `codex.exe` over
/// `codex-code-mode-host.exe`), else the shortest remaining one.
fn pick_main(exes: &[PathBuf], product: &str) -> Option<PathBuf> {
    let candidates: Vec<&PathBuf> = exes.iter().filter(|p| !is_helper(p)).collect();
    let product = product.to_lowercase();
    let words: Vec<&str> = product
        .split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        .filter(|w| w.len() >= 3 && !["the", "app", "for", "and", "ide"].contains(w))
        .collect();
    let matches = |p: &&&PathBuf| {
        let stem: String = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
            .collect();
        words
            .iter()
            .any(|w| stem == *w || stem == format!("{w}exe") || stem.starts_with(w))
    };
    let shortest = |list: Vec<&PathBuf>| list.into_iter().min_by_key(|p| leaf_len(p)).cloned();
    let matching: Vec<&PathBuf> = candidates.iter().filter(matches).copied().collect();
    if matching.is_empty() {
        shortest(candidates)
    } else {
        shortest(matching)
    }
}

fn sorted_entries(dir: &Path) -> Vec<std::fs::DirEntry> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name().to_string_lossy().to_lowercase());
    entries
}

/// Subdirectories, junctions and directory symlinks included (Codex lays out `Codex\bin` as
/// a junction).
fn list_dirs(dir: &Path) -> Vec<PathBuf> {
    sorted_entries(dir)
        .into_iter()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() || t.is_symlink()))
        .map(|e| e.path())
        .collect()
}

/// `*.exe` regular files directly in `dir` (a symlinked exe is not listed, as before).
fn list_exes(dir: &Path) -> Vec<PathBuf> {
    sorted_entries(dir)
        .into_iter()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
        .collect()
}

/// Product folders with exes, at most `depth` levels down; a branch stops at the first level
/// that has exes (the launcher sits next to its helpers) while siblings are still scanned.
fn collect_products(dir: &Path, depth: u32, out: &mut Vec<(PathBuf, Vec<PathBuf>)>) {
    let here = list_exes(dir);
    if !here.is_empty() {
        out.push((dir.to_path_buf(), here));
    } else if depth > 0 {
        for sub in list_dirs(dir).into_iter().take(MAX_SUBDIRS) {
            collect_products(&sub, depth - 1, out);
        }
    }
}

/// The folder chain below `root` without generic or numeric parts (`OpenAI\Codex\bin` →
/// "OpenAI Codex"), or the folder's own name.
fn name_from_path(root: &Path, dir: &Path) -> String {
    let rel = dir.strip_prefix(root).unwrap_or(dir);
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .filter(|p| !p.is_empty() && !generic_container(p) && !mostly_numeric(p))
        .collect();
    if parts.is_empty() {
        dir.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        parts.join(" ")
    }
}

/// `nameForExe`: vendor + product when both say something ("OpenAI" + "Codex").
fn name_for_exe(root: &Path, vendor: &Path, exe: &Path) -> String {
    let v = name_from_path(root, vendor);
    let e = exe
        .parent()
        .map(|d| name_from_path(root, d))
        .unwrap_or_default();
    if !e.is_empty() && e.to_lowercase() != v.to_lowercase() {
        if !v.is_empty() && !e.to_lowercase().contains(&v.to_lowercase()) {
            return format!("{v} {e}");
        }
        return e;
    }
    v
}

/// Apps under a `%LOCALAPPDATA%\Programs`-style root: ≤ 250 vendor folders, two levels deep.
pub fn scan_programs(root: &Path) -> Vec<InstalledApp> {
    let mut out = Vec::new();
    for vendor in list_dirs(root).into_iter().take(MAX_PRODUCTS) {
        let mut products = Vec::new();
        collect_products(&vendor, 2, &mut products);
        for (dir, exes) in products {
            let Some(main) = pick_main(&exes, &name_from_path(root, &dir)) else {
                continue;
            };
            let display = name_for_exe(root, &vendor, &main);
            let main = main.to_string_lossy();
            if let Ok(path) = AppPath::parse(&main) {
                out.push(InstalledApp {
                    name: sanitize_name(&display, &main),
                    path,
                });
            }
        }
    }
    out
}

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// Every installed app found: registry Uninstall keys (HKLM 64-bit, HKLM 32-bit, HKCU), then
/// `%LOCALAPPDATA%\Programs`; one entry per path (case-insensitive), first source wins.
/// Blocking (registry + directory walk). Nothing needs elevation.
pub fn discover() -> Vec<InstalledApp> {
    use vpnte_winnet::registry::{Hive, View};
    let mut found = Vec::new();
    for (hive, view, label) in [
        (Hive::LocalMachine, View::Bits64, "HKLM"),
        (Hive::LocalMachine, View::Bits32, "HKLM WOW6432Node"),
        (Hive::CurrentUser, View::Native, "HKCU"),
    ] {
        match uninstall_entries(hive, view) {
            Ok(apps) => found.extend(apps),
            // A hive we cannot read only means fewer suggestions.
            Err(err) => tracing::debug!(%err, root = label, "uninstall key not readable"),
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        found.extend(scan_programs(&PathBuf::from(local).join("Programs")));
    }
    let mut seen = std::collections::HashSet::new();
    found.retain(|a| seen.insert(a.path.as_str().to_lowercase()));
    found
}

fn uninstall_entries(
    hive: vpnte_winnet::registry::Hive,
    view: vpnte_winnet::registry::View,
) -> windows::core::Result<Vec<InstalledApp>> {
    use vpnte_winnet::registry::{Access, Key, Value};
    let Some(root) = Key::open(hive, UNINSTALL, Access::Read, view)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for name in root.subkey_names()? {
        let Ok(Some(key)) = root.open_subkey(&name, Access::Read) else {
            continue;
        };
        // REG_EXPAND_SZ values (`%ProgramFiles%\…`) are expanded, plain strings are not.
        let text = |v: &str| match key.value(v) {
            Ok(Some(Value::Sz(s))) => Some(s.trim().to_owned()),
            Ok(Some(Value::ExpandSz(s))) => Some(expand_env(s.trim())),
            _ => None,
        };
        let Some(display) = text("DisplayName").filter(|s| !s.is_empty()) else {
            continue;
        };
        let location = text("InstallLocation");
        let icon = text("DisplayIcon");
        if let Some(app) = uninstall_app(
            &display,
            location.as_deref(),
            icon.as_deref(),
            &|p| p.is_file(),
            &list_exes,
        ) {
            out.push(app);
        }
    }
    Ok(out)
}

/// The executable of one Uninstall entry: `DisplayIcon` when it is an existing `.exe` that is
/// not a helper and a usable absolute path (the old "first exe in the folder" often picked
/// `unins000.exe`), else the main exe of `InstallLocation` by the product-name heuristic.
fn uninstall_app(
    display: &str,
    location: Option<&str>,
    icon: Option<&str>,
    exists: &dyn Fn(&Path) -> bool,
    exes_in: &dyn Fn(&Path) -> Vec<PathBuf>,
) -> Option<InstalledApp> {
    let from_icon = icon.map(icon_path).and_then(|p| {
        let path = Path::new(&p);
        let usable = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("exe"))
            && !is_helper(path)
            && exists(path);
        usable.then(|| AppPath::parse(&p).ok()).flatten()
    });
    let path = match from_icon {
        Some(p) => p,
        None => {
            // Some installers write the folder quoted.
            let dir = location?.trim().trim_matches('"').trim_end_matches('\\');
            if dir.is_empty() {
                return None;
            }
            let main = pick_main(&exes_in(Path::new(dir)), display)?;
            if !exists(&main) {
                return None;
            }
            AppPath::parse(&main.to_string_lossy()).ok()?
        }
    };
    Some(InstalledApp {
        name: sanitize_name(display, path.as_str()),
        path,
    })
}

/// `"C:\Foo, Inc\app.exe",0` → `C:\Foo, Inc\app.exe`: only a trailing `,<index>` is an icon
/// index (the old code cut at the first comma and lost such paths).
fn icon_path(icon: &str) -> String {
    let s = icon.trim();
    let s = match s.rsplit_once(',') {
        Some((head, idx))
            if {
                let idx = idx.trim();
                let digits = idx.strip_prefix('-').unwrap_or(idx);
                !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
            } =>
        {
            head
        }
        _ => s,
    };
    s.trim().trim_matches('"').trim().to_owned()
}

/// `%NAME%` → the variable's value; unknown names stay as written (like
/// `ExpandEnvironmentStringsW`).
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = &after[..end];
        match std::env::var(name).ok().filter(|_| !name.is_empty()) {
            Some(value) => {
                out.push_str(&value);
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests;
