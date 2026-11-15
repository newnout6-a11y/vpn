//! Marker-delimited blocks we own inside user files (`gradle.properties`, Android Studio
//! `studio64.exe.vmoptions`), and the line-exact removal of the old app's Gradle leftovers.
//!
//! Only the block changes; every other byte of the file is kept, so a user edit made while the
//! block was in place survives the rollback (the old whole-file backup lost it, spec G2 / D-06).
//! Gradle reads `gradle.properties` top to bottom and later keys win, so a block appended at the
//! end shadows the user's own proxy lines only while it is there.
use std::io;
use std::path::Path;

use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::write_atomic;

use super::endpoint::host_bare;
use super::journal::{BlockKind, Val};

/// No `127.*`: Java matches the glob against host names too, so `127.0.0.1.t.example` would go
/// around the proxy (as Chromium did with `192.168.*`); the rest of loopback reaches the engine,
/// which sends it direct.
const GRADLE_NON_PROXY: &str = "systemProp.http.nonProxyHosts=localhost|127.0.0.1|[::1]";
/// The old app's last line of each block it wrote (only recognised, never written).
const LEGACY_GRADLE_NON_PROXY: &str = "systemProp.http.nonProxyHosts=localhost|127.*|[::1]";
const VM_NON_PROXY: &str = "-Dhttp.nonProxyHosts=localhost|127.0.0.1";
/// The old app's Gradle header (its blocks had no end marker).
const LEGACY_GRADLE_HEADER: &str = "# VPN Tunnel Enforcer";
const GRADLE_KEYS: [&str; 7] = [
    "systemProp.socksProxyHost",
    "systemProp.socksProxyPort",
    "systemProp.http.proxyHost",
    "systemProp.http.proxyPort",
    "systemProp.https.proxyHost",
    "systemProp.https.proxyPort",
    "systemProp.http.nonProxyHosts",
];
const VM_KEYS: [&str; 7] = [
    "-DsocksProxyHost",
    "-DsocksProxyPort",
    "-Dhttp.proxyHost",
    "-Dhttp.proxyPort",
    "-Dhttps.proxyHost",
    "-Dhttps.proxyPort",
    "-Dhttp.nonProxyHosts",
];

fn markers(kind: BlockKind) -> (&'static str, &'static str) {
    match kind {
        BlockKind::Gradle => (
            "# >>> VPN Tunnel Enforcer (managed) >>>",
            "# <<< VPN Tunnel Enforcer <<<",
        ),
        BlockKind::VmOptions => ("# VPN-Tunnel-Enforcer", "# /VPN-Tunnel-Enforcer"),
    }
}

/// The block for `addr` (`\n` line ends, final newline). SOCKS and HTTP use different JVM property
/// families: a SOCKS port behind `http.proxyHost` (or the reverse) silently breaks every download.
pub fn render(kind: BlockKind, addr: &HostPort, proxy: ProxyKind) -> String {
    let (begin, end) = markers(kind);
    let (host, port) = (host_bare(addr), addr.port());
    let (prefix, non_proxy) = match kind {
        BlockKind::Gradle => ("systemProp.", GRADLE_NON_PROXY),
        BlockKind::VmOptions => ("-D", VM_NON_PROXY),
    };
    let props: &[&str] = match proxy {
        ProxyKind::Socks5 => &["socksProxy"],
        ProxyKind::Http => &["http.proxy", "https.proxy"],
    };
    let mut out = format!("{begin}\n");
    for p in props {
        out.push_str(&format!("{prefix}{p}Host={host}\n{prefix}{p}Port={port}\n"));
    }
    out.push_str(&format!("{non_proxy}\n{end}\n"));
    out
}

/// Whether `text` is a block of ours: the markers around managed `key=value` lines only.
pub fn is_block(kind: BlockKind, text: &str) -> bool {
    let (begin, end) = markers(kind);
    let keys: &[&str] = match kind {
        BlockKind::Gradle => &GRADLE_KEYS,
        BlockKind::VmOptions => &VM_KEYS,
    };
    let lines: Vec<&str> = text.lines().collect();
    lines.len() >= 3
        && lines.first() == Some(&begin)
        && lines.last() == Some(&end)
        && lines[1..lines.len() - 1]
            .iter()
            .all(|l| is_property(l, keys))
}

/// A line the old app wrote into `gradle.properties` (its header or a managed key).
pub fn is_legacy_gradle_line(line: &str) -> bool {
    line == LEGACY_GRADLE_HEADER || is_property(line, &GRADLE_KEYS)
}

fn is_property(line: &str, keys: &[&str]) -> bool {
    line.split_once('=').is_some_and(|(k, v)| {
        keys.contains(&k)
            && !v.is_empty()
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_:|*[]".contains(&b))
    })
}

/// A file split into lines: byte range including the line end, and the text without it.
fn lines(content: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < content.len() {
        let end = content[start..]
            .find('\n')
            .map_or(content.len(), |i| start + i + 1);
        let text = content[start..end].trim_end_matches(['\n', '\r']);
        out.push((start, end, text));
        start = end;
    }
    out
}

pub(crate) fn malformed(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}

/// Byte range of our block. Two blocks, or a marker without its partner, is not ours to guess
/// about: an error (no write).
fn find(kind: BlockKind, content: &str) -> io::Result<Option<(usize, usize)>> {
    let (begin, end) = markers(kind);
    let mut found = None;
    let mut open = None;
    for (start, stop, text) in lines(content) {
        if text == begin {
            if open.is_some() || found.is_some() {
                return Err(malformed("repeated block marker"));
            }
            open = Some(start);
        } else if text == end {
            let start = open
                .take()
                .ok_or_else(|| malformed("block end without start"))?;
            found = Some((start, stop));
        }
    }
    if open.is_some() {
        return Err(malformed("block start without end"));
    }
    Ok(found)
}

/// File content, `None` when the file does not exist.
pub(crate) fn load(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| malformed("not UTF-8")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn eol(content: &str) -> &'static str {
    if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Our block in `path` as `Val::Text` (`\n` line ends), `Val::Absent` without block or file.
pub fn read(kind: BlockKind, path: &Path) -> io::Result<Val> {
    let Some(content) = load(path)? else {
        return Ok(Val::Absent);
    };
    Ok(match find(kind, &content)? {
        Some((start, stop)) => Val::Text(
            lines(&content[start..stop])
                .iter()
                .map(|(_, _, text)| format!("{text}\n"))
                .collect(),
        ),
        None => Val::Absent,
    })
}

/// Puts the block in place (replacing ours, else appended) or removes it (`Val::Absent`), keeping
/// the file's line ends. Returns `true` when the file had to be created. `create = false` refuses
/// to create a missing file (an Android Studio `.vmoptions` that only held our block would
/// replace the IDE's own options on older launchers).
pub fn write(kind: BlockKind, path: &Path, value: &Val, create: bool) -> io::Result<bool> {
    let existing = load(path)?;
    let created = existing.is_none();
    let content = existing.unwrap_or_default();
    let range = find(kind, &content)?;
    let next = match value {
        Val::Text(block) if is_block(kind, block) => {
            if created && !create {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "refusing to create the file",
                ));
            }
            let eol = eol(&content);
            let rendered: String = block.lines().map(|l| format!("{l}{eol}")).collect();
            match range {
                Some((start, stop)) => {
                    format!("{}{rendered}{}", &content[..start], &content[stop..])
                }
                None if content.is_empty() || content.ends_with('\n') => {
                    format!("{content}{rendered}")
                }
                None => format!("{content}{eol}{rendered}"),
            }
        }
        Val::Absent => match range {
            Some((start, stop)) => format!("{}{}", &content[..start], &content[stop..]),
            None => return Ok(false),
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a managed block",
            ));
        }
    };
    if next != content {
        write_atomic(path, next.as_bytes())?;
    }
    Ok(created)
}

/// Deletes the file when nothing but whitespace is left in it.
pub fn prune(path: &Path) -> io::Result<()> {
    match load(path)? {
        Some(content) if content.trim().is_empty() => std::fs::remove_file(path),
        _ => Ok(()),
    }
}

/// Legacy lines: `Val::Text` (all of `wanted`, `\n`-joined) while any of them is still in the
/// file, `Val::Absent` when none is.
pub fn read_lines(path: &Path, wanted: &[String]) -> io::Result<Val> {
    let Some(content) = load(path)? else {
        return Ok(Val::Absent);
    };
    let present = lines(&content)
        .iter()
        .any(|(_, _, text)| wanted.iter().any(|w| w == text));
    Ok(if present {
        Val::Text(wanted.join("\n"))
    } else {
        Val::Absent
    })
}

/// Deletes every occurrence of each of `wanted` and nothing else.
pub fn remove_lines(path: &Path, wanted: &[String]) -> io::Result<()> {
    let Some(content) = load(path)? else {
        return Ok(());
    };
    let next: String = lines(&content)
        .into_iter()
        .filter(|(_, _, text)| !wanted.iter().any(|w| w == text))
        .map(|(start, stop, _)| &content[start..stop])
        .collect();
    if next != content {
        write_atomic(path, next.as_bytes())?;
    }
    Ok(())
}

/// The old app's Gradle lines in `content` (legacy import, spec §6.8). Its strip rule removed
/// only the header, so repeated applies left headerless `systemProp.*` runs behind. With the old
/// whole-file backup at hand, ours = every old header plus every managed-key line that the
/// backup does not have; without it, ours = headers, the managed-key lines right after a header,
/// and every run of managed-key lines ending with the non-proxy line (every old block ended so).
pub fn legacy_gradle_lines(content: &str, backup: Option<&str>) -> Vec<String> {
    let texts: Vec<&str> = lines(content).iter().map(|(_, _, t)| *t).collect();
    let managed = |t: &str| is_property(t, &GRADLE_KEYS);
    let mut ours = vec![false; texts.len()];
    match backup {
        Some(backup) => {
            let kept: Vec<&str> = lines(backup).iter().map(|(_, _, t)| *t).collect();
            for (i, t) in texts.iter().enumerate() {
                ours[i] = *t == LEGACY_GRADLE_HEADER || (managed(t) && !kept.contains(t));
            }
        }
        None => {
            let mut i = 0;
            while i < texts.len() {
                if texts[i] == LEGACY_GRADLE_HEADER {
                    ours[i] = true;
                    i += 1;
                    while i < texts.len() && managed(texts[i]) {
                        ours[i] = true;
                        i += 1;
                    }
                    continue;
                }
                let run = texts[i..].iter().take_while(|t| managed(t)).count();
                if run > 0 && texts[i + run - 1] == LEGACY_GRADLE_NON_PROXY {
                    ours[i..i + run].iter_mut().for_each(|o| *o = true);
                }
                i += run.max(1);
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for (t, _) in texts.iter().zip(&ours).filter(|(_, o)| **o) {
        if !out.iter().any(|o| o == t) {
            out.push((*t).to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests;
