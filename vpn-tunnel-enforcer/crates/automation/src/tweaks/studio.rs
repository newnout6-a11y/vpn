//! Android Studio target: the IDE proxy (`HttpConfigurable` in `options\proxy.settings.xml`, per
//! the owner decision; the old app used `other.xml`, F-120) of the newest installed version only,
//! plus the JVM proxy block in an existing `studio64.exe.vmoptions` (the First Run Wizard reads
//! only JVM properties). Each option is edited on its own, so `PROXY_EXCEPTIONS`, authentication
//! and anything else in the component survive (spec AS1). No install = not detected, nothing
//! created. The current-version file layout is inferred from public IntelliJ samples.
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::write_atomic;

use super::block;
use super::endpoint::host_bare;
use super::journal::{BlockKind, Feature, StudioOption, Target, Val};

static COMPONENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<component\s+name="HttpConfigurable"\s*(/?)>"#).expect("static regex")
});
static APP_EMPTY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<application\s*/>").expect("static regex"));

/// The newest `AndroidStudio<version>` directory under `root` (`%APPDATA%\Google`). Versions
/// compare numerically per component; a `Preview` sorts below the release of the same number.
pub fn newest_install(root: &Path) -> io::Result<Option<PathBuf>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut best: Option<((Vec<u32>, bool), PathBuf)> = None;
    for entry in entries {
        let entry = entry?;
        let Some(version) = entry.file_name().to_str().and_then(parse_version) else {
            continue;
        };
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, entry.path()));
        }
    }
    Ok(best.map(|(_, path)| path))
}

/// `AndroidStudio2024.2` → `([2024, 2], true)`; `AndroidStudioPreview2025.1` → `([2025, 1], false)`.
fn parse_version(name: &str) -> Option<(Vec<u32>, bool)> {
    let rest = name.strip_prefix("AndroidStudio")?;
    let (release, rest) = match rest.strip_prefix("Preview") {
        Some(rest) => (false, rest),
        None => (true, rest),
    };
    let parts = rest
        .split('.')
        .map(|p| p.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    Some((parts, release))
}

/// `<version dir>\options\proxy.settings.xml`.
pub fn settings_file(install: &Path) -> PathBuf {
    install.join("options").join("proxy.settings.xml")
}

/// `<version dir>\studio64.exe.vmoptions`.
pub fn vmoptions_file(install: &Path) -> PathBuf {
    install.join(BlockKind::VmOptions.file_name())
}

/// The four IDE options, and the JVM block when the user already has a vmoptions file.
pub fn plan(install: &Path, addr: &HostPort, kind: ProxyKind) -> Vec<(Feature, Target, Val)> {
    let path = settings_file(install);
    let socks = matches!(kind, ProxyKind::Socks5);
    let mut plan: Vec<_> = StudioOption::ALL
        .into_iter()
        .map(|option| {
            let value = match option {
                StudioOption::UseHttpProxy => "true".to_owned(),
                StudioOption::ProxyHost => host_bare(addr),
                StudioOption::ProxyPort => addr.port().to_string(),
                StudioOption::ProxyTypeIsSocks => socks.to_string(),
            };
            let target = Target::StudioOpt {
                path: path.clone(),
                option,
            };
            (Feature::DevStudio, target, Val::Text(value))
        })
        .collect();
    let vmoptions = vmoptions_file(install);
    if vmoptions.is_file() {
        let text = block::render(BlockKind::VmOptions, addr, kind);
        let target = Target::Block {
            kind: BlockKind::VmOptions,
            path: vmoptions,
        };
        plan.push((Feature::DevStudio, target, Val::Text(text)));
    }
    plan
}

/// The option's value (XML-unescaped), `Val::Absent` without option, component or file.
pub fn read_option(path: &Path, option: StudioOption) -> io::Result<Val> {
    let Some(content) = block::load(path)? else {
        return Ok(Val::Absent);
    };
    let Some(comp) = component(&content)? else {
        return Ok(Val::Absent);
    };
    let body = &content[comp.body.clone()];
    Ok(match find_option(body, option)? {
        Some((_, value)) => Val::Text(unescape(value)),
        None => Val::Absent,
    })
}

/// Sets or removes one option, creating the file (`true`) or the component when needed.
pub fn write_option(path: &Path, option: StudioOption, value: &Val) -> io::Result<bool> {
    let value = match value {
        Val::Text(v) => Some(v.as_str()),
        Val::Absent => None,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IDE options are text",
            ));
        }
    };
    let (content, created) = match (block::load(path)?, value) {
        (None, None) => return Ok(false),
        (None, Some(_)) => (
            format!("<application>\n{}</application>\n", empty_component("\n")),
            true,
        ),
        (Some(content), _) => (content, false),
    };
    let next = edit(&content, option, value)?;
    if created || next != content {
        write_atomic(path, next.as_bytes())?;
    }
    Ok(created)
}

/// Deletes a settings file that holds nothing but an empty `HttpConfigurable` component.
pub fn prune(path: &Path) -> io::Result<()> {
    let Some(content) = block::load(path)? else {
        return Ok(());
    };
    let rest = match component(&content)? {
        Some(c) if content[c.body.clone()].contains('<') => return Ok(()),
        Some(c) => format!("{}{}", &content[..c.start], &content[c.end..]),
        None => content.clone(),
    };
    let rest = rest.trim();
    let rest = match rest.strip_prefix("<?xml") {
        Some(decl) => decl.split_once("?>").map_or("", |(_, r)| r.trim()),
        None => rest,
    };
    let empty = rest
        .strip_prefix("<application>")
        .and_then(|r| r.strip_suffix("</application>"))
        .is_some_and(|inner| inner.trim().is_empty());
    if empty {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

struct Component {
    start: usize,
    /// Between the open and the close tag (empty and at the tag end when self-closing).
    body: std::ops::Range<usize>,
    end: usize,
    self_closing: bool,
}

fn component(content: &str) -> io::Result<Option<Component>> {
    let mut all = COMPONENT.captures_iter(content);
    let Some(caps) = all.next() else {
        return Ok(None);
    };
    if all.next().is_some() {
        return Err(block::malformed("two HttpConfigurable components"));
    }
    let open = caps.get(0).ok_or_else(|| block::malformed("no match"))?;
    if caps.get(1).is_some_and(|m| !m.is_empty()) {
        return Ok(Some(Component {
            start: open.start(),
            body: open.end()..open.end(),
            end: open.end(),
            self_closing: true,
        }));
    }
    let close = content[open.end()..]
        .find("</component>")
        .map(|i| open.end() + i)
        .ok_or_else(|| block::malformed("HttpConfigurable not closed"))?;
    if content[open.end()..close].contains("<component") {
        return Err(block::malformed("nested component"));
    }
    Ok(Some(Component {
        start: open.start(),
        body: open.end()..close,
        end: close + "</component>".len(),
        self_closing: false,
    }))
}

/// The option element's range in `body` and its raw value. Any other spelling of the same option
/// (a duplicate, a nested `<value>`) is not ours to guess about: an error, no write.
fn find_option(
    body: &str,
    option: StudioOption,
) -> io::Result<Option<(std::ops::Range<usize>, &str)>> {
    let name = option.name();
    let mentions = body.matches(&format!("name=\"{name}\"")).count();
    let re = Regex::new(&format!(
        r#"<option\s+name="{name}"\s+value="([^"]*)"\s*/>"#
    ))
    .map_err(io::Error::other)?;
    let found: Vec<_> = re.captures_iter(body).collect();
    match (mentions, found.as_slice()) {
        (0, []) => Ok(None),
        (1, [caps]) => match (caps.get(0), caps.get(1)) {
            (Some(all), Some(value)) => Ok(Some((all.range(), value.as_str()))),
            _ => Err(block::malformed("option without value")),
        },
        _ => Err(block::malformed("option not in the expected form")),
    }
}

fn empty_component(eol: &str) -> String {
    format!("  <component name=\"HttpConfigurable\">{eol}  </component>{eol}")
}

/// `content` with `option` set to `value` (`None` removes it).
fn edit(content: &str, option: StudioOption, value: Option<&str>) -> io::Result<String> {
    let eol = block::eol(content);
    let Some(comp) = component(content)? else {
        if value.is_none() {
            return Ok(content.to_owned());
        }
        return edit(&insert_component(content, eol)?, option, value);
    };
    if comp.self_closing {
        if value.is_none() {
            return Ok(content.to_owned());
        }
        let open = "<component name=\"HttpConfigurable\">";
        let expanded = format!(
            "{}{open}{eol}  </component>{}",
            &content[..comp.start],
            &content[comp.end..]
        );
        return edit(&expanded, option, value);
    }
    let base = comp.body.start;
    let element = |v: &str| {
        format!(
            "<option name=\"{}\" value=\"{}\" />",
            option.name(),
            escape(v)
        )
    };
    Ok(
        match (find_option(&content[comp.body.clone()], option)?, value) {
            (Some((range, _)), Some(v)) => format!(
                "{}{}{}",
                &content[..base + range.start],
                element(v),
                &content[base + range.end..]
            ),
            (Some((range, _)), None) => {
                let (start, end) = whole_line(content, base + range.start, base + range.end);
                format!("{}{}", &content[..start], &content[end..])
            }
            (None, Some(v)) => {
                let close = comp.body.end;
                let line_start = content[..close].rfind('\n').map_or(0, |i| i + 1);
                let indent = &content[line_start..close];
                if indent.trim().is_empty() {
                    format!(
                        "{}{indent}  {}{eol}{}",
                        &content[..line_start],
                        element(v),
                        &content[line_start..]
                    )
                } else {
                    format!("{}{}{}", &content[..close], element(v), &content[close..])
                }
            }
            (None, None) => content.to_owned(),
        },
    )
}

/// Extends `start..end` to its whole line when nothing else is on that line.
fn whole_line(content: &str, start: usize, end: usize) -> (usize, usize) {
    let line_start = content[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = content[end..]
        .find('\n')
        .map_or(content.len(), |i| end + i + 1);
    let alone =
        content[line_start..start].trim().is_empty() && content[end..line_end].trim().is_empty();
    if alone {
        (line_start, line_end)
    } else {
        (start, end)
    }
}

/// Adds an empty `HttpConfigurable` component to the application element; a file without one
/// is not an IDE settings file we understand.
fn insert_component(content: &str, eol: &str) -> io::Result<String> {
    let component = empty_component(eol);
    if let Some(close) = content.find("</application>") {
        let line_start = content[..close].rfind('\n').map_or(0, |i| i + 1);
        let at = if content[line_start..close].trim().is_empty() {
            line_start
        } else {
            close
        };
        return Ok(format!("{}{component}{}", &content[..at], &content[at..]));
    }
    let m = APP_EMPTY
        .find(content)
        .ok_or_else(|| block::malformed("no application element"))?;
    Ok(format!(
        "{}<application>{eol}{component}</application>{}",
        &content[..m.start()],
        &content[m.end()..]
    ))
}

fn escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape(v: &str) -> String {
    v.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests;
