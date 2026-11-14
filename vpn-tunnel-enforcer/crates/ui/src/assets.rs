//! Embedded UI assets served from memory through the `app` custom protocol, and the index page.
//!
//! wry maps the protocol `app` to `http://app.localhost/<path>` on Windows (WebView2 has no custom
//! schemes). The page itself lives at `http://dioxus.index.html/`, so fonts, which are always CORS
//! fetches, need `Access-Control-Allow-Origin`. Works with plain `cargo build`: no `dx`, no
//! `asset!()`, no files next to the exe.
use std::borrow::Cow;
use std::path::Path;

use dioxus::desktop::wry::WebViewId;
use dioxus::desktop::wry::http::{Request, Response, StatusCode, header};
use include_dir::{Dir, File, include_dir};
use vpnte_base::i18n::Lang;

use crate::theme::{Scheme, Theme, vars_css};

/// Everything under `crates/ui/assets/` (`build.rs` makes cargo rebuild when files change).
static ASSETS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/assets");

/// Origin of the embedded files.
pub const ORIGIN: &str = "http://app.localhost";

/// Content-Security-Policy of the page.
///
/// WHY: dioxus-desktop's own `dioxus://` handler falls back to serving ANY existing local path
/// (`fetch('/Windows/win.ini')` returned the file in the spike, and `//host/share` makes the
/// process open a UNC path). The CSP stops such requests in the renderer. The exact-path
/// `connect-src` entries keep dioxus' sync XHR (`//__events`, `//__file_dialog`) and its edits
/// WebSocket working; `'unsafe-inline'` is required by dioxus' injected module script (it carries
/// a per-run key, so no hash) and by `style:` attributes. The WebView itself does no network I/O.
pub const CSP: &str = "default-src 'none'; \
    script-src http://app.localhost 'unsafe-inline'; \
    style-src http://app.localhost 'unsafe-inline'; \
    font-src http://app.localhost; \
    img-src http://app.localhost data:; \
    connect-src http://dioxus.index.html//__events http://dioxus.index.html//__file_dialog ws://127.0.0.1:*; \
    base-uri 'none'; form-action 'none'; frame-src 'none'; object-src 'none'";

/// Stylesheets before the page CSS, in cascade order: swiss.css comes first exactly as in the old
/// bundle, so equal-specificity conflicts with the Tailwind-derived files resolve the same way.
const STYLESHEETS: [&str; 4] = [
    "css/swiss.css",
    "css/base.css",
    "css/utilities.css",
    "css/widgets.css",
];

/// An embedded file by its path under `assets/`, e.g. `css/base.css`.
pub fn file(path: &str) -> Option<&'static [u8]> {
    ASSETS.get_file(path).map(File::contents)
}

/// Every embedded file directly in `dir` with extension `ext`, sorted by name.
fn files_in(dir: &str, ext: &str) -> Vec<&'static str> {
    let mut paths: Vec<&'static str> = ASSETS
        .get_dir(dir)
        .into_iter()
        .flat_map(Dir::files)
        .filter(|f| f.path().extension().is_some_and(|e| e == ext))
        .filter_map(|f| f.path().to_str())
        .collect();
    paths.sort_unstable();
    paths
}

/// The embedded file a request path names. Stylesheets copied verbatim from the old bundle
/// reference fonts as `assets/fonts/…` relative to themselves, i.e. `/css/assets/fonts/…`: the
/// embedded directory *is* `assets/`, so a path naming it is resolved after its last `assets`
/// segment.
fn resolve(path: &str) -> Option<&'static File<'static>> {
    let rel = path.trim_start_matches('/');
    ASSETS.get_file(rel).or_else(|| {
        let segments: Vec<&str> = rel.split('/').collect();
        let at = segments.iter().rposition(|s| *s == "assets")?;
        ASSETS.get_file(segments[at + 1..].join("/"))
    })
}

fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// `Config::with_custom_protocol("app", serve)`. Runs on the UI thread, so it only borrows.
pub fn serve(_id: WebViewId, req: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    let path = req.uri().path();
    let response = match resolve(path) {
        Some(file) => Response::builder()
            .header(header::CONTENT_TYPE, mime(file.path()))
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            // The WebView2 profile keeps its HTTP cache across runs; a new build must not be
            // served last build's stylesheet.
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Cow::Borrowed(file.contents())),
        None => {
            tracing::warn!(path, "app:// 404");
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Cow::Borrowed(&b"not found"[..]))
        }
    };
    // The builder only fails on invalid header values; ours are constants.
    response.unwrap_or_else(|_| Response::new(Cow::Borrowed(&[][..])))
}

/// Resolves a stylesheet-relative `url()` the way the browser does: against the directory of
/// `sheet`, `..` and `.` folded, `/…` taken from the origin root.
fn resolve_url(sheet: &str, url: &str) -> String {
    let mut segments: Vec<&str> = if url.starts_with('/') {
        Vec::new()
    } else {
        let mut dir: Vec<&str> = sheet.split('/').collect();
        dir.pop();
        dir
    };
    for part in url.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(part),
        }
    }
    segments.join("/")
}

/// Fonts the stylesheets load (`@font-face` `url()`s), as paths on [`ORIGIN`]. Preloading them
/// lets the first layout use them: with `font-display: swap` the first frame would otherwise show
/// Segoe UI and the big status word would be fitted twice.
fn font_paths(sheets: &[&str]) -> Vec<String> {
    const FONT_EXTS: [&str; 4] = [".ttf", ".otf", ".woff2", ".woff"];
    let mut out: Vec<String> = Vec::new();
    for sheet in sheets {
        let Some(css) = ASSETS.get_file(sheet).and_then(File::contents_utf8) else {
            continue;
        };
        for chunk in css.split("url(").skip(1) {
            let Some(end) = chunk.find(')') else { continue };
            let url = chunk[..end].trim().trim_matches(['\'', '"']);
            if url.starts_with("data:") || !FONT_EXTS.iter().any(|e| url.ends_with(e)) {
                continue;
            }
            let path = resolve_url(sheet, url);
            if !out.contains(&path) {
                out.push(path);
            }
        }
    }
    out
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The index page (`Config::with_custom_index`): CSP; `lang` and `data-theme` on `<html>`; the
/// palette block and the paper background already in place for the first frame; fonts preloaded;
/// stylesheets linked in cascade order (swiss, base, utilities, widgets, then `css/pages/*.css` by
/// name), each only if it is embedded; `js/*.js` by name. dioxus inserts its loader before
/// `</body>` and mounts into `<div id="main">`.
pub fn index_html(title: &str, lang: Lang, theme: &Theme, scheme: Scheme) -> String {
    let pages = files_in("css/pages", "css");
    let sheets: Vec<&str> = STYLESHEETS
        .iter()
        .copied()
        .filter(|s| ASSETS.contains(s))
        .chain(pages)
        .collect();
    let mut head = String::new();
    for font in font_paths(&sheets) {
        let ext = font.rsplit('.').next().unwrap_or("ttf");
        head.push_str(&format!(
            "<link rel=\"preload\" href=\"{ORIGIN}/{font}\" as=\"font\" type=\"font/{ext}\" crossorigin>\n"
        ));
    }
    for sheet in &sheets {
        head.push_str(&format!(
            "<link rel=\"stylesheet\" href=\"{ORIGIN}/{sheet}\" crossorigin>\n"
        ));
    }
    for script in files_in("js", "js") {
        head.push_str(&format!(
            "<script src=\"{ORIGIN}/{script}\" defer crossorigin></script>\n"
        ));
    }
    format!(
        r#"<!DOCTYPE html>
<html lang="{lang}" data-theme="{scheme}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>html,body{{margin:0;height:100%;overflow:hidden;background:{paper}}}</style>
<style id="theme-vars">{vars}</style>
{head}</head>
<body><div id="main"></div></body>
</html>"#,
        lang = lang.code(),
        scheme = scheme.name(),
        title = escape_html(title),
        paper = scheme.paper().hex(),
        vars = vars_css(&theme.palette(scheme), scheme),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{Palette, ThemeMode};

    fn get(path: &str) -> Response<Cow<'static, [u8]>> {
        let req = Request::builder()
            .uri(format!("{ORIGIN}{path}"))
            .body(Vec::new())
            .unwrap();
        serve("main", req)
    }

    #[test]
    fn serves_embedded_files_with_cors() {
        let css = get("/css/swiss.css");
        assert_eq!(css.status(), StatusCode::OK);
        assert_eq!(
            css.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );
        assert!(css.body().starts_with(b"/* swiss.css"));
        // swiss.css says url('assets/fonts/…'), which resolves against /css/
        let font = get("/css/assets/fonts/InterTight-Variable.ttf");
        assert_eq!(font.status(), StatusCode::OK);
        assert_eq!(font.headers()[header::CONTENT_TYPE], "font/ttf");
        assert_eq!(font.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(
            font.body().len(),
            file("fonts/InterTight-Variable.ttf").unwrap().len()
        );
        assert_eq!(
            get("/fonts/JetBrainsMono-Variable.ttf").status(),
            StatusCode::OK
        );
        assert_eq!(
            get("/locales/ru.json").headers()[header::CONTENT_TYPE],
            "application/json"
        );
    }

    #[test]
    fn unknown_paths_are_not_found() {
        for path in [
            "/",
            "/nope.css",
            "/css/",
            "/../Cargo.toml",
            "/assets/",
            "/css/assets/../build.rs",
        ] {
            assert_eq!(get(path).status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// Every country the exit-IP detector reports (`ui.panels.country.*`) has a flag coin, and
    /// every flag file a rule names is embedded and served as SVG.
    #[test]
    fn every_detector_country_has_a_flag() {
        let css = std::str::from_utf8(file("css/utilities.css").unwrap()).unwrap();
        let panels: serde_json::Value =
            serde_json::from_str(include_str!("../locales/ui-panels.en.json")).unwrap();
        let countries = panels["ui"]["panels"]["country"].as_object().unwrap();
        assert_eq!(countries.len(), 65);
        for code in countries.keys() {
            let rule = format!(".fi-{}.fis", code.to_ascii_lowercase());
            assert!(css.contains(&rule), "{rule}");
        }
        for chunk in css.split("url(\"../flags/").skip(1) {
            let name = &chunk[..chunk.find('"').unwrap()];
            let svg = get(&format!("/flags/{name}"));
            assert_eq!(svg.status(), StatusCode::OK, "{name}");
            assert_eq!(svg.headers()[header::CONTENT_TYPE], "image/svg+xml");
        }
    }

    #[test]
    fn stylesheet_urls_resolve_like_the_browser() {
        assert_eq!(
            resolve_url("css/swiss.css", "assets/fonts/a.ttf"),
            "css/assets/fonts/a.ttf"
        );
        assert_eq!(
            resolve_url("css/pages/x.css", "../../fonts/a.ttf"),
            "fonts/a.ttf"
        );
        assert_eq!(
            resolve_url("css/pages/x.css", "./b.woff2"),
            "css/pages/b.woff2"
        );
        assert_eq!(resolve_url("css/base.css", "/fonts/a.ttf"), "fonts/a.ttf");
        assert_eq!(
            font_paths(&["css/swiss.css", "css/utilities.css"]),
            [
                "css/assets/fonts/InterTight-Variable.ttf",
                "css/assets/fonts/JetBrainsMono-Variable.ttf"
            ]
        );
    }

    /// ui-dashboard §2.16 / §2.18: the first frame already has the resolved theme, language,
    /// palette and paper background; stylesheets come in cascade order, each only if embedded.
    #[test]
    fn index_page_carries_everything_the_first_frame_needs() {
        let theme = Theme::builtin(ThemeMode::Dark);
        let html = index_html("A <b> & \"c\"", Lang::Ru, &theme, Scheme::Dark);
        assert!(html.contains(r#"<html lang="ru" data-theme="dark">"#));
        assert!(html.contains(&format!(r#"content="{CSP}""#)));
        assert!(html.contains("<title>A &lt;b&gt; &amp; &quot;c&quot;</title>"));
        assert!(html.contains("background:#1c1b18"));
        assert!(html.contains(&format!(
            r#"<style id="theme-vars">{}</style>"#,
            vars_css(&Palette::DARK, Scheme::Dark)
        )));
        assert!(
            html.contains(r#"<div id="main"></div>"#)
                && html.contains("</head>")
                && html.contains("</body>")
        );
        let font = format!(
            r#"<link rel="preload" href="{ORIGIN}/css/assets/fonts/InterTight-Variable.ttf" as="font" type="font/ttf" crossorigin>"#
        );
        assert!(html.contains(&font), "{html}");
        let links: Vec<&str> = html
            .match_indices(r#"rel="stylesheet" href=""#)
            .map(|(i, m)| {
                let rest = &html[i + m.len()..];
                &rest[..rest.find('"').unwrap()]
            })
            .collect();
        let mut expected: Vec<String> = STYLESHEETS
            .iter()
            .filter(|s| file(s).is_some())
            .chain(files_in("css/pages", "css").iter())
            .map(|s| format!("{ORIGIN}/{s}"))
            .collect();
        assert_eq!(links, expected);
        expected.truncate(3);
        assert_eq!(expected[0], format!("{ORIGIN}/css/swiss.css"));
        assert_eq!(expected[2], format!("{ORIGIN}/css/utilities.css"));
        for script in files_in("js", "js") {
            assert!(html.contains(&format!(
                r#"<script src="{ORIGIN}/{script}" defer crossorigin>"#
            )));
        }
    }

    #[test]
    fn light_index_uses_the_light_paper() {
        let html = index_html(
            "t",
            Lang::En,
            &Theme::builtin(ThemeMode::Light),
            Scheme::Light,
        );
        assert!(html.contains(r#"<html lang="en" data-theme="light">"#));
        assert!(html.contains("background:#f2f0eb"));
        assert!(html.contains("--rgb-bg:230 233 240;"));
    }
}
