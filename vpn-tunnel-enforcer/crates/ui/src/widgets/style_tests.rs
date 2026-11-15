//! Source tests over every stylesheet under `assets/css` (p-ux-frame, the owner's findings of
//! 15.11.2026): the strip has no CSS drag region, floating surfaces share one quiet treatment
//! instead of hard offset shadows, and a hover never repaints a selected item.
use std::fs;
use std::path::Path;

/// One style rule: where it is, its selector list, its declarations (property in lower case).
struct Rule {
    file: String,
    selectors: Vec<String>,
    decls: Vec<(String, String)>,
}

impl Rule {
    fn get(&self, prop: &str) -> Option<&str> {
        self.decls
            .iter()
            .rev()
            .find(|(p, _)| p == prop)
            .map(|(_, v)| v.as_str())
    }
}

/// Every stylesheet the app loads: `assets/css/*.css` and `assets/css/pages/*.css`.
fn sheets() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/css");
    let mut out = Vec::new();
    for dir in [root.clone(), root.join("pages")] {
        for entry in fs::read_dir(&dir).expect("css dir") {
            let path = entry.expect("css entry").path();
            if path.extension().is_some_and(|e| e == "css") {
                let text = fs::read_to_string(&path).expect("css file");
                let name = path
                    .strip_prefix(&root)
                    .expect("under css")
                    .display()
                    .to_string();
                out.push((name, text));
            }
        }
    }
    assert!(out.len() > 10, "stylesheets found: {}", out.len());
    out
}

fn strip_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        rest = rest[start + 2..]
            .find("*/")
            .map_or("", |end| &rest[start + 2 + end + 2..]);
    }
    out.push_str(rest);
    out
}

/// `text` split at `sep` outside parentheses, brackets and quotes.
fn split_top(text: &str, sep: char) -> Vec<String> {
    let (mut parts, mut cur, mut depth, mut quote) = (Vec::new(), String::new(), 0i32, None);
    for ch in text.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (None, '(' | '[') => depth += 1,
            (None, ')' | ']') => depth -= 1,
            (None, c) if c == sep && depth == 0 => {
                parts.push(cur.trim().to_owned());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_owned());
    }
    parts
}

/// Style rules of `css` in source order; `@media` / `@supports` blocks are read through,
/// `@keyframes` / `@font-face` skipped.
fn parse(file: &str, css: &str, out: &mut Vec<Rule>) {
    let mut rest = css;
    while let Some(open) = rest.find('{') {
        let mut depth = 0;
        let close = rest[open..]
            .char_indices()
            .find_map(|(i, c)| {
                depth += match c {
                    '{' => 1,
                    '}' => -1,
                    _ => 0,
                };
                (depth == 0).then_some(open + i)
            })
            .unwrap_or(rest.len() - 1);
        let prelude = rest[..open].rsplit(';').next().unwrap_or_default().trim();
        let block = &rest[open + 1..close];
        if prelude.starts_with("@media") || prelude.starts_with("@supports") {
            parse(file, block, out);
        } else if !prelude.starts_with('@') {
            let decls = split_top(block, ';')
                .into_iter()
                .filter_map(|d| {
                    let (p, v) = d.split_once(':')?;
                    let v = v.trim().trim_end_matches("!important").trim();
                    Some((p.trim().to_ascii_lowercase(), v.to_owned()))
                })
                .collect();
            out.push(Rule {
                file: file.to_owned(),
                selectors: split_top(prelude, ','),
                decls,
            });
        }
        rest = &rest[close + 1..];
    }
}

fn rules() -> Vec<Rule> {
    let mut out = Vec::new();
    for (name, text) in sheets() {
        parse(&name, &strip_comments(&text), &mut out);
    }
    out
}

fn rules_of(css: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    parse("inline.css", &strip_comments(css), &mut out);
    out
}

/// The compound selectors of `selector`, split at combinators outside parentheses and brackets.
fn compounds(selector: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), 0i32);
    for ch in selector.chars() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ' ' | '>' | '+' | '~' if depth == 0 => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `compound` without its `:not(…)` groups, and the text inside those groups.
fn split_not(compound: &str) -> (String, String) {
    let (mut outside, mut inside, mut rest) = (String::new(), String::new(), compound);
    while let Some(at) = rest.find(":not(") {
        outside.push_str(&rest[..at]);
        let body = &rest[at + 5..];
        let mut depth = 1;
        let end = body
            .char_indices()
            .find_map(|(i, c)| {
                depth += match c {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
                (depth == 0).then_some(i)
            })
            .unwrap_or(body.len());
        inside.push_str(&body[..end]);
        inside.push(' ');
        rest = body.get(end + 1..).unwrap_or_default();
    }
    outside.push_str(rest);
    (outside, inside)
}

/// Selected, pressed and current states, with the name a `:not(…)` uses to leave them alone.
const STATES: [(&str, &str); 10] = [
    (".is-on", "is-on"),
    (".is-active", "is-active"),
    (".is-selected", "is-selected"),
    (".is-current", "is-current"),
    (".is-checked", "is-checked"),
    ("[aria-pressed='true']", "aria-pressed"),
    ("[aria-selected='true']", "aria-selected"),
    ("[aria-checked='true']", "aria-checked"),
    ("[aria-current", "aria-current"),
    (":checked", "checked"),
];

fn has_token(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(i, _)| {
        !text[i + token.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn state_of(compound: &str) -> Option<&'static str> {
    let (outside, _) = split_not(compound);
    STATES
        .iter()
        .find(|(token, _)| has_token(&outside, token))
        .map(|(_, name)| *name)
}

fn interactive(compound: &str) -> bool {
    let (outside, _) = split_not(compound);
    [":hover", ":active", ":focus"]
        .iter()
        .any(|p| outside.contains(p))
}

/// Type and component class names of `compound`: `is-*` modifiers (states, `is-danger`…) are
/// shared by unrelated components, so they never tie two rules to one element.
fn names(compound: &str) -> Vec<String> {
    let (outside, _) = split_not(compound);
    let ident = |s: &str| -> String {
        s.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect()
    };
    let mut out: Vec<String> = Some(ident(&outside))
        .filter(|t| !t.is_empty())
        .into_iter()
        .collect();
    for part in outside.split('.').skip(1) {
        let class = ident(part);
        if !class.is_empty() && !class.starts_with("is-") {
            out.push(class);
        }
    }
    out
}

fn pseudo_element(compound: &str) -> Option<&str> {
    compound.split_once("::").map(|(_, p)| p)
}

/// Text colour and fill a rule sets, normalised.
fn colours(rule: &Rule) -> Vec<(&'static str, String)> {
    let norm = |v: &str| {
        v.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    };
    rule.decls
        .iter()
        .filter_map(|(p, v)| match p.as_str() {
            "color" => Some(("color", norm(v))),
            "background" | "background-color" => Some(("background", norm(v))),
            _ => None,
        })
        .collect()
}

/// Classes whose hover over `.is-on` is designed: the start page's power button shows its stop
/// look as `.is-on` and wipes in the action colour on hover («Пломба»), readable in both themes.
const DESIGNED: [&str; 1] = ["swiss-power"];

/// Every hover / active / focus rule that would repaint a selected, pressed or current item: it
/// reaches the same element as the state rule, does not leave the state out with `:not(…)`, and
/// sets another text colour or fill than the state does.
fn hover_conflicts(rules: &[Rule]) -> Vec<String> {
    let shares = |a: &str, b: &str| names(a).iter().any(|n| names(b).contains(n));
    let mut bad = Vec::new();
    for s in rules {
        let s_colours = colours(s);
        for s_sel in s.selectors.iter().filter(|_| !s_colours.is_empty()) {
            let sc = compounds(s_sel);
            let Some(s_subject) = sc.last() else { continue };
            // a rule that styles a hover itself is a hover look, not a resting state
            if sc.iter().any(|c| interactive(c))
                || names(s_subject)
                    .iter()
                    .any(|n| DESIGNED.contains(&n.as_str()))
            {
                continue;
            }
            for (s_at, state) in sc.iter().filter_map(|c| Some((c, state_of(c)?))) {
                for h in rules {
                    let h_colours = colours(h);
                    for h_sel in h.selectors.iter().filter(|_| !h_colours.is_empty()) {
                        let hc = compounds(h_sel);
                        let (Some(h_at), Some(h_subject)) =
                            (hc.iter().find(|c| interactive(c)), hc.last())
                        else {
                            continue;
                        };
                        // styled together with the state: that is the state's own hover look
                        if hc.iter().any(|c| state_of(c) == Some(state))
                            || split_not(h_at).1.contains(state)
                            || !shares(s_at, h_at)
                            || !shares(s_subject, h_subject)
                            || pseudo_element(s_subject) != pseudo_element(h_subject)
                        {
                            continue;
                        }
                        for (key, value) in &s_colours {
                            if let Some((_, hv)) = h_colours.iter().rev().find(|(k, _)| k == key)
                                && hv != value
                            {
                                bad.push(format!(
                                    "{}: `{h_sel}` sets {key} {hv} over {}: `{s_sel}` ({value})",
                                    h.file, s.file
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    bad
}

/// The owner's Logs page (15.11.2026): the hovered selected source button «Приложение» turned
/// ink on ink. No stylesheet repaints a selected item under the pointer, in either theme.
#[test]
fn hover_keeps_selected_colours() {
    let bad = hover_conflicts(&rules());
    assert!(
        bad.is_empty(),
        "a hover repaints a selected item:\n{}",
        bad.join("\n")
    );
}

/// The checker finds the original mistake and accepts its fix.
#[test]
fn hover_checker_finds_the_segmented_mistake() {
    let old = ".w-seg-item:hover:not(:disabled) { color: var(--ink); }
        .w-seg-item.is-on { background: var(--ink); color: var(--paper); }";
    assert_eq!(hover_conflicts(&rules_of(old)).len(), 1);
    let fixed = old.replace(":not(:disabled)", ":not(:disabled, .is-on)");
    assert!(hover_conflicts(&rules_of(&fixed)).is_empty());
    let same = ".a:hover { color: var(--ink); } .a[aria-current='page'] { color: var(--ink); }";
    assert!(hover_conflicts(&rules_of(same)).is_empty());
    let row = ".t tr:hover > .td { background: var(--rule); }
        .t tr.is-selected > .td { background: var(--ink); }";
    assert_eq!(hover_conflicts(&rules_of(row)).len(), 1);
}

/// Every outer shadow of `rule` that is a hard offset band (an offset without blur).
fn hard_shadows(rule: &Rule) -> Vec<String> {
    let Some(value) = rule.get("box-shadow") else {
        return Vec::new();
    };
    split_top(value, ',')
        .into_iter()
        .filter(|shadow| {
            if shadow.contains("inset") || shadow.starts_with("var(") || shadow == "none" {
                return false;
            }
            let px: Vec<f64> = shadow
                .split_whitespace()
                .map_while(|w| w.strip_suffix("px").unwrap_or(w).parse().ok())
                .collect();
            let at = |i: usize| px.get(i).copied().unwrap_or(0.0);
            at(2) == 0.0 && (at(0) != 0.0 || at(1) != 0.0)
        })
        .collect()
}

/// The owner's «серо-белые полосы» on the links dialog (15.11.2026) were hard offset shadows.
#[test]
fn no_hard_offset_shadows() {
    let bad: Vec<String> = rules()
        .iter()
        .flat_map(|r| {
            hard_shadows(r)
                .into_iter()
                .map(|s| format!("{} {:?}: {s}", r.file, r.selectors))
        })
        .collect();
    assert!(bad.is_empty(), "hard offset shadows:\n{}", bad.join("\n"));
    let old = rules_of(".m { box-shadow: 8px 8px 0 var(--rule); }");
    assert_eq!(
        hard_shadows(&old[0]).len(),
        1,
        "the checker sees the old modal shadow"
    );
}

/// Floating surfaces take the one quiet treatment, defined once per theme in swiss.css.
#[test]
fn floating_surfaces_share_one_treatment() {
    let rules = rules();
    for surface in [
        ".w-modal",
        ".w-select-pop",
        ".swiss-toast",
        ".srv-menu-pop",
        ".set-savebar",
    ] {
        let rule = rules
            .iter()
            .find(|r| r.selectors.iter().any(|s| s == surface) && r.get("box-shadow").is_some())
            .unwrap_or_else(|| panic!("{surface} has no shadow rule"));
        assert_eq!(
            rule.get("box-shadow"),
            Some("var(--float-shadow)"),
            "{surface}"
        );
        assert_eq!(
            rule.get("background"),
            Some("var(--float-paper)"),
            "{surface}"
        );
        assert_eq!(
            rule.get("border"),
            Some("1px solid var(--rule)"),
            "{surface}"
        );
    }
    let defined: Vec<&str> = rules
        .iter()
        .filter(|r| r.get("--float-shadow").is_some() && r.get("--float-paper").is_some())
        .map(|r| r.file.as_str())
        .collect();
    assert_eq!(
        defined,
        ["swiss.css", "swiss.css"],
        "light and dark, nowhere else"
    );
}

/// The strip moves the window through Windows' move loop (shell.rs); a CSS drag region would take
/// its press away from the page in WebView2, so no stylesheet declares one.
#[test]
fn no_css_drag_region() {
    for (name, text) in sheets() {
        assert!(!strip_comments(&text).contains("app-region"), "{name}");
    }
}
