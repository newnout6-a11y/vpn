//! Tiny i18next-compatible lookup over the app's JSON locale files.
//!
//! Supported (what `assets/locales/{ru,en}.json` use): nested keys addressed as `a.b.c`,
//! `{{var}}` interpolation, plural suffixes chosen by `count` with CLDR rules (ru: one/few/many/
//! other, en: one/other), fallback language `en`, a call-site default text, and finally the key.
//! The UI crate adds the reactive language signal and the `t!` macro on top of [`lookup`].
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub const FALLBACK: Lang = Lang::En;
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }
    /// Parses a locale tag such as `ru`, `ru-RU` or `en_US`.
    pub fn from_tag(tag: &str) -> Option<Lang> {
        match tag.get(..2)?.to_ascii_lowercase().as_str() {
            "ru" => Some(Lang::Ru),
            "en" => Some(Lang::En),
            _ => None,
        }
    }
}

type Catalog = HashMap<String, String>;

static CATALOGS: OnceLock<[Catalog; 2]> = OnceLock::new();

/// Registers the locale layers once at startup: each layer is a `(ru_json, en_json)` pair of
/// i18next-style documents; later layers override earlier ones (base UI file first, then one
/// fragment per crate).
pub fn init(layers: &[(&str, &str)]) {
    let mut ru = Catalog::new();
    let mut en = Catalog::new();
    for (ru_json, en_json) in layers {
        ru.extend(flatten(ru_json));
        en.extend(flatten(en_json));
    }
    let _ = CATALOGS.set([ru, en]);
}

fn catalog(lang: Lang) -> Option<&'static Catalog> {
    CATALOGS.get().map(|c| &c[lang as usize])
}

fn flatten(json: &str) -> Catalog {
    fn walk(prefix: &str, v: &serde_json::Value, out: &mut Catalog) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    walk(&key, v, out);
                }
            }
            serde_json::Value::String(s) => {
                out.insert(prefix.to_owned(), s.clone());
            }
            other => {
                out.insert(prefix.to_owned(), other.to_string());
            }
        }
    }
    let mut out = Catalog::new();
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => walk("", &value, &mut out),
        Err(err) => tracing::error!(%err, "locale file is not valid JSON; its keys are skipped"),
    }
    out
}

/// CLDR cardinal plural category (integers + decimals).
pub fn plural_category(lang: Lang, n: f64) -> &'static str {
    let integer = n.fract() == 0.0;
    match lang {
        Lang::En => {
            if n == 1.0 {
                "one"
            } else {
                "other"
            }
        }
        Lang::Ru => {
            if !integer {
                return "other";
            }
            let i = n.abs() as u64;
            let (m10, m100) = (i % 10, i % 100);
            if m10 == 1 && m100 != 11 {
                "one"
            } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
                "few"
            } else {
                "many"
            }
        }
    }
}

fn interpolate(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let name = after[..end].trim();
                match vars.iter().find(|(k, _)| *k == name) {
                    Some((_, v)) => out.push_str(v),
                    None => out.push_str(&rest[start..start + 2 + end + 2]), // keep unknown placeholder
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Pure lookup (no signal read) — used by tests and by `translate`.
pub fn lookup(lang: Lang, key: &str, vars: &[(&str, String)], default: Option<&str>) -> String {
    let count = vars
        .iter()
        .find(|(k, _)| *k == "count")
        .and_then(|(_, v)| v.parse::<f64>().ok());
    let langs: &[Lang] = if lang == Lang::FALLBACK {
        &[lang]
    } else {
        &[lang, Lang::FALLBACK]
    };
    for &l in langs {
        let Some(cat) = catalog(l) else { continue };
        if let Some(n) = count
            && let Some(s) = cat.get(&format!("{key}_{}", plural_category(l, n)))
        {
            return interpolate(s, vars);
        }
        if let Some(s) = cat.get(key) {
            return interpolate(s, vars);
        }
    }
    interpolate(default.unwrap_or(key), vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load() {
        init(&[(
            include_str!("../../ui/assets/locales/ru.json"),
            include_str!("../../ui/assets/locales/en.json"),
        )]);
    }

    fn n(count: f64) -> Vec<(&'static str, String)> {
        vec![("count", count.to_string())]
    }

    #[test]
    fn russian_plural_rules() {
        let cases = [
            (0.0, "many"),
            (1.0, "one"),
            (2.0, "few"),
            (4.0, "few"),
            (5.0, "many"),
            (11.0, "many"),
            (12.0, "many"),
            (14.0, "many"),
            (21.0, "one"),
            (22.0, "few"),
            (25.0, "many"),
            (101.0, "one"),
            (111.0, "many"),
            (1.5, "other"),
        ];
        for (c, cat) in cases {
            assert_eq!(plural_category(Lang::Ru, c), cat, "n={c}");
        }
        assert_eq!(plural_category(Lang::En, 1.0), "one");
        assert_eq!(plural_category(Lang::En, 0.0), "other");
    }

    #[test]
    fn plural_lookup_ru_en() {
        load();
        let k = "servers.groups.serverCount";
        assert_eq!(lookup(Lang::Ru, k, &n(1.0), None), "1 сервер");
        assert_eq!(lookup(Lang::Ru, k, &n(3.0), None), "3 сервера");
        assert_eq!(lookup(Lang::Ru, k, &n(5.0), None), "5 серверов");
        assert_eq!(lookup(Lang::Ru, k, &n(21.0), None), "21 сервер");
        assert_eq!(lookup(Lang::Ru, k, &n(1.5), None), "1.5 серверов");
        assert_eq!(lookup(Lang::En, k, &n(1.0), None), "1 server");
        assert_eq!(lookup(Lang::En, k, &n(2.0), None), "2 servers");
    }

    #[test]
    fn interpolation_and_fallbacks() {
        load();
        let v = vec![("name", "Riga-2".to_string())];
        assert_eq!(
            lookup(Lang::Ru, "dashboard.switchingServer", &v, None),
            "Переключение сервера: Riga-2"
        );
        assert_eq!(
            lookup(Lang::En, "dashboard.switchingServer", &v, None),
            "Switching server: Riga-2"
        );
        // missing var keeps placeholder (i18next behaviour)
        assert_eq!(
            lookup(Lang::Ru, "dashboard.switchingServer", &[], None),
            "Переключение сервера: {{name}}"
        );
        // missing key -> default text -> key
        assert_eq!(
            lookup(Lang::Ru, "no.such.key", &[], Some("Серверы")),
            "Серверы"
        );
        assert_eq!(lookup(Lang::Ru, "no.such.key", &[], None), "no.such.key");
        // whitespace inside braces
        assert_eq!(
            interpolate("{{ a }}+{{b}}", &[("a", "1".into()), ("b", "2".into())]),
            "1+2"
        );
    }
}
