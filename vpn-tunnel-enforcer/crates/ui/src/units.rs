//! Display units shared by the pages.

use crate::lang::translate;

/// Catalog keys of the byte units, smallest first (`{{n}} КБ` / `{{n}} KB`).
const UNITS: [&str; 5] = [
    "ui.units.b",
    "ui.units.kb",
    "ui.units.mb",
    "ui.units.gb",
    "ui.units.tb",
];

/// A byte count split for display, the same on every page: whole bytes below 1 KB, then one
/// decimal (halves round up) in KB, MB, GB or TB, base 1024. Returns the number and the unit's
/// catalog key.
fn scale_bytes(bytes: u64) -> (String, &'static str) {
    let mut unit = 0;
    let mut scale = 1u64;
    while unit < UNITS.len() - 1 && bytes / 1024 >= scale {
        scale *= 1024;
        unit += 1;
    }
    if unit == 0 {
        return (bytes.to_string(), UNITS[0]);
    }
    let tenths = (bytes as f64 / scale as f64 * 10.0).round() as u64;
    (format!("{}.{}", tenths / 10, tenths % 10), UNITS[unit])
}

/// `4.8 МБ` / `4.8 MB` in the current language. The unit words come from the catalog so the
/// pages match the start page and Settings, which already wrote «ГБ» / «МБ» in Russian
/// (UI thread: subscribes the caller to the language).
pub fn format_bytes(bytes: u64) -> String {
    let (n, key) = scale_bytes(bytes);
    translate(key, &[("n", n)], None)
}

#[cfg(test)]
mod tests {
    use super::{UNITS, scale_bytes};
    use crate::test_locales::flatten;

    /// The vectors of the old Logs, Servers and Traffic formats, on the one shared format.
    #[test]
    fn byte_sizes() {
        let at = |b: u64| {
            let (n, key) = scale_bytes(b);
            format!("{n} {}", key.rsplit('.').next().unwrap_or_default())
        };
        assert_eq!(at(0), "0 b");
        assert_eq!(at(1000), "1000 b");
        assert_eq!(at(1023), "1023 b");
        assert_eq!(at(1024), "1.0 kb");
        assert_eq!(at(1280), "1.3 kb");
        assert_eq!(at(1536), "1.5 kb");
        assert_eq!(at(586 * 1024), "586.0 kb");
        assert_eq!(at(5_000_000), "4.8 mb");
        assert_eq!(at(15 * 1024 * 1024), "15.0 mb");
        assert_eq!(at(3 * 1024 * 1024 * 1024), "3.0 gb");
        assert_eq!(at(200 * 1024 * 1024 * 1024), "200.0 gb");
        assert_eq!(at(5 * 1024 * 1024 * 1024 * 1024), "5.0 tb");
        assert_eq!(at(u64::MAX), "16777216.0 tb");
    }

    /// ui-unslop: Russian units are Cyrillic (as «Мбит/с» and the start page's «ГБ»), English Latin.
    #[test]
    fn unit_words_per_language() {
        let ru = flatten(include_str!("../locales/ui-frame.ru.json"));
        let en = flatten(include_str!("../locales/ui-frame.en.json"));
        let words = |c: &std::collections::BTreeMap<String, String>| {
            UNITS
                .map(|k| c.get(k).cloned().unwrap_or_default())
                .join(" ")
        };
        assert_eq!(words(&ru), "{{n}} Б {{n}} КБ {{n}} МБ {{n}} ГБ {{n}} ТБ");
        assert_eq!(words(&en), "{{n}} B {{n}} KB {{n}} MB {{n}} GB {{n}} TB");
    }
}
