//! Text helpers of the update UI: short day labels, the notes in the user's language, the
//! time of the last check.
use std::collections::BTreeMap;

use jiff::tz::TimeZone;
use vpnte_base::i18n::Lang;
use vpnte_base::types::UnixMs;

const MONTHS_EN: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `2026-11-12` -> «12.11» / "12 Nov"; anything else is shown as given.
pub fn day_label(iso: &str, lang: Lang) -> String {
    let Ok(date) = iso.parse::<jiff::civil::Date>() else {
        return iso.to_owned();
    };
    match lang {
        Lang::Ru => format!("{:02}.{:02}", date.day(), date.month()),
        Lang::En => {
            let month = MONTHS_EN[usize::from(date.month().unsigned_abs()).saturating_sub(1) % 12];
            format!("{} {month}", date.day())
        }
    }
}

/// The notes in `lang`, else Russian, else English, else any.
pub fn notes_for(notes: &BTreeMap<String, String>, lang: Lang) -> Option<&str> {
    let code = match lang {
        Lang::Ru => "ru",
        Lang::En => "en",
    };
    [code, "ru", "en"]
        .iter()
        .find_map(|c| notes.get(*c))
        .or_else(|| notes.values().next())
        .map(String::as_str)
        .filter(|n| !n.trim().is_empty())
}

/// `at` in local time: «12.11 14:03» / "12 Nov 14:03".
pub(super) fn time_label(at: UnixMs, lang: Lang) -> String {
    let Ok(ts) = jiff::Timestamp::from_millisecond(at) else {
        return String::new();
    };
    let local = ts.to_zoned(TimeZone::system());
    let day = day_label(&local.date().to_string(), lang);
    format!("{day} {:02}:{:02}", local.hour(), local.minute())
}

/// A byte count as whole megabytes with one decimal (`12.4`).
pub(super) fn megabytes(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1_048_576.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_notes_read_naturally() {
        assert_eq!(day_label("2026-11-12", Lang::Ru), "12.11");
        assert_eq!(day_label("2026-11-12", Lang::En), "12 Nov");
        assert_eq!(day_label("soon", Lang::Ru), "soon");
        let notes: BTreeMap<String, String> = [
            ("ru".into(), "Исправления".into()),
            ("en".into(), "Fixes".into()),
        ]
        .into();
        assert_eq!(notes_for(&notes, Lang::En), Some("Fixes"));
        assert_eq!(notes_for(&notes, Lang::Ru), Some("Исправления"));
        let only_ru: BTreeMap<String, String> = [("ru".into(), "Исправления".into())].into();
        assert_eq!(notes_for(&only_ru, Lang::En), Some("Исправления"));
        assert_eq!(notes_for(&BTreeMap::new(), Lang::En), None);
        assert_eq!(megabytes(45_000_000), "42.9");
    }
}
