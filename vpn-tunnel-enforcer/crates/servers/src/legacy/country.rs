//! Old `country` values: CLDR English names, bare ISO codes, or a name to infer from.
use vpnte_profiles::countries::{self, Iso2};

/// CLDR English names (`Intl.DisplayNames(['en'])`, what the old geo path stored) that differ from
/// the country table even after `&` -> `and` and `St.` -> `Saint`.
const CLDR_NAMES: &[(&str, &str)] = &[
    ("Türkiye", "TR"),
    ("Hong Kong SAR China", "HK"),
    ("Macao SAR China", "MO"),
    ("Congo - Kinshasa", "CD"),
    ("Congo - Brazzaville", "CG"),
    ("Côte d’Ivoire", "CI"),
    ("Myanmar (Burma)", "MM"),
    ("Palestinian Territories", "PS"),
    ("St. Vincent & Grenadines", "VC"),
    ("Heard & McDonald Islands", "HM"),
    ("South Georgia & South Sandwich Islands", "GS"),
    ("Caribbean Netherlands", "BQ"),
];

/// Old `country` value -> ISO2: an exact English name first (token inference would read
/// `Hong Kong SAR China` as CN), then a bare code (key-health values), then name inference.
pub(super) fn legacy_country(text: &str) -> Option<Iso2> {
    let text = text.trim();
    english_name(text)
        .or_else(|| Iso2::new(text))
        .or_else(|| countries::infer(text))
}

fn english_name(text: &str) -> Option<Iso2> {
    if let Some((_, code)) = CLDR_NAMES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(text))
    {
        return Iso2::new(code);
    }
    let mut plain = text.replace(" & ", " and ");
    if let Some(rest) = plain.strip_prefix("St. ") {
        plain = format!("Saint {rest}");
    }
    let letters = b'A'..=b'Z';
    letters
        .clone()
        .flat_map(|a| letters.clone().map(move |b| [a, b]))
        .filter_map(|pair| Iso2::new(std::str::from_utf8(&pair).ok()?))
        .find(|&code| countries::name_en(code).eq_ignore_ascii_case(&plain))
}
