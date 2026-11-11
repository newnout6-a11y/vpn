//! Country a server claims by its name: a flag emoji, an ISO code or an English / native /
//! Russian name. The claim is computed on demand and never stored; a verified exit country wins.
mod table;

use std::fmt;
use std::sync::LazyLock;

use icu_normalizer::DecomposingNormalizerBorrowed;
use serde::{Deserialize, Serialize};
use vpnte_base::i18n::Lang;

use table::{ALIASES, COUNTRIES, WORDS};

/// ISO 3166-1 alpha-2 code (`DE`). Only assigned codes (and `XK`, Kosovo) can be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "&'static str")]
pub struct Iso2(u8);

/// A string that is not a known country code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown country code")]
pub struct UnknownCountry;

impl Iso2 {
    /// The country `code` names (any case, surrounding whitespace ignored).
    pub fn new(code: &str) -> Option<Self> {
        let code = code.trim();
        if code.len() != 2 {
            return None;
        }
        let code = code.to_ascii_uppercase();
        let index = COUNTRIES
            .binary_search_by(|(c, ..)| (*c).cmp(code.as_str()))
            .ok()?;
        u8::try_from(index).ok().map(Iso2)
    }

    /// The code, upper case.
    pub fn as_str(self) -> &'static str {
        self.entry().0
    }

    fn entry(self) -> &'static (&'static str, &'static str, &'static str) {
        // Every `Iso2` comes from `new`, so the index is in range.
        &COUNTRIES[usize::from(self.0)]
    }
}

impl fmt::Display for Iso2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for Iso2 {
    type Error = UnknownCountry;
    fn try_from(code: String) -> Result<Self, Self::Error> {
        Iso2::new(&code).ok_or(UnknownCountry)
    }
}

impl From<Iso2> for &'static str {
    fn from(code: Iso2) -> Self {
        code.as_str()
    }
}

/// Flag emoji of `code` (`🇩🇪`).
pub fn flag(code: Iso2) -> String {
    code.as_str()
        .bytes()
        .filter_map(|b| char::from_u32(0x1F1E6 + u32::from(b - b'A')))
        .collect()
}

/// English short name (`Germany`).
pub fn name_en(code: Iso2) -> &'static str {
    code.entry().1
}

/// Russian short name (`Германия`).
pub fn name_ru(code: Iso2) -> &'static str {
    code.entry().2
}

/// Name in `lang`.
pub fn name(code: Iso2, lang: Lang) -> &'static str {
    match lang {
        Lang::Ru => name_ru(code),
        Lang::En => name_en(code),
    }
}

/// Characters of a name looked at; profile names are at most 256 characters long.
const MAX_NAME_CHARS: usize = 256;

/// The country a server name claims (servers §3.14, ui-dashboard D-12); the first rule that hits:
/// 1. the first flag emoji of a known code (`🇮🇷 Iran`; the England / Scotland / Wales flags
///    count as `GB`);
/// 2. the whole name is a code (`nl`);
/// 3. the first word that starts with a country alias (`Польша 1`, `latviavless4`,
///    `VlessGermany`, `Hong Kong`); `Jerusalem` or `Busan` never become US, because aliases match
///    word starts, not substrings;
/// 4. the first word of exactly two upper-case letters that is a code (`DE-1`, `JP Tokyo`), except
///    `GB` after a number (a traffic amount: `Осталось 50 GB`, `Trial 100GB`).
///
/// `AI` and `TV` count only as flags: in names they mean artificial intelligence and television
/// (no VPN servers in Anguilla or Tuvalu). Words split at non-alphanumerics, at lower-to-upper
/// case changes and between letters and digits, after NFKD folding (accents and styled Unicode
/// letters fold to plain ones).
pub fn infer(name: &str) -> Option<Iso2> {
    let name: String = name.chars().take(MAX_NAME_CHARS).collect();
    flag_code(&name)
        .or_else(|| Iso2::new(&name).filter(claimable))
        .or_else(|| {
            let words = words(&name);
            alias_match(&words).or_else(|| spelled_code(&words))
        })
}

/// False for the codes that only a flag can claim (see [`infer`]).
fn claimable(code: &Iso2) -> bool {
    !matches!(code.as_str(), "AI" | "TV")
}

/// Rule 4 of [`infer`].
fn spelled_code(words: &[Word]) -> Option<Iso2> {
    let mut after_number = false;
    for word in words {
        if let Some(code) = word.code.filter(claimable)
            && !(after_number && code.as_str() == "GB")
        {
            return Some(code);
        }
        after_number = word.folded.chars().all(char::is_numeric);
    }
    None
}

/// Letter of a regional-indicator symbol (`🇩` -> `D`).
fn indicator_letter(c: char) -> Option<char> {
    let offset = u32::from(c).checked_sub(0x1F1E6).filter(|o| *o < 26)?;
    char::from_u32(u32::from(b'A') + offset)
}

/// First regional-indicator pair naming a known code; indicators pair up from the start of a run.
/// A subdivision flag (`🏴` + tag letters, England / Scotland / Wales) names its country.
fn flag_code(name: &str) -> Option<Iso2> {
    let mut first = None;
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1F3F4}'
            && let Some(code) = subdivision_country(chars.clone())
        {
            return Some(code);
        }
        let Some(letter) = indicator_letter(c) else {
            first = None;
            continue;
        };
        match first.take() {
            None => first = Some(letter),
            Some(a) => {
                if let Some(code) = Iso2::new(&String::from_iter([a, letter])) {
                    return Some(code);
                }
            }
        }
    }
    None
}

/// Country of the tag sequence after `🏴`: an ISO 3166-2 code in tag letters (U+E0061..) starts
/// with the country (`gbsct` -> `GB`).
fn subdivision_country(mut tags: impl Iterator<Item = char>) -> Option<Iso2> {
    let mut letter = || {
        let offset = u32::from(tags.next()?)
            .checked_sub(0xE0061)
            .filter(|o| *o < 26)?;
        char::from_u32(u32::from(b'A') + offset)
    };
    let code = [letter()?, letter()?];
    Iso2::new(&String::from_iter(code))
}

/// One word of a name: folded to lower case, plus the code it spells when it was written as two
/// upper-case letters.
struct Word {
    folded: String,
    code: Option<Iso2>,
}

/// NFKD without combining marks (U+0300..U+036F): `Türkiye` -> `Turkiye`, `𝐆𝐞𝐫𝐦𝐚𝐧𝐲` -> `Germany`,
/// `й` -> `и` (aliases are folded the same way).
fn decompose(text: &str) -> impl Iterator<Item = char> + '_ {
    DecomposingNormalizerBorrowed::new_nfkd()
        .normalize_iter(text.chars())
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c))
}

fn words(name: &str) -> Vec<Word> {
    fn flush(words: &mut Vec<Word>, current: &mut String) {
        if current.is_empty() {
            return;
        }
        let spelled = current.len() == 2 && current.bytes().all(|b| b.is_ascii_uppercase());
        let code = if spelled { Iso2::new(current) } else { None };
        words.push(Word {
            folded: current.to_lowercase(),
            code,
        });
        current.clear();
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev: Option<char> = None;
    for c in decompose(name) {
        if !c.is_alphanumeric() {
            flush(&mut words, &mut current);
            prev = None;
            continue;
        }
        if let Some(p) = prev
            && ((p.is_lowercase() && c.is_uppercase()) || p.is_numeric() != c.is_numeric())
        {
            flush(&mut words, &mut current);
        }
        current.push(c);
        prev = Some(c);
    }
    flush(&mut words, &mut current);
    words
}

/// How an alias meets a word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// The word starts with it.
    Prefix,
    /// The words from here on, run together, start with it.
    Phrase,
    /// The word is it.
    Whole,
}

struct Alias {
    folded: String,
    fit: Fit,
    code: Iso2,
}

static ALIAS_TABLE: LazyLock<Vec<Alias>> = LazyLock::new(|| {
    let fold = |text: &str| -> String {
        decompose(text)
            .filter(|c| c.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    };
    let spread = |table: &'static [(&'static str, &'static [&'static str])], whole: bool| {
        table.iter().flat_map(move |(code, aliases)| {
            let code = Iso2::new(code);
            aliases.iter().filter_map(move |text| {
                let fit = match (whole, text.contains(' ')) {
                    (true, _) => Fit::Whole,
                    (false, true) => Fit::Phrase,
                    (false, false) => Fit::Prefix,
                };
                code.map(|code| Alias {
                    folded: fold(text),
                    fit,
                    code,
                })
            })
        })
    };
    spread(ALIASES, false).chain(spread(WORDS, true)).collect()
});

/// The longest alias that fits the first word any alias fits.
fn alias_match(words: &[Word]) -> Option<Iso2> {
    let joined: String = words.iter().map(|w| w.folded.as_str()).collect();
    let mut offset = 0;
    for word in words {
        let rest = &joined[offset..];
        offset += word.folded.len();
        let fits = |a: &&Alias| match a.fit {
            Fit::Prefix => word.folded.starts_with(&a.folded),
            Fit::Phrase => rest.starts_with(&a.folded),
            Fit::Whole => word.folded == a.folded,
        };
        if let Some(alias) = ALIAS_TABLE
            .iter()
            .filter(fits)
            .max_by_key(|a| a.folded.len())
        {
            return Some(alias.code);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(name: &str) -> Option<&'static str> {
        infer(name).map(Iso2::as_str)
    }

    #[test]
    fn table_is_sorted_complete_and_aliases_resolve() {
        assert!(COUNTRIES.windows(2).all(|w| w[0].0 < w[1].0));
        // 249 assigned ISO 3166-1 codes plus XK.
        assert_eq!(COUNTRIES.len(), 250);
        assert!(
            COUNTRIES
                .iter()
                .all(|(c, en, ru)| c.len() == 2 && !en.is_empty() && !ru.is_empty())
        );
        let total: usize = ALIASES
            .iter()
            .chain(WORDS)
            .map(|(_, aliases)| aliases.len())
            .sum();
        assert_eq!(ALIAS_TABLE.len(), total);
        assert!(ALIAS_TABLE.iter().all(|a| !a.folded.is_empty()));
    }

    /// servers §7 "Countries" (`countries.test.ts`) and its new vectors.
    #[test]
    fn servers_vectors() {
        assert_eq!(code("🇳🇱 Netherlands"), Some("NL"));
        assert_eq!(code("latviavless4"), Some("LV"));
        assert_eq!(code("netherlandsvless1"), Some("NL"));
        assert_eq!(code("usavless1"), Some("US"));
        assert_eq!(code("🇩🇪 Дарвин ВПН"), Some("DE"));
        assert_eq!(Iso2::new("SE").map(flag).as_deref(), Some("🇸🇪"));
        for not_us in ["Busan", "Jerusalem", "Lausanne"] {
            assert_eq!(code(not_us), None, "{not_us}");
        }
        assert_eq!(code("Германия"), Some("DE"));
        assert_eq!(code("AE ОАЭ"), Some("AE"));
        assert_eq!(code("🇮🇷 Iran"), Some("IR"));
    }

    /// ui-dashboard §7.6 (`countryGlyph.test.ts`) and the D-12 fix: Russian names match.
    #[test]
    fn dashboard_vectors() {
        assert_eq!(code("Hong Kong"), Some("HK"));
        assert_eq!(code("HK"), Some("HK"));
        assert_eq!(code("Польша 1"), Some("PL"));
        assert_eq!(code("США-2"), Some("US"));
        assert_eq!(code("JP Tokyo Premium"), Some("JP"));
        // "Auto" rows are a UI decision; the name claims no country.
        assert_eq!(code("Fastest"), None);
    }

    #[test]
    fn words_split_at_case_digit_and_punctuation() {
        assert_eq!(code("VlessGermany"), Some("DE"));
        assert_eq!(code("TheNetherlands"), Some("NL"));
        assert_eq!(code("UnitedKingdom-3"), Some("GB"));
        assert_eq!(code("server1germany"), Some("DE"));
        assert_eq!(code("DE1 Frankfurt"), Some("DE"));
        assert_eq!(code("[NL] Amsterdam"), Some("NL"));
        assert_eq!(code("VPN-RU"), Some("RU"));
        assert_eq!(code("United Arab Emirates"), Some("AE"));
        assert_eq!(code("South Africa / Johannesburg"), Some("ZA"));
        assert_eq!(code("Новая Зеландия"), Some("NZ"));
    }

    #[test]
    fn folding_and_word_rules() {
        assert_eq!(code("Türkiye"), Some("TR"));
        assert_eq!(code("𝐆𝐞𝐫𝐦𝐚𝐧𝐲"), Some("DE"));
        assert_eq!(code("ＤＥ"), Some("DE"));
        assert_eq!(code("Китай"), Some("CN"));
        assert_eq!(code("Гонконг"), Some("HK"));
        assert_eq!(code("Великобритания 2"), Some("GB"));
        assert_eq!(code("UK London"), Some("GB"));
        assert_eq!(code("ukko"), None);
        assert_eq!(code("Индивидуальный сервер"), None);
        assert_eq!(code("de"), Some("DE"));
        assert_eq!(code("Germany via NL"), Some("DE"));
        assert_eq!(code("Fast EU node"), None);
        assert_eq!(code(""), None);
    }

    /// Upper-case words that are not a country claim: traffic amounts and common abbreviations.
    #[test]
    fn units_and_abbreviations_are_not_codes() {
        for name in [
            "Trial 100GB",
            "Осталось 10.5 GB",
            "🤖 AI-сервер",
            "Smart TV",
            "AI",
            "tv",
        ] {
            assert_eq!(code(name), None, "{name}");
        }
        assert_eq!(code("GB 2"), Some("GB"));
        assert_eq!(code("Node 50GB DE"), Some("DE"));
        assert_eq!(code("AI US"), Some("US"));
        assert_eq!(code("🇦🇮 Anguilla"), Some("AI"));
    }

    #[test]
    fn flags_pair_from_the_start_of_a_run() {
        assert_eq!(code("🇩🇪🇳🇱 chain"), Some("DE"));
        assert_eq!(code("🇪🇺 Germany"), Some("DE"));
        assert_eq!(code("🇪🇺🇫🇷"), Some("FR"));
        assert_eq!(code("🇽🇰 Pristina"), Some("XK"));
    }

    /// Subdivision flags (`🏴` + tag letters + cancel tag) name their country; a bare black flag
    /// names none.
    #[test]
    fn subdivision_flags_name_their_country() {
        let flag = |sub: &str| {
            let tags: String = sub
                .chars()
                .filter_map(|c| char::from_u32(0xE0000 + u32::from(c)))
                .collect();
            format!("\u{1F3F4}{tags}\u{E007F}")
        };
        for sub in ["gbeng", "gbsct", "gbwls"] {
            assert_eq!(code(&format!("{} Node 1", flag(sub))), Some("GB"), "{sub}");
        }
        assert_eq!(code(&format!("{}🇩🇪 chain", flag("gbsct"))), Some("GB"));
        assert_eq!(code(&format!("{} LA", flag("usca"))), Some("US"));
        assert_eq!(code("\u{1F3F4} Node"), None);
    }

    #[test]
    fn codes_names_and_serde() {
        let de = Iso2::new(" de ").unwrap();
        assert_eq!((de.as_str(), de.to_string()), ("DE", "DE".to_owned()));
        assert_eq!((name_en(de), name_ru(de)), ("Germany", "Германия"));
        assert_eq!(name(Iso2::new("AE").unwrap(), Lang::Ru), "ОАЭ");
        assert_eq!(name(Iso2::new("US").unwrap(), Lang::En), "United States");
        assert_eq!(Iso2::new("EU"), None);
        assert_eq!(Iso2::new("DEU"), None);
        assert_eq!(serde_json::to_string(&de).unwrap(), "\"DE\"");
        assert_eq!(
            serde_json::from_str::<Iso2>("\"nl\"").unwrap().as_str(),
            "NL"
        );
        assert!(serde_json::from_str::<Iso2>("\"ZZ\"").is_err());
        assert_eq!(flag(Iso2::new("GB").unwrap()), "🇬🇧");
    }
}
