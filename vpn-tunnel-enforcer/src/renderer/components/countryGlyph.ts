/**
 * Country recognition by profile name.
 *
 * Subscriptions ship profiles named like "Poland", "Польша 1", "🇩🇪 Germany",
 * "JP Tokyo Premium", etc. Servers rarely have geolocation metadata baked in,
 * and live ipapi probing is rate-limited on the free tier — so the most
 * reliable cheap signal is the human-readable name. We pattern-match it once
 * and return three things: emoji flag, ISO-3166 alpha-2 code, and a Russian
 * country label that matches the rest of the UI.
 *
 * Order of patterns matters — more specific names (e.g. "United Kingdom")
 * must be checked before substrings ("United"). Patterns are mostly
 * Russian + English, since the app's UI is bilingual.
 */

export interface CountryHit {
  flag: string
  iso2: string
  label: string
}

const TABLE: ReadonlyArray<{ rx: RegExp; hit: CountryHit }> = [
  // Generic / non-country profile labels
  { rx: /\b(?:fast|fastest|best|premium|auto)\b/i, hit: { flag: '⚡', iso2: '', label: 'Auto' } },

  // Europe
  { rx: /\b(?:poland|польш)/i,                  hit: { flag: '🇵🇱', iso2: 'PL', label: 'Польша' } },
  { rx: /\b(?:norway|норв)/i,                   hit: { flag: '🇳🇴', iso2: 'NO', label: 'Норвегия' } },
  { rx: /\b(?:sweden|швец)/i,                   hit: { flag: '🇸🇪', iso2: 'SE', label: 'Швеция' } },
  { rx: /\b(?:finland|финлянд)/i,               hit: { flag: '🇫🇮', iso2: 'FI', label: 'Финляндия' } },
  { rx: /\b(?:denmark|дани)/i,                  hit: { flag: '🇩🇰', iso2: 'DK', label: 'Дания' } },
  { rx: /\b(?:iceland|исланд)/i,                hit: { flag: '🇮🇸', iso2: 'IS', label: 'Исландия' } },
  { rx: /\b(?:latvia|латв)/i,                   hit: { flag: '🇱🇻', iso2: 'LV', label: 'Латвия' } },
  { rx: /\b(?:lithuania|литв)/i,                hit: { flag: '🇱🇹', iso2: 'LT', label: 'Литва' } },
  { rx: /\b(?:estonia|эстон)/i,                 hit: { flag: '🇪🇪', iso2: 'EE', label: 'Эстония' } },
  { rx: /\b(?:germany|герман|deutsch)/i,        hit: { flag: '🇩🇪', iso2: 'DE', label: 'Германия' } },
  { rx: /\b(?:france|франц)/i,                  hit: { flag: '🇫🇷', iso2: 'FR', label: 'Франция' } },
  { rx: /\b(?:netherlands|нидерланд|holland|голланд)/i, hit: { flag: '🇳🇱', iso2: 'NL', label: 'Нидерланды' } },
  { rx: /\b(?:belgium|бельги)/i,                hit: { flag: '🇧🇪', iso2: 'BE', label: 'Бельгия' } },
  { rx: /\b(?:luxembourg|люксембург)/i,         hit: { flag: '🇱🇺', iso2: 'LU', label: 'Люксембург' } },
  { rx: /\b(?:switzerland|швейцар)/i,           hit: { flag: '🇨🇭', iso2: 'CH', label: 'Швейцария' } },
  { rx: /\b(?:austria|австри[яи])/i,            hit: { flag: '🇦🇹', iso2: 'AT', label: 'Австрия' } },
  { rx: /\b(?:italy|итал)/i,                    hit: { flag: '🇮🇹', iso2: 'IT', label: 'Италия' } },
  { rx: /\b(?:spain|испан)/i,                   hit: { flag: '🇪🇸', iso2: 'ES', label: 'Испания' } },
  { rx: /\b(?:portugal|португал)/i,             hit: { flag: '🇵🇹', iso2: 'PT', label: 'Португалия' } },
  { rx: /\b(?:ireland|ирланд)/i,                hit: { flag: '🇮🇪', iso2: 'IE', label: 'Ирландия' } },
  { rx: /\b(?:united kingdom|^uk$|\buk\b|britain|британ|англ)/i, hit: { flag: '🇬🇧', iso2: 'GB', label: 'Великобритания' } },
  { rx: /\b(?:czech|чехи)/i,                    hit: { flag: '🇨🇿', iso2: 'CZ', label: 'Чехия' } },
  { rx: /\b(?:slovakia|словак)/i,               hit: { flag: '🇸🇰', iso2: 'SK', label: 'Словакия' } },
  { rx: /\b(?:hungary|венгри)/i,                hit: { flag: '🇭🇺', iso2: 'HU', label: 'Венгрия' } },
  { rx: /\b(?:romania|румын)/i,                 hit: { flag: '🇷🇴', iso2: 'RO', label: 'Румыния' } },
  { rx: /\b(?:bulgaria|болгар)/i,               hit: { flag: '🇧🇬', iso2: 'BG', label: 'Болгария' } },
  { rx: /\b(?:greece|греци)/i,                  hit: { flag: '🇬🇷', iso2: 'GR', label: 'Греция' } },
  { rx: /\b(?:ukraine|украин)/i,                hit: { flag: '🇺🇦', iso2: 'UA', label: 'Украина' } },
  { rx: /\b(?:moldova|молдов)/i,                hit: { flag: '🇲🇩', iso2: 'MD', label: 'Молдова' } },
  { rx: /\b(?:serbia|серби)/i,                  hit: { flag: '🇷🇸', iso2: 'RS', label: 'Сербия' } },
  { rx: /\b(?:croatia|хорват)/i,                hit: { flag: '🇭🇷', iso2: 'HR', label: 'Хорватия' } },
  { rx: /\b(?:cyprus|кипр)/i,                   hit: { flag: '🇨🇾', iso2: 'CY', label: 'Кипр' } },
  { rx: /\b(?:russia|росс)/i,                   hit: { flag: '🇷🇺', iso2: 'RU', label: 'Россия' } },
  { rx: /\b(?:belarus|белорус|беларус)/i,       hit: { flag: '🇧🇾', iso2: 'BY', label: 'Беларусь' } },
  { rx: /\b(?:turkey|турци)/i,                  hit: { flag: '🇹🇷', iso2: 'TR', label: 'Турция' } },
  { rx: /\b(?:armenia|армени)/i,                hit: { flag: '🇦🇲', iso2: 'AM', label: 'Армения' } },
  { rx: /\b(?:georgia|грузи)/i,                 hit: { flag: '🇬🇪', iso2: 'GE', label: 'Грузия' } },
  { rx: /\b(?:azerbaijan|азербайдж)/i,          hit: { flag: '🇦🇿', iso2: 'AZ', label: 'Азербайджан' } },

  // Asia
  { rx: /\b(?:japan|япон)/i,                    hit: { flag: '🇯🇵', iso2: 'JP', label: 'Япония' } },
  { rx: /\b(?:korea|коре)/i,                    hit: { flag: '🇰🇷', iso2: 'KR', label: 'Корея' } },
  { rx: /\b(?:china|китай|hong\s*kong|hk\b|гонконг)/i, hit: { flag: '🇨🇳', iso2: 'CN', label: 'Китай' } },
  { rx: /\b(?:taiwan|тайван)/i,                 hit: { flag: '🇹🇼', iso2: 'TW', label: 'Тайвань' } },
  { rx: /\b(?:singapore|сингапур)/i,            hit: { flag: '🇸🇬', iso2: 'SG', label: 'Сингапур' } },
  { rx: /\b(?:malaysia|малайзи)/i,              hit: { flag: '🇲🇾', iso2: 'MY', label: 'Малайзия' } },
  { rx: /\b(?:thailand|таиланд)/i,              hit: { flag: '🇹🇭', iso2: 'TH', label: 'Таиланд' } },
  { rx: /\b(?:vietnam|вьетнам)/i,               hit: { flag: '🇻🇳', iso2: 'VN', label: 'Вьетнам' } },
  { rx: /\b(?:indonesia|индонез)/i,             hit: { flag: '🇮🇩', iso2: 'ID', label: 'Индонезия' } },
  { rx: /\b(?:philippines|филиппин)/i,          hit: { flag: '🇵🇭', iso2: 'PH', label: 'Филиппины' } },
  { rx: /\b(?:india|инди[яи])/i,                hit: { flag: '🇮🇳', iso2: 'IN', label: 'Индия' } },
  { rx: /\b(?:pakistan|пакистан)/i,             hit: { flag: '🇵🇰', iso2: 'PK', label: 'Пакистан' } },
  { rx: /\b(?:kazakhstan|казах)/i,              hit: { flag: '🇰🇿', iso2: 'KZ', label: 'Казахстан' } },
  { rx: /\b(?:uzbekistan|узбек)/i,              hit: { flag: '🇺🇿', iso2: 'UZ', label: 'Узбекистан' } },
  { rx: /\b(?:israel|израил)/i,                 hit: { flag: '🇮🇱', iso2: 'IL', label: 'Израиль' } },
  { rx: /\b(?:emirates|эмират|^uae$|\buae\b)/i, hit: { flag: '🇦🇪', iso2: 'AE', label: 'ОАЭ' } },

  // Americas
  { rx: /\b(?:usa|america|united states|сша|америк)/i, hit: { flag: '🇺🇸', iso2: 'US', label: 'США' } },
  { rx: /\b(?:canada|канад)/i,                  hit: { flag: '🇨🇦', iso2: 'CA', label: 'Канада' } },
  { rx: /\b(?:mexico|мексик)/i,                 hit: { flag: '🇲🇽', iso2: 'MX', label: 'Мексика' } },
  { rx: /\b(?:brazil|бразил)/i,                 hit: { flag: '🇧🇷', iso2: 'BR', label: 'Бразилия' } },
  { rx: /\b(?:argentina|аргентин)/i,            hit: { flag: '🇦🇷', iso2: 'AR', label: 'Аргентина' } },
  { rx: /\b(?:chile|чили)/i,                    hit: { flag: '🇨🇱', iso2: 'CL', label: 'Чили' } },

  // Oceania
  { rx: /\b(?:australia|австрал)/i,             hit: { flag: '🇦🇺', iso2: 'AU', label: 'Австралия' } },
  { rx: /\b(?:new zealand|новая зеланд)/i,      hit: { flag: '🇳🇿', iso2: 'NZ', label: 'Новая Зеландия' } },

  // Africa
  { rx: /\b(?:south africa|юар|южн.*африк)/i,   hit: { flag: '🇿🇦', iso2: 'ZA', label: 'ЮАР' } },
  { rx: /\b(?:egypt|египет)/i,                  hit: { flag: '🇪🇬', iso2: 'EG', label: 'Египет' } }
]

/**
 * Look up a country by free-form profile name. Returns null when no
 * confident match is found — callers should display a neutral globe glyph.
 */
export function detectCountry(name: string | null | undefined): CountryHit | null {
  if (!name) return null
  if (/\b(?:hong\s*kong|hk\b)/i.test(name)) {
    return { flag: '🇭🇰', iso2: 'HK', label: 'Hong Kong' }
  }
  for (const { rx, hit } of TABLE) {
    if (rx.test(name)) return hit
  }
  return null
}

/**
 * Convenience accessor used in legacy call-sites that only care about the
 * emoji flag. Returns the globe glyph as a fallback so the UI never renders
 * an empty box.
 */
export function countryFlag(name: string | null | undefined): string {
  return detectCountry(name)?.flag ?? '🌐'
}

export function countryFlagFromCountryOrName(country: string | null | undefined, name: string | null | undefined): string {
  return detectCountry(country)?.flag ?? detectCountry(name)?.flag ?? '🌐'
}
