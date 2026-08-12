export interface CountryMetadata {
  iso2: string
  label: string
  aliases: readonly string[]
}

const COUNTRIES: readonly CountryMetadata[] = [
  { iso2: 'PL', label: 'Poland', aliases: ['poland'] },
  { iso2: 'NO', label: 'Norway', aliases: ['norway'] },
  { iso2: 'SE', label: 'Sweden', aliases: ['sweden'] },
  { iso2: 'FI', label: 'Finland', aliases: ['finland'] },
  { iso2: 'DK', label: 'Denmark', aliases: ['denmark'] },
  { iso2: 'IS', label: 'Iceland', aliases: ['iceland'] },
  { iso2: 'LV', label: 'Latvia', aliases: ['latvia'] },
  { iso2: 'LT', label: 'Lithuania', aliases: ['lithuania'] },
  { iso2: 'EE', label: 'Estonia', aliases: ['estonia'] },
  { iso2: 'DE', label: 'Germany', aliases: ['germany', 'deutschland'] },
  { iso2: 'FR', label: 'France', aliases: ['france'] },
  { iso2: 'NL', label: 'Netherlands', aliases: ['netherlands', 'holland'] },
  { iso2: 'BE', label: 'Belgium', aliases: ['belgium'] },
  { iso2: 'LU', label: 'Luxembourg', aliases: ['luxembourg'] },
  { iso2: 'CH', label: 'Switzerland', aliases: ['switzerland'] },
  { iso2: 'AT', label: 'Austria', aliases: ['austria'] },
  { iso2: 'IT', label: 'Italy', aliases: ['italy'] },
  { iso2: 'ES', label: 'Spain', aliases: ['spain'] },
  { iso2: 'PT', label: 'Portugal', aliases: ['portugal'] },
  { iso2: 'IE', label: 'Ireland', aliases: ['ireland'] },
  { iso2: 'GB', label: 'United Kingdom', aliases: ['unitedkingdom', 'greatbritain', 'britain'] },
  { iso2: 'CZ', label: 'Czechia', aliases: ['czechia', 'czechrepublic'] },
  { iso2: 'SK', label: 'Slovakia', aliases: ['slovakia'] },
  { iso2: 'HU', label: 'Hungary', aliases: ['hungary'] },
  { iso2: 'RO', label: 'Romania', aliases: ['romania'] },
  { iso2: 'BG', label: 'Bulgaria', aliases: ['bulgaria'] },
  { iso2: 'GR', label: 'Greece', aliases: ['greece'] },
  { iso2: 'UA', label: 'Ukraine', aliases: ['ukraine'] },
  { iso2: 'MD', label: 'Moldova', aliases: ['moldova'] },
  { iso2: 'RS', label: 'Serbia', aliases: ['serbia'] },
  { iso2: 'HR', label: 'Croatia', aliases: ['croatia'] },
  { iso2: 'CY', label: 'Cyprus', aliases: ['cyprus'] },
  { iso2: 'RU', label: 'Russia', aliases: ['russia'] },
  { iso2: 'BY', label: 'Belarus', aliases: ['belarus'] },
  { iso2: 'TR', label: 'Turkey', aliases: ['turkey', 'turkiye'] },
  { iso2: 'AM', label: 'Armenia', aliases: ['armenia'] },
  { iso2: 'GE', label: 'Georgia', aliases: ['georgia'] },
  { iso2: 'AZ', label: 'Azerbaijan', aliases: ['azerbaijan'] },
  { iso2: 'JP', label: 'Japan', aliases: ['japan'] },
  { iso2: 'KR', label: 'South Korea', aliases: ['southkorea', 'korea'] },
  { iso2: 'HK', label: 'Hong Kong', aliases: ['hongkong'] },
  { iso2: 'CN', label: 'China', aliases: ['china'] },
  { iso2: 'TW', label: 'Taiwan', aliases: ['taiwan'] },
  { iso2: 'SG', label: 'Singapore', aliases: ['singapore'] },
  { iso2: 'MY', label: 'Malaysia', aliases: ['malaysia'] },
  { iso2: 'TH', label: 'Thailand', aliases: ['thailand'] },
  { iso2: 'VN', label: 'Vietnam', aliases: ['vietnam'] },
  { iso2: 'ID', label: 'Indonesia', aliases: ['indonesia'] },
  { iso2: 'PH', label: 'Philippines', aliases: ['philippines'] },
  { iso2: 'IN', label: 'India', aliases: ['india'] },
  { iso2: 'PK', label: 'Pakistan', aliases: ['pakistan'] },
  { iso2: 'KZ', label: 'Kazakhstan', aliases: ['kazakhstan'] },
  { iso2: 'UZ', label: 'Uzbekistan', aliases: ['uzbekistan'] },
  { iso2: 'IL', label: 'Israel', aliases: ['israel'] },
  { iso2: 'AE', label: 'United Arab Emirates', aliases: ['unitedarabemirates', 'emirates', 'uae'] },
  { iso2: 'US', label: 'United States', aliases: ['unitedstates', 'unitedstatesofamerica', 'america', 'usa'] },
  { iso2: 'CA', label: 'Canada', aliases: ['canada'] },
  { iso2: 'MX', label: 'Mexico', aliases: ['mexico'] },
  { iso2: 'BR', label: 'Brazil', aliases: ['brazil'] },
  { iso2: 'AR', label: 'Argentina', aliases: ['argentina'] },
  { iso2: 'CL', label: 'Chile', aliases: ['chile'] },
  { iso2: 'AU', label: 'Australia', aliases: ['australia'] },
  { iso2: 'NZ', label: 'New Zealand', aliases: ['newzealand'] },
  { iso2: 'ZA', label: 'South Africa', aliases: ['southafrica'] },
  { iso2: 'EG', label: 'Egypt', aliases: ['egypt'] }
]

const BY_ISO2 = new Map(COUNTRIES.map(country => [country.iso2, country]))

function flagIso2(value: string): string | null {
  const points = Array.from(value)
  for (let index = 0; index < points.length - 1; index++) {
    const first = points[index].codePointAt(0) ?? 0
    const second = points[index + 1].codePointAt(0) ?? 0
    if (first < 0x1f1e6 || first > 0x1f1ff || second < 0x1f1e6 || second > 0x1f1ff) continue
    return String.fromCharCode(65 + first - 0x1f1e6, 65 + second - 0x1f1e6)
  }
  return null
}

function compactCountryText(value: string): string {
  return value
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '')
}

export function countryByIso2(iso2: string | null | undefined): CountryMetadata | null {
  if (!iso2) return null
  return BY_ISO2.get(iso2.trim().toUpperCase()) ?? null
}

export function inferCountryMetadata(value: string | null | undefined): CountryMetadata | null {
  if (!value) return null
  const fromFlag = flagIso2(value)
  if (fromFlag) return countryByIso2(fromFlag)

  const exactIso = countryByIso2(value)
  if (exactIso) return exactIso

  const compact = compactCountryText(value)
  if (!compact) return null
  return COUNTRIES.find(country =>
    compact === compactCountryText(country.label) || country.aliases.some(alias => compact.includes(alias))
  ) ?? null
}

export function countryFlagEmoji(iso2: string | null | undefined): string | null {
  const country = countryByIso2(iso2)
  if (!country) return null
  return Array.from(country.iso2)
    .map(letter => String.fromCodePoint(0x1f1e6 + letter.charCodeAt(0) - 65))
    .join('')
}
