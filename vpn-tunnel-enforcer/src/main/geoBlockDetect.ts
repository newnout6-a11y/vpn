/**
 * Geo-block detection — figure out whether a site is *actually* usable from a
 * given exit, not just whether it returned bytes.
 *
 * Why this exists. "HTTP 200" means "the server answered", NOT "the content is
 * available here". Gemini, ChatGPT, many streaming/banking sites return a
 * perfectly healthy 200 OK whose body says "not available in your country".
 * The old detector regex-matched a handful of English phrases on innerText —
 * fragile (one wording change breaks it) and narrow (English only, misses the
 * Russian / structural cases).
 *
 * The approach here layers several signals, strongest first:
 *
 *   1. DIFFERENTIAL (the reliable one). We already render the page through BOTH
 *      the foreign exit (VPN) and the local exit (direct). A site that works
 *      abroad but is geo-blocked locally shows a measurable gap: the local
 *      render is tiny / redirects to an "unavailable" URL / has a different
 *      title / carries block markers the foreign render doesn't. This needs no
 *      language list and survives wording changes.
 *
 *   2. HARD HTTP signal. 451 "Unavailable For Legal Reasons" is, by definition,
 *      a legal/geo block. A main-frame 403 to a normal content URL is a strong
 *      hint too.
 *
 *   3. FINAL-URL shape. Geo-blocks routinely redirect to /sorry, /unavailable,
 *      /unsupported-country, ?error=country_unsupported, etc. Matching the URL
 *      shape is language-independent.
 *
 *   4. MARKER text (the weak fallback, used mainly when we can't compare —
 *      i.e. VPN off). Broadened to many phrasings and both English + Russian,
 *      but only TRUSTED on a short "interstitial-sized" page so a long article
 *      that merely mentions "not available in your country" isn't flagged.
 *
 * Everything here is PURE (no electron/network) and unit-tested. The caller
 * (urlAvailability) gathers PageSignal objects from the offscreen browser and
 * feeds them in.
 */

export interface PageSignal {
  /** The URL we asked the browser to load. */
  requestedUrl: string
  /** The URL the main frame ended on after redirects (location.href). */
  finalUrl: string | null
  /** document.title at probe time. */
  title: string | null
  /** Lower-cased innerText sample (truncated by the caller). */
  textSample: string
  /** Full innerText length (NOT the truncated sample length). */
  textLength: number
  /** Main-frame HTTP response code, when the caller could capture it. */
  httpStatus: number | null
}

export interface GeoBlockVerdict {
  blocked: boolean
  /** 0..1 — how confident we are. */
  confidence: number
  /** Human-readable signals that fired, for logs + UI. */
  reasons: string[]
}

// ─── Signal tables ───────────────────────────────────────────────────────────

/**
 * URL path/query fragments that geo-block landing pages use. Matched against
 * the FINAL url (post-redirect), case-insensitive. Language-independent.
 */
const BLOCK_URL_PATTERNS: RegExp[] = [
  /\/sorry(?:\/|\b)/i,
  /\/unavailable(?:\/|\b)/i,
  /\/not-?available(?:\/|\b)/i,
  /\/unsupported[-_]?country/i,
  /\/geo[-_]?block/i,
  /\/geoblock/i,
  /\/region[-_]?block/i,
  /\/blocked(?:\/|\b)/i,
  /\/restricted(?:\/|\b)/i,
  /[?&]error=country/i,
  /[?&]reason=geo/i,
  /country[_-]?unsupported/i,
  /not[_-]?in[_-]?region/i
]

/**
 * Content markers. Broad, multilingual. Each is a phrase that, in a short
 * interstitial page, strongly implies a geo/region block. We deliberately
 * include partial phrasings ("in your country", "in your region") because the
 * verb varies ("not available", "isn't supported", "unavailable", "can't be
 * accessed") — pairing the constant locative tail with a short body keeps the
 * false-positive rate low without enumerating every verb.
 */
const BLOCK_MARKERS: string[] = [
  // English — full phrases
  'not available in your country',
  "isn't available in your country",
  'is not available in your country',
  'not available in your region',
  'not supported in your country',
  'not supported in your region',
  "isn't supported in your country",
  'not supported in your location',
  'not available in your location',
  'services are not available in your country',
  'this content is not available',
  'content is not available in your',
  'unavailable for legal reasons',
  'not available in the country',
  'access from your country',
  'access from your region',
  'restricted in your region',
  'restricted in your country',
  'blocked in your country',
  'available in your country or region',
  'geographic restriction',
  'geo-restricted',
  'due to your geographic',
  // English — constant locative tails (used with the short-body gate below)
  'in your country',
  'in your region',
  'in your location',
  // Russian
  'недоступно в вашей стране',
  'недоступен в вашей стране',
  'недоступна в вашей стране',
  'недоступно в вашем регионе',
  'недоступен в вашем регионе',
  'не доступно в вашей стране',
  'в вашей стране недоступ',
  'в вашем регионе недоступ',
  'сервис недоступен в вашей',
  'недоступно в вашем местоположении',
  'ограничен доступ из вашей страны',
  // Spanish / Portuguese / German / French — common ones
  'no disponible en tu país',
  'não está disponível no seu país',
  'nicht in deinem land verfügbar',
  "n'est pas disponible dans votre pays"
]

/** Below this innerText length we treat the page as an "interstitial" — i.e.
 *  a block/error page rather than real content. Tuned generously: real app
 *  shells render thousands of chars; block pages are a sentence or two. */
const INTERSTITIAL_TEXT_MAX = 2200

// ─── Single-page scoring ──────────────────────────────────────────────────────

/**
 * Score ONE rendered page for geo-block likelihood. Used as the fallback when
 * we only have one exit to look at (VPN off). Conservative on long pages.
 */
export function scoreSinglePage(sig: PageSignal): GeoBlockVerdict {
  const reasons: string[] = []
  let score = 0

  // 1. Hard HTTP signal.
  if (sig.httpStatus === 451) {
    reasons.push('HTTP 451 (Unavailable For Legal Reasons)')
    score += 0.9
  } else if (sig.httpStatus === 403 && sig.textLength < INTERSTITIAL_TEXT_MAX) {
    reasons.push('HTTP 403 на короткой странице')
    score += 0.5
  }

  // 2. Final-URL shape.
  const finalUrl = (sig.finalUrl || '').toLowerCase()
  if (finalUrl && BLOCK_URL_PATTERNS.some((re) => re.test(finalUrl))) {
    reasons.push('перенаправление на страницу-заглушку')
    score += 0.6
  }

  // 3. Markers in title (titles are short, so a marker here is meaningful).
  const title = (sig.title || '').toLowerCase()
  if (title && BLOCK_MARKERS.some((m) => title.includes(m))) {
    reasons.push('маркер блокировки в заголовке')
    score += 0.6
  }

  // 4. Markers in body — only trusted on an interstitial-sized page, so a long
  //    article quoting "not available in your country" isn't flagged.
  const text = sig.textSample || ''
  const markerHit = BLOCK_MARKERS.find((m) => text.includes(m))
  if (markerHit) {
    if (sig.textLength <= INTERSTITIAL_TEXT_MAX) {
      reasons.push('текст блокировки на короткой странице')
      score += 0.6
    } else {
      // Long page mentioning it — weak, not enough alone.
      reasons.push('упоминание блокировки на длинной странице (слабый сигнал)')
      score += 0.2
    }
  }

  const confidence = Math.min(1, score)
  return { blocked: confidence >= 0.6, confidence, reasons }
}

// ─── Differential comparison ──────────────────────────────────────────────────

/**
 * Compare a FOREIGN-exit render (assumed working — VPN) against a LOCAL-exit
 * render (the RU/ISP path). Decide whether the LOCAL render is geo-blocked.
 *
 * This is the strong, language-independent path. We declare the local side
 * blocked when the foreign side clearly works AND the local side shows a
 * block-shaped difference:
 *   - local hard-blocks (451 / single-page verdict), or
 *   - local redirected to a block-shaped URL the foreign side didn't, or
 *   - local is a tiny page while foreign is substantially larger (the classic
 *     "full app abroad, one-line notice at home"), or
 *   - local carries a block marker the foreign render does not.
 */
export function compareRenders(foreign: PageSignal, local: PageSignal): GeoBlockVerdict {
  const reasons: string[] = []
  let score = 0

  // If the foreign side itself looks blocked/broken, a differential is
  // meaningless — bail to "inconclusive" (not blocked-by-geo).
  const foreignSingle = scoreSinglePage(foreign)
  if (foreignSingle.blocked) {
    return { blocked: false, confidence: 0, reasons: ['зарубежный путь тоже не отдал нормальную страницу'] }
  }

  // Local hard signals (carry over single-page scoring for the local side).
  const localSingle = scoreSinglePage(local)
  if (localSingle.blocked) {
    reasons.push(...localSingle.reasons.map((r) => `локально: ${r}`))
    score += localSingle.confidence
  }

  // Redirect divergence: local lands on a block-shaped URL, foreign doesn't.
  const localUrl = (local.finalUrl || '').toLowerCase()
  const foreignUrl = (foreign.finalUrl || '').toLowerCase()
  const localUrlBlock = !!localUrl && BLOCK_URL_PATTERNS.some((re) => re.test(localUrl))
  const foreignUrlBlock = !!foreignUrl && BLOCK_URL_PATTERNS.some((re) => re.test(foreignUrl))
  if (localUrlBlock && !foreignUrlBlock) {
    reasons.push('локально редирект на заглушку, за рубежом — нет')
    score += 0.7
  }

  // Size gap: foreign substantially bigger AND local interstitial-sized.
  if (
    local.textLength < INTERSTITIAL_TEXT_MAX &&
    foreign.textLength > local.textLength * 3 &&
    foreign.textLength > 3000
  ) {
    reasons.push('за рубежом полноценная страница, локально — почти пустая')
    score += 0.5
  }

  // Marker divergence: a block marker present locally but not abroad.
  const localText = `${local.title || ''}\n${local.textSample || ''}`.toLowerCase()
  const foreignText = `${foreign.title || ''}\n${foreign.textSample || ''}`.toLowerCase()
  const localMarker = BLOCK_MARKERS.find((m) => localText.includes(m) && !foreignText.includes(m))
  if (localMarker) {
    reasons.push('маркер блокировки есть локально, но не за рубежом')
    score += 0.6
  }

  const confidence = Math.min(1, score)
  return { blocked: confidence >= 0.6, confidence, reasons }
}
