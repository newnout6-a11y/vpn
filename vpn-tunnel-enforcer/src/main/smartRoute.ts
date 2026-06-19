/**
 * Smart RU split-routing.
 *
 * Goal: let Russian destinations (banks, government portals, shops, local
 * services, optionally maps) egress with the user's REAL IP via `direct-out`,
 * while everything else goes through the VPN. This solves the real-world pain:
 *   - foreign sites should see the VPN's location (bypass RU blocks);
 *   - but RU banks / gosuslugi / marketplaces geo-fence or risk-score foreign
 *     IPs, so reaching them THROUGH a foreign VPN gets you blocked, captcha'd,
 *     or logged out.
 *
 * Why not just "route *.ru direct": that's both too narrow and too broad.
 *   - Too narrow: Sberbank, Ozon, VK, Yandex serve critical assets/APIs on
 *     .com / .net / regional CDNs; a TLD check misses them.
 *   - Too broad: plenty of .ru domains are fronted by Cloudflare/foreign CDNs
 *     where "direct" gains nothing.
 * The robust signal is twofold and is exactly what mature clients
 * (Hiddify, Nekoray) use:
 *   1. geoip-ru        — route by the DESTINATION IP's country. Catches any
 *                        RU-hosted service regardless of its domain/TLD.
 *   2. geosite-category-gov-ru — curated upstream list of RU government /
 *                        banking domains (covers .com/.рф faces too). We do
 *                        NOT use the broad `category-ru` list: it means
 *                        "popular IN Russia" and includes YouTube/Google,
 *                        which must stay on the VPN.
 *
 * We pull these as sing-box `remote` rule-sets (binary .srs) downloaded
 * THROUGH the tunnel (download_detour: proxy-out — GitHub raw is itself often
 * throttled/blocked in RU, and the tunnel is up by the time the rule-set
 * loads) and cached via experimental.cache_file so they survive restarts and
 * refresh once a day.
 *
 * DNS correctness: a domain matched for direct egress must ALSO be resolved by
 * a direct (RU-visible) resolver — otherwise the tunnelled DNS returns the
 * site's nearest-to-the-VPN CDN node, the resolved IP isn't in geoip-ru, and
 * the connection wrongly goes through the VPN. So we add a `dns-direct` server
 * (local system resolver, NOT detoured) and a DNS rule binding the RU domain
 * rule-sets to it. This module emits that DNS rule too.
 *
 * Everything here is PURE (no electron, no store) so it's unit-testable; the
 * caller passes the resolved options in.
 */

export interface SmartRouteOptions {
  /** Master switch. When false, all generators return empty. */
  enabled: boolean
  /** Also route online maps direct (Yandex/2GIS/Google Maps tiles). */
  mapsDirect: boolean
  /**
   * Tag of the direct-resolver DNS server the caller will define in the dns
   * block (so RU domains resolve to their real RU IPs). Defaults to
   * 'dns-direct'.
   */
  directDnsTag?: string
  /**
   * Absolute path to the directory holding the bundled `.srs` rule-set files
   * (geoip-ru.srs, geosite-category-gov-ru.srs). When set, rule-sets are
   * emitted as `type: 'local'` — sing-box loads them straight off disk with
   * ZERO network dependency.
   *
   * WHY THIS MATTERS (the bug that motivated it): when rule-sets were `remote`
   * sing-box downloaded them THROUGH proxy-out at startup. A sing-box `remote`
   * rule-set whose initial fetch fails is a FATAL startup error — the whole
   * core refuses to run. So a slow/blocked GitHub fetch meant TUN never came
   * up, the kill-switch was skipped, and the user's REAL IP was exposed while
   * the UI still said "Подключено". Local files can't time out, so the routing
   * nicety can never again take down the core tunnel.
   *
   * When omitted, falls back to `remote` download (legacy / direct unit-test
   * callers that don't stage the files).
   */
  ruleSetDir?: string
}

// Rule-set tags + their upstream .srs URLs.
//
// IMPORTANT — what we deliberately do NOT use: `geosite-category-ru`.
// Despite the name it is NOT "Russian-owned services". It's the v2fly
// "category-ru" list = "domains popular/accessed IN Russia", which INCLUDES
// youtube.com, google, and other foreign giants. Routing that category direct
// sent YouTube down the throttled ISP path (TSPU) and killed it, while leaving
// the tunnel up — the "Telegram works, YouTube doesn't" breakage the user hit.
// We only use the genuinely-Russian signals: gov/banks geosite + geoip-ru.
export const RU_GEOIP_RULESET = 'geoip-ru'
export const RU_GOV_GEOSITE_RULESET = 'geosite-category-gov-ru'

const RULESET_URLS: Record<string, string> = {
  [RU_GEOIP_RULESET]: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs',
  [RU_GOV_GEOSITE_RULESET]: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-gov-ru.srs'
}

// Local .srs filenames as bundled in app resources / staged into the runtime
// dir. Loaded with `type: local` so startup has no network dependency.
const RULESET_LOCAL_FILES: Record<string, string> = {
  [RU_GEOIP_RULESET]: 'geoip-ru.srs',
  [RU_GOV_GEOSITE_RULESET]: 'geosite-category-gov-ru.srs'
}

export interface SmartRouteRuleSetDescriptor {
  tag: string
  url: string
  fileName: string
  label: string
}

export function smartRouteRuleSetCatalog(): SmartRouteRuleSetDescriptor[] {
  return [
    {
      tag: RU_GEOIP_RULESET,
      url: RULESET_URLS[RU_GEOIP_RULESET],
      fileName: RULESET_LOCAL_FILES[RU_GEOIP_RULESET],
      label: 'RU GeoIP'
    },
    {
      tag: RU_GOV_GEOSITE_RULESET,
      url: RULESET_URLS[RU_GOV_GEOSITE_RULESET],
      fileName: RULESET_LOCAL_FILES[RU_GOV_GEOSITE_RULESET],
      label: 'RU gov geosite'
    }
  ]
}

/** The bundled .srs filenames the caller must stage into the runtime dir. */
export function smartRouteLocalRuleSetFiles(): string[] {
  return [RU_GEOIP_RULESET, ...ruDomainRuleSets()].map((tag) => RULESET_LOCAL_FILES[tag])
}

/**
 * The domain rule-sets used for RU-direct matching. ONLY the government/banks
 * list — see the comment above on why category-ru is intentionally excluded.
 */
function ruDomainRuleSets(): string[] {
  return [RU_GOV_GEOSITE_RULESET]
}

/**
 * Online-maps domains that benefit from real-location egress. Kept as a small
 * inline list rather than a rule-set: it's tiny, stable, and there's no
 * upstream "maps" geosite we can rely on. Suffix-matched.
 */
const MAPS_DOMAIN_SUFFIXES = [
  '.maps.yandex.net',
  '.maps.yandex.ru',
  '.2gis.com',
  '.2gis.ru',
  '.maps.googleapis.com',
  '.maps.gstatic.com'
]

/**
 * Media/CDN domains that must stay on the VPN even when their resolved IP is
 * in Russia.
 *
 * Why: YouTube and adjacent Google media CDNs regularly resolve to RU-hosted
 * cache nodes (`80.77.175.44-47` in the latest diagnostic dump). If those
 * flows hit the Smart RU `geoip-ru -> direct-out` rule, they leave through the
 * ISP path, get throttled / reset, and playback stalls on a black screen for a
 * few seconds before Chromium retries elsewhere. We pin the domains to
 * `proxy-out` / `dns-remote` BEFORE the RU-direct rules so the sniffed SNI/Host
 * wins over the IP-country match.
 *
 * Keep this list intentionally narrow: broad Google suffixes like
 * `.googleapis.com` or `.gstatic.com` would collide with `mapsDirect`.
 */
const VPN_PINNED_MEDIA_SUFFIXES = [
  '.youtube.com',
  '.youtu.be',
  '.youtube-nocookie.com',
  '.googlevideo.com',
  '.ytimg.com',
  '.ggpht.com',
  '.youtubei.googleapis.com',
  '.youtube-ui.l.google.com'
]

/**
 * IP / "what's my location" checker services. These MUST always egress through
 * the VPN (proxy-out), never direct — for two reasons:
 *   1. Many are RU-hosted or on .ru (2ip.ru, ip.bel.ru, …). Smart RU routing
 *      would otherwise send them DIRECT, the page would show the user's REAL
 *      IP, and the user would wrongly conclude "the VPN is leaking".
 *   2. Conceptually an IP checker answers "what does the world see as my IP" —
 *      while the VPN is on, the honest answer is the VPN's exit IP. Pinning
 *      these to proxy-out makes the checkers agree with what every other
 *      foreign site sees.
 * Matched as domain_suffix (covers apex + subdomains). Exported so the
 * routing self-test can avoid using a pinned domain as its RU-probe.
 */
export const IP_CHECKER_SUFFIXES = [
  // Global
  '.ipify.org',
  '.ipinfo.io',
  '.myip.com',
  '.ifconfig.me',
  '.icanhazip.com',
  '.ipapi.co',
  '.ip-api.com',
  '.whatismyipaddress.com',
  '.whatismyip.com',
  '.iplocation.net',
  '.ipleak.net',
  '.browserleaks.com',
  '.dnsleaktest.com',
  '.whoer.net',
  '.wtfismyip.com',
  '.myexternalip.com',
  '.getmyip.com',
  '.ip.sb',
  '.seeip.org',
  '.bigdatacloud.net',
  // Russian
  '.2ip.ru',
  '.2ip.io',
  '.myip.ru',
  '.smart-ip.net',
  '.ip-ping.ru'
]

/**
 * Turn a list of leading-dot suffixes (".2ip.ru", ".ipify.org") into a
 * sing-box matcher object that catches BOTH the apex and any subdomain.
 *
 * THE BUG THIS FIXES: in sing-box, `domain_suffix: ".2ip.ru"` matches
 * `www.2ip.ru` but NOT the bare apex `2ip.ru` — the leading dot makes it
 * "subdomains only". So a user visiting `2ip.ru` (apex) slipped past the
 * IP-checker pin, fell through to the RU-direct rules (2ip.ru is RU-hosted),
 * egressed direct, and saw their REAL IP — exactly the "VPN leaks" symptom.
 *
 * Correct form: emit the apex as an exact `domain` match AND the dotted form
 * as `domain_suffix`. Both keys in one rule are OR'd by sing-box. We keep the
 * leading-dot suffix (rather than a dotless `domain_suffix: "2ip.ru"`) because
 * the dotless form over-matches unrelated hosts like `my2ip.ru`.
 *
 * Returns `{ domain, domain_suffix }` ready to spread into a rule object.
 */
export function suffixListToMatcher(suffixes: string[]): {
  domain: string[]
  domain_suffix: string[]
} {
  const domain: string[] = []
  const domain_suffix: string[] = []
  for (const raw of suffixes) {
    const s = String(raw || '').trim()
    if (!s) continue
    const dotted = s.startsWith('.') ? s : `.${s}`
    const apex = dotted.slice(1) // strip the single leading dot
    if (apex) domain.push(apex)
    domain_suffix.push(dotted)
  }
  return { domain, domain_suffix }
}

/**
 * Rule-set definitions to splice into route.rule_set. Empty when disabled.
 *
 * When `opts.ruleSetDir` is set we emit `type: 'local'` entries pointing at the
 * bundled .srs files — sing-box loads them off disk, so a missing GitHub/slow
 * tunnel can never make startup fail (the bug this fixes: a `remote` rule-set
 * whose initial download times out is a FATAL sing-box startup error, which
 * took the whole tunnel down and exposed the real IP).
 *
 * When `ruleSetDir` is absent we fall back to the legacy `remote` form
 * (`downloadDetour` = proxy-out) for direct/unit-test callers.
 */
export function smartRouteRuleSets(
  opts: SmartRouteOptions,
  downloadDetour = 'proxy-out'
): Array<Record<string, any>> {
  if (!opts.enabled) return []
  const tags = [RU_GEOIP_RULESET, ...ruDomainRuleSets()]
  return tags.map((tag) => {
    if (opts.ruleSetDir) {
      // Forward slashes are valid on Windows in sing-box JSON and avoid having
      // to JSON-escape backslashes; join manually so we don't pull in `path`
      // (keeps this module pure/portable for the unit tests).
      const dir = opts.ruleSetDir.replace(/\\/g, '/').replace(/\/+$/, '')
      return {
        type: 'local',
        tag,
        format: 'binary',
        path: `${dir}/${RULESET_LOCAL_FILES[tag]}`
      }
    }
    return {
      type: 'remote',
      tag,
      format: 'binary',
      url: RULESET_URLS[tag],
      download_detour: downloadDetour,
      update_interval: '1d'
    }
  })
}

/**
 * Route rules that send RU traffic to direct-out. Emitted AFTER the user's own
 * domain rules (so an explicit user override still wins) and BEFORE the
 * private-range / catch-all rules. Empty when disabled.
 *
 * Order within: domains first (cheap, sniffed SNI), then geoip (needs the
 * resolved IP). Maps (optional) is a plain domain_suffix rule.
 */
export function smartRouteRules(opts: SmartRouteOptions): Array<Record<string, any>> {
  if (!opts.enabled) return []
  const rules: Array<Record<string, any>> = []

  // 0. IP/location checkers ALWAYS go through the VPN — placed FIRST so they
  //    win over the RU-direct rules below. Otherwise an RU-hosted checker
  //    (2ip.ru) would match geoip-ru/geosite-ru and egress direct, showing the
  //    user's real IP and faking a "leak". Match apex AND subdomains — a bare
  //    `domain_suffix: ".2ip.ru"` would miss the apex `2ip.ru` (the common
  //    case: users open `2ip.ru`, not `www.2ip.ru`).
  rules.push({ ...suffixListToMatcher(IP_CHECKER_SUFFIXES), outbound: 'proxy-out' })

  // 0.5. Media/CDN domains that often resolve to RU caches MUST still use the
  // VPN. Otherwise the later geoip-ru direct rule steals them and breaks video.
  rules.push({ ...suffixListToMatcher(VPN_PINNED_MEDIA_SUFFIXES), outbound: 'proxy-out' })

  // 1. Curated RU domain lists → direct.
  rules.push({ rule_set: ruDomainRuleSets(), outbound: 'direct-out' })

  // 2. Optional: online maps → direct (real location).
  if (opts.mapsDirect) {
    rules.push({ ...suffixListToMatcher(MAPS_DOMAIN_SUFFIXES), outbound: 'direct-out' })
  }

  // 3. RU-hosted IPs → direct (catches services regardless of domain/TLD).
  rules.push({ rule_set: RU_GEOIP_RULESET, outbound: 'direct-out' })

  return rules
}

/**
 * DNS rule that makes RU domains resolve via the direct resolver, so the
 * resolved IP is the real RU one and geoip-ru matches. Empty when disabled.
 * The caller must define a DNS server with tag `directDnsTag`.
 */
export function smartRouteDnsRules(opts: SmartRouteOptions): Array<Record<string, any>> {
  if (!opts.enabled) return []
  const server = opts.directDnsTag || 'dns-direct'
  const rules: Array<Record<string, any>> = []
  // IP checkers: resolve through the REMOTE (tunnelled) resolver, NOT the
  // direct one — matched first so an RU-hosted checker doesn't fall into the
  // RU-direct DNS rule below and resolve to its RU node. Apex + subdomains.
  rules.push({ ...suffixListToMatcher(IP_CHECKER_SUFFIXES), server: 'dns-remote' })
  // Media/CDN domains: same story as route rules above — keep them on the
  // tunnelled resolver so we don't prefer RU CDN nodes for throttled media.
  rules.push({ ...suffixListToMatcher(VPN_PINNED_MEDIA_SUFFIXES), server: 'dns-remote' })
  // RU domains → direct resolver (real RU IPs, so geoip-ru matches).
  rules.push({ rule_set: ruDomainRuleSets(), server })
  if (opts.mapsDirect) {
    rules.push({ ...suffixListToMatcher(MAPS_DOMAIN_SUFFIXES), server })
  }
  return rules
}

/**
 * Whether the smart-route feature needs a direct DNS server defined. Mirrors
 * `enabled` but named for intent at the call site in the DNS block builder.
 */
export function smartRouteNeedsDirectDns(opts: SmartRouteOptions): boolean {
  return opts.enabled
}
