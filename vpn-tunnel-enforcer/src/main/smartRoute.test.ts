/**
 * Tests for the pure smart RU split-routing generators.
 */

import { describe, it, expect } from 'vitest'
import {
  smartRouteRuleSets,
  smartRouteRules,
  smartRouteDnsRules,
  smartRouteNeedsDirectDns,
  suffixListToMatcher,
  RU_GEOIP_RULESET,
  RU_GOV_GEOSITE_RULESET,
  type SmartRouteOptions
} from './smartRoute'

const ON: SmartRouteOptions = { enabled: true, mapsDirect: false, directDnsTag: 'dns-direct' }
const OFF: SmartRouteOptions = { enabled: false, mapsDirect: false }
const ON_MAPS: SmartRouteOptions = { enabled: true, mapsDirect: true, directDnsTag: 'dns-direct' }

describe('smartRouteRuleSets', () => {
  it('returns [] when disabled', () => {
    expect(smartRouteRuleSets(OFF)).toEqual([])
  })

  it('returns geoip + gov geosite remote rule-sets through proxy-out (NOT category-ru)', () => {
    const sets = smartRouteRuleSets(ON, 'proxy-out')
    const tags = sets.map((s) => s.tag)
    expect(tags).toEqual([RU_GEOIP_RULESET, RU_GOV_GEOSITE_RULESET])
    // category-ru must NOT be present — it includes YouTube/Google and would
    // route them direct (TSPU kills them). Regression guard.
    expect(tags).not.toContain('geosite-category-ru')
    for (const s of sets) {
      expect(s.type).toBe('remote')
      expect(s.format).toBe('binary')
      expect(s.download_detour).toBe('proxy-out')
      expect(String(s.url)).toMatch(/^https:\/\/raw\.githubusercontent\.com\/SagerNet\/.+\.srs$/)
    }
  })
})

describe('smartRouteRules', () => {
  it('returns [] when disabled', () => {
    expect(smartRouteRules(OFF)).toEqual([])
  })

  it('pins IP checkers to proxy-out FIRST (before RU-direct rules)', () => {
    const rules = smartRouteRules(ON)
    const idxChecker = rules.findIndex(
      (r) => Array.isArray(r.domain_suffix) && r.outbound === 'proxy-out'
    )
    const idxRuDirect = rules.findIndex((r) => Array.isArray(r.rule_set))
    expect(idxChecker).toBe(0)
    expect(idxChecker).toBeLessThan(idxRuDirect)
    // 2ip.ru (RU-hosted checker) must be in the pinned set so it doesn't go direct.
    const checkerRule = rules[idxChecker]
    expect(checkerRule.domain_suffix).toContain('.2ip.ru')
    expect(checkerRule.domain_suffix).toContain('.ipify.org')
  })

  it('pins the APEX of an IP checker, not just subdomains (2ip.ru bug)', () => {
    // Regression: domain_suffix ".2ip.ru" matches www.2ip.ru but NOT the bare
    // apex 2ip.ru in sing-box. The user opened `2ip.ru` and saw their real IP
    // because the apex slipped past the pin into the RU-direct rules.
    const rules = smartRouteRules(ON)
    const pin = rules[0]
    expect(pin.outbound).toBe('proxy-out')
    // Apex present as an EXACT domain match.
    expect(Array.isArray(pin.domain)).toBe(true)
    expect(pin.domain).toContain('2ip.ru')
    expect(pin.domain).toContain('ipify.org')
    // Subdomains still covered via suffix.
    expect(pin.domain_suffix).toContain('.2ip.ru')
  })

  it('routes RU domain lists and geoip-ru to direct-out', () => {
    const rules = smartRouteRules(ON)
    const domainRule = rules.find((r) => Array.isArray(r.rule_set))
    expect(domainRule?.outbound).toBe('direct-out')
    expect(domainRule?.rule_set).toEqual([RU_GOV_GEOSITE_RULESET])
    const geoipRule = rules.find((r) => r.rule_set === RU_GEOIP_RULESET)
    expect(geoipRule?.outbound).toBe('direct-out')
  })

  it('omits maps unless mapsDirect is set', () => {
    // Note: the IP-checker pin also uses domain_suffix, so check specifically
    // for a maps domain routed to direct-out.
    const hasMaps = (rules: Array<Record<string, any>>) =>
      rules.some((r) => Array.isArray(r.domain_suffix) && r.outbound === 'direct-out' &&
        r.domain_suffix.some((d: string) => d.includes('2gis') || d.includes('yandex')))
    expect(hasMaps(smartRouteRules(ON))).toBe(false)
    const withMaps = smartRouteRules(ON_MAPS)
    const mapsRule = withMaps.find((r) => Array.isArray(r.domain_suffix) && r.outbound === 'direct-out')
    expect(mapsRule?.outbound).toBe('direct-out')
    expect(mapsRule?.domain_suffix.some((d: string) => d.includes('yandex'))).toBe(true)
  })

  it('domain rule comes before geoip rule (cheap SNI match first)', () => {
    const rules = smartRouteRules(ON)
    const idxDomain = rules.findIndex((r) => Array.isArray(r.rule_set))
    const idxGeoip = rules.findIndex((r) => r.rule_set === RU_GEOIP_RULESET)
    expect(idxDomain).toBeLessThan(idxGeoip)
  })
})

describe('smartRouteDnsRules', () => {
  it('returns [] when disabled', () => {
    expect(smartRouteDnsRules(OFF)).toEqual([])
  })

  it('resolves IP checkers via dns-remote (tunnelled) FIRST', () => {
    const rules = smartRouteDnsRules(ON)
    const first = rules[0]
    expect(Array.isArray(first.domain_suffix)).toBe(true)
    expect(first.server).toBe('dns-remote')
    expect(first.domain_suffix).toContain('.2ip.ru')
  })

  it('binds RU domain rule-sets to the direct resolver tag', () => {
    const rules = smartRouteDnsRules(ON)
    const ruRule = rules.find((r) => Array.isArray(r.rule_set))
    expect(ruRule?.server).toBe('dns-direct')
    expect(ruRule?.rule_set).toEqual([RU_GOV_GEOSITE_RULESET])
  })

  it('defaults the resolver tag to dns-direct when not provided', () => {
    const rules = smartRouteDnsRules({ enabled: true, mapsDirect: false })
    const ruRule = rules.find((r) => Array.isArray(r.rule_set))
    expect(ruRule?.server).toBe('dns-direct')
  })

  it('adds maps DNS rule when mapsDirect is set', () => {
    const rules = smartRouteDnsRules(ON_MAPS)
    expect(rules.some((r) => Array.isArray(r.domain_suffix) && r.domain_suffix.some((d: string) => d.includes('2gis')) && r.server === 'dns-direct')).toBe(true)
  })
})

describe('smartRouteNeedsDirectDns', () => {
  it('mirrors enabled', () => {
    expect(smartRouteNeedsDirectDns(ON)).toBe(true)
    expect(smartRouteNeedsDirectDns(OFF)).toBe(false)
  })
})

describe('suffixListToMatcher', () => {
  it('emits both apex domain and dotted suffix', () => {
    const m = suffixListToMatcher(['.2ip.ru', '.ipify.org'])
    expect(m.domain).toEqual(['2ip.ru', 'ipify.org'])
    expect(m.domain_suffix).toEqual(['.2ip.ru', '.ipify.org'])
  })

  it('normalises entries without a leading dot', () => {
    const m = suffixListToMatcher(['2ip.ru'])
    expect(m.domain).toEqual(['2ip.ru'])
    expect(m.domain_suffix).toEqual(['.2ip.ru'])
  })

  it('skips empty/whitespace entries', () => {
    const m = suffixListToMatcher(['', '   ', '.x.com'])
    expect(m.domain).toEqual(['x.com'])
    expect(m.domain_suffix).toEqual(['.x.com'])
  })
})
