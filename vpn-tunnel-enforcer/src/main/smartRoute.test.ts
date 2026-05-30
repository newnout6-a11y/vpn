/**
 * Tests for the pure smart RU split-routing generators.
 */

import { describe, it, expect } from 'vitest'
import {
  smartRouteRuleSets,
  smartRouteRules,
  smartRouteDnsRules,
  smartRouteNeedsDirectDns,
  RU_GEOIP_RULESET,
  RU_GEOSITE_RULESET,
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

  it('returns geoip + two geosite remote rule-sets through proxy-out', () => {
    const sets = smartRouteRuleSets(ON, 'proxy-out')
    const tags = sets.map((s) => s.tag)
    expect(tags).toEqual([RU_GEOIP_RULESET, RU_GEOSITE_RULESET, RU_GOV_GEOSITE_RULESET])
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

  it('routes RU domain lists and geoip-ru to direct-out', () => {
    const rules = smartRouteRules(ON)
    const domainRule = rules.find((r) => Array.isArray(r.rule_set))
    expect(domainRule?.outbound).toBe('direct-out')
    expect(domainRule?.rule_set).toEqual([RU_GEOSITE_RULESET, RU_GOV_GEOSITE_RULESET])
    const geoipRule = rules.find((r) => r.rule_set === RU_GEOIP_RULESET)
    expect(geoipRule?.outbound).toBe('direct-out')
  })

  it('omits maps unless mapsDirect is set', () => {
    expect(smartRouteRules(ON).some((r) => Array.isArray(r.domain_suffix))).toBe(false)
    const withMaps = smartRouteRules(ON_MAPS)
    const mapsRule = withMaps.find((r) => Array.isArray(r.domain_suffix))
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

  it('binds RU domain rule-sets to the direct resolver tag', () => {
    const rules = smartRouteDnsRules(ON)
    expect(rules[0].server).toBe('dns-direct')
    expect(rules[0].rule_set).toEqual([RU_GEOSITE_RULESET, RU_GOV_GEOSITE_RULESET])
  })

  it('defaults the resolver tag to dns-direct when not provided', () => {
    const rules = smartRouteDnsRules({ enabled: true, mapsDirect: false })
    expect(rules[0].server).toBe('dns-direct')
  })

  it('adds maps DNS rule when mapsDirect is set', () => {
    const rules = smartRouteDnsRules(ON_MAPS)
    expect(rules.some((r) => Array.isArray(r.domain_suffix) && r.server === 'dns-direct')).toBe(true)
  })
})

describe('smartRouteNeedsDirectDns', () => {
  it('mirrors enabled', () => {
    expect(smartRouteNeedsDirectDns(ON)).toBe(true)
    expect(smartRouteNeedsDirectDns(OFF)).toBe(false)
  })
})
