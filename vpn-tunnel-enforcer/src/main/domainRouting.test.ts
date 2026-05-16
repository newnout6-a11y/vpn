/**
 * Unit tests for domainRouting.ts pure functions.
 */

import { describe, it, expect } from 'vitest'
import { matchDomain, parseDomainList } from './domainRouting'
import type { DomainRule } from '../shared/ipc-types'

// ─── Helper ──────────────────────────────────────────────────────────────────

function makeRule(
  pattern: string,
  priority: number,
  action: 'vpn' | 'direct' | 'block' = 'vpn'
): DomainRule {
  return { id: `rule-${priority}`, pattern, action, priority, hitCount: 0 }
}

// ─── matchDomain ─────────────────────────────────────────────────────────────

describe('matchDomain', () => {
  it('returns null for empty rules list', () => {
    expect(matchDomain([], 'example.com')).toBeNull()
  })

  it('returns null for empty domain', () => {
    const rules = [makeRule('example.com', 0)]
    expect(matchDomain(rules, '')).toBeNull()
  })

  it('matches exact domain', () => {
    const rules = [makeRule('example.com', 0)]
    expect(matchDomain(rules, 'example.com')).toEqual(rules[0])
  })

  it('exact match is case-insensitive', () => {
    const rules = [makeRule('Example.COM', 0)]
    expect(matchDomain(rules, 'example.com')).toEqual(rules[0])
  })

  it('wildcard *.x.com matches subdomain', () => {
    const rules = [makeRule('*.example.com', 0)]
    expect(matchDomain(rules, 'sub.example.com')).toEqual(rules[0])
  })

  it('wildcard *.x.com matches deep subdomain', () => {
    const rules = [makeRule('*.example.com', 0)]
    expect(matchDomain(rules, 'a.b.c.example.com')).toEqual(rules[0])
  })

  it('wildcard *.x.com does NOT match the base domain itself', () => {
    const rules = [makeRule('*.example.com', 0)]
    expect(matchDomain(rules, 'example.com')).toBeNull()
  })

  it('returns first matching rule by priority', () => {
    const rules = [
      makeRule('*.example.com', 1, 'direct'),
      makeRule('sub.example.com', 0, 'vpn')
    ]
    // sub.example.com matches both, but priority 0 rule wins
    const result = matchDomain(rules, 'sub.example.com')
    expect(result?.action).toBe('vpn')
    expect(result?.priority).toBe(0)
  })

  it('returns null when no rule matches', () => {
    const rules = [makeRule('*.google.com', 0), makeRule('facebook.com', 1)]
    expect(matchDomain(rules, 'twitter.com')).toBeNull()
  })

  it('handles domain with leading/trailing whitespace', () => {
    const rules = [makeRule('example.com', 0)]
    expect(matchDomain(rules, '  example.com  ')).toEqual(rules[0])
  })
})

// ─── parseDomainList ─────────────────────────────────────────────────────────

describe('parseDomainList', () => {
  it('returns empty array for empty string', () => {
    expect(parseDomainList('')).toEqual([])
  })

  it('parses single domain', () => {
    const result = parseDomainList('example.com')
    expect(result).toHaveLength(1)
    expect(result[0].pattern).toBe('example.com')
    expect(result[0].priority).toBe(0)
    expect(result[0].action).toBe('direct')
    expect(result[0].hitCount).toBe(0)
  })

  it('parses multiple domains with newlines', () => {
    const text = 'example.com\ngoogle.com\n*.facebook.com'
    const result = parseDomainList(text)
    expect(result).toHaveLength(3)
    expect(result[0].pattern).toBe('example.com')
    expect(result[0].priority).toBe(0)
    expect(result[1].pattern).toBe('google.com')
    expect(result[1].priority).toBe(1)
    expect(result[2].pattern).toBe('*.facebook.com')
    expect(result[2].priority).toBe(2)
  })

  it('skips empty lines', () => {
    const text = 'example.com\n\n\ngoogle.com\n'
    const result = parseDomainList(text)
    expect(result).toHaveLength(2)
  })

  it('trims whitespace from lines', () => {
    const text = '  example.com  \n\tgoogle.com\t'
    const result = parseDomainList(text)
    expect(result[0].pattern).toBe('example.com')
    expect(result[1].pattern).toBe('google.com')
  })

  it('handles Windows-style line endings (CRLF)', () => {
    const text = 'example.com\r\ngoogle.com\r\n'
    const result = parseDomainList(text)
    expect(result).toHaveLength(2)
  })

  it('skips whitespace-only lines', () => {
    const text = 'example.com\n   \n\t\ngoogle.com'
    const result = parseDomainList(text)
    expect(result).toHaveLength(2)
  })

  it('assigns unique IDs to each rule', () => {
    const text = 'a.com\nb.com\nc.com'
    const result = parseDomainList(text)
    const ids = result.map((r) => r.id)
    expect(new Set(ids).size).toBe(3)
  })
})
