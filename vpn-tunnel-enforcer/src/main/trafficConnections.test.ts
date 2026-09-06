import { describe, it, expect, vi } from 'vitest'

vi.mock('electron-store', () => ({
  default: class {
    private v: Record<string, unknown> = { domains: {} }
    get(k: string) { return this.v[k] }
    set(k: string, val: unknown) { this.v[k] = val }
  }
}))
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import {
  normalizeHost,
  shouldRecordHost,
  mergeConnectionSample,
  pruneDomains,
  DOH_INFRA_HOSTS,
  type TrafficDomainRecord,
  type SamplerSeen
} from './trafficConnections'

describe('normalizeHost', () => {
  it('lowercases, trims, drops trailing dot and port', () => {
    expect(normalizeHost('  WWW.Example.COM.  ')).toBe('www.example.com')
    expect(normalizeHost('example.com:443')).toBe('example.com')
    expect(normalizeHost('[2606:4700:4700::1111]:853')).toBe('2606:4700:4700::1111')
  })
  it('returns null for empties', () => {
    expect(normalizeHost('')).toBeNull()
    expect(normalizeHost(null)).toBeNull()
    expect(normalizeHost(undefined)).toBeNull()
  })
})

describe('shouldRecordHost', () => {
  it('accepts a normal public domain', () => {
    expect(shouldRecordHost('youtube.com')).toBe('youtube.com')
    expect(shouldRecordHost('i.ytimg.com')).toBe('i.ytimg.com')
  })
  it('rejects IP literals', () => {
    expect(shouldRecordHost('13.143.214.3')).toBeNull()
    expect(shouldRecordHost('2606:4700:4700::1111')).toBeNull()
  })
  it('rejects localhost / lan / reverse-dns / service-discovery', () => {
    expect(shouldRecordHost('localhost')).toBeNull()
    expect(shouldRecordHost('printer.local')).toBeNull()
    expect(shouldRecordHost('host.lan')).toBeNull()
    expect(shouldRecordHost('1.0.0.127.in-addr.arpa')).toBeNull()
    expect(shouldRecordHost('_ldap._tcp.dc._msdcs.corp.example')).toBeNull()
  })
  it('rejects DoH resolver hostnames', () => {
    for (const h of ['cloudflare-dns.com', 'dns.google', 'one.one.one.one']) {
      expect(DOH_INFRA_HOSTS.has(h)).toBe(true)
      expect(shouldRecordHost(h)).toBeNull()
    }
  })
  it('rejects the caller-supplied infra hosts (VPN server)', () => {
    const infra = new Set([...DOH_INFRA_HOSTS, 'no.savethis.cloud'])
    expect(shouldRecordHost('no.savethis.cloud', infra)).toBeNull()
    expect(shouldRecordHost('savethis.cloud', infra)).toBe('savethis.cloud')
  })
  it('rejects bare labels with no dot', () => {
    expect(shouldRecordHost('router')).toBeNull()
  })
})

const infra = DOH_INFRA_HOSTS

describe('mergeConnectionSample', () => {
  it('adds a new domain and counts the connection once', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    const seen: SamplerSeen = new Map()
    const snap = {
      connections: [
        { id: 'c1', metadata: { host: 'github.com' }, upload: 100, download: 900 }
      ]
    }
    const r1 = mergeConnectionSample(domains, snap, seen, infra, 1000)
    expect(r1.changed).toBe(true)
    expect(domains['github.com']).toMatchObject({
      domain: 'github.com', count: 1, bytesUp: 100, bytesDown: 900, firstSeen: 1000, lastSeen: 1000
    })
  })

  it('accrues only the byte delta on a repeat sighting of the same connection', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    const seen: SamplerSeen = new Map()
    const mk = (up: number, down: number) => ({
      connections: [{ id: 'c1', metadata: { host: 'github.com' }, upload: up, download: down }]
    })
    mergeConnectionSample(domains, mk(100, 900), seen, infra, 1000)
    mergeConnectionSample(domains, mk(150, 2000), seen, infra, 2000)
    expect(domains['github.com'].count).toBe(1)
    expect(domains['github.com'].bytesUp).toBe(150)
    expect(domains['github.com'].bytesDown).toBe(2000)
    expect(domains['github.com'].lastSeen).toBe(2000)
  })

  it('counts a brand-new connection id to the same domain as another visit', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    const seen: SamplerSeen = new Map()
    mergeConnectionSample(domains, {
      connections: [{ id: 'c1', metadata: { host: 'github.com' }, upload: 10, download: 10 }]
    }, seen, infra, 1000)
    mergeConnectionSample(domains, {
      connections: [{ id: 'c2', metadata: { host: 'github.com' }, upload: 20, download: 20 }]
    }, seen, infra, 1500)
    expect(domains['github.com'].count).toBe(2)
    expect(domains['github.com'].bytesUp).toBe(30)
  })

  it('drops closed connections from the seen map', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    const seen: SamplerSeen = new Map()
    mergeConnectionSample(domains, {
      connections: [{ id: 'c1', metadata: { host: 'a.com' }, upload: 1, download: 1 }]
    }, seen, infra, 1000)
    expect(seen.has('c1')).toBe(true)
    mergeConnectionSample(domains, { connections: [] }, seen, infra, 2000)
    expect(seen.has('c1')).toBe(false)
  })

  it('ignores connections with no recordable host', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    const seen: SamplerSeen = new Map()
    const r = mergeConnectionSample(domains, {
      connections: [
        { id: 'c1', metadata: { host: '' }, upload: 5, download: 5 },
        { id: 'c2', metadata: { host: '13.143.214.3' }, upload: 5, download: 5 },
        { id: 'c3', metadata: { host: 'cloudflare-dns.com' }, upload: 5, download: 5 }
      ]
    }, seen, infra, 1000)
    expect(r.changed).toBe(false)
    expect(Object.keys(domains)).toEqual([])
  })

  it('handles a null / malformed snapshot', () => {
    const seen: SamplerSeen = new Map()
    expect(mergeConnectionSample({}, null, seen, infra, 1).changed).toBe(false)
    expect(mergeConnectionSample({}, { connections: null }, seen, infra, 1).changed).toBe(false)
  })
})

describe('pruneDomains', () => {
  it('keeps the N most-recently-seen', () => {
    const domains: Record<string, TrafficDomainRecord> = {}
    for (let i = 0; i < 10; i++) {
      domains[`d${i}.com`] = { domain: `d${i}.com`, firstSeen: i, lastSeen: i, count: 1, bytesUp: 0, bytesDown: 0 }
    }
    pruneDomains(domains, 3)
    expect(Object.keys(domains).sort()).toEqual(['d7.com', 'd8.com', 'd9.com'])
  })
  it('is a no-op below the cap', () => {
    const domains: Record<string, TrafficDomainRecord> = {
      'a.com': { domain: 'a.com', firstSeen: 1, lastSeen: 1, count: 1, bytesUp: 0, bytesDown: 0 }
    }
    pruneDomains(domains, 100)
    expect(Object.keys(domains)).toEqual(['a.com'])
  })
})
