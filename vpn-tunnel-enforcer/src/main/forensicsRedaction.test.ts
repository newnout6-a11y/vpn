/**
 * Tests for forensicsRedaction — the pseudonymization applied to
 * traffic-forensics artifacts before they go into a support ZIP (finding #5).
 *
 * Two things have to hold simultaneously, and they pull against each other:
 *   1. No real address or domain leaves the machine.
 *   2. The artifacts stay diagnosable — cross-file correlation (this DNS answer
 *      → that flow → that reset) must survive, or users go back to sending raw
 *      captures and the fix makes privacy worse, not better.
 * Most of the tests below pin property 2, because property 1 is easy to get
 * right by over-masking and property 2 is what over-masking destroys.
 */

import { describe, expect, it } from 'vitest'
import {
  createForensicsRedactor,
  redactJsonDocument,
  redactNdjson
} from './forensicsRedaction'

describe('createForensicsRedactor — IPv4', () => {
  it('replaces a public address with a class-tagged token', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('connect to 203.0.113.7:443')

    expect(out).not.toContain('203.0.113.7')
    expect(out).toContain('<ip-public-1>')
    expect(out).toContain(':443')
  })

  it('assigns the same token to the same address across separate calls', () => {
    // This is the whole point: dns.ndjson and flows.ndjson are redacted by
    // separate calls and must still line up.
    const r = createForensicsRedactor()
    const dns = r.redactText('a.example.com -> 203.0.113.7')
    const flow = r.redactText('flow 203.0.113.7:443 reset')

    const token = dns.match(/<ip-public-\d+>/)?.[0]
    expect(token).toBeTruthy()
    expect(flow).toContain(token!)
  })

  it('assigns distinct tokens to distinct addresses', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('203.0.113.7 talked to 198.51.100.9')

    expect(out).toContain('<ip-public-1>')
    expect(out).toContain('<ip-public-2>')
  })

  it('distinguishes private from public, because that is the leak question', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('10.0.0.5 192.168.1.1 172.16.3.4 100.64.0.1 169.254.1.2 8.8.8.8')

    expect((out.match(/<ip-private-\d+>/g) ?? []).length).toBe(5)
    expect((out.match(/<ip-public-\d+>/g) ?? []).length).toBe(1)
  })

  it('leaves loopback readable', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('proxy on 127.0.0.1:10808, bound 0.0.0.0')

    expect(out).toContain('127.0.0.1')
    expect(out).toContain('0.0.0.0')
  })

  it('leaves our own TUN addresses readable', () => {
    // tunPathConfirmed reasoning is unreadable without them, and they are
    // constants from this source tree — masking them protects nothing.
    const r = createForensicsRedactor()
    const out = r.redactText('gw 192.168.250.253 resolver 192.168.250.254')

    expect(out).toContain('192.168.250.253')
    expect(out).toContain('192.168.250.254')
  })

  it('does not mangle version strings that look like dotted quads', () => {
    const r = createForensicsRedactor()
    // A 4-part version is genuinely ambiguous with an IPv4 literal; make sure
    // whatever we do is at least consistent and does not corrupt surrounding text.
    const out = r.redactText('sing-box version 1.9.3 build ok')

    expect(out).toContain('sing-box version 1.9.3 build ok')
  })
})

describe('createForensicsRedactor — IPv6 and MAC', () => {
  it('replaces a public IPv6 address', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('remote 2001:db8::dead:beef port 443')

    expect(out).not.toContain('2001:db8::dead:beef')
    expect(out).toContain('<ipv6-public-1>')
  })

  it('classifies link-local and unique-local IPv6 as private', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('fe80::1%eth0 and fd00::abcd')

    expect((out.match(/<ipv6-private-\d+>/g) ?? []).length).toBe(2)
  })

  it('leaves ::1 readable', () => {
    const r = createForensicsRedactor()
    expect(r.redactText('bound ::1')).toContain('::1')
  })

  it('replaces MAC addresses in both separator styles', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('nic aa:bb:cc:dd:ee:ff peer 00-11-22-33-44-55')

    expect(out).not.toContain('aa:bb:cc:dd:ee:ff')
    expect(out).not.toContain('00-11-22-33-44-55')
    expect(out).toContain('<mac-1>')
    expect(out).toContain('<mac-2>')
  })

  it('treats case variants of one MAC as the same device', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('AA:BB:CC:DD:EE:FF then aa:bb:cc:dd:ee:ff')

    expect((out.match(/<mac-1>/g) ?? []).length).toBe(2)
    expect(out).not.toContain('<mac-2>')
  })

  it('does not let a MAC be shredded by the IPv6 pattern', () => {
    // Both patterns match colon-separated hex; the MAC must win or the
    // artifact fills with bogus IPv6 tokens.
    const r = createForensicsRedactor()
    const out = r.redactText('aa:bb:cc:dd:ee:ff')

    expect(out).toBe('<mac-1>')
  })
})

describe('createForensicsRedactor — hostnames', () => {
  it('masks the registrable label but keeps the public suffix', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('query for secret-service.example.com')

    expect(out).not.toContain('secret-service')
    expect(out).not.toContain('example')
    expect(out).toContain('.com')
  })

  it('keeps .ru visible so smart-RU routing stays analyzable', () => {
    // "Was an RU host sent direct, was a foreign host sent direct" is the
    // split-routing question, and it is answerable from the suffix alone.
    const r = createForensicsRedactor()
    const out = r.redactText('gosuslugi.ru and foreign.com')

    expect(out).toContain('.ru')
    expect(out).toContain('.com')
    expect(out).not.toContain('gosuslugi')
    expect(out).not.toContain('foreign')
  })

  it('gives subdomains of one domain the same token', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('a.example.com b.example.com other.net')

    const tokens = out.match(/<domain-\d+>/g) ?? []
    expect(tokens.length).toBe(3)
    expect(tokens[0]).toBe(tokens[1])
    expect(tokens[2]).not.toBe(tokens[0])
  })

  it('records subdomain depth without disclosing the labels', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('deep.cdn.example.com')

    expect(out).toContain('<sub2>')
    expect(out).not.toContain('deep')
    expect(out).not.toContain('cdn')
  })

  it('masks a whole unclassifiable name rather than guessing a split', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('server.internal-corp-tld')

    expect(out).not.toContain('server')
  })

  it('leaves localhost readable', () => {
    const r = createForensicsRedactor()
    expect(r.redactText('via localhost')).toContain('localhost')
  })

  it('does not mistake our own artifact filenames for hostnames', () => {
    const r = createForensicsRedactor()
    const out = r.redactText('missing expected artifact: wfp-state.xml, summary.json, pktmon-trace.txt')

    expect(out).toContain('wfp-state.xml')
    expect(out).toContain('summary.json')
    expect(out).toContain('pktmon-trace.txt')
  })
})

describe('createForensicsRedactor — JSON', () => {
  it('redacts string values and leaves schema keys readable', () => {
    const r = createForensicsRedactor()
    const out = r.redactJson({
      remoteAddress: '203.0.113.7',
      remotePort: 443,
      queryName: 'tracker.example.org',
      verdict: false
    }) as Record<string, unknown>

    // Keys are ours, not the user's — they must stay readable to be useful.
    expect(Object.keys(out).sort()).toEqual(['queryName', 'remoteAddress', 'remotePort', 'verdict'])
    expect(out.remoteAddress).toBe('<ip-public-1>')
    expect(out.remotePort).toBe(443)
    expect(out.verdict).toBe(false)
    expect(String(out.queryName)).not.toContain('tracker')
  })

  it('walks nested objects and arrays', () => {
    const r = createForensicsRedactor()
    const out = JSON.stringify(r.redactJson({
      flows: [
        { peer: '203.0.113.7', nested: { host: 'a.example.com' } },
        { peer: '198.51.100.9' }
      ]
    }))

    expect(out).not.toContain('203.0.113.7')
    expect(out).not.toContain('198.51.100.9')
    expect(out).not.toContain('example')
  })
})

describe('redactNdjson', () => {
  it('redacts each line and preserves line structure', () => {
    const r = createForensicsRedactor()
    const body = [
      JSON.stringify({ ts: 1, peer: '203.0.113.7' }),
      JSON.stringify({ ts: 2, peer: '203.0.113.7' }),
      ''
    ].join('\n')

    const out = redactNdjson(body, r)
    const lines = out.split('\n')

    expect(lines.length).toBe(3)
    expect(out).not.toContain('203.0.113.7')
    // Same address on both lines → same token.
    expect((out.match(/<ip-public-1>/g) ?? []).length).toBe(2)
    expect(JSON.parse(lines[0]).ts).toBe(1)
  })

  it('still scrubs a truncated trailing line instead of passing it through', () => {
    // The capture may have been mid-write. A line we cannot parse is exactly
    // the line most likely to contain a raw address.
    const r = createForensicsRedactor()
    const body = `${JSON.stringify({ ts: 1, peer: '203.0.113.7' })}\n{"ts":2,"peer":"198.51.100.9`

    const out = redactNdjson(body, r)

    expect(out).not.toContain('203.0.113.7')
    expect(out).not.toContain('198.51.100.9')
  })
})

describe('redactJsonDocument', () => {
  it('pretty-prints redacted JSON', () => {
    const r = createForensicsRedactor()
    const out = redactJsonDocument(JSON.stringify({ peer: '203.0.113.7' }), r)

    expect(out).toContain('<ip-public-1>')
    expect(out).toContain('\n')
  })

  it('falls back to text redaction for malformed JSON', () => {
    const r = createForensicsRedactor()
    const out = redactJsonDocument('{ this is not json 203.0.113.7', r)

    expect(out).not.toContain('203.0.113.7')
    expect(out).toContain('<ip-public-1>')
  })
})

describe('stats', () => {
  it('counts distinct replaced values for the export manifest', () => {
    const r = createForensicsRedactor()
    r.redactText('203.0.113.7 203.0.113.7 198.51.100.9 a.example.com b.example.com aa:bb:cc:dd:ee:ff 2001:db8::1')

    const stats = r.stats()
    expect(stats.ipv4).toBe(2)
    expect(stats.ipv6).toBe(1)
    expect(stats.mac).toBe(1)
    // Both hosts share one registrable domain.
    expect(stats.hosts).toBe(1)
  })

  it('does not count pass-through values', () => {
    const r = createForensicsRedactor()
    r.redactText('127.0.0.1 ::1 192.168.250.254 localhost')

    expect(r.stats()).toEqual({ ipv4: 0, ipv6: 0, mac: 0, hosts: 0 })
  })
})

describe('independence between exports', () => {
  it('does not share tokens across redactor instances', () => {
    // Each export gets a fresh mapping so token N in one bundle cannot be
    // cross-referenced against token N in another.
    const a = createForensicsRedactor()
    const b = createForensicsRedactor()

    a.redactText('198.51.100.9')
    const first = a.redactText('203.0.113.7')
    const second = b.redactText('203.0.113.7')

    expect(first).toBe('<ip-public-2>')
    expect(second).toBe('<ip-public-1>')
  })
})
