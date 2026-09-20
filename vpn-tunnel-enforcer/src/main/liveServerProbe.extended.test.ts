import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  isPublicFqdn,
  queryDoH,
  evaluateLiveCheckFindings,
  LIVE_PROBE_THRESHOLDS
} from './liveServerProbe'
import {
  parseCloudflareTrace,
  classifyOutboundProbeFailure
} from './keyHealthChecker'
import {
  sanitizeLiveCheckForStorage,
  computeHistoryDiff
} from './liveServerHistory'
import type {
  LiveServerCheck,
  TunnelHandshakeResult,
  LiveEgressResult,
  PathDiagnostics,
  PmtuDiagnostics,
  DnsDiagnostics
} from '../shared/ipc-types'

describe('Extended Live Server Probe Unit & Contract Tests', () => {
  describe('isPublicFqdn Hostname Guard', () => {
    it('allows valid public domain names', () => {
      expect(isPublicFqdn('example.com')).toBe(true)
      expect(isPublicFqdn('vpn.sub.service.org')).toBe(true)
      expect(isPublicFqdn('node-12.fra.example.co.uk')).toBe(true)
    })

    it('rejects IPv4 and IPv6 literals from public DoH leaking', () => {
      expect(isPublicFqdn('127.0.0.1')).toBe(false)
      expect(isPublicFqdn('192.168.1.1')).toBe(false)
      expect(isPublicFqdn('10.0.0.1')).toBe(false)
      expect(isPublicFqdn('::1')).toBe(false)
      expect(isPublicFqdn('2001:db8::1')).toBe(false)
      expect(isPublicFqdn('fe80::1')).toBe(false)
    })

    it('rejects single-label and private hostnames', () => {
      expect(isPublicFqdn('localhost')).toBe(false)
      expect(isPublicFqdn('myserver')).toBe(false)
      expect(isPublicFqdn('gateway.local')).toBe(false)
      expect(isPublicFqdn('node.lan')).toBe(false)
      expect(isPublicFqdn('nas.internal')).toBe(false)
      expect(isPublicFqdn('printer.home.arpa')).toBe(false)
    })
  })

  describe('queryDoH DNS-over-HTTPS Wire Format', () => {
    it('parses RFC 8427 DNS JSON wire response with TTL and AD flag', async () => {
      const mockFetch = vi.fn().mockImplementation((url: string) => {
        if (url.endsWith('type=AAAA')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({
              Status: 0,
              AD: true,
              Answer: [
                { name: 'vpn.example.com.', type: 28, TTL: 600, data: '2001:db8::1' }
              ]
            })
          })
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            Status: 0,
            AD: true,
            Answer: [
              { name: 'vpn.example.com.', type: 1, TTL: 300, data: '198.51.100.1' },
              { name: 'vpn.example.com.', type: 1, TTL: 300, data: '198.51.100.2' }
            ]
          })
        })
      })

      const origFetch = globalThis.fetch
      globalThis.fetch = mockFetch as any

      try {
        const result = await queryDoH(
          'google-doh',
          'Google Public DNS',
          'https://dns.google/resolve',
          'vpn.example.com'
        )

        expect(result.status).toBe('ok')
        expect(result.authenticatedData).toBe(true)
        expect(result.records.length).toBe(3)
        expect(result.records.map((r) => r.value)).toEqual([
          '198.51.100.1',
          '198.51.100.2',
          '2001:db8::1'
        ])
        expect(result.records[0].ttl).toBe(300)
        expect(result.records[2].ttl).toBe(600)
      } finally {
        globalThis.fetch = origFetch
      }
    })

    it('handles DoH network failure gracefully without throwing', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network unreachable'))
      const origFetch = globalThis.fetch
      globalThis.fetch = mockFetch as any

      try {
        const result = await queryDoH(
          'cloudflare-doh',
          'Cloudflare DoH',
          'https://cloudflare-dns.com/dns-query',
          'vpn.example.com'
        )

        expect(result.status).toBe('error')
        expect(result.error).toContain('Network unreachable')
        expect(result.records).toEqual([])
      } finally {
        globalThis.fetch = origFetch
      }
    })
  })

  describe('parseCloudflareTrace Reflector Parsing', () => {
    it('parses valid cloudflare trace payload', () => {
      const trace = `fl=123f45\nh=1.1.1.1\nip=203.0.113.195\nts=1700000000\nvisit_scheme=https\nuag=Mozilla/5.0\ncolo=FRA\nsliver=none\nhttp=http/2\nloc=DE\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n`
      const parsed = parseCloudflareTrace(trace)
      expect(parsed.egressIp).toBe('203.0.113.195')
      expect(parsed.country).toBe('DE')
    })

    it('returns empty object on empty or invalid trace', () => {
      expect(parseCloudflareTrace('')).toEqual({})
      expect(parseCloudflareTrace('error 502 Bad Gateway')).toEqual({})
    })
  })

  describe('classifyOutboundProbeFailure Handshake Reason Classification', () => {
    it('identifies authentication failures', () => {
      expect(classifyOutboundProbeFailure('vless', 'user authentication failed: bad key')).toBe('auth-failed')
      expect(classifyOutboundProbeFailure('vmess', 'wrong uuid in request header')).toBe('auth-failed')
    })

    it('identifies TLS and Reality failures', () => {
      expect(classifyOutboundProbeFailure('vless', 'reality verification failed: invalid server name')).toBe('tls-failed')
      expect(classifyOutboundProbeFailure('trojan', 'x509: certificate signed by unknown authority')).toBe('tls-failed')
    })

    it('identifies timeouts and unreachable network', () => {
      expect(classifyOutboundProbeFailure('shadowsocks', 'dial tcp 198.51.100.1:443: i/o timeout')).toBe('timeout')
      expect(classifyOutboundProbeFailure('vless', 'connection refused')).toBe('timeout')
    })
  })

  describe('sanitizeLiveCheckForStorage Credential Scrubbing', () => {
    it('masks UUIDs and secrets inside handshake evidence and errors', () => {
      const mockCheck: LiveServerCheck = {
        id: 'chk-1',
        profileId: 'p1',
        host: 'vpn.example.com',
        port: 443,
        mode: 'extended',
        startedAt: '2026-09-20T12:00:00Z',
        finishedAt: '2026-09-20T12:00:05Z',
        durationMs: 5000,
        findings: [],
        dns: { status: 'ok', durationMs: 20, a: ['198.51.100.1'], aaaa: [], cnameChain: [] },
        reachability: { status: 'ok', durationMs: 15, tcpReachable: true, port: 443 },
        handshake: {
          status: 'auth_failed',
          durationMs: 120,
          protocol: 'vless',
          error: 'Authentication failed for uuid: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d with secret topSecretKey123',
          evidence: {
            detail: 'Client uuid a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d rejected by remote server',
            transport: 'reality',
            inboundPort: 12345
          }
        }
      }

      const sanitized = sanitizeLiveCheckForStorage(mockCheck)

      // UUID must be masked
      expect(sanitized.handshake?.error).not.toContain('a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d')
      expect(sanitized.handshake?.error).toContain('[REDACTED_UUID]')

      // Evidence detail must be masked
      expect(sanitized.handshake?.evidence?.detail).not.toContain('a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d')
      expect(sanitized.handshake?.evidence?.detail).toContain('[REDACTED_UUID]')

      // Non-sensitive fields preserved
      expect(sanitized.handshake?.protocol).toBe('vless')
      expect(sanitized.handshake?.evidence?.transport).toBe('reality')
      expect(sanitized.handshake?.evidence?.inboundPort).toBe(12345)
    })
  })

  describe('computeHistoryDiff for Extended Diagnostics', () => {
    const baseCheck: LiveServerCheck = {
      id: 'chk-prev',
      profileId: 'p1',
      host: 'vpn.example.com',
      port: 443,
      mode: 'extended',
      startedAt: '2026-09-20T12:00:00Z',
      finishedAt: '2026-09-20T12:00:05Z',
      durationMs: 5000,
      findings: [],
      dns: { status: 'ok', durationMs: 20, a: ['198.51.100.1'], aaaa: [], cnameChain: [] },
      reachability: { status: 'ok', durationMs: 15, tcpReachable: true, port: 443 },
      handshake: { status: 'ok', durationMs: 80, protocol: 'vmess' },
      egress: {
        status: 'ok',
        durationMs: 300,
        exitIpv4: '198.51.100.42',
        reflectors: []
      },
      pmtu: {
        status: 'ok',
        durationMs: 400,
        destination: '198.51.100.42',
        family: 4,
        method: 'icmp-df',
        pmtu: 1500
      }
    }

    it('detects handshake status transitions', () => {
      const current: LiveServerCheck = {
        ...baseCheck,
        id: 'chk-curr',
        handshake: { status: 'auth_failed', durationMs: 50, protocol: 'vmess' }
      }

      const diff = computeHistoryDiff(current, baseCheck)
      expect(diff?.handshakeChanged).toBe(true)
    })

    it('detects egress IP changes', () => {
      const current: LiveServerCheck = {
        ...baseCheck,
        id: 'chk-curr',
        egress: {
          status: 'ok',
          durationMs: 320,
          exitIpv4: '203.0.113.88',
          reflectors: []
        }
      }

      const diff = computeHistoryDiff(current, baseCheck)
      expect(diff?.egressChanged).toBe(true)
    })

    it('detects PMTU changes and degradations', () => {
      const current: LiveServerCheck = {
        ...baseCheck,
        id: 'chk-curr',
        pmtu: {
          status: 'lower_bound',
          durationMs: 450,
          destination: '198.51.100.42',
          family: 4,
          method: 'icmp-df',
          pmtu: 1372
        }
      }

      const diff = computeHistoryDiff(current, baseCheck)
      expect(diff?.pmtuChanged).toBe(true)
    })
  })

  describe('evaluateLiveCheckFindings Extended Rules', () => {
    const defaultDns: DnsDiagnostics = {
      status: 'ok',
      durationMs: 50,
      a: ['198.51.100.1'],
      aaaa: [],
      cnameChain: []
    }

    it('emits DNS_RESOLVER_MISMATCH finding on resolver discrepancies', () => {
      const dnsWithDiscrepancy: DnsDiagnostics = {
        ...defaultDns,
        discrepancies: [
          'Google DoH resolves to different IPs than System DNS (GeoDNS / split-horizon detected)'
        ]
      }

      const findings = evaluateLiveCheckFindings({
        host: 'vpn.example.com',
        dns: dnsWithDiscrepancy
      })

      const mismatchFinding = findings.find((f) => f.code === 'DNS_RESOLVER_DISCREPANCY')
      expect(mismatchFinding).toBeDefined()
      expect(mismatchFinding?.severity).toBe('info')
      expect(mismatchFinding?.detail).toContain('GeoDNS')
    })

    it('emits TUNNEL_HANDSHAKE_FAILED with error severity on auth_failed', () => {
      const handshake: TunnelHandshakeResult = {
        status: 'auth_failed',
        durationMs: 95,
        protocol: 'vless',
        error: 'VLESS credentials rejected'
      }

      const findings = evaluateLiveCheckFindings({
        host: 'vpn.example.com',
        dns: defaultDns,
        handshake
      })

      const finding = findings.find((f) => f.code === 'TUNNEL_HANDSHAKE_FAILED')
      expect(finding).toBeDefined()
      expect(finding?.severity).toBe('error')
      expect(finding?.detail).toContain('VLESS')
    })

    it('emits DIRECT_UNDERLAY_LEAK with error severity when egress leaks underlay IP', () => {
      const egress: LiveEgressResult = {
        status: 'ok',
        durationMs: 400,
        exitIpv4: '95.165.12.34',
        underlayPath: 'direct',
        reflectors: []
      }

      const findings = evaluateLiveCheckFindings({
        host: 'vpn.example.com',
        dns: defaultDns,
        egress
      })

      const leakFinding = findings.find((f) => f.code === 'DIRECT_UNDERLAY_LEAK')
      expect(leakFinding).toBeDefined()
      expect(leakFinding?.severity).toBe('error')
    })

    it('emits PMTU_BLACKHOLE_SUSPECTED when blackhole is detected', () => {
      const pmtu: PmtuDiagnostics = {
        status: 'blackhole_suspected',
        durationMs: 1500,
        destination: '198.51.100.1',
        family: 4,
        method: 'icmp-df',
        detail: 'ICMP packets larger than 1372B dropped without ICMP Fragmentation Needed message'
      }

      const findings = evaluateLiveCheckFindings({
        host: 'vpn.example.com',
        dns: defaultDns,
        pmtu
      })

      const pmtuFinding = findings.find((f) => f.code === 'PMTU_BLACKHOLE_SUSPECTED')
      expect(pmtuFinding).toBeDefined()
      expect(pmtuFinding?.severity).toBe('warning')
    })

    it('emits LOW_PMTU when MTU is constrained below 1300B', () => {
      const pmtu: PmtuDiagnostics = {
        status: 'lower_bound',
        durationMs: 600,
        destination: '198.51.100.1',
        family: 4,
        method: 'icmp-df',
        pmtu: 1280
      }

      const findings = evaluateLiveCheckFindings({
        host: 'vpn.example.com',
        dns: defaultDns,
        pmtu
      })

      const degradedFinding = findings.find((f) => f.code === 'LOW_PMTU')
      expect(degradedFinding).toBeDefined()
      expect(degradedFinding?.severity).toBe('warning')
      expect(degradedFinding?.detail).toContain('1280')
    })
  })
})
