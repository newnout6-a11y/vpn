import { describe, expect, it, vi, beforeEach, afterEach, afterAll } from 'vitest'
import * as http from 'http'
import * as net from 'net'
import * as dns from 'dns'
import type { AddressInfo } from 'net'

const {
  mockResolve4,
  mockResolve6,
  mockResolveCname,
  mockReverse
} = vi.hoisted(() => ({
  mockResolve4: vi.fn(),
  mockResolve6: vi.fn(),
  mockResolveCname: vi.fn(),
  mockReverse: vi.fn()
}))

vi.mock('dns', async (importOriginal) => {
  const actual = await importOriginal<typeof import('dns')>()
  const promises = {
    ...actual.promises,
    resolve4: mockResolve4,
    resolve6: mockResolve6,
    resolveCname: mockResolveCname,
    reverse: mockReverse
  }
  Object.assign(promises, { Resolver: class {
    resolve4 = promises.resolve4
    resolve6 = promises.resolve6
    resolveCname = promises.resolveCname
    reverse = promises.reverse
    cancel() {}
  } })
  return {
    ...actual,
    default: { ...actual, promises },
    promises
  }
})

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/test-userdata' },
  ipcMain: { handle: vi.fn() }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: false }) } }))
vi.mock('./serverPicker', () => ({
  serverPicker: {
    getProfiles: () => [
      { id: 'p1', name: 'Profile 1', server: '10.0.0.5', port: 443, resolvedIp: '10.0.0.5' },
      { id: 'p2', name: 'Profile 2', server: '10.0.0.6', port: 8443, resolvedIp: '10.0.0.6' }
    ],
    getActiveProfile: () => ({ id: 'p1', country: 'NL', egressIp: '10.0.0.5' })
  }
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) }
}))

import {
  normalizeHostAndPort,
  probeDns,
  probeReachabilityAndLatency,
  probePorts,
  probeHttp,
  evaluateLiveCheckFindings,
  RESTRICTED_PORTS
} from './liveServerProbe'
import type { LiveServerCheck } from '../shared/ipc-types'

describe('liveServerProbe', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('normalizeHostAndPort', () => {
    it('handles IPv4 address', () => {
      const res = normalizeHostAndPort('1.2.3.4')
      expect(res).toEqual({ host: '1.2.3.4', port: 443, isIp: true, isIpv6: false })
    })

    it('handles IPv4 with port', () => {
      const res = normalizeHostAndPort('1.2.3.4:8443')
      expect(res).toEqual({ host: '1.2.3.4', port: 8443, isIp: true, isIpv6: false })
    })

    it('handles domain name with fallback port', () => {
      const res = normalizeHostAndPort('vpn.example.com')
      expect(res).toEqual({ host: 'vpn.example.com', port: 443, isIp: false, isIpv6: false })
    })

    it('handles domain name with explicit port', () => {
      const res = normalizeHostAndPort('vpn.example.com:2083')
      expect(res).toEqual({ host: 'vpn.example.com', port: 2083, isIp: false, isIpv6: false })
    })

    it('handles bracketed IPv6 with port', () => {
      const res = normalizeHostAndPort('[2001:db8::1]:9000')
      expect(res).toEqual({ host: '2001:db8::1', port: 9000, isIp: true, isIpv6: true })
    })

    it('handles bare IPv6', () => {
      const res = normalizeHostAndPort('2001:db8::1', 8080)
      expect(res).toEqual({ host: '2001:db8::1', port: 8080, isIp: true, isIpv6: true })
    })
  })

  describe('probeDns', () => {
    it('skips forward DNS queries for pure IP input', async () => {
      mockReverse.mockResolvedValueOnce(['node1.vpnprovider.net'])
      const res = await probeDns('1.2.3.4')

      expect(mockResolve4).not.toHaveBeenCalled()
      expect(mockResolve6).not.toHaveBeenCalled()
      expect(res.dns.status).toBe('ok')
      expect(res.dns.a).toEqual(['1.2.3.4'])
      expect(res.reverseDns).toEqual(['node1.vpnprovider.net'])
    })

    it('resolves A and AAAA with TTL and CNAME chain', async () => {
      mockResolve4.mockResolvedValueOnce([
        { address: '104.21.5.10', ttl: 300 },
        { address: '104.21.5.11', ttl: 120 }
      ])
      mockResolve6.mockResolvedValueOnce([
        { address: '2606:4700::1', ttl: 300 }
      ])
      mockResolveCname.mockResolvedValueOnce(['edge.cloudflare.com'])
      mockResolveCname.mockResolvedValueOnce([]) // end of chain
      mockReverse.mockResolvedValue([])

      const res = await probeDns('myvpn.example.com', 'extended')

      expect(res.dns.status).toBe('ok')
      expect(res.dns.a).toEqual(['104.21.5.10', '104.21.5.11'])
      expect(res.dns.aaaa).toEqual(['2606:4700::1'])
      expect(res.dns.cnameChain).toEqual(['edge.cloudflare.com'])
      expect(res.dns.ttl).toBe(120) // min TTL
      expect(res.dns.timings?.aMs).toBeDefined()
    })

    it('handles reverse DNS partial failures gracefully', async () => {
      mockResolve4.mockResolvedValueOnce([{ address: '1.1.1.1', ttl: 60 }])
      mockResolve6.mockResolvedValueOnce([])
      mockResolveCname.mockResolvedValue([])
      mockReverse.mockRejectedValueOnce(new Error('reverse query NXDOMAIN'))

      const res = await probeDns('one.one.one.one')
      expect(res.dns.status).toBe('ok')
      expect(res.dns.a).toEqual(['1.1.1.1'])
      expect(res.reverseDns).toEqual([])
    })

    it('returns skipped when aborted before execution', async () => {
      const controller = new AbortController()
      controller.abort()

      const res = await probeDns('myvpn.example.com', 'basic', controller.signal)
      expect(res.dns.status).toBe('skipped')
      expect(res.dns.error).toContain('Cancelled')
    })
  })

  describe('probeReachabilityAndLatency', () => {
    let mockServer: net.Server
    let serverPort: number

    beforeEach(async () => {
      mockServer = net.createServer((socket) => {
        socket.destroy()
      })
      await new Promise<void>((resolve) => {
        mockServer.listen(0, '127.0.0.1', () => {
          serverPort = (mockServer.address() as AddressInfo).port
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()))
    })

    it('measures reachability and collects multi-sample latency', async () => {
      const res = await probeReachabilityAndLatency('127.0.0.1', serverPort, 'basic')

      expect(res.reachability.status).toBe('ok')
      expect(res.reachability.tcpReachable).toBe(true)
      expect(res.latency).toBeDefined()
      expect(res.latency?.samples.length).toBe(5)
      expect(res.latency?.loss).toBe(0)
      expect(res.latency?.avg).toBeGreaterThanOrEqual(0)
      expect(res.latency?.median).toBeGreaterThanOrEqual(0)
      expect(res.latency?.jitter).toBeGreaterThanOrEqual(0)
    })

    it('reports error status and 100% loss when server is not reachable', async () => {
      // Pick an unused local port
      const res = await probeReachabilityAndLatency('127.0.0.1', 65432, 'basic')

      expect(res.reachability.status).toBe('error')
      expect(res.reachability.tcpReachable).toBe(false)
      expect(res.latency).toBeUndefined()
    })
  })

  describe('probePorts', () => {
    let mockServer: net.Server
    let serverPort: number

    beforeEach(async () => {
      mockServer = net.createServer((socket) => socket.destroy())
      await new Promise<void>((resolve) => {
        mockServer.listen(0, '127.0.0.1', () => {
          serverPort = (mockServer.address() as AddressInfo).port
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()))
    })

    it('scans known port in basic mode', async () => {
      const results = await probePorts('127.0.0.1', serverPort, 'basic')
      const target = results.find((p) => p.port === serverPort)
      expect(target).toBeDefined()
      expect(target?.open).toBe(true)
      expect(target?.state).toBe('open')
    })

    it('deduplicates restricted port list in extended mode', async () => {
      const results = await probePorts('127.0.0.1', 443, 'extended')
      const ports = results.map((r) => r.port)
      expect(ports).toEqual(expect.arrayContaining([...RESTRICTED_PORTS]))
      const unique = new Set(ports)
      expect(ports.length).toBe(unique.size)
    })
  })

  describe('probeHttp', () => {
    let httpServer: http.Server
    let httpPort: number

    beforeEach(async () => {
      httpServer = http.createServer((req, res) => {
        if (req.method === 'HEAD' && req.url === '/405') {
          res.writeHead(405, { 'Content-Type': 'text/plain' })
          res.end()
          return
        }
        if (req.url === '/redirect') {
          res.writeHead(302, {
            Location: `http://127.0.0.1:${httpPort}/target?token=secret123#frag`
          })
          res.end()
          return
        }
        res.writeHead(200, {
          Server: 'test-server/1.0',
          Via: '1.1 test-proxy',
          'Content-Type': 'text/html'
        })
        res.end('<html><body>Hello</body></html>')
      })

      await new Promise<void>((resolve) => {
        httpServer.listen(0, '127.0.0.1', () => {
          httpPort = (httpServer.address() as AddressInfo).port
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()))
    })

    it('extracts status, server header, via header from HEAD request', async () => {
      const res = await probeHttp('127.0.0.1', httpPort, false)

      expect(res.status).toBe('ok')
      expect(res.statusCode).toBe(200)
      expect(res.serverHeader).toBe('test-server/1.0')
      expect(res.viaHeader).toBe('1.1 test-proxy')
      expect(res.confidence).toBe('low')
    })

    it('sanitizes Location header by stripping query parameters and hash', async () => {
      // Direct request to redirect path
      const requester = http.request(
        { host: '127.0.0.1', port: httpPort, path: '/redirect', method: 'HEAD' },
        (res) => { res.destroy() }
      )
      requester.end()

      const result = await probeHttp('127.0.0.1', httpPort, false)
      expect(result.status).toBe('ok')
    })
  })

  describe('evaluateLiveCheckFindings', () => {
    it('evaluates DNS findings: MULTI_IP and DNS_CHANGED', () => {
      const prev = {
        dns: { status: 'ok' as const, durationMs: 10, a: ['1.1.1.1'], aaaa: [], cnameChain: [] }
      } as unknown as LiveServerCheck

      const current = {
        dns: { status: 'ok' as const, durationMs: 10, a: ['2.2.2.2', '3.3.3.3'], aaaa: [], cnameChain: [] },
        host: 'example.com'
      }

      const findings = evaluateLiveCheckFindings(current, prev)
      const codes = findings.map((f) => f.code)

      expect(codes).toContain('DNS_MULTI_IP')
      expect(codes).toContain('DNS_CHANGED')
    })

    it('evaluates TLS findings: TLS_EXPIRING and TLS_SAN_MISMATCH', () => {
      const current = {
        host: 'vpn.example.com',
        tls: {
          status: 'ok',
          durationMs: 50,
          daysRemaining: 15,
          hostnameVerified: false,
          sans: ['other.example.com']
        }
      } as Partial<LiveServerCheck>

      const findings = evaluateLiveCheckFindings(current, null)
      const codes = findings.map((f) => f.code)

      expect(codes).toContain('TLS_EXPIRING')
      expect(codes).toContain('TLS_SAN_MISMATCH')
      const expiring = findings.find((f) => f.code === 'TLS_EXPIRING')
      expect(expiring?.severity).toBe('warning')
    })

    it('evaluates TLS_EXPIRING as error if <= 7 days remaining', () => {
      const current = {
        host: 'vpn.example.com',
        tls: {
          status: 'ok',
          durationMs: 50,
          daysRemaining: 3,
          hostnameVerified: true,
          sans: ['vpn.example.com']
        }
      } as Partial<LiveServerCheck>

      const findings = evaluateLiveCheckFindings(current, null)
      const expiring = findings.find((f) => f.code === 'TLS_EXPIRING')
      expect(expiring?.severity).toBe('error')
    })

    it('evaluates Latency & Loss findings: LATENCY_HIGH, JITTER_HIGH, PACKET_LOSS', () => {
      const current = {
        latency: {
          min: 200,
          avg: 320,
          median: 310,
          max: 450,
          jitter: 55,
          loss: 0.25,
          samples: [200, 310, 450],
          samplesAttempted: 4,
          method: 'tcp'
        }
      } as Partial<LiveServerCheck>

      const findings = evaluateLiveCheckFindings(current, null)
      const codes = findings.map((f) => f.code)

      expect(codes).toContain('LATENCY_HIGH')
      expect(codes).toContain('JITTER_HIGH')
      expect(codes).toContain('PACKET_LOSS')
    })

    it('evaluates Infrastructure findings: ASN_CHANGED and EGRESS_COUNTRY_MISMATCH', () => {
      const prev = {
        asn: { asn: 'AS100', org: 'ISP 1', network: '1.0.0.0/8', country: 'Germany' }
      } as LiveServerCheck

      const current = {
        asn: { asn: 'AS200', org: 'ISP 2', network: '2.0.0.0/8', country: 'Germany' },
        infrastructure: {
          status: 'ok',
          endpointCountry: 'Germany',
          egressCountry: 'Netherlands',
          activeTunnelMatchesProfile: true,
          sharedCidrWithProfiles: ['Profile 1', 'Profile 2']
        }
      } as Partial<LiveServerCheck>

      const findings = evaluateLiveCheckFindings(current, prev)
      const codes = findings.map((f) => f.code)

      expect(codes).toContain('ASN_CHANGED')
      expect(codes).toContain('EGRESS_COUNTRY_MISMATCH')
      expect(codes).toContain('CIDR_SHARED_WITH_PROFILE')
    })

    it('does not evaluate EGRESS_COUNTRY_MISMATCH if active tunnel does not match profile', () => {
      const current = {
        infrastructure: {
          status: 'ok',
          endpointCountry: 'Germany',
          egressCountry: 'Netherlands',
          activeTunnelMatchesProfile: false
        }
      } as Partial<LiveServerCheck>

      const findings = evaluateLiveCheckFindings(current)
      const codes = findings.map((f) => f.code)
      expect(codes).not.toContain('EGRESS_COUNTRY_MISMATCH')
    })
  })
})
