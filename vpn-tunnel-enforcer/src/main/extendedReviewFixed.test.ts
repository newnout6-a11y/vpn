import { it, expect, vi, afterEach } from 'vitest'
import { EventEmitter } from 'node:events'

const state = vi.hoisted(() => ({ ps: {}, response: '', tlsOptions: null as any }))

vi.mock('child_process', async (original) => {
  const actual = await original<any>()
  const spawn = vi.fn(() => {
    const child: any = new EventEmitter()
    child.stdout = new EventEmitter()
    child.stderr = new EventEmitter()
    child.kill = vi.fn()
    queueMicrotask(() => {
      child.stdout.emit('data', Buffer.from(JSON.stringify(state.ps)))
      child.emit('close', 0)
    })
    return child
  })
  return { ...actual, spawn, default: { ...actual, spawn } }
})

vi.mock('tls', async (original) => {
  const actual = await original<any>()
  const connect = vi.fn((options) => {
    state.tlsOptions = options
    const socket: any = new EventEmitter()
    socket.destroy = vi.fn()
    socket.write = vi.fn()
    queueMicrotask(() => {
      socket.emit('secureConnect')
      socket.emit('data', Buffer.from(state.response))
      socket.emit('end')
    })
    return socket
  })
  return { ...actual, connect, default: { ...actual, connect } }
})

import { queryDoH, isPublicFqdn, probePmtu, evaluateLiveCheckFindings } from './liveServerProbe'
import { verifyHttpsThroughSocket } from './keyHealthChecker'
import { sanitizeLiveCheckForStorage, computeHistoryDiff } from './liveServerHistory'

afterEach(() => vi.unstubAllGlobals())

it('verifies ipify HTTP 200 extracts IP and requires valid TLS', async () => {
  state.response = 'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n8.8.8.8'
  const result = await verifyHttpsThroughSocket(
    { destroy: vi.fn() } as any,
    { host: 'api.ipify.org', port: 443, serverName: 'api.ipify.org', path: '/?format=text' },
    100
  )
  expect(result.egressIp).toBe('8.8.8.8')
  expect(state.tlsOptions.rejectUnauthorized).toBe(true)
})

it('verifies failed reflector response is rejected with HTTP status error', async () => {
  state.response = 'HTTP/1.1 500 Server Error\r\n\r\nip=127.0.0.1\nloc=ZZ\n'
  await expect(
    verifyHttpsThroughSocket(
      { destroy: vi.fn() } as any,
      { host: '1.1.1.1', port: 443, serverName: 'cloudflare-dns.com', path: '/cdn-cgi/trace' },
      100
    )
  ).rejects.toThrow(/HTTP 500/)
})

it('verifies NXDOMAIN/SERVFAIL marked error in queryDoH', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ Status: 2, AD: true }) }))
  const result = await queryDoH('google-doh', 'test', 'https://fixture.invalid', 'example.com')
  expect(result.status).toBe('error')
  expect(result.rcode).toBe(2)
  expect(result.error).toContain('SERVFAIL')
})

it('verifies trailing-dot private names are rejected by isPublicFqdn guard', () => {
  expect(isPublicFqdn('nas.internal.')).toBe(false)
  expect(isPublicFqdn('localhost.')).toBe(false)
  expect(isPublicFqdn('example.com.')).toBe(true)
})

it('verifies packet loss/timeout without ICMP PacketTooBig yields lower_bound PMTU', async () => {
  state.ps = { Status: 'ok', BestPayload: 1372, TooBigCount: 0, TimeoutCount: 2 }
  const result = await probePmtu('8.8.8.8')
  expect(result.status).toBe('lower_bound')
  expect(result.pmtu).toBe(1400)
  expect(result.detail).toContain('не менее 1400')
})

it('verifies IPv6 uses 48B header overhead (40B IPv6 + 8B ICMPv6)', async () => {
  state.ps = { Status: 'ok', LargestAccepted: 1372, SmallestTooBig: 1380, TooBigCount: 2, TimeoutCount: 0 }
  const result = await probePmtu('2001:4860:4860::8888')
  expect(result.family).toBe(6)
  expect(result.pmtu).toBe(1420)
  expect(result.status).toBe('ok')
})

it('verifies wide gap between accepted and rejected yields lower_bound with interval', async () => {
  state.ps = {
    Status: 'ok',
    LargestAccepted: 1372,
    SmallestTooBig: 1472,
    AcceptedCount: 1,
    TooBigCount: 1,
    TimeoutCount: 0
  }
  const result = await probePmtu('8.8.8.8')
  expect(result.status).toBe('lower_bound')
  expect(result.pmtu).toBe(1400)
  expect(result.minTested).toBe(1400)
  expect(result.maxTested).toBe(1500)
  expect(result.detail).toContain('[1400 .. 1500]')
})

it('verifies healthy profile on underlay is not flagged as leak without baseline evidence', () => {
  const findings = evaluateLiveCheckFindings({
    egress: { status: 'ok', durationMs: 1, exitIpv4: '8.8.8.8', underlayPath: 'direct', reflectors: [] }
  } as any)
  expect(findings.some((f) => f.code === 'DIRECT_UNDERLAY_LEAK')).toBe(false)
})

it('verifies UUIDs in findings details and titles are scrubbed upon storage sanitization', () => {
  const uuid = '11111111-2222-3333-4444-555555555555'
  const check: any = {
    handshake: { status: 'auth_failed', protocol: 'vless', error: `wrong uuid ${uuid}`, durationMs: 1 }
  }
  check.findings = evaluateLiveCheckFindings(check)
  const stored = sanitizeLiveCheckForStorage(check)
  expect(stored.handshake!.error).not.toContain(uuid)
  expect(stored.findings.find((f) => f.code === 'TUNNEL_HANDSHAKE_FAILED')!.detail).not.toContain(uuid)
})

it('verifies incompatible PMTU methods/families are not flagged as a pmtuChanged diff', () => {
  const base: any = {
    host: '8.8.8.8',
    port: 443,
    startedAt: '2026-09-20',
    dns: { a: [], aaaa: [] },
    findings: [],
    pmtu: { status: 'ok', pmtu: 1500, method: 'interface-nlmtu', family: 4 }
  }
  const next: any = {
    ...base,
    pmtu: { status: 'lower_bound', pmtu: 1400, method: 'icmp-df', family: 6 }
  }
  expect(computeHistoryDiff(next, base)?.pmtuChanged).toBe(false)
})
