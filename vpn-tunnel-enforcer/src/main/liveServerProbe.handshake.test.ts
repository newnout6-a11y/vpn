import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  openTcpViaSocks: vi.fn(),
  verifyHttpsThroughSocket: vi.fn(),
  getDirectProxyPort: vi.fn<() => number | null>(() => 10808),
  getPhysicalAdapterDnsSources: vi.fn(async () => []),
  spawn: vi.fn(),
  tunStatus: {
    running: true,
    mode: 'directVpn',
    vpnProfileName: 'Profile 1',
    proxyAddr: '127.0.0.1:10808'
  }
}))

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/test-userdata' },
  ipcMain: { handle: vi.fn() }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ proxyEngine: 'auto' }) } }))
vi.mock('./serverPicker', () => ({
  serverPicker: {
    getProfiles: () => [],
    getActiveProfile: () => ({ id: 'p1', name: 'Profile 1' })
  }
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => mocks.tunStatus },
  getBundledResource: vi.fn(() => '/tmp/sing-box.exe'),
  getDirectProxyPort: mocks.getDirectProxyPort,
  pickFreeLocalPort: vi.fn(async () => 50123),
  isVpnOutboundUdpCapable: () => false,
  shouldBlockQuicUdp443: () => true
}))
vi.mock('./physicalAdapterLockdown', () => ({
  getPhysicalAdapterDnsSources: mocks.getPhysicalAdapterDnsSources
}))
vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  return { ...actual, spawn: mocks.spawn }
})
vi.mock('./keyHealthChecker', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./keyHealthChecker')>()
  return {
    ...actual,
    openTcpViaSocks: mocks.openTcpViaSocks,
    verifyHttpsThroughSocket: mocks.verifyHttpsThroughSocket,
    waitForLocalSocks: vi.fn(async () => {})
  }
})

import { evaluateLiveCheckFindings, probeTunnelHandshakeAndEgress } from './liveServerProbe'
import type { ServerProfile } from '../shared/ipc-types'

const activeProfile = {
  id: 'p1',
  name: 'Profile 1',
  protocol: 'vless',
  server: 'vpn.example.test',
  port: 443,
  status: 'unknown',
  ping: null,
  outbound: {
    type: 'vless',
    server: 'vpn.example.test',
    server_port: 443,
    tls: { enabled: true, alpn: ['h2'] }
  }
} as unknown as ServerProfile

describe('probeTunnelHandshakeAndEgress handshake classification', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.openTcpViaSocks.mockImplementation(async (_socks, host: string) => {
      if (host === 'usher.ttvnw.net' || host === 'static.twitchcdn.net' || host === 'speed.cloudflare.com') {
        throw new Error(`fixture connection failed for ${host}`)
      }
      return { destroy: vi.fn() }
    })
    mocks.verifyHttpsThroughSocket.mockImplementation(async (_socket, destination: { host: string }) => {
      if (destination.host === '1.1.1.1') {
        throw new Error('probe destination closed without HTTP response')
      }
      if (destination.host === 'api.ipify.org') return { egressIp: '203.0.113.42' }
      if (destination.host === 'api6.ipify.org') throw new Error('ENETUNREACH')
      throw new Error(`unexpected reflector ${destination.host}`)
    })
  })

  it('uses the active tunnel and isolates Cloudflare failure from handshake and remaining probes', async () => {
    const result = await probeTunnelHandshakeAndEgress(activeProfile, '203.0.113.42', undefined, true)

    expect(result.handshake.status).toBe('ok')
    expect(result.handshake.evidence?.inboundPort).toBe(10808)
    expect(result.egress.reflectors).toEqual(expect.arrayContaining([
      expect.objectContaining({
        source: 'cloudflare-trace',
        status: 'error',
        error: 'probe destination closed without HTTP response'
      }),
      expect.objectContaining({ source: 'ipify', status: 'ok', ip: '203.0.113.42' })
    ]))
    expect(result.egress.reflectors.filter(r => r.source === 'cloudflare-trace')).toHaveLength(1)
    expect(result.egress.status).toBe('partial')
    expect(result.mediaStream.status).not.toBe('skipped')
    expect(result.throughput?.status).not.toBe('skipped')
    expect(result.throughput?.route).toBe('active-tunnel')
    expect(evaluateLiveCheckFindings({ handshake: result.handshake }).some(f => f.code === 'TUNNEL_HANDSHAKE_FAILED')).toBe(false)

    expect(mocks.getDirectProxyPort).toHaveBeenCalledOnce()
    expect(mocks.getPhysicalAdapterDnsSources).not.toHaveBeenCalled()
    expect(mocks.spawn).not.toHaveBeenCalled()
    expect(mocks.openTcpViaSocks.mock.calls.every(([socks]) => socks.port === 10808)).toBe(true)
    expect(mocks.openTcpViaSocks.mock.calls.map(([, host]) => host)).toEqual(expect.arrayContaining([
      '1.1.1.1',
      'api.ipify.org',
      'api6.ipify.org',
      'usher.ttvnw.net',
      'static.twitchcdn.net',
      'speed.cloudflare.com'
    ]))
  })

  it('uses later reflectors to verify the tunnel when Cloudflare SOCKS CONNECT fails', async () => {
    mocks.openTcpViaSocks.mockImplementationOnce(async (_socks, host: string) => {
      if (host === '1.1.1.1') throw new Error('Cloudflare destination unreachable')
      return { destroy: vi.fn() }
    })

    const result = await probeTunnelHandshakeAndEgress(activeProfile)

    expect(result.handshake.status).toBe('ok')
    expect(result.egress.reflectors).toEqual(expect.arrayContaining([
      expect.objectContaining({
        source: 'cloudflare-trace',
        status: 'error',
        error: 'Cloudflare destination unreachable'
      }),
      expect.objectContaining({ source: 'ipify', status: 'ok', ip: '203.0.113.42' })
    ]))
    expect(mocks.openTcpViaSocks).toHaveBeenCalledWith(
      expect.objectContaining({ port: 10808 }),
      'api.ipify.org',
      443,
      3500,
      undefined
    )
    expect(result.mediaStream.status).not.toBe('skipped')
  })

  it('skips an active-tunnel probe when its SOCKS inbound is unavailable', async () => {
    mocks.getDirectProxyPort.mockReturnValueOnce(null)

    const result = await probeTunnelHandshakeAndEgress(activeProfile, '203.0.113.42', undefined, true)

    expect(result.handshake.status).toBe('skipped')
    expect(result.egress.status).toBe('skipped')
    expect(result.mediaStream.status).toBe('skipped')
    expect(result.throughput).toEqual({
      status: 'skipped',
      durationMs: 0,
      samples: [],
      route: 'active-tunnel'
    })
    expect(mocks.openTcpViaSocks).not.toHaveBeenCalled()
    expect(mocks.spawn).not.toHaveBeenCalled()
    expect(evaluateLiveCheckFindings({ handshake: result.handshake }).some(f => f.code === 'TUNNEL_HANDSHAKE_FAILED')).toBe(false)
  })
})
