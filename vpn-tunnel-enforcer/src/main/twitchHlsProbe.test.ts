import { describe, it, expect, vi, beforeEach } from 'vitest'
import { isVpnOutboundUdpCapable, shouldBlockQuicUdp443 } from './tunController'
import { probeMediaStream, evaluateLiveCheckFindings } from './liveServerProbe'
import type { LiveServerCheck, LiveMediaStreamDiagnostics, ServerProfile } from '../shared/ipc-types'

// Mock Electron & Logger
vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  },
  ipcMain: {
    handle: vi.fn()
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./notifications', () => ({ notify: vi.fn() }))
vi.mock('./settings', () => ({
  settingsStore: {
    get: () => ({ proxyEngine: 'auto', disableGeoLookup: false })
  }
}))

describe('Twitch HLS & QUIC Error #2000 mitigation', () => {
  describe('isVpnOutboundUdpCapable', () => {
    it('identifies native UDP protocols as UDP-capable', () => {
      expect(isVpnOutboundUdpCapable({ type: 'hysteria2' })).toBe(true)
      expect(isVpnOutboundUdpCapable({ type: 'tuic' })).toBe(true)
      expect(isVpnOutboundUdpCapable({ type: 'wireguard' })).toBe(true)
    })

    it('identifies VLESS with packet encoding as UDP-capable', () => {
      expect(isVpnOutboundUdpCapable({ type: 'vless', packet_encoding: 'xudp' })).toBe(true)
      expect(isVpnOutboundUdpCapable({ type: 'vless', packet_encoding: 'packetaddr' })).toBe(true)
    })

    it('identifies standard VLESS Reality without packet encoding as NOT UDP-capable', () => {
      expect(isVpnOutboundUdpCapable({
        type: 'vless',
        tls: { enabled: true, reality: { enabled: true, public_key: 'abc' } }
      })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'vless' })).toBe(false)
    })

    it('respects explicit network: "tcp" as NOT UDP-capable even for UDP protocols', () => {
      expect(isVpnOutboundUdpCapable({ type: 'hysteria2', network: 'tcp' })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'vless', packet_encoding: 'xudp', network: 'tcp' })).toBe(false)
    })

    it('identifies HTTP, Naive, AnyTLS, ShadowTLS as NOT UDP-capable', () => {
      expect(isVpnOutboundUdpCapable({ type: 'http' })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'naive' })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'anytls' })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'shadowtls' })).toBe(false)
    })

    it('handles Shadowsocks and SOCKS5 UDP support', () => {
      expect(isVpnOutboundUdpCapable({ type: 'shadowsocks' })).toBe(true)
      expect(isVpnOutboundUdpCapable({ type: 'shadowsocks', network: 'tcp' })).toBe(false)
      expect(isVpnOutboundUdpCapable({ type: 'socks' })).toBe(true)
      expect(isVpnOutboundUdpCapable({ type: 'socks', network: 'tcp' })).toBe(false)
    })
  })

  describe('shouldBlockQuicUdp443', () => {
    it('blocks QUIC (UDP/443) for directVpn when outbound is TCP-only (prevents Twitch #2000)', () => {
      const vlessReality = {
        type: 'vless',
        server: '1.2.3.4',
        server_port: 443,
        tls: { reality: { enabled: true } }
      }
      expect(shouldBlockQuicUdp443(vlessReality, 'socks5', true)).toBe(true)
    })

    it('does NOT block QUIC for directVpn when outbound is genuinely UDP-capable', () => {
      const hy2 = { type: 'hysteria2', server: '1.2.3.4', server_port: 443 }
      const vlessXudp = { type: 'vless', server: '1.2.3.4', server_port: 443, packet_encoding: 'xudp' }
      expect(shouldBlockQuicUdp443(hy2, 'socks5', true)).toBe(false)
      expect(shouldBlockQuicUdp443(vlessXudp, 'socks5', true)).toBe(false)
    })

    it('always blocks QUIC for HTTP proxy mode', () => {
      expect(shouldBlockQuicUdp443({ type: 'hysteria2' }, 'http', false)).toBe(true)
    })
  })

  describe('probeMediaStream diagnostics evaluation', () => {
    it('evaluates error2000Risk as false and quicFallbackGuarded as true for TCP-only VLESS when guarded', async () => {
      const profile: ServerProfile = {
        id: 'prof-vless-reality',
        name: 'VLESS Reality Node',
        protocol: 'vless',
        server: 'vpn.example.com',
        port: 443,
        status: 'online',
        outbound: {
          type: 'vless',
          server: 'vpn.example.com',
          server_port: 443,
          tls: { reality: { enabled: true } }
        }
      }

      const result = await probeMediaStream(profile, undefined, new AbortController().signal)
      expect(result.quicFallbackGuarded).toBe(true)
      expect(result.error2000Risk).toBe(false)
      expect(result.detail).toContain('Защита от QUIC blackhole активна')
    })

    it('evaluates UDP capable profile as quicFallbackGuarded without risk', async () => {
      const profile: ServerProfile = {
        id: 'prof-hy2',
        name: 'Hysteria2 Node',
        protocol: 'hysteria2',
        server: 'hy2.example.com',
        port: 443,
        status: 'online',
        outbound: {
          type: 'hysteria2',
          server: 'hy2.example.com',
          server_port: 443
        }
      }

      const result = await probeMediaStream(profile, undefined, new AbortController().signal)
      expect(result.quicFallbackGuarded).toBe(true)
      expect(result.error2000Risk).toBe(false)
      expect(result.detail).toContain('поддерживает UDP/QUIC')
    })
  })

  describe('evaluateLiveCheckFindings for Media Stream', () => {
    it('generates TWITCH_MEDIA_ERROR_2000_RISK finding when error2000Risk is true', () => {
      const check: Partial<LiveServerCheck> = {
        id: 'check-1',
        host: 'vpn.example.com',
        port: 443,
        mode: 'basic',
        mediaStream: {
          status: 'warning',
          durationMs: 120,
          twitchHlsReachable: true,
          quicFallbackGuarded: false,
          error2000Risk: true,
          detail: 'QUIC stall detected'
        },
        dns: { status: 'ok', durationMs: 10, a: ['1.1.1.1'], aaaa: [], cnameChain: [] },
        reachability: { status: 'ok', durationMs: 20, tcpReachable: true, port: 443 }
      }

      const findings = evaluateLiveCheckFindings(check)
      const riskFinding = findings.find(f => f.code === 'TWITCH_MEDIA_ERROR_2000_RISK')
      expect(riskFinding).toBeDefined()
      expect(riskFinding?.severity).toBe('warning')
      expect(riskFinding?.title).toContain('Twitch #2000')
      expect(riskFinding?.evidence?.error2000Risk).toBe(true)
    })

    it('generates TWITCH_HLS_OK finding when stream is reachable and guarded', () => {
      const check: Partial<LiveServerCheck> = {
        id: 'check-2',
        host: 'vpn.example.com',
        port: 443,
        mode: 'basic',
        mediaStream: {
          status: 'ok',
          durationMs: 95,
          twitchHlsReachable: true,
          quicFallbackGuarded: true,
          error2000Risk: false,
          detail: 'HLS guarded'
        },
        dns: { status: 'ok', durationMs: 10, a: ['1.1.1.1'], aaaa: [], cnameChain: [] },
        reachability: { status: 'ok', durationMs: 20, tcpReachable: true, port: 443 }
      }

      const findings = evaluateLiveCheckFindings(check)
      const okFinding = findings.find(f => f.code === 'TWITCH_HLS_OK')
      expect(okFinding).toBeDefined()
      expect(okFinding?.severity).toBe('info')
      expect(okFinding?.title).toContain('Twitch HLS защищены')
    })

    it('generates TWITCH_MEDIA_UNREACHABLE finding when Twitch CDN is not reachable', () => {
      const check: Partial<LiveServerCheck> = {
        id: 'check-3',
        host: 'vpn.example.com',
        port: 443,
        mode: 'basic',
        mediaStream: {
          status: 'error',
          durationMs: 1500,
          twitchHlsReachable: false,
          quicFallbackGuarded: true,
          error2000Risk: false,
          error: 'Connection timeout to usher.ttvnw.net'
        },
        dns: { status: 'ok', durationMs: 10, a: ['1.1.1.1'], aaaa: [], cnameChain: [] },
        reachability: { status: 'ok', durationMs: 20, tcpReachable: true, port: 443 }
      }

      const findings = evaluateLiveCheckFindings(check)
      const unreachableFinding = findings.find(f => f.code === 'TWITCH_MEDIA_UNREACHABLE')
      expect(unreachableFinding).toBeDefined()
      expect(unreachableFinding?.severity).toBe('warning')
      expect(unreachableFinding?.title).toContain('Twitch HLS недоступны')
    })
  })
})
