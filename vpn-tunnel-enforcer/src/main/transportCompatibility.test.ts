import { describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { dirname, join, resolve } from 'path'

vi.mock('./tunController', () => ({ getTunRuntimeDir: () => tmpdir(), getBundledResource: (name: string) => name, pickFreeLocalPort: vi.fn(), copyResourceIfStale: vi.fn() }))
vi.mock('./firewallKillSwitch', () => ({ ensureKillSwitchProgramAllowed: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { parseVpnProfiles, exportOutboundToUri } from './vpnProfiles'
import { toXrayOutbound, buildXrayConfig } from './xrayEngine'
import { resolveProxyEngine } from './proxyEngine'

const UUID = '11111111-2222-4333-8444-555555555555'
function uri(protocol: string, type: string, params: Record<string, string> = {}) {
  const query = new URLSearchParams({ security: 'tls', type, sni: 'front.example.com', ...params })
  if (protocol === 'vmess') return 'vmess://' + Buffer.from(JSON.stringify({ add: '192.0.2.1', port: 443, id: UUID, net: type, tls: 'tls', sni: 'front.example.com', path: params.path || params.serviceName,
    host: params.host, mode: params.mode, extra: params.extra ? JSON.parse(params.extra) : undefined })).toString('base64')
  return `${protocol}://${protocol === 'trojan' ? 'SYNTHETIC_PASSWORD' : UUID}@192.0.2.1:443?${query}#Example`
}

describe('XHTTP and gRPC URI round-trip (AT-04-001 / AT-04-002 / AT-04-006)', () => {
  it.each(['vless', 'trojan', 'vmess'])('preserves %s XHTTP path, host, mode and extra through export', protocol => {
    const extra = { noSSEHeader: true, custom: { escaped: '%2F&=%25', array: [true, 0, 'text'] } }
    const [profile] = parseVpnProfiles(uri(protocol, 'xhttp', { path: '/a%2Fb', host: 'front.example.com', mode: 'packet-up', extra: JSON.stringify(extra) }))
    expect(profile).toBeDefined()
    expect(resolveProxyEngine(profile.outbound, 'auto')).toBe('xray')
    expect(() => resolveProxyEngine(profile.outbound, 'sing-box')).toThrow(/Xray/)
    const original = JSON.stringify(profile.outbound)
    const raw = toXrayOutbound(profile.outbound)
    expect(raw.streamSettings.xhttpSettings).toMatchObject({ path: '/a%2Fb', host: 'front.example.com', mode: 'packet-up', extra })
    const exported = exportOutboundToUri(profile)!
    const [restored] = parseVpnProfiles(exported)
    expect(restored.outbound.transport).toEqual(profile.outbound.transport)
    expect(toXrayOutbound(restored.outbound).streamSettings).toEqual(raw.streamSettings)
    expect(JSON.stringify(profile.outbound)).toBe(original)
  })
  it.each(['vless', 'trojan', 'vmess'])('preserves explicit gRPC multi-mode for %s', protocol => {
    for (const mode of ['gun', 'multi']) {
      const [profile] = parseVpnProfiles(uri(protocol, 'grpc', { serviceName: 'service-name', mode }))
      expect(profile.outbound.transport.multi_mode).toBe(mode === 'multi')
      expect(toXrayOutbound(profile.outbound).streamSettings.grpcSettings).toEqual({ serviceName: 'service-name', multiMode: mode === 'multi' })
      expect(resolveProxyEngine(profile.outbound, 'auto')).toBe('xray')
      const [restored] = parseVpnProfiles(exportOutboundToUri(profile)!)
      expect(restored.outbound.transport).toEqual(profile.outbound.transport)
    }
  })
  it('does not interpret idle_timeout as multiMode, and supports saved legacy XHTTP method', () => {
    const [profile] = parseVpnProfiles(uri('vless', 'grpc', { serviceName: 'svc' }))
    profile.outbound.transport.idle_timeout = '60s'
    expect(toXrayOutbound(profile.outbound).streamSettings.grpcSettings.multiMode).toBe(false)
    const [xhttp] = parseVpnProfiles(uri('vless', 'xhttp'))
    xhttp.outbound.transport.method = 'stream-up'
    expect(toXrayOutbound(xhttp.outbound).streamSettings.xhttpSettings.mode).toBe('stream-up')
    expect(parseVpnProfiles(exportOutboundToUri(xhttp)!)[0].outbound.transport.mode).toBe('stream-up')
  })
  it.each(['not-a-mode', 'null', '[]', '{broken'])('rejects invalid XHTTP mode/extra instead of a lossy connection: %s', value => {
    const params: Record<string, string> = value === 'not-a-mode' ? { mode: value } : { extra: value }
    expect(parseVpnProfiles(uri('vless', 'xhttp', params))).toEqual([])
  })
  it('rejects contradictory gRPC mode flags and preserves boolean aliases', () => {
    expect(parseVpnProfiles(uri('vless', 'grpc', { mode: 'gun', multiMode: 'true' }))).toEqual([])
    expect(parseVpnProfiles(uri('vless', 'grpc', { multiMode: 'maybe' }))).toEqual([])
    expect(parseVpnProfiles(uri('vless', 'grpc', { multiMode: 'false' }))[0].outbound.transport.multi_mode).toBe(false)
  })
  it.runIf(process.platform === 'win32')('passes bundled Xray preflight for every XHTTP mode and gRPC gun/multi', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vpnte-transport-check-'))
    try {
      for (const [type, mode] of [['xhttp', 'auto'], ['xhttp', 'packet-up'], ['xhttp', 'stream-up'], ['xhttp', 'stream-one'], ['grpc', 'gun'], ['grpc', 'multi']]) {
        const [profile] = parseVpnProfiles(uri('vless', type, { mode, ...(type === 'xhttp' ? { extra: JSON.stringify({ noSSEHeader: true }) } : { serviceName: 'svc' }) }))
        const config = buildXrayConfig(toXrayOutbound(profile.outbound), 50123)
        config.log.error = ''
        const file = join(directory, 'config.json')
        writeFileSync(file, JSON.stringify(config))
        expect(() => execFileSync(resolve('resources/xray.exe'), ['run', '-test', '-c', file], { windowsHide: true, stdio: 'pipe', timeout: 10000 })).not.toThrow()
      }
    } finally {
      if (dirname(resolve(directory)) !== resolve(tmpdir())) throw new Error('Unsafe cleanup target')
      rmSync(directory, { recursive: true, force: true })
    }
  })
})
