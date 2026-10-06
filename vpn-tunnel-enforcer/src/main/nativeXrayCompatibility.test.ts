import { describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { dirname, join, resolve } from 'path'

vi.mock('./tunController', () => ({
  getTunRuntimeDir: () => tmpdir(), getBundledResource: (name: string) => name,
  pickFreeLocalPort: vi.fn(), copyResourceIfStale: vi.fn()
}))
vi.mock('./firewallKillSwitch', () => ({ ensureKillSwitchProgramAllowed: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { applyClientDeviceToOutbound, exportOutboundToUri, exportOutboundForSharing, parseVpnProfiles, redactSensitiveConfig } from './vpnProfiles'
import { buildXrayConfig, buildXrayProbeConfig, resolveXrayConfigEndpoints, toXrayOutbound } from './xrayEngine'
import { compileNativeXrayProfile, getNativeXrayProfile, NATIVE_XRAY_FIELD, preserveNativeXrayProfile } from './nativeXrayProfile'
import { resolveProxyEngine } from './proxyEngine'

const PUBLIC_KEY = 'V5UzfRyMpjdzNd_scfbrd_vumJUTrLR_qMYTwjvsTA8'
function vless(tag: string, address = '192.0.2.1', dialerProxy?: string): any {
  return {
    tag, protocol: 'vless', settings: { vnext: [{ address, port: 443, users: [{ id: '11111111-2222-4333-8444-555555555555', encryption: 'none', flow: '' }] }] },
    mux: { enabled: true, concurrency: 6, xudpConcurrency: 4, xudpProxyUDP443: 'reject' },
    streamSettings: { network: 'tcp', tcpSettings: { header: { type: 'none' } }, security: 'reality',
      realitySettings: { serverName: 'front.example.com', publicKey: PUBLIC_KEY, fingerprint: 'firefox' },
      ...(dialerProxy ? { sockopt: { dialerProxy } } : {}) }
  }
}
function document(): any {
  return {
    remarks: 'Norway',
    inbounds: [{ listen: '0.0.0.0', protocol: 'socks', port: 12345, tag: 'untrusted-listener' }],
    api: { services: ['HandlerService'] }, dns: { servers: ['untrusted.example.com'] },
    log: { error: 'C:/untrusted/location.log' },
    policy: { levels: { '0': { handshake: 7, connIdle: 300 } } },
    outbounds: [
      vless('norwayvless1'),
      { tag: 'norwayhysteria1', protocol: 'hysteria', settings: { address: '192.0.2.2', port: 443, version: 2 }, streamSettings: { network: 'hysteria', hysteriaSettings: { version: 2, auth: 'SYNTHETIC_AUTH' }, security: 'tls', tlsSettings: { serverName: 'front.example.com' } } },
      vless('bridgenorwayvless1', '192.0.2.1', 'LOOP-L1'), vless('l1bridgevless1', '192.0.2.3'),
      { tag: 'LOOP-L2', protocol: 'loopback', settings: { inboundTag: 'L2-REROUTE' } },
      { tag: 'LOOP-L1', protocol: 'loopback', settings: { inboundTag: 'L1-REROUTE' } },
      { tag: 'direct', protocol: 'freedom' }, { tag: 'unused', protocol: 'freedom' }
    ],
    routing: {
      balancers: [
        { tag: 'l1', selector: ['norwayvless'], strategy: { type: 'leastLoad', settings: { expected: 1 } }, fallbackTag: 'LOOP-L2' },
        { tag: 'l2', selector: ['norwayhysteria'], strategy: { type: 'leastLoad' }, fallbackTag: 'bridgenorwayvless1' },
        { tag: 'bridge', selector: ['l1bridge'], strategy: { type: 'leastLoad' }, fallbackTag: 'direct' }
      ],
      rules: [
        { type: 'field', domain: ['untrusted.example.com'], outboundTag: 'direct' },
        { type: 'field', inboundTag: ['L2-REROUTE'], balancerTag: 'l2' },
        { type: 'field', inboundTag: ['L1-REROUTE'], balancerTag: 'bridge' },
        { type: 'field', network: 'tcp,udp', balancerTag: 'l1' }
      ]
    },
    burstObservatory: { subjectSelector: ['norway', 'l1bridge'], pingConfig: { destination: 'https://example.com/', interval: '1m', sampling: 1, timeout: '5s' } }
  }
}
function compile(doc = document()) {
  const [profile] = parseVpnProfiles(JSON.stringify(doc))
  const out = applyClientDeviceToOutbound(profile.outbound, 'pc')
  return { profile, out, config: buildXrayConfig(toXrayOutbound(out, { clientDevice: 'pc' }), 50123, { nativeProfile: getNativeXrayProfile(out) }) }
}

describe('AT-04-002 / AT-04-006 / AT-02-002: preserved Xray connection pipeline', () => {
  it('AT-02-008 / AT-06-001: keeps sniffed domains for routing without rewriting native graph destinations', () => {
    const { config } = compile()
    expect(config.inbounds[0].sniffing).toEqual({
      enabled: true, destOverride: ['tls', 'http', 'quic'], routeOnly: true
    })
    expect(config.routing.rules.find((rule: any) => rule.inboundTag?.includes('in') && rule.balancerTag))
      .toMatchObject({ balancerTag: 'vpnte-balancer:l1' })
    expect(config.routing.balancers.find((balancer: any) => balancer.tag === 'vpnte-balancer:l1'))
      .toMatchObject({ fallbackTag: 'vpnte-source:LOOP-L2' })
  })
  it('exports complete JSON and re-imports the bridge graph without provider listeners or application bypass', () => {
    const { profile, config } = compile()
    const shared = exportOutboundForSharing(profile)!
    expect(shared.format).toBe('json')
    const doc = JSON.parse(shared.content)
    expect(doc.inbounds).toBeUndefined()
    expect(doc.api).toBeUndefined()
    expect(doc.dns).toBeUndefined()
    expect(doc.log).toBeUndefined()
    expect(shared.content).not.toContain('vpnte_xray')
    expect(shared.content).not.toContain('untrusted')
    const [restored] = parseVpnProfiles(shared.content)
    expect(restored.name).toBe(profile.name)
    const rebuilt = buildXrayConfig(toXrayOutbound(restored.outbound), 50124, { nativeProfile: getNativeXrayProfile(restored.outbound) })
    expect(rebuilt.routing.balancers).toHaveLength(config.routing.balancers.length)
    expect(rebuilt.outbounds.filter((o: any) => o.protocol === 'vless').map((o: any) => o.mux)).toEqual(config.outbounds.filter((o: any) => o.protocol === 'vless').map((o: any) => o.mux))
    expect(rebuilt.outbounds.some((o: any) => o.streamSettings?.sockopt?.dialerProxy)).toBe(true)
    const simple = { ...profile, name: 'Simple', outbound: { ...profile.outbound } }
    delete simple.outbound[NATIVE_XRAY_FIELD]
    expect(parseVpnProfiles(JSON.stringify([doc, exportOutboundToUri(simple)])).map(p => p.name)).toEqual(['Norway', 'Simple'])
  })
  it('exports independent native JSON and ordinary sing-box multiplex without degradation', () => {
    const [profile] = parseVpnProfiles(JSON.stringify(vless('single')))
    const restored = parseVpnProfiles(exportOutboundForSharing(profile)!.content)
    expect(restored).toHaveLength(1)
    expect(toXrayOutbound(restored[0].outbound).mux).toEqual(toXrayOutbound(profile.outbound).mux)
    const [singbox] = parseVpnProfiles(JSON.stringify({ type: 'trojan', server: '192.0.2.1', server_port: 443, password: 'SYNTHETIC', multiplex: { enabled: false, padding: true } }))
    const shared = exportOutboundForSharing(singbox)!
    expect(shared.format).toBe('json')
    expect(parseVpnProfiles(shared.content)[0].outbound.multiplex).toEqual(singbox.outbound.multiplex)
    const simple = { ...singbox, outbound: { ...singbox.outbound } }
    delete simple.outbound.multiplex
    expect(exportOutboundForSharing(simple)!.format).toBe('uri')
  })
  it('keeps one provider JSON document as one connection, with its automatic failover', () => {
    const profiles = parseVpnProfiles(JSON.stringify([document(), { ...document(), remarks: 'Sweden' }]))
    expect(profiles.map(p => p.name)).toEqual(['Norway', 'Sweden'])
    expect(getNativeXrayProfile(profiles[0].outbound)?.entry).toEqual({ balancerTag: 'l1' })
  })

  it('does not duplicate unrelated subscription credentials for independent JSON outbounds (AT-04-001)', () => {
    const profiles = parseVpnProfiles(JSON.stringify({ outbounds: Array.from({ length: 100 }, (_, i) => vless(`node-${i}`)) }))
    expect(profiles).toHaveLength(100)
    expect(profiles.every(p => getNativeXrayProfile(p.outbound)?.outbounds.length === 1)).toBe(true)
  })

  it('preserves fingerprint, mux and original stream settings across import, device defaults and compilation', () => {
    const doc = document(), original = JSON.stringify(doc)
    const { out, config } = compile(doc)
    const root = config.outbounds.find((o: any) => o.tag === 'proxy')
    expect(out.tls.utls.fingerprint).toBe('firefox')
    expect(root.streamSettings).toEqual(doc.outbounds[0].streamSettings)
    expect(root.mux).toEqual(doc.outbounds[0].mux)
    expect(config.policy).toEqual(doc.policy)
    expect(JSON.stringify(doc)).toBe(original)
  })

  it('restores bridge, loopback and balancer dependencies without tag collisions', () => {
    const { config } = compile()
    const bridge = config.outbounds.find((o: any) => o.tag === 'vpnte-source:bridgenorwayvless1')
    expect(bridge.streamSettings.sockopt.dialerProxy).toBe('vpnte-source:LOOP-L1')
    expect(config.outbounds.find((o: any) => o.tag === 'vpnte-source:LOOP-L1').settings.inboundTag).toBe('vpnte-loop:L1-REROUTE')
    expect(config.routing.rules).toContainEqual({ type: 'field', inboundTag: ['vpnte-loop:L1-REROUTE'], balancerTag: 'vpnte-balancer:bridge' })
    expect(config.routing.balancers.find((b: any) => b.tag === 'vpnte-balancer:l1').selector).toEqual(['proxy'])
    expect(config.routing.balancers.find((b: any) => b.tag === 'vpnte-balancer:l2').fallbackTag).toBe('vpnte-source:bridgenorwayvless1')
    expect(config.outbounds.some((o: any) => o.tag.endsWith(':unused'))).toBe(false)
  })

  it('does not inherit provider listeners, API, DNS, log paths or global direct application rules', () => {
    const { config } = compile()
    expect(config.inbounds).toHaveLength(1)
    expect(config.inbounds[0].listen).toBe('127.0.0.1')
    expect(config.api).toBeUndefined()
    expect(config.dns).toBeUndefined()
    expect(JSON.stringify(config)).not.toContain('untrusted')
    expect(config.routing.rules.at(-1).outboundTag).toBe('block')
    expect(config.routing.rules[0].inboundTag).toEqual(['in'])
    expect(config.burstObservatory.subjectSelector).toEqual(expect.arrayContaining(['proxy', 'vpnte-source:l1bridgevless1']))
  })

  it('checks a bridge through the same graph and applies the physical probe detour only at leaves', () => {
    const doc = document()
    delete doc.routing.balancers
    doc.routing.rules = [{ type: 'field', inboundTag: ['L1-REROUTE'], outboundTag: 'l1bridgevless1' }]
    const profile = parseVpnProfiles(JSON.stringify(doc)).find(p => p.name === 'bridgenorwayvless1')!
    const config = buildXrayProbeConfig(profile.outbound, 50124, { directProxy: { host: '127.0.0.1', port: 18000 } })
    expect(config.outbounds.find((o: any) => o.tag === 'proxy').streamSettings.sockopt.dialerProxy).toBe('vpnte-source:LOOP-L1')
    expect(config.outbounds.find((o: any) => o.tag === 'vpnte-source:l1bridgevless1').streamSettings.sockopt.dialerProxy).toBe('probe-direct-out')
    expect(config.outbounds.find((o: any) => o.tag === 'probe-direct-out').settings.servers[0].port).toBe(18000)
  })

  it('resolves every reachable endpoint once, retains SNI and leaves input untouched', async () => {
    const doc = document()
    doc.outbounds[0].settings.vnext[0].address = 'one.example.com'
    doc.outbounds[2].settings.vnext[0].address = 'one.example.com'
    doc.outbounds[3].settings.vnext[0].address = 'two.example.com'
    doc.outbounds[1].settings.address = 'three.example.com'
    const { config } = compile(doc)
    const resolver = vi.fn(async () => '192.0.2.44')
    await resolveXrayConfigEndpoints(config, resolver)
    expect(resolver).toHaveBeenCalledTimes(3)
    expect(config.outbounds.find((o: any) => o.tag === 'proxy').settings.vnext[0].address).toBe('192.0.2.44')
    expect(config.outbounds.find((o: any) => o.protocol === 'hysteria').settings.address).toBe('192.0.2.44')
    expect(config.outbounds.find((o: any) => o.tag === 'proxy').streamSettings.realitySettings.serverName).toBe('front.example.com')
    expect(doc.outbounds[0].settings.vnext[0].address).toBe('one.example.com')
  })

  it('propagates resolution cancellation instead of publishing a partially resolved graph', async () => {
    const { config } = compile()
    config.outbounds[0].settings.vnext[0].address = 'one.example.com'
    await expect(resolveXrayConfigEndpoints(config, async () => { throw new Error('Cancelled') })).rejects.toThrow('Cancelled')
    expect(config.outbounds[0].settings.vnext[0].address).toBe('one.example.com')
  })

  // AT-04-006 / AT-02-004: no native graph is published with unresolved leaves.
  it.each([null, '', 'invalid-address'])('rejects resolver result %s without partially mutating endpoints', async unresolved => {
    const { config } = compile()
    const endpoints = config.outbounds.filter((o: any) => o.settings?.vnext?.length)
    endpoints[0].settings.vnext[0].address = 'good.example.com'
    endpoints[1].settings.vnext[0].address = 'unresolved.example.com'
    const before = JSON.stringify(config)
    const resolver = vi.fn(async (host: string) => host === 'good.example.com' ? '192.0.2.44' : unresolved)
    await expect(resolveXrayConfigEndpoints(config, resolver)).rejects.toThrow('Не удалось разрешить адрес узла native Xray')
    expect(JSON.stringify(config)).toBe(before)
  })

  it('retains literal IPv4/IPv6 endpoints and accepts resolved IPv6 without changing SNI', async () => {
    const config = { outbounds: [
      { protocol: 'vless', settings: { vnext: [{ address: '192.0.2.1' }, { address: '2001:db8::1' }, { address: 'leaf.example.com' }] }, streamSettings: { tlsSettings: { serverName: 'front.example.com' } } }
    ] }
    const resolver = vi.fn(async () => '2001:db8::2')
    await resolveXrayConfigEndpoints(config, resolver)
    expect(resolver).toHaveBeenCalledExactlyOnceWith('leaf.example.com')
    expect(config.outbounds[0].settings.vnext.map(node => node.address)).toEqual(['192.0.2.1', '2001:db8::1', '2001:db8::2'])
    expect(config.outbounds[0].streamSettings.tlsSettings.serverName).toBe('front.example.com')
  })

  it('requires Xray for native JSON and refuses to export it as a degraded URI', () => {
    const { profile } = compile()
    expect(resolveProxyEngine(profile.outbound, 'auto')).toBe('xray')
    expect(() => resolveProxyEngine(profile.outbound, 'sing-box')).toThrow(/Xray/)
    expect(exportOutboundToUri(profile)).toBeNull()
  })

  it('redacts the entire preserved graph, including dependent credentials and probe URLs', () => {
    const { profile } = compile()
    const redacted = JSON.stringify(redactSensitiveConfig(profile.outbound))
    expect(redacted).not.toContain('SYNTHETIC_AUTH')
    expect(redacted).not.toContain(PUBLIC_KEY)
    expect(redacted).not.toContain('https://example.com/')
    expect((redactSensitiveConfig(profile.outbound) as any)[NATIVE_XRAY_FIELD]).toBe('<redacted>')
  })

  it('preserves native XHTTP extra and mode without converting the connection into TCP', () => {
    const raw = vless('xhttp')
    raw.streamSettings = { network: 'xhttp', security: 'tls', tlsSettings: { serverName: 'front.example.com', fingerprint: 'firefox' }, xhttpSettings: { mode: 'packet-up', path: '/path', host: 'front.example.com', extra: { noSSEHeader: true } } }
    const [profile] = parseVpnProfiles(JSON.stringify(raw))
    expect(toXrayOutbound(profile.outbound).streamSettings).toEqual(raw.streamSettings)
  })

  it('isolates a selected credential from multi-user / multi-endpoint source outbounds', () => {
    const raw = vless('multi')
    raw.settings.vnext[0].users.push({ id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', encryption: 'none' })
    raw.settings.vnext.push({ address: '192.0.2.55', port: 443, users: [{ id: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff', encryption: 'none' }] })
    const profiles = parseVpnProfiles(JSON.stringify(raw))
    expect(profiles).toHaveLength(3)
    for (const profile of profiles) {
      const outbound = toXrayOutbound(profile.outbound)
      expect(outbound.settings.vnext).toHaveLength(1)
      expect(outbound.settings.vnext[0].users).toHaveLength(1)
      expect(outbound.settings.vnext[0].users[0].id).toBe(profile.outbound.uuid)
    }
  })

  it('rejects missing / cyclic dependencies and a provider fallback that sends application traffic directly', () => {
    const raw = vless('selected', '192.0.2.1', 'missing')
    expect(() => compileNativeXrayProfile(preserveNativeXrayProfile(raw), raw)).toThrow(/Missing.*dependency/)
    const loop = { tag: 'loop', protocol: 'loopback', settings: { inboundTag: 'again' } }
    const native = { version: 1 as const, selectedTag: 'selected', entry: { outboundTag: 'selected' }, outbounds: [{ ...raw, streamSettings: { sockopt: { dialerProxy: 'loop' } } }, loop], routing: { rules: [{ type: 'field', inboundTag: ['again'], outboundTag: 'selected' }] } }
    expect(() => compileNativeXrayProfile(native, native.outbounds[0])).toThrow(/Cyclic/)
    const doc = document()
    doc.routing.balancers[0].fallbackTag = 'direct'
    expect(() => preserveNativeXrayProfile(doc.outbounds[0], doc, { balancerTag: 'l1' })).toThrow(/bypass VPN protection/)
    expect(parseVpnProfiles(JSON.stringify(doc))).toEqual([])
  })

  it('rejects local-file references before starting any core process', () => {
    const doc = document()
    doc.outbounds[0].streamSettings.realitySettings.certificateFile = 'C:/Users/secret.pem'
    expect(() => preserveNativeXrayProfile(doc.outbounds[0], doc, { balancerTag: 'l1' })).toThrow(/external local file/)
    expect(parseVpnProfiles(JSON.stringify(doc))).toEqual([])
  })

  it.runIf(process.platform === 'win32')('passes the bundled Xray config check for the complete synthetic VLESS/Hysteria/bridge graph', () => {
    const { config } = compile()
    const dir = mkdtempSync(join(tmpdir(), 'vpnte-native-xray-test-'))
    try {
      const [restored] = parseVpnProfiles(exportOutboundForSharing(compile().profile)!.content)
      const rebuilt = buildXrayConfig(toXrayOutbound(restored.outbound), 50124, { nativeProfile: getNativeXrayProfile(restored.outbound) })
      for (const target of [config, rebuilt]) {
        const file = join(dir, 'config.json')
        target.log.error = ''
        writeFileSync(file, JSON.stringify(target))
        expect(() => execFileSync(resolve('resources/xray.exe'), ['run', '-test', '-c', file], { cwd: dir, windowsHide: true, timeout: 10000, stdio: 'pipe' })).not.toThrow()
      }
    } finally {
      if (dirname(resolve(dir)) !== resolve(tmpdir())) throw new Error('Unsafe temporary cleanup target')
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
