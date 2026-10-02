import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ values: new Map<string, any>(), identity: vi.fn(), interfaces: vi.fn() }))
vi.mock('./adaptiveNetworkIdentity', () => ({ readAdaptiveNetworkIdentity: state.identity }))
vi.mock('os', async original => ({ ...await original<typeof import('os')>(), networkInterfaces: state.interfaces }))

vi.mock('electron', () => ({
  safeStorage: {
    isEncryptionAvailable: () => false,
    encryptString: (value: string) => Buffer.from(value),
    decryptString: (value: Buffer) => value.toString('utf8')
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    get(key: string) { return state.values.get(key) }
    set(key: string, value: unknown) { state.values.set(key, value) }
    delete(key: string) { state.values.delete(key) }
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { nextAdaptiveMode, resolveAdaptiveCapabilities, isTunOrVpnAdapter, networkFingerprint,
  profileFingerprint, readAdaptiveNetworkFingerprint, beginAdaptiveConnection, markAdaptiveSuccess,
  markAdaptiveTransition, resetAdaptiveBypassStatus, invalidateAdaptiveLearningContext, getAdaptiveBypassStatus } from './adaptiveBypass'

const interfaces: any = { 'Wi-Fi': [{ address: '192.168.1.100', netmask: '255.255.255.0', family: 'IPv4', mac: '00:11:22:33:44:55', internal: false }] }
const identity = [{ alias: 'Wi-Fi', guid: 'fixture-guid', profiles: ['Home network'], gateways: ['192.168.1.1'] }]
const profile = { name: 'Example', clientDevice: 'pc', outbound: { type: 'vless', server: 'server.test', server_port: 443,
  uuid: 'PRIVATE_CREDENTIAL', transport: { type: 'ws', path: '/path' }, obfs: { type: 'fixture', password: 'OBFS_CREDENTIAL' },
  tls: { enabled: true, server_name: 'front.test', utls: { fingerprint: 'firefox' }, reality: { public_key: 'REALITY_KEY' } } } }
beforeEach(() => {
  state.values.set('learning', {})
  state.identity.mockReset().mockResolvedValue(identity)
  state.interfaces.mockReset().mockReturnValue(interfaces)
  resetAdaptiveBypassStatus()
})

async function begin(p: any = profile, legacyStealthMode = false) {
  return beginAdaptiveConnection({ enabled: true, legacyStealthMode, mode: 'directVpn', profile: p,
    networkIdentity: await readAdaptiveNetworkFingerprint() })
}
async function learn(p: any = profile) {
  await begin(p)
  markAdaptiveTransition('mtu-compatibility')
  await markAdaptiveSuccess(p)
}

describe('adaptive bypass capability matrix', () => {
  it('keeps local external proxies externally managed', () => {
    const capabilities = resolveAdaptiveCapabilities('localProxy')

    expect(capabilities.externallyManaged).toBe(true)
    expect(nextAdaptiveMode('external-managed', capabilities)).toBeNull()
  })

  it('allows TLS compatibility for regular TLS but not Reality', () => {
    const tls = resolveAdaptiveCapabilities('directVpn', { outbound: { tls: { enabled: true } } })
    const reality = resolveAdaptiveCapabilities('directVpn', {
      outbound: { tls: { enabled: true, reality: { enabled: true } } }
    })

    expect(tls.canUseTlsCompatibility).toBe(true)
    expect(nextAdaptiveMode('baseline', tls)).toBe('tls-compatibility')
    expect(reality.canUseTlsCompatibility).toBe(false)
    expect(nextAdaptiveMode('baseline', reality)).toBe('mtu-compatibility')
  })

  it('does not loop after the MTU compatibility attempt', () => {
    const capabilities = resolveAdaptiveCapabilities('directVpn', { outbound: { tls: { enabled: true } } })

    expect(nextAdaptiveMode('tls-compatibility', capabilities)).toBe('mtu-compatibility')
    expect(nextAdaptiveMode('mtu-compatibility', capabilities)).toBeNull()
  })
})

describe('adaptive identity and learning regressions (AT-10-007 / F-126 / F-128)', () => {
  it('keeps a canonical profile hash across object key order and unrelated display metadata', () => {
    const reordered = { ...profile, id: 'other-id', name: 'Renamed', outbound: Object.fromEntries(Object.entries(profile.outbound).reverse()) }
    expect(profileFingerprint(reordered)).toBe(profileFingerprint(profile))
    expect(profileFingerprint({ ...profile, outbound: { ...profile.outbound, tag: 'another', bind_interface: 'Wi-Fi' } })).toBe(profileFingerprint(profile))
  })
  it.each(['transport', 'reality', 'obfs', 'device', 'fingerprint', 'native-graph', 'credential'])('invalidates learned decisions when %s changes', async field => {
    await learn()
    expect((await begin()).mode).toBe('mtu-compatibility')
    const changed: any = JSON.parse(JSON.stringify(profile))
    if (field === 'transport') changed.outbound.transport.type = 'grpc'
    if (field === 'reality') changed.outbound.tls.reality.public_key = 'NEW_KEY'
    if (field === 'obfs') changed.outbound.obfs.password = 'NEW_PASSWORD'
    if (field === 'device') changed.clientDevice = 'android'
    if (field === 'fingerprint') changed.outbound.tls.utls.fingerprint = 'chrome'
    if (field === 'native-graph') changed.outbound.vpnte_xray = { routing: { balancers: [{ tag: 'new' }] } }
    if (field === 'credential') changed.outbound.uuid = 'NEW_PRIVATE_CREDENTIAL'
    expect((await begin(changed)).mode).toBe('baseline')
  })
  it('does not confuse a hotspot with another Wi-Fi on the same card and subnet', async () => {
    await learn()
    state.identity.mockResolvedValue([{ ...identity[0], profiles: ['Galaxy S24 Ultra'] }])
    expect((await begin()).mode).toBe('baseline')
    state.identity.mockResolvedValue(identity)
    expect((await begin()).mode).toBe('mtu-compatibility')
  })
  it('changes the hash for a gateway change but not DHCP renewal or IPv6 lockdown', () => {
    const base = networkFingerprint(interfaces, identity)
    expect(networkFingerprint(interfaces, [{ ...identity[0], gateways: ['192.168.1.254'] }])).not.toBe(base)
    const dual = { 'Wi-Fi': [...interfaces['Wi-Fi'], { ...interfaces['Wi-Fi'][0], address: '2001:db8::1234', netmask: 'ffff:ffff:ffff:ffff::', family: 'IPv6' }] }
    expect(networkFingerprint(dual, identity)).toBe(base)
    expect(networkFingerprint({ 'Wi-Fi': [{ ...interfaces['Wi-Fi'][0], address: '192.168.1.111' }] }, identity)).toBe(base)
    expect(networkFingerprint({ 'Wi-Fi': [{ ...interfaces['Wi-Fi'][0], address: '10.42.0.10' }] }, identity)).not.toBe(base)
  })
  it('invalidates old key versions and keeps only HMAC identifiers in learning storage', async () => {
    state.values.set('learning', { 'old-hash:old-profile': { mode: 'tls-compatibility', expiresAt: Date.now() + 99999 } })
    expect((await begin()).mode).toBe('baseline')
    await learn()
    const saved = JSON.stringify(state.values.get('learning'))
    expect(Object.keys(state.values.get('learning'))[0]).toMatch(/^v2:/)
    for (const secret of ['Home network', '192.168.1.1', 'PRIVATE_CREDENTIAL', 'REALITY_KEY', 'server.test']) expect(saved).not.toContain(secret)
  })
  it('does not reuse or persist a decision when network identity is unknown', async () => {
    await learn()
    state.identity.mockResolvedValue(null)
    expect((await begin()).mode).toBe('baseline')
    const before = JSON.stringify(state.values.get('learning'))
    markAdaptiveTransition('mtu-compatibility')
    await markAdaptiveSuccess(profile)
    expect(JSON.stringify(state.values.get('learning'))).toBe(before)
  })
  it('does not publish a stale learning result or connected status after a newer start', async () => {
    await begin()
    markAdaptiveTransition('mtu-compatibility')
    let release!: (value: any) => void
    state.identity.mockImplementationOnce(() => new Promise(done => { release = done }))
    const pending = markAdaptiveSuccess(profile)
    await begin()
    release(identity)
    await pending
    expect(getAdaptiveBypassStatus().phase).toBe('connecting')
    expect(state.values.get('learning')).toEqual({})
  })
  it('refuses to learn when the SSID changed during the stability window, even with the same IP', async () => {
    await begin()
    markAdaptiveTransition('mtu-compatibility')
    state.identity.mockResolvedValue([{ ...identity[0], profiles: ['Other network'] }])
    await markAdaptiveSuccess(profile)
    expect(state.values.get('learning')).toEqual({})
    expect(getAdaptiveBypassStatus().phase).toBe('connected')
  })
  it('network-change invalidation cancels pending learning and preserves current lifecycle status', async () => {
    await begin()
    markAdaptiveTransition('mtu-compatibility')
    let release!: (value: any) => void
    state.identity.mockImplementationOnce(() => new Promise(done => { release = done }))
    const pending = markAdaptiveSuccess(profile)
    invalidateAdaptiveLearningContext()
    release(identity)
    await pending
    expect(state.values.get('learning')).toEqual({})
    expect(getAdaptiveBypassStatus().phase).toBe('adapting')
  })
  it('does not learn while adaptation is disabled', async () => {
    beginAdaptiveConnection({ enabled: false, legacyStealthMode: false, mode: 'directVpn', profile, networkIdentity: await readAdaptiveNetworkFingerprint() })
    markAdaptiveTransition('mtu-compatibility')
    await markAdaptiveSuccess(profile)
    expect(state.values.get('learning')).toEqual({})
  })
})

describe('adaptive bypass network fingerprinting', () => {
  it('identifies TUN, Wintun, and VPN adapter names', () => {
    expect(isTunOrVpnAdapter('Ethernet 5')).toBe(true)
    expect(isTunOrVpnAdapter('VPNTE-TUN')).toBe(true)
    expect(isTunOrVpnAdapter('wintun-adapter')).toBe(true)
    expect(isTunOrVpnAdapter('sing-box tun')).toBe(true)
    expect(isTunOrVpnAdapter('WireGuard Tunnel')).toBe(true)
    expect(isTunOrVpnAdapter('OpenVPN TAP')).toBe(true)
    expect(isTunOrVpnAdapter('Wi-Fi')).toBe(false)
    expect(isTunOrVpnAdapter('Ethernet')).toBe(false)
  })

  it('calculates stable networkFingerprint ignoring newly spawned TUN adapter', () => {
    const physicalInterfaces = {
      'Wi-Fi': [
        {
          address: '192.168.1.100',
          netmask: '255.255.255.0',
          family: 'IPv4',
          mac: '00:11:22:33:44:55',
          internal: false,
          cidr: '192.168.1.100/24'
        } as any
      ]
    }

    const physicalWithTun = {
      ...physicalInterfaces,
      'Ethernet 5': [
        {
          address: '192.168.250.253',
          netmask: '255.255.255.252',
          family: 'IPv4',
          mac: '00:00:00:00:00:01',
          internal: false,
          cidr: '192.168.250.253/30'
        } as any
      ]
    }

    const fpBefore = networkFingerprint(physicalInterfaces)
    const fpAfter = networkFingerprint(physicalWithTun)

    expect(fpBefore).toBe(fpAfter)
    expect(fpBefore).not.toBe('')
  })
})
