/**
 * Unit tests for generateSingboxConfig() and parseProxyAddress() in
 * tunController.ts.
 *
 * Focus areas:
 *   - clash_api + mixed-direct-in ports are bind-safe (honour the
 *     pre-resolved overrides, never collide). Regression guard for the
 *     WSAEACCES-on-clash-port bug.
 *   - DNS bootstrap is added only when the endpoint is a hostname.
 *   - stealth mode flips MTU 1500 → 1280 and adds record_fragment to
 *     non-Reality TLS but NOT to Reality.
 *   - UDP is blocked for tcp-only / HTTP outbounds.
 *   - uTLS + ALPN are always injected on TLS outbounds.
 *   - parseProxyAddress handles IPv4 / IPv6 / bad input.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'

// ─── Mock the import chain so tunController loads under vitest/node ──────────
vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private data: Record<string, any> = {}
    get(key?: string) {
      if (!key) return { settings: {} }
      return this.data[key]
    }
    set(key: string, value: any) {
      this.data[key] = value
    }
  }
}))

vi.mock('sudo-prompt', () => ({ default: { exec: vi.fn() }, exec: vi.fn() }))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./notifications', () => ({ notify: vi.fn().mockResolvedValue(undefined) }))
vi.mock('./admin', () => ({
  execElevated: vi.fn().mockResolvedValue({ stdout: '', stderr: '' }),
  isProcessElevated: vi.fn().mockResolvedValue(false)
}))
vi.mock('./firewallKillSwitch', () => ({
  enableKillSwitch: vi.fn(),
  disableKillSwitch: vi.fn(),
  disableKillSwitchIfActive: vi.fn(),
  isKillSwitchActive: vi.fn().mockResolvedValue(false)
}))
vi.mock('./physicalAdapterLockdown', () => ({
  applyPhysicalAdapterLockdown: vi.fn(),
  isPhysicalAdapterLockdownApplied: vi.fn().mockResolvedValue(false),
  repairOrphanedPhysicalAdapterDns: vi.fn(),
  rollbackPhysicalAdapterLockdownIfApplied: vi.fn()
}))
vi.mock('./systemNetwork', () => ({
  rollbackTunNetworkBaselineIfApplied: vi.fn().mockResolvedValue({ success: true })
}))
vi.mock('./ipMonitor', () => ({
  ipMonitor: { suspend: vi.fn(), resume: vi.fn(), getStatus: vi.fn() }
}))
vi.mock('./leakSelfTest', () => ({ cancelLeakSelfTest: vi.fn() }))
vi.mock('./competingTunDetector', () => ({
  startCompetingTunWatch: vi.fn(),
  stopCompetingTunWatch: vi.fn()
}))

// Mutable active DNS profile so tests can flip it. buildRemoteDnsServers()
// require()s this module at call time. vi.hoisted so the state object exists
// before the hoisted vi.mock factory closes over it.
const dnsState = vi.hoisted(() => ({ active: null as any }))
const domainState = vi.hoisted(() => ({ rules: [] as Array<Record<string, any>> }))
vi.mock('./dnsProfiles', () => ({
  dnsProfiles: {
    getActiveDnsProfile: () => dnsState.active
  }
}))

vi.mock('./domainRouting', () => ({
  generateDomainRouteRules: () => domainState.rules
}))

import { generateSingboxConfig, parseProxyAddress } from './tunController'

// ─── Helpers ─────────────────────────────────────────────────────────────────

interface SingboxConfig {
  dns: { servers: Array<{ tag: string; type: string }> }
  inbounds: Array<Record<string, any>>
  outbounds: Array<Record<string, any>>
  route: { rules: Array<Record<string, any>>; final: string }
  experimental: { clash_api: { external_controller: string } }
}

function gen(
  upstream: Parameters<typeof generateSingboxConfig>[0],
  proxyType: 'socks5' | 'http' = 'socks5',
  directProcessNames: string[] = [],
  options: { stealthMode?: boolean; directProxyPortOverride?: number; clashPortOverride?: number } = {}
): SingboxConfig {
  return generateSingboxConfig(upstream, proxyType, directProcessNames, options) as unknown as SingboxConfig
}

function clashPortOf(cfg: SingboxConfig): number {
  const ctrl = cfg.experimental.clash_api.external_controller
  return Number(ctrl.split(':').pop())
}

function directPortOf(cfg: SingboxConfig): number {
  const mixed = cfg.inbounds.find((i) => i.tag === 'mixed-direct-in')
  return Number(mixed?.listen_port)
}

const realityOutbound = {
  type: 'vless',
  server: 'example.com',
  server_port: 443,
  uuid: 'abc',
  network: 'tcp',
  tls: {
    enabled: true,
    server_name: 'www.microsoft.com',
    reality: { enabled: true, public_key: 'k' }
  }
}

const plainTlsOutbound = {
  type: 'vless',
  server: 'example.com',
  server_port: 443,
  uuid: 'abc',
  tls: { enabled: true, server_name: 'example.com' }
}

// ─── parseProxyAddress ──────────────────────────────────────────────────────

describe('parseProxyAddress', () => {
  it('parses host:port', () => {
    expect(parseProxyAddress('127.0.0.1:10808')).toEqual({ host: '127.0.0.1', port: 10808 })
  })

  it('parses bracketed IPv6', () => {
    expect(parseProxyAddress('[::1]:1080')).toEqual({ host: '::1', port: 1080 })
  })

  it('throws on missing port', () => {
    expect(() => parseProxyAddress('127.0.0.1')).toThrow()
  })

  it('throws on out-of-range port', () => {
    expect(() => parseProxyAddress('127.0.0.1:70000')).toThrow()
  })

  it('throws on empty host', () => {
    expect(() => parseProxyAddress(':1080')).toThrow()
  })
})

// ─── Port bind-safety (the WSAEACCES regression) ─────────────────────────────

describe('generateSingboxConfig port selection', () => {
  it('honours explicit clashPortOverride and directProxyPortOverride', () => {
    const cfg = gen('127.0.0.1:10808', 'socks5', [], {
      directProxyPortOverride: 34567,
      clashPortOverride: 34568
    })
    expect(directPortOf(cfg)).toBe(34567)
    expect(clashPortOf(cfg)).toBe(34568)
  })

  it('never lets clash and direct ports collide even if overrides clash', () => {
    // Caller mistakenly hands the same port for both — config must not bind
    // two listeners to the same port.
    const cfg = gen('127.0.0.1:10808', 'socks5', [], {
      directProxyPortOverride: 40000,
      clashPortOverride: 40000
    })
    expect(directPortOf(cfg)).not.toBe(clashPortOf(cfg))
  })

  it('falls back to a valid ephemeral port when no override supplied', () => {
    const cfg = gen('127.0.0.1:10808')
    const clash = clashPortOf(cfg)
    const direct = directPortOf(cfg)
    for (const p of [clash, direct]) {
      expect(Number.isInteger(p)).toBe(true)
      expect(p).toBeGreaterThanOrEqual(1)
      expect(p).toBeLessThanOrEqual(65535)
    }
    expect(clash).not.toBe(direct)
  })

  it('ignores an out-of-range clashPortOverride and still emits a valid port', () => {
    const cfg = gen('127.0.0.1:10808', 'socks5', [], { clashPortOverride: 999999 })
    const clash = clashPortOf(cfg)
    expect(clash).toBeGreaterThanOrEqual(1)
    expect(clash).toBeLessThanOrEqual(65535)
  })
})

// ─── DNS bootstrap ────────────────────────────────────────────────────────────

describe('generateSingboxConfig DNS bootstrap', () => {
  it('adds a local bootstrap DNS server when the endpoint is a hostname', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: 'sub.example.com' } })
    const tags = cfg.dns.servers.map((s) => s.tag)
    expect(tags).toContain('dns-bootstrap')
  })

  it('omits bootstrap DNS when the endpoint is a bare IP', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const tags = cfg.dns.servers.map((s) => s.tag)
    expect(tags).not.toContain('dns-bootstrap')
  })
})

// ─── Stealth mode ─────────────────────────────────────────────────────────────

describe('generateSingboxConfig stealth mode', () => {
  it('uses MTU 1500 by default and 1280 in stealth mode', () => {
    const normal = gen({ outbound: { ...plainTlsOutbound } })
    const stealth = gen({ outbound: { ...plainTlsOutbound } }, 'socks5', [], { stealthMode: true })
    const mtuOf = (c: SingboxConfig) => c.inbounds.find((i) => i.type === 'tun')?.mtu
    expect(mtuOf(normal)).toBe(1500)
    expect(mtuOf(stealth)).toBe(1280)
  })

  it('adds record_fragment to non-Reality TLS in stealth mode', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } }, 'socks5', [], { stealthMode: true })
    const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
    expect(out.tls.record_fragment).toBe(true)
  })

  it('does NOT add record_fragment to Reality outbounds in stealth mode', () => {
    const cfg = gen({ outbound: { ...realityOutbound } }, 'socks5', [], { stealthMode: true })
    const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
    expect(out.tls.record_fragment).toBeUndefined()
  })

  it('always injects uTLS chrome + ALPN on TLS outbounds', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
    expect(out.tls.utls?.enabled).toBe(true)
    expect(out.tls.utls?.fingerprint).toBeTruthy()
    expect(Array.isArray(out.tls.alpn)).toBe(true)
  })

  it('strips multiplex/mux from imported outbounds (DPI-harmful)', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, multiplex: { enabled: true, protocol: 'h2mux' }, mux: { enabled: true } } })
    const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
    expect(out.multiplex).toBeUndefined()
    expect(out.mux).toBeUndefined()
  })

  it('stealth fingerprint pool excludes Safari (implausible on Windows)', () => {
    // Probe many servers; none should ever get the safari fp.
    for (let i = 0; i < 50; i++) {
      const cfg = gen({ outbound: { ...plainTlsOutbound, server: `s${i}.example.com`, uuid: `u${i}` } }, 'socks5', [], { stealthMode: true })
      const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
      expect(out.tls.utls.fingerprint).not.toBe('safari')
      expect(['chrome', 'firefox', 'edge']).toContain(out.tls.utls.fingerprint)
    }
  })

  it('does not overwrite explicit client-device fingerprints in stealth mode', () => {
    for (const [clientDevice, fingerprint] of [
      ['pc', 'chrome'],
      ['android', 'android'],
      ['ios', 'ios'],
      ['mac', 'safari']
    ] as const) {
      const cfg = gen(
        { outbound: { ...plainTlsOutbound }, clientDevice },
        'socks5',
        [],
        { stealthMode: true }
      )
      const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
      expect(out.tls.utls.fingerprint).toBe(fingerprint)
      expect(out.tls.record_fragment).toBe(true)
    }
  })
})

// ─── UDP blocking ─────────────────────────────────────────────────────────────

describe('generateSingboxConfig UDP rules', () => {
  it('blocks all UDP for tcp-only outbounds', () => {
    const cfg = gen({ outbound: { ...realityOutbound, network: 'tcp' } })
    const udpBlockAll = cfg.route.rules.some(
      (r) => r.network === 'udp' && r.outbound === 'block-out' && r.port === undefined
    )
    expect(udpBlockAll).toBe(true)
  })

  it('blocks UDP/443 (QUIC) for HTTP proxy mode', () => {
    const cfg = gen('127.0.0.1:8080', 'http')
    const quicBlock = cfg.route.rules.some(
      (r) => r.network === 'udp' && r.port === 443 && r.outbound === 'block-out'
    )
    expect(quicBlock).toBe(true)
  })

  it('routes final traffic through proxy-out', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    expect(cfg.route.final).toBe('proxy-out')
  })
})

// ─── Direct process routing (split-tunnel core processes) ────────────────────

describe('generateSingboxConfig process routing', () => {
  it('routes known proxy-core processes directly in localProxy mode', () => {
    const cfg = gen('127.0.0.1:10808', 'socks5', ['MyApp.exe'])
    const directRule = cfg.route.rules.find(
      (r) => Array.isArray(r.process_name) && r.outbound === 'direct-out'
    )
    expect(directRule).toBeTruthy()
    expect(directRule!.process_name).toContain('MyApp.exe')
  })

  it('does NOT add a process_name direct rule in directVpn mode', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    const directRule = cfg.route.rules.find((r) => Array.isArray(r.process_name))
    expect(directRule).toBeUndefined()
  })
})

// ─── DNS profile integration ──────────────────────────────────────────────────

describe('generateSingboxConfig DNS profile', () => {
  afterEach(() => {
    dnsState.active = null
  })

  it('uses Cloudflare/Google DoT fallback when no profile is active', () => {
    dnsState.active = null
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote.server).toBe('1.1.1.1')
    // DoT (tls) — the known-working tunnelled resolver. A DoH (https) attempt
    // (F11) timed out almost every query through the Reality tunnel in the
    // field and was reverted.
    expect(remote.type).toBe('tls')
  })

  it('applies a plain DNS profile as udp servers through proxy-out', () => {
    dnsState.active = { id: 'x', name: 'Quad9', primary: '9.9.9.9', secondary: '149.112.112.112', type: 'plain' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const servers = cfg.dns.servers as any[]
    const remote = servers.find((s) => s.tag === 'dns-remote')
    const backup = servers.find((s) => s.tag === 'dns-backup')
    expect(remote).toMatchObject({ type: 'udp', server: '9.9.9.9', detour: 'proxy-out' })
    expect(backup).toMatchObject({ type: 'udp', server: '149.112.112.112', detour: 'proxy-out' })
  })

  it('applies a DoH profile as https server with bare host', () => {
    dnsState.active = { id: 'x', name: 'DoH', primary: 'https://dns.google/dns-query', type: 'doh' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote).toMatchObject({ type: 'https', server: 'dns.google', detour: 'proxy-out' })
  })

  it('applies a DoT profile as tls server with bare host', () => {
    dnsState.active = { id: 'x', name: 'DoT', primary: 'tls://dns.google', type: 'dot' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote).toMatchObject({ type: 'tls', server: 'dns.google', detour: 'proxy-out' })
  })

  it('keeps the dns-remote tag so default_domain_resolver resolves', () => {
    dnsState.active = { id: 'x', name: 'Quad9', primary: '9.9.9.9', type: 'plain' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    expect(cfg.route.final).toBe('proxy-out')
    expect(cfg.dns.servers.some((s: any) => s.tag === 'dns-remote')).toBe(true)
  })
})

// ─── Domain routing injection (D1 — was dead) ──────────────────────────────────

describe('generateSingboxConfig domain routing', () => {
  afterEach(() => {
    domainState.rules = []
  })

  it('injects domain rules into route.rules after hijack-dns, before private ranges', () => {
    domainState.rules = [{ outbound: 'block-out', domain: ['ads.example.com'] }]
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const rules = cfg.route.rules
    const hijackIdx = rules.findIndex((r) => r.action === 'hijack-dns')
    const domainIdx = rules.findIndex((r) => Array.isArray(r.domain) && r.domain.includes('ads.example.com'))
    const privateIdx = rules.findIndex((r) => Array.isArray(r.ip_cidr) && r.ip_cidr.includes('127.0.0.0/8'))
    expect(domainIdx).toBeGreaterThan(hijackIdx)
    expect(domainIdx).toBeLessThan(privateIdx)
    expect(rules[domainIdx].outbound).toBe('block-out')
  })

  it('adds no domain rules when the user has none', () => {
    domainState.rules = []
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const hasDomainRule = cfg.route.rules.some((r) => r.domain || r.domain_suffix || r.domain_keyword)
    expect(hasDomainRule).toBe(false)
  })
})

// ─── Smart RU split-routing ──────────────────────────────────────────────────

describe('generateSingboxConfig smart RU split', () => {
  afterEach(() => {
    domainState.rules = []
  })

  const genSmart = (opts: { smartRuSplit?: boolean; smartRuMapsDirect?: boolean; smartRuRuleSetDir?: string }) =>
    generateSingboxConfig(
      { outbound: { ...plainTlsOutbound } },
      'socks5',
      [],
      opts
    ) as any

  it('adds NOTHING when smartRuSplit is off (config unchanged)', () => {
    const cfg = genSmart({})
    expect(cfg.route.rule_set).toBeUndefined()
    expect(cfg.dns.rules).toBeUndefined()
    expect(cfg.dns.servers.find((s: any) => s.tag === 'dns-direct')).toBeUndefined()
    // No direct-routing rule_set rules in the route.
    expect(cfg.route.rules.some((r: any) => r.rule_set)).toBe(false)
  })

  it('always enables cache_file for the DNS answer cache (perf, even w/o smart-RU)', () => {
    // cache_file is now always-on: persisting the DNS cache across restarts is
    // what kills the cold-start DNS storm. Previously gated on smart-RU.
    const off = genSmart({})
    expect(off.experimental.cache_file?.enabled).toBe(true)
    const on = genSmart({ smartRuSplit: true })
    expect(on.experimental.cache_file?.enabled).toBe(true)
  })

  it('adds RU rule-sets + geoip + cache_file when enabled (remote fallback w/o dir)', () => {
    const cfg = genSmart({ smartRuSplit: true })
    // rule_set definitions present and pointing at SagerNet srs.
    const tags = (cfg.route.rule_set ?? []).map((rs: any) => rs.tag)
    expect(tags).toContain('geoip-ru')
    expect(tags).not.toContain('geosite-category-ru')
    expect(tags).toContain('geosite-category-gov-ru')
    for (const rs of cfg.route.rule_set) {
      expect(rs.type).toBe('remote')
      expect(rs.download_detour).toBe('proxy-out')
      expect(String(rs.url)).toMatch(/\.srs$/)
    }
    // cache_file enabled so srs persists across restarts.
    expect(cfg.experimental.cache_file?.enabled).toBe(true)
  })

  it('emits LOCAL rule-sets when a ruleSetDir is staged (no network at startup)', () => {
    // The IP-leak fix (finding F8): with the .srs bundled and staged, sing-box
    // loads them off disk so a slow/blocked GitHub fetch can never make the
    // core fail to start (which used to leak the real IP).
    const cfg = genSmart({ smartRuSplit: true, smartRuRuleSetDir: 'C:\\rt' })
    expect(Array.isArray(cfg.route.rule_set)).toBe(true)
    for (const rs of cfg.route.rule_set) {
      expect(rs.type).toBe('local')
      expect(rs.url).toBeUndefined()
      expect(rs.download_detour).toBeUndefined()
      expect(String(rs.path)).toMatch(/\.srs$/)
    }
  })

  it('routes RU domains and RU IPs to direct-out', () => {
    const cfg = genSmart({ smartRuSplit: true })
    const directRuleSetRules = cfg.route.rules.filter(
      (r: any) => r.rule_set && r.outbound === 'direct-out'
    )
    // One for the geosite domain lists, one for geoip-ru.
    expect(directRuleSetRules.length).toBeGreaterThanOrEqual(2)
    const hasGeoip = cfg.route.rules.some(
      (r: any) => r.rule_set === 'geoip-ru' && r.outbound === 'direct-out'
    )
    expect(hasGeoip).toBe(true)
  })

  it('binds RU domains to a direct DNS resolver (no CDN mismatch)', () => {
    const cfg = genSmart({ smartRuSplit: true })
    expect(cfg.dns.servers.find((s: any) => s.tag === 'dns-direct')).toBeTruthy()
    const dnsRule = (cfg.dns.rules ?? []).find(
      (r: any) => r.rule_set && r.server === 'dns-direct'
    )
    expect(dnsRule).toBeTruthy()
  })

  it('adds maps domains direct ONLY when mapsDirect is on', () => {
    const off = genSmart({ smartRuSplit: true, smartRuMapsDirect: false })
    const offHasMaps = off.route.rules.some(
      (r: any) => Array.isArray(r.domain_suffix) && r.domain_suffix.some((d: string) => d.includes('2gis'))
    )
    expect(offHasMaps).toBe(false)

    const on = genSmart({ smartRuSplit: true, smartRuMapsDirect: true })
    const onHasMaps = on.route.rules.some(
      (r: any) => Array.isArray(r.domain_suffix) && r.domain_suffix.some((d: string) => d.includes('2gis'))
    )
    expect(onHasMaps).toBe(true)
  })

  it('keeps user domain rules BEFORE the smart-route rules (user override wins)', () => {
    domainState.rules = [{ domain: ['bank.example'], outbound: 'proxy-out' }]
    const cfg = genSmart({ smartRuSplit: true })
    const idxUser = cfg.route.rules.findIndex((r: any) => Array.isArray(r.domain) && r.domain.includes('bank.example'))
    const idxSmart = cfg.route.rules.findIndex((r: any) => r.rule_set)
    expect(idxUser).toBeGreaterThanOrEqual(0)
    expect(idxSmart).toBeGreaterThan(idxUser)
  })
})
