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
vi.mock('./dnsProfiles', () => ({
  dnsProfiles: {
    getActiveDnsProfile: () => dnsState.active
  }
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

  it('uses Cloudflare/Google fallback when no profile is active', () => {
    dnsState.active = null
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote.server).toBe('1.1.1.1')
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
