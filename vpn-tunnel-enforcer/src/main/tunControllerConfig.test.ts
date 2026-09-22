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

import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'

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

import { mkdtempSync, writeFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { generateSingboxConfig, parseProxyAddress, readRecentSingBoxOutboundFault, isVpnOutboundUdpCapable, shouldBlockQuicUdp443 } from './tunController'

function repeatLine(line: string, n: number): string {
  return Array.from({ length: n }, () => line).join('\n')
}
const REALITY_LINE =
  '+0300 2026-09-02 10:54:31 ERROR [123 200ms] connection: open connection to 1.1.1.1:443 using outbound/vless[proxy-out]: reality verification failed'

// ─── Helpers ─────────────────────────────────────────────────────────────────

interface SingboxConfig {
  dns: { servers: Array<{ tag: string; type: string }>; final?: string }
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

describe('generateSingboxConfig runtime logging', () => {
  it('keeps Traffic History events at info without enabling debug-volume logs', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } }) as any

    expect(cfg.log).toMatchObject({ level: 'info', timestamp: true })
  })
})

describe('generateSingboxConfig TUN session lifetime', () => {
  it('rotates idle UDP flows so Windows DNS does not reuse stale sessions indefinitely', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    const tun = cfg.inbounds.find((inbound) => inbound.tag === 'tun-in')

    expect(tun?.udp_timeout).toBe('30s')
  })
})

// ─── DNS bootstrap ────────────────────────────────────────────────────────────

describe('generateSingboxConfig DNS bootstrap', () => {
  it('adds a bootstrap DNS server when the endpoint is a hostname', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: 'sub.example.com' } })
    const tags = cfg.dns.servers.map((s) => s.tag)
    expect(tags).toContain('dns-bootstrap')
  })

  it('uses direct UDP remote DNS bootstrap resolvers without invalid direct-out detours or local recursion', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: 'sub.example.com' } })
    const bootstrapServers = (cfg.dns.servers as any[]).filter((s) => String(s.tag).startsWith('dns-remote-bootstrap'))

    expect(bootstrapServers).toHaveLength(2)
    expect(bootstrapServers[0]).toMatchObject({ type: 'udp', server: '1.1.1.1' })
    expect(bootstrapServers[1]).toMatchObject({ type: 'udp', server: '8.8.8.8' })
    expect(bootstrapServers.every((s) => s.detour === undefined)).toBe(true)
  })

  it('sets dns.final to dns-remote so app DNS never falls through to bootstrap', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: 'sub.example.com' } })
    expect(cfg.dns.servers[0].tag).toBe('dns-remote-bootstrap')
    expect(cfg.dns.final).toBe('dns-remote')
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

  it('preserves multiplex for VLESS/Reality to mitigate TSPU Signal 3 parallel ClientHello blocking', () => {
    const cfg = gen({
      outbound: {
        ...realityOutbound,
        multiplex: { enabled: true, protocol: 'h2mux', padding: true }
      }
    })
    const out = cfg.outbounds.find((o) => o.tag === 'proxy-out')!
    expect(out.multiplex).toEqual({ enabled: true, protocol: 'h2mux', padding: true })
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
  it('blocks UDP/443 (QUIC) and public UDP for TCP-only VLESS profiles to prevent Twitch Error #2000', () => {
    // VLESS Reality without packet_encoding cannot carry UDP. Leaving UDP/443 unblocked causes
    // Twitch HLS streaming to blackhole and throw Error #2000 in Chromium/Yandex.
    for (const outbound of [realityOutbound, plainTlsOutbound]) {
      const cfg = gen({ outbound: { ...outbound } })
      const quicBlock = cfg.route.rules.some(
        (r) => r.network === 'udp' && r.port === 443 && r.action === 'reject'
      )
      const udpBlockAll = cfg.route.rules.some(
        (r) => r.network === 'udp' && r.action === 'reject' && r.port === undefined
      )
      expect(quicBlock).toBe(true)
      expect(udpBlockAll).toBe(true)
      expect(cfg.route.final).toBe('proxy-out')
    }
  })

  it('blocks UDP/443 (QUIC) for HTTP proxy mode', () => {
    const cfg = gen('127.0.0.1:8080', 'http')
    const quicBlock = cfg.route.rules.some(
      (r) => r.network === 'udp' && r.port === 443 && r.action === 'reject'
    )
    expect(quicBlock).toBe(true)
  })

  it('does not block UDP/443 (QUIC) or UDP for genuine UDP-capable directVpn outbounds (Hysteria2, VLESS with xudp)', () => {
    const hy2Outbound = {
      type: 'hysteria2',
      server: 'example.com',
      server_port: 443,
      password: 'pass'
    }
    const vlessXudpOutbound = {
      ...plainTlsOutbound,
      packet_encoding: 'xudp'
    }

    for (const outbound of [hy2Outbound, vlessXudpOutbound]) {
      const cfg = gen({ outbound: { ...outbound } })
      const quicBlock = cfg.route.rules.some(
        (r) => r.network === 'udp' && r.port === 443 && r.action === 'reject'
      )
      const udpBlockAll = cfg.route.rules.some(
        (r) => r.network === 'udp' && r.action === 'reject' && r.port === undefined
      )
      expect(quicBlock).toBe(false)
      expect(udpBlockAll).toBe(false)
      expect(cfg.route.final).toBe('proxy-out')
    }
  })

  it('correctly determines isVpnOutboundUdpCapable and shouldBlockQuicUdp443 across protocols', () => {
    expect(isVpnOutboundUdpCapable({ type: 'hysteria2' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'tuic' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'wireguard' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'shadowsocks' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'vless', packet_encoding: 'xudp' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'vless', packet_encoding: 'packetaddr' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'vless' })).toBe(false)
    expect(isVpnOutboundUdpCapable({ type: 'vless', tls: { reality: { enabled: true } } })).toBe(false)
    expect(isVpnOutboundUdpCapable({ type: 'vmess' })).toBe(false)
    expect(isVpnOutboundUdpCapable({ type: 'vmess', packet_encoding: 'xudp' })).toBe(true)
    expect(isVpnOutboundUdpCapable({ type: 'trojan' })).toBe(false)
    expect(isVpnOutboundUdpCapable({ type: 'http' })).toBe(false)
    expect(isVpnOutboundUdpCapable({ type: 'hysteria2', network: 'tcp' })).toBe(false)

    expect(shouldBlockQuicUdp443({ type: 'vless' }, 'socks5', true)).toBe(true)
    expect(shouldBlockQuicUdp443({ type: 'hysteria2' }, 'socks5', true)).toBe(false)
    expect(shouldBlockQuicUdp443({ type: 'vless', packet_encoding: 'xudp' }, 'socks5', true)).toBe(false)
    expect(shouldBlockQuicUdp443({ type: 'hysteria2' }, 'http', true)).toBe(true)
  })

  it('routes final traffic through proxy-out', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    expect(cfg.route.final).toBe('proxy-out')
  })
})

// ─── IPv4-only TUN (Happy Eyeballs stall fix) ────────────────────────────────

describe('generateSingboxConfig TUN is IPv4-only', () => {
  // Advertising IPv6 on the TUN made Windows tell apps "IPv6 is available";
  // Chrome/Yandex then tried YouTube/Google over IPv6 first, the WFP kill-switch
  // silently dropped those packets, and the browser waited the full Happy-Eyeballs
  // timeout (~5-10s) before falling back to IPv4 — the "YouTube hangs then springs
  // to life" symptom. The TUN must therefore expose no IPv6 at all.
  const tunOf = (cfg: SingboxConfig) => cfg.inbounds.find((i) => i.tag === 'tun-in')!

  it('does not assign an IPv6 address to the TUN', () => {
    const tun = tunOf(gen({ outbound: { ...realityOutbound } }))
    expect((tun.address as string[]).some((a) => a.includes(':'))).toBe(false)
  })

  it('does not capture IPv6 (no ::/1, 8000::/1) in route_address', () => {
    const tun = tunOf(gen({ outbound: { ...realityOutbound } }))
    expect((tun.route_address as string[]).some((a) => a.includes(':'))).toBe(false)
  })

  it('has no IPv6 reject rule (nothing to reject once IPv6 is not captured)', () => {
    const cfg = gen({ outbound: { ...realityOutbound } })
    const ipv6Reject = cfg.route.rules.some(
      (r) => Array.isArray(r.ip_cidr) && r.ip_cidr.includes('::/0') && r.action === 'reject'
    )
    expect(ipv6Reject).toBe(false)
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

  it('only adds the managed external proxy runtime to direct-out in directVpn mode', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound } })
    const directRule = cfg.route.rules.find(
      (r) => Array.isArray(r.process_name) && r.outbound === 'direct-out'
    ) as any

    expect(directRule).toBeTruthy()
    expect(directRule.process_name).toContain('vpnte-external-proxy.exe')
    expect(directRule.process_name).toContain('vpnte-xray.exe')
    expect(directRule.process_name).toHaveLength(2)
  })
})

// ─── DNS profile integration ──────────────────────────────────────────────────

describe('generateSingboxConfig DNS profile', () => {
  afterEach(() => {
    dnsState.active = null
  })

  it('uses Cloudflare/Google DoH fallback when no profile is active', () => {
    dnsState.active = null
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    const backup = cfg.dns.servers.find((s: any) => s.tag === 'dns-backup') as any
    expect(remote).toMatchObject({
      type: 'https',
      server: '1.1.1.1',
      path: '/dns-query',
      detour: 'proxy-out',
      tls: { server_name: 'cloudflare-dns.com' }
    })
    expect(backup).toMatchObject({
      type: 'https',
      server: '8.8.8.8',
      path: '/dns-query',
      detour: 'proxy-out',
      tls: { server_name: 'dns.google' }
    })
  })

  it('applies a plain DNS profile as tcp servers through proxy-out', () => {
    dnsState.active = { id: 'x', name: 'Quad9', primary: '9.9.9.9', secondary: '149.112.112.112', type: 'plain' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const servers = cfg.dns.servers as any[]
    const remote = servers.find((s) => s.tag === 'dns-remote')
    const backup = servers.find((s) => s.tag === 'dns-backup')
    expect(remote).toMatchObject({ type: 'tcp', server: '9.9.9.9', detour: 'proxy-out' })
    expect(backup).toMatchObject({ type: 'tcp', server: '149.112.112.112', detour: 'proxy-out' })
  })

  it('applies a DoH profile as https server mapping known hostnames to IP literals with SNI', () => {
    dnsState.active = { id: 'x', name: 'DoH', primary: 'https://dns.google:443/dns-query', type: 'doh' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote).toMatchObject({
      type: 'https',
      server: '8.8.8.8',
      path: '/dns-query',
      detour: 'proxy-out',
      tls: { server_name: 'dns.google' }
    })
  })

  it('applies a custom DoH profile preserving host, path, port and SNI', () => {
    dnsState.active = { id: 'x', name: 'CustomDoH', primary: 'https://custom-dns.example.com:443/dns-query', type: 'doh' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote).toMatchObject({
      type: 'https',
      server: 'custom-dns.example.com',
      path: '/dns-query',
      detour: 'proxy-out',
      tls: { server_name: 'custom-dns.example.com' }
    })
  })

  it('applies a DoT profile as tls server preserving host, port and SNI', () => {
    dnsState.active = { id: 'x', name: 'DoT', primary: 'tls://dns.google:853', type: 'dot' }
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const remote = cfg.dns.servers.find((s: any) => s.tag === 'dns-remote') as any
    expect(remote).toMatchObject({
      type: 'tls',
      server: 'dns.google',
      server_port: 853,
      detour: 'proxy-out',
      tls: { server_name: 'dns.google' }
    })
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

  it('injects domain rules into route.rules after hijack-dns', () => {
    domainState.rules = [{ outbound: 'block-out', domain: ['ads.example.com'] }]
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const rules = cfg.route.rules
    const hijackIdx = rules.findIndex((r) => r.action === 'hijack-dns')
    const domainIdx = rules.findIndex((r) => Array.isArray(r.domain) && r.domain.includes('ads.example.com'))
    expect(domainIdx).toBeGreaterThan(hijackIdx)
    expect(rules[domainIdx].outbound).toBe('block-out')
  })

  it('prevents DNS bypass on tethering by omitting RFC1918 from route_exclude_address and placing ip_is_private after hijack-dns', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '1.2.3.4' } })
    const tunInbound: any = cfg.inbounds.find((i: any) => i.type === 'tun')
    expect(tunInbound).toBeTruthy()
    expect(tunInbound.route_exclude_address).toBeDefined()
    expect(tunInbound.route_exclude_address).toContain('127.0.0.0/8')
    expect(tunInbound.route_exclude_address).not.toContain('192.168.0.0/16')
    expect(tunInbound.route_exclude_address).not.toContain('172.16.0.0/12')
    expect(tunInbound.route_exclude_address).not.toContain('10.0.0.0/8')

    const rules = cfg.route.rules
    const hijackIdx = rules.findIndex((r: any) => r.protocol === 'dns' && r.action === 'hijack-dns')
    const privateIdx = rules.findIndex((r: any) => r.ip_is_private === true && r.outbound === 'direct-out')
    expect(hijackIdx).toBeGreaterThanOrEqual(0)
    expect(privateIdx).toBeGreaterThan(hijackIdx)
  })

  it('excludes the direct VPN server IP from TUN auto-route so the tunnel can dial its endpoint', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: '91.224.75.185' } })
    const tunInbound: any = cfg.inbounds.find((i: any) => i.type === 'tun')
    expect(tunInbound.route_exclude_address).toContain('91.224.75.185/32')
  })

  it('does not add a hostname VPN endpoint to route_exclude_address', () => {
    const cfg = gen({ outbound: { ...plainTlsOutbound, server: 'example.com' } })
    const tunInbound: any = cfg.inbounds.find((i: any) => i.type === 'tun')
    expect(tunInbound.route_exclude_address).not.toContain('example.com/32')
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
    const offHasMapsProxy = off.route.rules.some(
      (r: any) => Array.isArray(r.domain_suffix) && r.domain_suffix.some((d: string) => d.includes('2gis')) && r.outbound === 'proxy-out'
    )
    expect(offHasMapsProxy).toBe(true)

    const on = genSmart({ smartRuSplit: true, smartRuMapsDirect: true })
    const onHasMapsDirect = on.route.rules.some(
      (r: any) => Array.isArray(r.domain_suffix) && r.domain_suffix.some((d: string) => d.includes('2gis')) && r.outbound === 'direct-out'
    )
    expect(onHasMapsDirect).toBe(true)
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

// ─── sing-box outbound fault reader ─────────────────────────────────────────

describe('readRecentSingBoxOutboundFault', () => {
  let dir: string
  const write = (content: string): string => {
    const p = join(dir, 'sing-box.log')
    writeFileSync(p, content, 'utf8')
    return p
  }

  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vpnte-fault-')) })
  afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

  it('flags a repeated REALITY verification failure', async () => {
    expect(await readRecentSingBoxOutboundFault(write(repeatLine(REALITY_LINE, 5)))).toBe('reality-key-mismatch')
  })

  it('ignores a single transient REALITY error during startup', async () => {
    const log = [
      '+0300 2026-09-02 10:54:30 INFO sing-box started (0.40s)',
      REALITY_LINE,
      '+0300 2026-09-02 10:54:40 INFO [999 20ms] outbound/vless[proxy-out]: outbound connection to www.gstatic.com:443'
    ].join('\n')
    expect(await readRecentSingBoxOutboundFault(write(log))).toBeNull()
  })

  it('flags a repeated TLS handshake failure', async () => {
    const line = '+0300 2026-09-02 10:54:31 ERROR [1 100ms] connection: open connection to proxy-out: remote error: tls: handshake failure'
    expect(await readRecentSingBoxOutboundFault(write(repeatLine(line, 4)))).toBe('tls-handshake-failed')
  })

  it('flags a repeatedly unreachable upstream', async () => {
    const line = '+0300 2026-09-02 10:54:31 ERROR [1 4s] connection: dial tcp 203.0.113.7:443: i/o timeout'
    expect(await readRecentSingBoxOutboundFault(write(repeatLine(line, 3)))).toBe('upstream-unreachable')
  })

  it('returns null when the log is clean', async () => {
    expect(await readRecentSingBoxOutboundFault(write('+0300 2026-09-02 10:54:31 INFO sing-box started (0.40s)'))).toBeNull()
  })

  it('returns null when the log file does not exist', async () => {
    expect(await readRecentSingBoxOutboundFault(join(dir, 'nope.log'))).toBeNull()
  })
})

describe('generateSingboxConfig with xraySocksPort', () => {
  it('configures proxy-out as SOCKS5 127.0.0.1:xraySocksPort and excludes real remote IP from TUN', () => {
    const upstream = {
      outbound: {
        type: 'vless',
        server: '185.100.100.1',
        server_port: 443,
        uuid: 'abc'
      }
    }
    const cfg: any = generateSingboxConfig(upstream, 'socks5', [], {
      xraySocksPort: 25555,
      resolvedVpnEndpointIp: '185.100.100.1'
    })

    const proxyOut = cfg.outbounds.find((o: any) => o.tag === 'proxy-out')
    expect(proxyOut).toBeDefined()
    expect(proxyOut.type).toBe('socks')
    expect(proxyOut.server).toBe('127.0.0.1')
    expect(proxyOut.server_port).toBe(25555)
    expect(proxyOut.version).toBe('5')
    expect(proxyOut.udp_fragment).toBe(true)

    const tunIn = cfg.inbounds.find((i: any) => i.type === 'tun')
    expect(tunIn.route_exclude_address).toContain('185.100.100.1/32')
    expect(tunIn.route_exclude_address).not.toContain('127.0.0.1/32')
  })

  it('includes directProcessNames in direct-out route rules in directVpn mode', () => {
    const upstream = {
      outbound: {
        type: 'vless',
        server: '185.100.100.1',
        server_port: 443,
        uuid: 'abc'
      }
    }
    const cfg: any = generateSingboxConfig(upstream, 'socks5', ['custom-app.exe'], {})
    const directRule = cfg.route.rules.find((r: any) => r.outbound === 'direct-out' && Array.isArray(r.process_name))
    expect(directRule).toBeDefined()
    expect(directRule.process_name).toContain('custom-app.exe')
  })

  it('sets udp_fragment: true on SOCKS outbound in localProxy (Happ) mode', () => {
    const cfg: any = generateSingboxConfig('127.0.0.1:10808', 'socks5', [], {})
    const proxyOut = cfg.outbounds.find((o: any) => o.tag === 'proxy-out')
    expect(proxyOut).toMatchObject({
      type: 'socks',
      server: '127.0.0.1',
      server_port: 10808,
      udp_fragment: true
    })
  })
})

