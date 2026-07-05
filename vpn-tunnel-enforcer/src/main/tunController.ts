import { exec as execCb, execFile as execFileCb } from 'child_process'
import { writeFile, mkdir, copyFile, access, rename, stat } from 'fs/promises'
import { join, dirname } from 'path'
import { promisify } from 'util'
import { createConnection, createServer, isIP } from 'net'
import { networkInterfaces } from 'os'
import { app } from 'electron'
import sudo from 'sudo-prompt'
import { execElevated, isProcessElevated } from './admin'
import { logEvent } from './appLogger'
import { rollbackTunNetworkBaselineIfApplied } from './systemNetwork'
import { settingsStore } from './settings'
import { notify } from './notifications'
import {
  disableKillSwitch,
  disableKillSwitchIfActive,
  enableKillSwitch,
  isKillSwitchActive
} from './firewallKillSwitch'
import {
  applyPhysicalAdapterLockdown,
  getPhysicalAdapterDnsSources,
  repairOrphanedPhysicalAdapterDns,
  rollbackPhysicalAdapterLockdownIfApplied
} from './physicalAdapterLockdown'
import {
  clientFingerprintForDevice,
  normalizeClientDevice,
  type VpnProfile
} from './vpnProfiles'
import type { ClientDevice } from '../shared/ipc-types'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_ADDRESS_CIDR, TUN_IPV4_RESOLVER, TUN_INTERFACE_METRIC, isOwnTunAddress, ALL_KNOWN_ALIASES } from './tunAdapter'
import { ipMonitor } from './ipMonitor'
import { cancelLeakSelfTest } from './leakSelfTest'
import { startCompetingTunWatch, stopCompetingTunWatch } from './competingTunDetector'
import { dnsProfiles } from './dnsProfiles'
import { granularKillSwitchStore, serverPickerStore, serverGroupsStore } from './sharedStores'
import { generateDomainRouteRules } from './domainRouting'
import {
  smartRouteRules,
  smartRouteRuleSets,
  smartRouteDnsRules,
  smartRouteLocalRuleSetFiles,
  type SmartRouteOptions
} from './smartRoute'
import { getPreferredSmartRouteRuleSetSourceDir } from './ruleSetManager'
import { selectTunMtu } from './networkCompatibility'
import type { PhysicalAdapterDnsSource } from './physicalAdapterLockdown'

const exec = promisify(execCb)
const execFile = promisify(execFileCb)

function recordForensicTunEvent(event: string, details: Record<string, unknown> = {}): void {
  import('./trafficForensics')
    .then(({ recordTrafficForensicsAppEvent }) => recordTrafficForensicsAppEvent({
      source: 'tun',
      event,
      details
    }))
    .catch(() => undefined)
}

export interface TunStatus {
  running: boolean
  mode?: 'localProxy' | 'directVpn'
  proxyAddr: string | null
  proxyType: 'socks5' | 'http' | null
  vpnProfileName?: string | null
  vpnProtocol?: string | null
  pid: number | null
  warning?: string | null
  proxyReachable?: boolean
  // Wall-clock ms since the current TUN run started (null when not running).
  // Used by the renderer for the "uptime" pill on the hero card.
  startedAt?: number | null
  // Tracks consecutive auto-restart attempts after an unexpected sing-box
  // crash. 0 when TUN is up and stable; goes 1..N during recovery; resets to
  // 0 once the new run survives the stabilisation window.
  restartAttempt?: number
}

interface StartOptions {
  mode?: 'localProxy' | 'directVpn'
  proxyAddr?: string
  proxyType?: 'socks5' | 'http'
  vpnProfile?: VpnProfile
  // Requested legacy Windows Firewall kill-switch. Currently ignored in start()
  // because broad physical-adapter block rules also block the VPN core itself.
  enableFirewallKillSwitch?: boolean
  // When true, also disable IPv6 + force IPv4 DNS to TUN's resolver on every
  // physical adapter. This modifies adapter-level network settings and catches
  // leaks from apps that bring their own DNS-over-HTTPS or that prefer IPv6
  // default routes (e.g. Yandex Browser). Reverted on stop.
  enableAdapterLockdown?: boolean
  // Keep DHCP/public-Wi-Fi DNS on the physical adapter instead of forcing it to
  // VPNTE-TUN. This avoids captive-portal/Windows "no internet" false positives.
  publicWifiCompatibility?: boolean
  // Anti-DPI mitigations (TSPU bypass): MTU 1280 in TUN inbound and TLS
  // record-fragment in non-Reality outbounds. Read from settings on every
  // start so toggling the UI immediately takes effect on the next restart.
  stealthMode?: boolean
}

// Localhost clash-API state. Populated when sing-box starts; cleared on
// stop. Used by url-availability checks (and any future "test through a
// specific outbound" caller) to issue /proxies/<tag>/delay queries without
// having to spawn another sing-box.
let clashApiInfo: { port: number; secret: string } | null = null

let directProxyPort: number | null = null;

export function getDirectProxyPort(): number | null {
  return directProxyPort;
}

export function getClashApiInfo(): { port: number; secret: string } | null {
  return clashApiInfo
}

function randomLocalPort(): number {
  // We bind to 127.0.0.1 only and require a secret, so picking a random
  // ephemeral-range port is enough. 49152-65535 is the IANA private range
  // and unlikely to collide with anything mainstream the user has running.
  return 49152 + Math.floor(Math.random() * (65535 - 49152))
}

// Ask the OS for a port we can actually bind to right now. Windows reserves
// chunks of the ephemeral range for Hyper-V/WSL/containers (the "excluded
// port range"); a randomly-picked port can land inside one of those and
// sing-box then fails to bind with WSAEACCES ("An attempt was made to access
// a socket in a way forbidden"). createServer().listen(0) makes the OS hand
// back a port from outside any excluded range, which is the cheapest reliable
// signal that the port is bindable from user-space. We close immediately —
// there is a tiny TOCTOU window between close and sing-box's bind, but in
// practice the OS does not hand the same port to a second listener that fast.
export function pickFreeLocalPort(exclude: number[] = []): Promise<number> {
  const excludeSet = new Set(exclude)
  const tryOnce = (): Promise<number> => new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', (err) => {
      try { server.close() } catch { /* ignore */ }
      reject(err)
    })
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      const port = addr && typeof addr === 'object' ? addr.port : 0
      server.close(() => {
        if (port > 0) resolve(port)
        else reject(new Error('createServer returned no port'))
      })
    })
  })

  return (async () => {
    let lastErr: unknown = null
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const port = await tryOnce()
        if (!excludeSet.has(port)) return port
      } catch (err) {
        lastErr = err
      }
    }
    if (lastErr) throw lastErr
    // All 5 attempts collided with the exclude list — fall back to a random
    // port outside the excluded set. Astronomically unlikely, but we bias
    // toward returning *something* over throwing.
    let fallback = randomLocalPort()
    while (excludeSet.has(fallback)) fallback = randomLocalPort()
    return fallback
  })()
}

function randomSecret(): string {
  // 32 hex chars = 128 bits. Generated per run; never persisted. Use the CSPRNG
  // (crypto.randomBytes) rather than Math.random: this token gates the local
  // clash_api controller, and Math.random is predictable enough that a hostile
  // local process could feasibly guess it. crypto is cheap and removes all doubt.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { randomBytes } = require('crypto') as typeof import('crypto')
    return randomBytes(16).toString('hex')
  } catch {
    // Fallback only if crypto is somehow unavailable (never on Electron/Node).
    const bytes = new Uint8Array(16)
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256)
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
  }
}
let currentStatus: TunStatus = {
  running: false,
  mode: 'localProxy',
  proxyAddr: null,
  proxyType: null,
  vpnProfileName: null,
  vpnProtocol: null,
  pid: null,
  warning: null,
  proxyReachable: true,
  startedAt: null,
  restartAttempt: 0
}
let statusCallbacks: ((status: string) => void)[] = []
let watchdogTimer: ReturnType<typeof setInterval> | null = null
let watchdogFailures = 0
let startInProgress = false
let stopInProgress = false
const DIRECT_VPN_WATCHDOG_SUPPRESS_MS = 45000

// Auto-restart bookkeeping. We remember the last successful start params so we
// can replay them after an unexpected sing-box crash without asking the user.
// Cleared on a user-initiated stop so we don't try to "recover" from a
// deliberate shutdown.
let lastStartOptions: StartOptions | null = null
let restartAttempt = 0
let restartTimer: ReturnType<typeof setTimeout> | null = null
let stableTimer: ReturnType<typeof setTimeout> | null = null
let recoveryCancelGeneration = 0
// Set to true while inside `stop()` (and right after `start()` returns failure)
// so the onExit handler doesn't kick off a recovery loop.
let userInitiatedStop = false
const RESTART_BACKOFF_MS = [2000, 5000, 10000] as const
const STABLE_RESET_MS = 30000

// Post-trial auto-failover: when sing-box can't keep the active key alive
// AND that key belongs to an "expired" group (subscription panel is gone
// but the keys themselves may still work for a while), we try the next live
// key in the same group instead of just disengaging the kill-switch. The
// flag prevents two concurrent failover attempts from stomping each other
// when, for example, watchdog and onExit both notice the death.
let postTrialFailoverInProgress = false


function clearRestartTimers() {
  if (restartTimer) {
    clearTimeout(restartTimer)
    restartTimer = null
  }
  if (stableTimer) {
    clearTimeout(stableTimer)
    stableTimer = null
  }
}

const RUNTIME_EXE_NAME = 'vpnte-sing-box.exe'
const CRONET_DLL_NAME = 'libcronet.dll'
const PROXY_CORE_PROCESS_NAMES = [
  // Happ
  'Happ.exe',
  'happd.exe',
  // Xray / V2Ray
  'xray.exe',
  'v2ray.exe',
  'v2rayN.exe',
  // sing-box
  'sing-box.exe',
  'singbox.exe',
  'sing-tun.exe',
  // Clash family
  'mihomo.exe',
  'clash.exe',
  'clash-meta.exe',
  'clash-verge.exe',
  'clash-verge-service.exe',
  'flclash.exe',
  'FlClash.exe',
  'mihomo-party.exe',
  'verge-mihomo.exe',
  // Hiddify
  'hiddify.exe',
  'Hiddify.exe',
  'HiddifyN.exe',
  // NekoRay / NekoBox
  'nekoray.exe',
  'nekobox.exe',
  // Shadowsocks
  'shadowsocks.exe',
  'ss-local.exe',
  'shadowsocks-rust.exe',
  // Trojan
  'trojan.exe',
  // Outline
  'outline.exe',
  'Outline.exe',
  // WireGuard / OpenVPN
  'wireguard.exe',
  'openvpn.exe',
  // Karing
  'karing.exe',
  // Streisand
  'streisand.exe',
  // Surfboard
  'surfboard.exe',
]

export function getTunRuntimeDir(): string {
  return join(app.getPath('userData'), 'tun-runtime')
}

export function getBundledResource(name: string): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, name)
  }
  return join(app.getAppPath(), 'resources', name)
}

// Cheap "did the source change?" check for sing-box.exe (~30 MB) and wintun.dll.
// Both binaries live in app-resources and only change when the user installs a
// new app build, so on 99% of restarts they are byte-identical to the copy
// already sitting under userData/tun-runtime. Stat-based comparison (mtime+size)
// matches the heuristic Node uses for its own dependency-cache invalidation
// and is good enough — when in doubt we still fall back to a plain copyFile,
// so we can never end up with no destination file.
async function copyResourceIfStale(src: string, dst: string): Promise<boolean> {
  try {
    const [srcStat, dstStat] = await Promise.all([stat(src), stat(dst)])
    if (
      dstStat.size === srcStat.size &&
      dstStat.mtimeMs === srcStat.mtimeMs
    ) {
      return false
    }
  } catch {
    // dst doesn't exist, stat failed, or anything else odd — fall through to
    // the unconditional copyFile path below, which is the same behaviour we
    // had before this helper existed. We never want to silently skip the copy
    // and leave a stale (or missing) binary in the runtime dir.
  }
  await copyFile(src, dst)
  return true
}

export function parseProxyAddress(proxyAddr: string): { host: string; port: number } {
  const trimmed = proxyAddr.trim()
  const ipv6Match = trimmed.match(/^\[([^\]]+)]:(\d+)$/)
  if (ipv6Match) {
    const port = parseInt(ipv6Match[2], 10)
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error(`Некорректный порт прокси: ${ipv6Match[2]}`)
    }
    return { host: ipv6Match[1], port }
  }

  const separator = trimmed.lastIndexOf(':')
  if (separator <= 0 || separator === trimmed.length - 1) {
    throw new Error('Адрес прокси должен быть в формате host:port')
  }

  const host = trimmed.slice(0, separator).trim()
  const port = parseInt(trimmed.slice(separator + 1), 10)
  if (!host) throw new Error('Не указан host прокси')
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Некорректный порт прокси: ${trimmed.slice(separator + 1)}`)
  }
  return { host, port }
}

function normalizeProcessName(name: string): string | null {
  const trimmed = name.trim()
  if (!trimmed) return null
  return trimmed.toLowerCase().endsWith('.exe') ? trimmed : `${trimmed}.exe`
}

function uniqueProcessNames(names: string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const raw of names) {
    const name = normalizeProcessName(raw)
    if (!name) continue
    const key = name.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    result.push(name)
  }
  return result
}

/**
 * Thin wrapper over domainRouting.generateDomainRouteRules so a failure in the
 * domain-routing store can never break tunnel startup — we'd rather start the
 * tunnel without the user's domain rules than not start at all.
 */
function buildDomainRouteRules(): Array<Record<string, any>> {
  try {
    return generateDomainRouteRules()
  } catch (err) {
    logEvent('warn', 'tun', 'failed to build domain route rules — starting without them', err)
    return []
  }
}

const DNS_STRATEGY = 'ipv4_only'
const BOOTSTRAP_DNS_TAG = 'dns-bootstrap'
const REMOTE_DNS_TAG = 'dns-remote'
const REMOTE_DNS_BACKUP_TAG = 'dns-backup'
// DNS server tag for the direct (RU-visible) resolver used by smart RU split.
const SMART_DIRECT_DNS_TAG = 'dns-direct'

function uniqueNonEmpty(values: Array<string | null | undefined>): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const value of values) {
    const normalized = String(value ?? '').trim()
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
  }
  return out
}

function maybeServerPort(port: number | null | undefined): Record<string, number> {
  return port && Number.isInteger(port) && port > 0 && port <= 65535
    ? { server_port: port }
    : {}
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']')
    ? host.slice(1, -1)
    : host
}

function parseDnsUrl(raw: string, scheme: 'https' | 'tls'): { host: string; port: number | null; path?: string } | null {
  try {
    const normalized = scheme === 'tls'
      ? raw.replace(/^tls:\/\//i, 'https://')
      : raw
    const url = new URL(normalized)
    if (url.protocol !== 'https:') return null
    const host = stripIpv6Brackets(url.hostname)
    if (!host) return null
    const port = url.port ? Number(url.port) : null
    return {
      host,
      port: Number.isInteger(port) ? port : null,
      ...(scheme === 'https'
        ? { path: url.pathname && url.pathname !== '/' ? url.pathname : '/dns-query' }
        : {})
    }
  } catch {
    return null
  }
}

function tlsServerNameFor(host: string): Record<string, any> | undefined {
  return isIP(stripIpv6Brackets(host)) === 0
    ? { server_name: host }
    : undefined
}

function buildDohServer(
  tag: string,
  server: string,
  options: { path?: string; port?: number | null; serverName?: string } = {}
): Record<string, any> {
  const tls = options.serverName
    ? { server_name: options.serverName }
    : tlsServerNameFor(server)
  return {
    type: 'https',
    tag,
    server,
    ...maybeServerPort(options.port ?? null),
    path: options.path || '/dns-query',
    detour: 'proxy-out',
    ...(tls ? { tls } : {})
  }
}

/**
 * Build the remote DNS server list for the sing-box config from the user's
 * active DNS profile (Settings → DNS). Falls back to Cloudflare + Google when
 * no profile is selected. Every server detours through `proxy-out` so DNS is
 * tunnelled and never leaks to the ISP resolver.
 *
 * The first server MUST keep the tag `dns-remote` because the route block's
 * `default_domain_resolver` references it by name.
 *
 * Default fallback is DoH-over-HTTPS through `proxy-out`, not UDP/53. Field
 * diagnostics showed TCP over the VLESS/Reality tunnel still worked while DNS
 * timed out, so the default DNS path must not depend on VLESS UDP/XUDP health.
 * User-selected plain DNS profiles are sent as TCP/53 through the tunnel for
 * the same reason; user-selected DoH/DoT profiles keep their chosen transport.
 *
 * sing-box 1.13 server types:
 *   - plain IP  → { type: 'tcp', server: '1.1.1.1' }
 *   - DoH       → { type: 'https', server: 'dns.google', ... }
 *   - DoT       → { type: 'tls', server: 'dns.google', ... }
 *
 * We read the profile defensively via a dynamic import of dnsProfiles to avoid
 * any load-order coupling, falling back to the hardcoded resolvers on any
 * error so a bad profile can never break tunnel startup.
 */
function buildRemoteDnsServers(): Array<Record<string, any>> {
  const fallback = [
    buildDohServer(REMOTE_DNS_TAG, 'cloudflare-dns.com'),
    buildDohServer(REMOTE_DNS_BACKUP_TAG, 'dns.google')
  ]
  try {
    const profile = dnsProfiles.getActiveDnsProfile()
    if (!profile || !profile.primary) return fallback

    const toServer = (address: string, tag: string): Record<string, any> | null => {
      const addr = String(address || '').trim()
      if (!addr) return null
      if (profile.type === 'doh') {
        const parsed = parseDnsUrl(addr, 'https')
        if (!parsed) return null
        return buildDohServer(tag, parsed.host, {
          path: parsed.path,
          port: parsed.port,
          serverName: isIP(parsed.host) === 0 ? parsed.host : undefined
        })
      }
      if (profile.type === 'dot') {
        const parsed = parseDnsUrl(addr, 'tls')
        if (!parsed) return null
        const tls = tlsServerNameFor(parsed.host)
        return {
          type: 'tls',
          tag,
          server: parsed.host,
          ...maybeServerPort(parsed.port),
          detour: 'proxy-out',
          ...(tls ? { tls } : {})
        }
      }
      return { type: 'tcp', tag, server: addr, detour: 'proxy-out' }
    }

    const servers: Array<Record<string, any>> = []
    const primary = toServer(profile.primary, REMOTE_DNS_TAG)
    if (!primary) return fallback
    servers.push(primary)
    if (profile.secondary) {
      const secondary = toServer(profile.secondary, REMOTE_DNS_BACKUP_TAG)
      if (secondary) servers.push(secondary)
    }
    return servers
  } catch {
    return fallback
  }
}

function buildDnsBootstrapServers(): Array<Record<string, any>> {
  return [
    { type: 'udp', tag: 'dns-remote-bootstrap', server: '1.1.1.1' },
    { type: 'udp', tag: 'dns-remote-bootstrap-backup', server: '8.8.8.8' }
  ]
}

function buildSmartDirectDnsServers(
  sources: PhysicalAdapterDnsSource[] | undefined,
  tag = SMART_DIRECT_DNS_TAG
): Array<Record<string, any>> {
  const upstreams = uniqueNonEmpty(
    (sources ?? []).flatMap((source) => source.ipv4DnsServers)
  )
  if (upstreams.length === 0) return [{ type: 'dhcp', tag }]
  return upstreams.map((server, index) => ({
    type: 'udp',
    tag: index === 0 ? tag : `${tag}-${index + 1}`,
    server
  }))
}

function isDomainServer(server: unknown): boolean {
  if (typeof server !== 'string') return false
  const trimmed = server.trim()
  if (!trimmed) return false
  const unbracketed = trimmed.startsWith('[') && trimmed.endsWith(']')
    ? trimmed.slice(1, -1)
    : trimmed
  return isIP(unbracketed) === 0
}

export function sanitizeProxyOutbound(outbound: Record<string, any>): { outbound: Record<string, any>; needsBootstrapDns: boolean } {
  const result = JSON.parse(JSON.stringify(outbound))
  const legacyStrategy = typeof result.domain_strategy === 'string' && result.domain_strategy.trim()
    ? result.domain_strategy.trim()
    : null
  const existingStrategy =
    result.domain_resolver &&
      typeof result.domain_resolver === 'object' &&
      typeof result.domain_resolver.strategy === 'string' &&
      result.domain_resolver.strategy.trim()
      ? result.domain_resolver.strategy.trim()
      : null

  delete result.domain_strategy
  delete result.domain_resolver

  // Strip multiplexing. Some panels ship `multiplex: { enabled: true }` (or
  // the legacy `mux`) in the outbound. Under modern DPI this is actively
  // harmful: muxing several logical streams over one connection makes the
  // flow's size/timing pattern more distinguishable, and it breaks Reality's
  // per-connection camouflage (Reality authenticates each ClientHello against
  // a real site — one long-lived muxed connection defeats that). We never
  // benefit from it on a single-user client, so remove it unconditionally.
  if (result.multiplex !== undefined) delete result.multiplex
  if (result.mux !== undefined) delete result.mux

  const outboundType = String(result.type || '').toLowerCase()

  if ((outboundType === 'vless' || outboundType === 'vmess') && result.network === 'tcp') {
    // Imported VLESS/VMess profiles can carry a stale tcp-only marker from
    // older builds even when the source profile never requested it. Keeping
    // that marker makes directVpn install QUIC/UDP guards and reproduces the
    // long browser fallback stalls seen in diagnostics.
    delete result.network
  }

  if (outboundType === 'hysteria2') {
    // Hysteria2 is QUIC-based. Older imports saved `network: "tcp"` because
    // other TLS protocols were tcp-only; keeping it here makes our UDP guard
    // block the very transport HY2 needs.
    if (result.network === 'tcp') delete result.network

    // sing-box 1.13 accepts salamander obfs and port hopping, but not the 1.14
    // HY2 additions such as gecko/realm/bbr_profile/packet-size knobs. Strip
    // unsupported fields at runtime so an imported future-profile cannot make
    // the whole tunnel fail at `sing-box check`.
    if (result.obfs && typeof result.obfs === 'object') {
      if (String(result.obfs.type || '').toLowerCase() === 'gecko') {
        delete result.obfs
      } else {
        delete result.obfs.min_packet_size
        delete result.obfs.max_packet_size
      }
    }
    delete result.hop_interval_max
    delete result.realm
    delete result.bbr_profile
    delete result.min_packet_size
    delete result.max_packet_size

    if (result.server_ports !== undefined) {
      const serverPorts = normalizeHysteria2ServerPortsForSingbox(result.server_ports)
      if (serverPorts) result.server_ports = serverPorts
      else delete result.server_ports
    }
    if (typeof result.server_ports === 'string' && result.server_ports.trim()) {
      delete result.server_port
    }
  }

  const needsBootstrapDns = isDomainServer(result.server)
  if (needsBootstrapDns) {
    result.domain_resolver = {
      server: BOOTSTRAP_DNS_TAG,
      strategy: existingStrategy || legacyStrategy || DNS_STRATEGY
    }
  }

  return { outbound: result, needsBootstrapDns }
}

function normalizeHysteria2ServerPortsForSingbox(value: unknown): string | null {
  if (Array.isArray(value) && value.length > 0) {
    return normalizeHysteria2ServerPortsForSingbox(value[0])
  }
  if (typeof value !== 'string') return null
  const match = value.trim().match(/^(\d{1,5})\s*[-:]\s*(\d{1,5})$/)
  if (!match) return null
  const start = Number(match[1])
  const end = Number(match[2])
  if (!Number.isInteger(start) || !Number.isInteger(end) || start <= 0 || end <= 0 || start > 65535 || end > 65535 || end < start) {
    return null
  }
  return `${start}:${end}`
}

function isTcpOnlyNetworkOutbound(outbound: Record<string, any>): boolean {
  const type = String(outbound.type || '').toLowerCase()
  if (type === 'hysteria2' || type === 'tuic') return false
  return typeof outbound.network === 'string' && outbound.network === 'tcp'
}

function shouldBlockQuicUdp443(
  proxyOutbound: Record<string, any>,
  proxyType: 'socks5' | 'http',
  isDirectVpn: boolean
): boolean {
  if (proxyType === 'http') return true
  if (isDirectVpn) {
    // For a native TUN tunnel (directVpn) we carry QUIC through the proxy
    // instead of rejecting UDP/443. Rejecting it does NOT make Chromium fail
    // over to TCP quickly: because of cached Alt-Svc (h3) advertisements and
    // QUIC connection timeouts, the browser stalls ~5–10s before falling back
    // — exactly the "YouTube hangs then springs to life" symptom, and it also
    // breaks HTTP/3-heavy flows like speedtest.net's server discovery.
    //
    // Letting UDP/443 ride the tunnel is never worse than rejecting it: if the
    // upstream relays UDP (standard for Xray/sing-box VLESS/VMess/Trojan/SS)
    // HTTP/3 works natively with no stall; if it does not, the browser falls
    // back to TCP just as it does today. Hysteria2/TUIC are native-UDP and
    // already carry QUIC, so they were never blocked here either.
    return false
  }
  // Local proxy mode always forwards the captured traffic into a loopback
  // SOCKS/HTTP hop that ultimately rides whatever upstream transport the app
  // selected. In practice Chromium will happily keep retrying HTTP/3 over
  // UDP/443 when that chain cannot carry QUIC reliably, which surfaces as
  // ERR_CONNECTION_CLOSED / stalled first loads on arbitrary sites.
  //
  // Block only UDP/443 here (not all UDP) so browsers fail fast on QUIC and
  // immediately fall back to TCP TLS, while non-browser UDP traffic on other
  // ports keeps its previous behaviour.
  return true
}

export function generateSingboxConfig(
  upstream: string | { outbound: Record<string, any>; proxyType?: 'socks5' | 'http'; clientDevice?: ClientDevice },
  proxyType: 'socks5' | 'http' = 'socks5',
  directProcessNames: string[] = [],
  options: {
    stealthMode?: boolean
    publicWifiCompatibility?: boolean
    directProxyPortOverride?: number
    clashPortOverride?: number
    smartRuSplit?: boolean
    smartRuMapsDirect?: boolean
    smartRuRuleSetDir?: string
    smartRuDirectDnsSources?: PhysicalAdapterDnsSource[]
  } = {}
): object {
  // Network-compatibility knobs adjust the TUN MTU:
  //   1. publicWifiCompatibility uses a safer 1380-byte MTU, which is much
  //      more tolerant of mobile-hotspot / public-Wi-Fi PMTU blackholes where
  //      some HTTPS sites stall on the first large TLS packets.
  //   2. stealthMode goes further down to 1280 so encrypted payload sizes
  //      drift away from values DPI signature databases pattern-match for VPN
  //      traffic, and 1280 is the IPv6-min-MTU floor so it always negotiates
  //      cleanly.
  //   2. tls.record_fragment on the proxy outbound (when the outbound has
  //      regular TLS, NOT Reality — Reality has its own ClientHello
  //      mimicry and fragmenting on top can break the auth handshake).
  //      record_fragment is the cheaper of the two TLS fragmenting modes
  //      offered by sing-box 1.12+; the docs explicitly recommend it as
  //      the first thing to try.
  const stealthMode = options.stealthMode === true
  const tunMtu = selectTunMtu({
    stealthMode,
    publicWifiCompatibility: options.publicWifiCompatibility === true
  })
  const isDirectVpn = typeof upstream !== 'string'
  const explicitClientDevice = isDirectVpn && upstream.clientDevice
    ? normalizeClientDevice(upstream.clientDevice)
    : null

  // Smart RU split-routing options. Pure here (caller passes resolved flags
  // from settings) so generateSingboxConfig stays unit-testable.
  const smartRoute: SmartRouteOptions = {
    enabled: options.smartRuSplit === true,
    mapsDirect: options.smartRuMapsDirect === true,
    directDnsTag: SMART_DIRECT_DNS_TAG,
    ruleSetDir: options.smartRuRuleSetDir
  }
  const parsedProxy = typeof upstream === 'string' ? parseProxyAddress(upstream) : null
  const proxyCoreProcesses = isDirectVpn ? [] : uniqueProcessNames([...PROXY_CORE_PROCESS_NAMES, ...directProcessNames])

  // sing-box 1.13 deprecates outbound domain_strategy; if the proxy/VPN
  // endpoint is a hostname, resolve only that bootstrap name directly, while
  // captured app DNS still goes through proxy-out and fails closed.
  const baseProxyOutbound = isDirectVpn
    ? { ...upstream.outbound, tag: 'proxy-out' }
    : proxyType === 'http'
      ? { type: 'http', tag: 'proxy-out', server: parsedProxy!.host, server_port: parsedProxy!.port }
      : { type: 'socks', tag: 'proxy-out', version: '5', server: parsedProxy!.host, server_port: parsedProxy!.port }
  const { outbound: proxyOutbound, needsBootstrapDns } = sanitizeProxyOutbound(baseProxyOutbound)

  // Always-on anti-DPI defaults plus stealth-mode extras, applied to the
  // outbound's TLS object. Two layers:
  //   1. uTLS + ALPN ("chrome" / h2,http/1.1) is forced on EVERY TLS
  //      outbound regardless of stealthMode. sing-box's default ClientHello
  //      is shaped like Go stdlib which TSPU/Russian ISPs rate-limit.
  //      parseLine usually sets these, but custom JSON outbounds — and
  //      anything that bypassed parseLine — can arrive without them.
  //   2. record_fragment is the stealth-mode-only knob that fragments the
  //      ClientHello at the TLS-record layer. It must NOT be applied to
  //      Reality, because Reality embeds auth in the structure of its
  //      camouflage ClientHello and fragmenting on top would scramble it
  //      and break Reality auth on the server side.
  if (proxyOutbound.tls && typeof proxyOutbound.tls === 'object') {
    const tls = proxyOutbound.tls as Record<string, any>
    const realityEnabled = tls.reality && typeof tls.reality === 'object'
      && tls.reality.enabled !== false

    if (!tls.utls || typeof tls.utls !== 'object' || tls.utls.enabled === false) {
      tls.utls = { enabled: true, fingerprint: 'chrome' }
    } else if (!tls.utls.fingerprint) {
      tls.utls.fingerprint = 'chrome'
    }
    if (explicitClientDevice) {
      tls.utls.fingerprint = clientFingerprintForDevice(explicitClientDevice)
    }
    if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) {
      tls.alpn = ['h2', 'http/1.1']
    }

    // In stealth mode on non-Reality outbounds, deterministically rotate
    // the uTLS fingerprint per-server. The seed combines server, port and
    // the per-key secret (uuid for VLESS/VMess, password for Trojan/HY2)
    // so the same outbound always picks the same fingerprint (stable for
    // server-side allowlists/sticky sessions) but different outbounds
    // within the same subscription look like different browsers, which
    // makes a big subscription harder to bulk-block by a single fp pattern.
    if (stealthMode && !realityEnabled && !explicitClientDevice && tls.utls && typeof tls.utls === 'object') {
      // Windows-plausible fingerprints only. Safari does not exist on Windows,
      // so a "safari" uTLS fp on a Windows client is itself an anomaly DPI can
      // flag — drop it. chrome/firefox/edge are all native to Windows. Keep
      // the deterministic per-key seed so a given server always picks the same
      // fp (stable for server-side sticky sessions) while a big subscription
      // still spreads across multiple browser fingerprints.
      const fps = ['chrome', 'firefox', 'edge'] as const
      const seed = String(proxyOutbound.server || '') + ':' + String(proxyOutbound.server_port || '') +
        ':' + String(proxyOutbound.uuid || proxyOutbound.password || '')
      let h = 0
      for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0
      tls.utls.fingerprint = fps[Math.abs(h) % fps.length]
    }

    if (stealthMode && !realityEnabled) {
      tls.record_fragment = true
    }
  }

  const logPath = join(getTunRuntimeDir(), 'sing-box.log').replace(/\\/g, '/')

  // Allocate a fresh clash-API port+secret for this run. Bound to
  // 127.0.0.1 so it is only reachable from the same machine, and the
  // secret is mandatory — anyone running another userland process on
  // the box still cannot probe outbounds without knowing the token.
  //
  // The port MUST be bind-safe. A pure random pick in 49152-65535 can land
  // inside a Windows Hyper-V/WSL "excluded port range", and then sing-box
  // fails to bind the clash_api external_controller with WSAEACCES and
  // exits at startup — the same failure mode we already pre-resolve away
  // for the mixed-direct-in port. prepareRuntime pre-resolves this via
  // pickFreeLocalPort and passes clashPortOverride; the random fallback
  // only kicks in for direct callers (tests) that don't supply one.
  let clashPort = options.clashPortOverride
  if (typeof clashPort !== 'number' || !Number.isInteger(clashPort) || clashPort <= 0 || clashPort > 65535) {
    clashPort = randomLocalPort()
  }
  const clashSecret = randomSecret()
  clashApiInfo = { port: clashPort, secret: clashSecret }

  let dPort = options.directProxyPortOverride
  if (typeof dPort !== 'number' || !Number.isInteger(dPort) || dPort <= 0 || dPort > 65535 || dPort === clashPort) {
    // Fall back to a random pick when the caller did not pre-resolve a port
    // (e.g. unit tests calling generateSingboxConfig directly). prepareRuntime
    // pre-resolves the port via pickFreeLocalPort to avoid Windows excluded
    // port ranges that cause WSAEACCES on bind.
    dPort = randomLocalPort()
    while (dPort === clashPort) {
      dPort = randomLocalPort()
    }
  }
  directProxyPort = dPort
  const domainRouteRules = buildDomainRouteRules()
  const smartRouteRouteRules = smartRouteRules(smartRoute)
  const smartRouteRuleSetDefs = smartRouteRuleSets(smartRoute)
  const smartDirectDnsServers = smartRoute.enabled
    ? buildSmartDirectDnsServers(options.smartRuDirectDnsSources, SMART_DIRECT_DNS_TAG)
    : []
  const quicUdp443BlockRules =
    shouldBlockQuicUdp443(proxyOutbound, proxyType, isDirectVpn)
      ? [{ network: 'udp', port: 443, action: 'reject', method: 'default', no_drop: true }]
      : []
  const allUdpBlockRules =
    isTcpOnlyNetworkOutbound(proxyOutbound) && isDirectVpn
      ? [{ network: 'udp', action: 'reject', method: 'default', no_drop: true }]
      : []
  const needsSniff = true // Always sniff so that SNI and HTTP Host are available for routing and proxying
  const directVpnEndpointRouteExcludes =
    isDirectVpn && typeof proxyOutbound.server === 'string' && isIP(proxyOutbound.server) === 4
      ? [`${proxyOutbound.server}/32`]
      : []

  return {
    log: { level: 'debug', timestamp: true, output: logPath },
    dns: {
      // sing-box 1.13.x rejects `detour: direct-out` on DNS servers when the
      // direct outbound has no explicit override/bind options ("detour to an
      // empty direct outbound makes no sense"). Bootstrap DNS therefore uses
      // the DNS server's own default direct dialer (no detour), not a detour to
      // direct-out and not `type: local`. `local` can recurse into the TUN
      // resolver after adapter lockdown pins physical DNS to 192.168.250.254.
      //
      // The remote resolvers come from the user's selected DNS profile
      // (Settings → DNS) when one is active, falling back to Cloudflare +
      // Google. Every remote server detours through proxy-out so DNS is
      // tunnelled and can't leak to the ISP resolver.
      servers: [
        ...buildDnsBootstrapServers(),
        ...buildRemoteDnsServers(),
        ...(needsBootstrapDns
          ? [{ type: 'udp', tag: BOOTSTRAP_DNS_TAG, server: '1.1.1.1' }]
          : []),
        // Smart RU split: use the physical adapter's pre-lockdown upstream DNS
        // servers directly, instead of `type: local`. Under strict_route + our
        // adapter DNS pinning, `local` loops back into the TUN resolver and
        // times out. Explicit UDP servers keep RU-visible resolution direct
        // without recursing into sing-box itself.
        ...smartDirectDnsServers
      ],
      // DNS rules: bind RU domain rule-sets to the direct resolver. Only
      // present when smart-route is on; empty otherwise so default behaviour
      // is unchanged (everything resolves via dns-remote through the tunnel).
      ...(smartRoute.enabled
        ? { rules: smartRouteDnsRules(smartRoute) }
        : {}),
      final: REMOTE_DNS_TAG,
      strategy: DNS_STRATEGY
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        interface_name: TUN_ADAPTER_ALIAS,
        // IPv4-only TUN. We deliberately do NOT give the TUN an IPv6 address
        // or capture IPv6 (no ::/1, 8000::/1 in route_address). Reason: the
        // whole stack is already IPv4-only — DNS strategy is ipv4_only and the
        // firewall kill-switch's LAN bypass is IPv4-only (it assumes IPv6 is
        // disabled). If the TUN advertises IPv6, Windows tells apps "IPv6 is
        // available" and Chrome/Yandex try YouTube/Google over IPv6 first
        // (Happy Eyeballs, using their own DoH so our ipv4_only DNS can't stop
        // them). Those IPv6 packets are then silently dropped by the WFP
        // kill-switch, so the browser waits the full Happy-Eyeballs timeout
        // (~5-10s) before falling back to IPv4 — exactly the "YouTube hangs
        // then springs to life" symptom. With no IPv6 on the TUN, apps see no
        // IPv6 route and go straight to IPv4. IPv6 leak prevention is handled
        // by the kill-switch (blocks all outbound IPv6) and adapter lockdown
        // (disables IPv6 on physical NICs), not by black-holing it in the TUN.
        address: [TUN_IPV4_ADDRESS_CIDR],
        mtu: tunMtu,
        auto_route: true,
        strict_route: true,
        route_address: ['0.0.0.0/1', '128.0.0.0/1'],
        route_exclude_address: [
          '127.0.0.0/8',
          '10.0.0.0/8',
          '172.16.0.0/12',
          '192.168.0.0/16',
          '169.254.0.0/16',
          '224.0.0.0/4',
          ...directVpnEndpointRouteExcludes
        ],
        stack: 'mixed'
      },
      {
        type: 'mixed',
        tag: 'mixed-direct-in',
        listen: '127.0.0.1',
        listen_port: dPort
      }
    ],
    outbounds: [
      proxyOutbound,
      { type: 'direct', tag: 'direct-out' },
      { type: 'block', tag: 'block-out' }
    ],
    route: {
      rules: [
        { inbound: 'mixed-direct-in', outbound: 'direct-out' },
        ...(
          proxyCoreProcesses.length > 0
            ? [{
              process_name: proxyCoreProcesses,
              outbound: 'direct-out'
            }]
            : []
        ),
        // QUIC handling (see shouldBlockQuicUdp443): for local HTTP-proxy
        // chains we still drop UDP/443 before sniffing. For a native tunnel
        // (directVpn) this list is empty so QUIC rides the tunnel instead —
        // rejecting it there does not fast-fail the browser to TCP and instead
        // causes the multi-second "YouTube hangs then springs to life" stalls.
        ...quicUdp443BlockRules,
        ...(needsSniff ? [{ action: 'sniff' }] : []),
        // DNS from captured apps must be hijacked BEFORE any blanket UDP
        // block. In directVpn+tpc-only mode we intentionally block the rest
        // of UDP, but if that rule runs first Windows DNS probes never reach
        // sing-box's resolver and the browser falls into DNS_PROBE failures.
        { protocol: 'dns', action: 'hijack-dns' },
        // Direct VPN outbounds that are genuinely TCP-only cannot carry any
        // other UDP at all. Keep this AFTER hijack-dns so DNS still resolves
        // through sing-box, then fail-closed for the remaining UDP traffic.
        ...allUdpBlockRules,
        // User-defined per-domain rules (Settings → Domain Routing). Injected
        // AFTER sniff (so the SNI/Host is available to match on) and the DNS
        // hijack, but BEFORE the private-range and catch-all rules so an
        // explicit "block youtube.com" / "route netflix direct" actually wins.
        // Empty array when the user has no rules — zero overhead.
        ...domainRouteRules,
        // Smart RU split-routing. RU domains (curated geosite) + RU-hosted
        // IPs (geoip-ru) go direct so banks/gov/shops see the real IP, while
        // everything else falls through to proxy-out. Placed AFTER the user's
        // own domain rules (explicit overrides win) and BEFORE private/catch-
        // all. Empty when the feature is off.
        ...smartRouteRouteRules
      ],
      // Rule-sets for smart RU split (geoip-ru + geosite gov-ru). Loaded
      // LOCALLY from bundled .srs files (type: local) so a slow/blocked GitHub
      // fetch can never make sing-box fail to start — a remote rule-set whose
      // initial download times out is FATAL in sing-box and used to take the
      // whole tunnel down (exposing the real IP). Empty when feature is off.
      ...(smartRoute.enabled && (smartRouteRuleSetDefs.length > 0)
        ? { rule_set: smartRouteRuleSetDefs }
        : {}),
      final: 'proxy-out',
      auto_detect_interface: true,
      default_domain_resolver: 'dns-remote'
    },
    // Localhost-only diagnostics API. Used by Settings → Availability
    // to test arbitrary URLs through both proxy-out and direct-out
    // without disrupting live traffic. NOT a remote-management
    // endpoint — bound to 127.0.0.1, secret randomised every start.
    experimental: {
      clash_api: {
        external_controller: `127.0.0.1:${clashPort}`,
        secret: clashSecret,
        default_mode: 'rule'
      },
      // cache_file persists the DNS answer cache (and downloaded rule-sets /
      // clash selections) across restarts. ALWAYS on now — it's a pure
      // performance win: warm reconnects skip re-resolving every hostname,
      // which directly cuts the cold-start DNS storm the user felt as
      // "каждое видео проверяется по несколько секунд". store_rdrc also
      // persists reject decisions. Relative path → runtime dir (sing-box cwd).
      cache_file: { enabled: true, path: 'cache.db', store_rdrc: true }
    }
  }
}

function notifyStatus(status: string) {
  statusCallbacks.forEach(cb => cb(status))
}

async function runPowerShell(script: string, timeout = 8000, elevated = false): Promise<string> {
  const prelude =
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();' +
    '$ProgressPreference="SilentlyContinue";'
  const command = `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(prelude + script, 'utf16le').toString('base64')}`
  if (elevated) {
    const { stdout } = await execElevated(command, { timeout, maxBuffer: 1024 * 1024 })
    return stdout.toString()
  }
  const { stdout } = await execFile('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy',
    'Bypass',
    '-EncodedCommand',
    Buffer.from(prelude + script, 'utf16le').toString('base64')
  ], {
    windowsHide: true,
    timeout,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })
  return stdout
}

async function isSingboxRunning(): Promise<boolean> {
  try {
    const { stdout } = await execFile('tasklist.exe', ['/FI', `IMAGENAME eq ${RUNTIME_EXE_NAME}`, '/FO', 'CSV', '/NH'], {
      windowsHide: true,
      timeout: 3000,
      encoding: 'utf8'
    })
    return String(stdout).toLowerCase().includes(RUNTIME_EXE_NAME.toLowerCase())
  } catch {
    return false
  }
}

function psSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

export async function killOwnedTunRuntimeProcesses(): Promise<{ success: boolean; candidates: number; killed: number; names: string[]; error?: string }> {
  if (process.platform !== 'win32') return { success: true, candidates: 0, killed: 0, names: [] }
  try {
    const runtimeDir = getTunRuntimeDir()
    const stdout = await runPowerShell(`
$runtimeDir = ${psSingleQuote(runtimeDir)}
$names = @(${psSingleQuote(RUNTIME_EXE_NAME)}, 'vpnte-etw-sidecar.exe')
$rows = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    ($names -contains $_.Name) -and
    $_.ExecutablePath -and
    $_.ExecutablePath.StartsWith($runtimeDir, [System.StringComparison]::OrdinalIgnoreCase)
  })
$killed = @()
foreach ($p in $rows) {
  try {
    Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
    $killed += [pscustomobject]@{ name = [string]$p.Name; pid = [int]$p.ProcessId }
  } catch {}
}
[pscustomobject]@{
  candidates = [int]$rows.Count
  killed = [int]$killed.Count
  names = @($killed | ForEach-Object { $_.name })
} | ConvertTo-Json -Compress -Depth 3
`, 8000)
    const parsed = JSON.parse(String(stdout || '{}').trim() || '{}')
    const names = Array.isArray(parsed.names) ? parsed.names.map((name: any) => String(name)) : []
    return {
      success: true,
      candidates: Number(parsed.candidates) || 0,
      killed: Number(parsed.killed) || 0,
      names
    }
  } catch (err: any) {
    logEvent('debug', 'tun', 'killOwnedRuntimeProcesses failed', err)
    return { success: false, candidates: 0, killed: 0, names: [], error: err?.message || String(err) }
  }
}

async function killOwnedRuntimeProcesses(): Promise<void> {
  await killOwnedTunRuntimeProcesses()
}

async function waitForOwnedRuntimeToExit(timeoutMs = 3000): Promise<boolean> {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (!(await isOwnedTunRuntimeRunning())) return true
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  return !(await isOwnedTunRuntimeRunning())
}

async function isOwnedTunRuntimeRunning(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    const runtimeDir = getTunRuntimeDir()
    const stdout = await runPowerShell(`
$runtimeDir = ${psSingleQuote(runtimeDir)}
$names = @(${psSingleQuote(RUNTIME_EXE_NAME)}, 'vpnte-etw-sidecar.exe')
$found = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    ($names -contains $_.Name) -and
    $_.ExecutablePath -and
    $_.ExecutablePath.StartsWith($runtimeDir, [System.StringComparison]::OrdinalIgnoreCase)
  } |
  Select-Object -First 1)
if ($found.Count -gt 0) { 'true' } else { 'false' }
`, 5000)
    return String(stdout || '').toLowerCase().includes('true')
  } catch (err) {
    logEvent('debug', 'tun', 'owned runtime status probe failed', err)
    return await isSingboxRunning()
  }
}

// Polls Get-NetAdapter until VPNTE-TUN reports Status=Up. Wintun creates the
// adapter shortly after sing-box opens its TUN inbound, but there's a small
// gap where Get-NetAdapter either doesn't see it or reports it as Disconnected.
// Firewall rules with -InterfaceAlias <TUN_ADAPTER_ALIAS> fail silently when the alias
// doesn't exist yet, so any caller that's about to install such a rule must
// wait for this helper to succeed first.
async function waitForTunInterface(timeoutMs = 5000): Promise<boolean> {
  if (process.platform !== 'win32') return false
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const interfaces = networkInterfaces()
    for (const name of Object.keys(interfaces)) {
      if (name === TUN_ADAPTER_ALIAS || ALL_KNOWN_ALIASES.includes(name)) {
        const entries = interfaces[name]
        if (entries && entries.some(e => e.family === 'IPv4' && !e.internal)) {
          return true
        }
      }
    }
    await new Promise(r => setTimeout(r, 150))
  }
  return false
}

/**
 * Force the TUN adapter's IPv4 InterfaceMetric to LOW so Windows always
 * prefers TUN routes over physical-adapter default routes. Without this,
 * Wi-Fi adapters with their default metric (auto-assigned 35-50 depending
 * on link speed) outrank our TUN's auto-assigned 256, and traffic leaks
 * via the physical adapter despite auto_route + strict_route in sing-box.
 *
 * We use Set-NetIPInterface -InterfaceAlias <TUN> -InterfaceMetric 5.
 * Metric 5 is well below typical wired (5-10) and Wi-Fi (35-50) auto values
 * but high enough to lose to localhost (1) and explicit user overrides.
 *
 * IPv4-only: the TUN no longer carries IPv6 routes (see the tun inbound
 * config), so we only set the IPv4 interface metric here.
 *
 * Best-effort: if the call fails (PowerShell unavailable, adapter alias
 * not found), we log a warning but don't fail the start. The leak window
 * still narrows because sing-box's strict_route handles most paths; this
 * is belt-and-braces for the edge case where InterfaceMetric tiebreak
 * decides default-route winner.
 */
async function applyLowTunInterfaceMetric(): Promise<void> {
  if (process.platform !== 'win32') return
  try {
    const { exec } = await import('child_process')
    const { promisify } = await import('util')
    const execAsync = promisify(exec)
    // 20ms netsh execution instead of 850ms PowerShell
    await execAsync(`netsh interface ipv4 set interface "${TUN_ADAPTER_ALIAS}" metric=${TUN_INTERFACE_METRIC}`, { windowsHide: true })
    logEvent('info', 'tun', `set TUN InterfaceMetric=${TUN_INTERFACE_METRIC}`, { output: 'ipv4:set' })
  } catch (err) {
    logEvent('warn', 'tun', 'failed to set TUN InterfaceMetric', err)
  }
}

// Single-shot "is anything to clean up?" probe. ONE PowerShell call returns
// the count of adapters matching ANY of our well-known aliases (live + legacy).
// Around 150ms vs 1-3s for the full per-alias sweep — used as a fast-path
// gate so a clean shutdown doesn't pay for an empty cleanup loop on the
// next start.
async function fastTunPresenceProbe(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    const { exec } = await import('child_process')
    const { promisify } = await import('util')
    const execAsync = promisify(exec)
    const { stdout } = await execAsync('netsh interface show interface', { windowsHide: true })
    return ALL_KNOWN_ALIASES.some((alias) => stdout.includes(alias))
  } catch (err) {
    // Probe failed — be conservative and let the caller run the full sweep.
    logEvent('debug', 'tun', 'fastTunPresenceProbe failed — assuming cleanup needed', err)
    return true
  }
}

async function removeStaleTunInterface(): Promise<void> {
  if (process.platform !== 'win32') return
  // Sweep over BOTH the live alias (TUN_ADAPTER_ALIAS) AND the legacy
  // 'VPNTE-TUN' name shipped by older builds. Without the legacy pass an
  // upgrading user could end up with two ghost adapters fighting over the
  // default route.
  // Fast-path skip: ALL_KNOWN_ALIASES is small (2 entries today) and a
  // single Get-NetAdapter -Name <list> call returns in ~150ms, so we use
  // the per-alias loop below ONLY when at least one matching adapter is
  // already present. Callers should still gate with fastTunPresenceProbe
  // for the parent-level skip, but the inner pre-check is cheap insurance
  // against future callers.
  if (!(await fastTunPresenceProbe())) {
    logEvent('debug', 'tun', 'removeStaleTunInterface: no aliases present, nothing to do')
    return
  }
  for (const alias of ALL_KNOWN_ALIASES) {
    // Wrap the whole body in PowerShell try/catch so a "no such adapter"
    // condition exits cleanly with our sentinel instead of spilling a
    // Get-NetAdapter error onto stderr and triggering a noisy warn-level
    // log on every start. The sentinels let the JS side classify the
    // outcome (no-op / removed / disabled) without parsing PS error text.
    const script = `
try {
  $adapter = Get-NetAdapter -Name '${alias}' -ErrorAction SilentlyContinue
  if (-not $adapter) {
    Write-Host '__VPNTE_NOOP__'
  } else {
    try {
      Remove-NetAdapter -Name '${alias}' -Confirm:$false -ErrorAction Stop
      Write-Host '__VPNTE_DONE__ removed'
    } catch {
      try {
        Disable-NetAdapter -Name '${alias}' -Confirm:$false -ErrorAction Stop
        $staleName = '${alias}-stale-' + (Get-Date -Format 'yyyyMMddHHmmss')
        try {
          Rename-NetAdapter -Name '${alias}' -NewName $staleName -Confirm:$false -ErrorAction Stop
          Write-Host "__VPNTE_DONE__ disabled-renamed $staleName"
        } catch {
          Write-Host "__VPNTE_ERR__ disabled-not-renamed $_"
        }
      } catch {
        Write-Host "__VPNTE_ERR__ $_"
      }
    }
  }
} catch {
  Write-Host "__VPNTE_ERR__ $_"
}
`
    try {
      const stdout = await runPowerShell(script, 15000, true)
      const out = String(stdout || '').trim()
      if (out.includes('__VPNTE_NOOP__')) {
        logEvent('debug', 'tun', `no stale TUN interface for ${alias}`)
      } else if (out.includes('__VPNTE_DONE__')) {
        logEvent('info', 'tun', `cleaned up stale TUN interface for ${alias}`, { output: out })
      } else if (out.includes('__VPNTE_ERR__')) {
        logEvent('warn', 'tun', `stale TUN interface cleanup failed for ${alias}`, { output: out })
      } else {
        // No sentinel — treat as benign (PS returned empty stdout); avoid the
        // legacy warn that fired on every start.
        logEvent('debug', 'tun', `stale TUN interface check returned no output for ${alias}`)
      }
    } catch (err) {
      logEvent('warn', 'tun', `stale TUN interface cleanup failed for ${alias}`, err)
    }
  }
}

// Kill-switch behavior: when the upstream proxy is unreachable, we INTENTIONALLY do NOT
// tear down sing-box. The TUN keeps strict_route + final=proxy-out, so traffic just
// times out at the dead proxy instead of leaking out the physical adapter. The watchdog
// only annotates the status so the UI can warn the user that traffic is currently
// blocked; it never kills the runtime on its own.
function markProxyUnreachable(reason: string): void {
  if (!currentStatus.running) return
  if (currentStatus.proxyReachable === false) return
  logEvent('warn', 'tun-watchdog', reason)
  currentStatus = { ...currentStatus, proxyReachable: false, warning: reason }
  notifyStatus('proxy-down')
}

function markProxyRecovered(): void {
  if (!currentStatus.running) return
  if (currentStatus.proxyReachable !== false) return
  logEvent('info', 'tun-watchdog', 'upstream proxy recovered, traffic flowing again')
  currentStatus = { ...currentStatus, proxyReachable: true, warning: null }
  notifyStatus('running')
}

function hasRecentPublicIpConfirmation(maxAgeMs: number): boolean {
  const lastSuccessAt = ipMonitor.getLastSuccessAt()
  return lastSuccessAt > 0 && Date.now() - lastSuccessAt <= maxAgeMs
}

function stopProxyWatchdog() {
  if (watchdogTimer) {
    clearInterval(watchdogTimer)
    watchdogTimer = null
  }
  watchdogFailures = 0
}

function startProxyWatchdog(proxyAddr: string) {
  stopProxyWatchdog()

  let parsed: { host: string; port: number }
  try {
    parsed = parseProxyAddress(proxyAddr)
  } catch (err: any) {
    logEvent('warn', 'tun-watchdog', 'watchdog disabled because proxy address is invalid', err)
    return
  }

  watchdogTimer = setInterval(async () => {
    if (!currentStatus.running) {
      stopProxyWatchdog()
      return
    }

    const alive = await probeTcp(parsed.host, parsed.port, 1500)
    if (alive) {
      watchdogFailures = 0
      markProxyRecovered()
      return
    }

    watchdogFailures += 1
    if (hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)) {
      watchdogFailures = 0
      logEvent('info', 'tun-watchdog', 'suppressing direct VPN probe failure because tunnel egress was recently confirmed', {
        host: parsed.host,
        port: parsed.port,
        proxyAddr,
        watchdogFailures,
        suppressWindowMs: DIRECT_VPN_WATCHDOG_SUPPRESS_MS
      })
      markProxyRecovered()
      return
    }
    if (watchdogFailures >= 3) {
      // Kill-switch: do NOT stop sing-box. The TUN keeps blocking traffic until proxy returns.
      markProxyUnreachable(
        `Прокси ${proxyAddr} не отвечает. Трафик блокируется в TUN, чтобы не утекать мимо VPN.`
      )
    } else {
      logEvent('warn', 'tun-watchdog', `upstream proxy probe failed (${watchdogFailures}/3)`, { proxyAddr })
    }
  }, 5000)
}

/**
 * Direct-VPN counterpart of startProxyWatchdog. In directVpn mode there is no
 * local proxy to probe — the upstream is the VLESS/Reality server itself. We
 * TCP-probe its host:port so a dead/unresponsive server (the "wsarecv: host
 * failed to respond" storm) is detected within ~15s and surfaced as
 * `proxy-down` with a clear "сервер X не отвечает" message, instead of leaving
 * the user staring at DNS timeouts and a misleading "leak" card.
 *
 * Note: a TCP connect succeeding doesn't fully prove the Reality handshake
 * works, but a TCP connect FAILING is a definitive "server is down" signal,
 * which is exactly the case we need to catch here. We use a slightly longer
 * 2s probe timeout because the server is remote (not localhost).
 */
function startServerWatchdog(host: string, port: number, label: string) {
  stopProxyWatchdog()
  watchdogTimer = setInterval(async () => {
    if (!currentStatus.running) {
      stopProxyWatchdog()
      return
    }

    const alive = await probeTcp(host, port, 2500)
    if (alive) {
      watchdogFailures = 0
      markProxyRecovered()
      return
    }

    watchdogFailures += 1
    if (hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)) {
      watchdogFailures = 0
      logEvent('info', 'tun-watchdog', 'suppressing direct VPN server probe failure because tunnel egress was recently confirmed', {
        host,
        port,
        label,
        suppressWindowMs: DIRECT_VPN_WATCHDOG_SUPPRESS_MS
      })
      markProxyRecovered()
      return
    }
    if (watchdogFailures >= 3) {
      markProxyUnreachable(
        `Сервер «${label}» не отвечает. Трафик блокируется в TUN (реальный IP не утекает). Выберите другой сервер.`
      )
    } else {
      logEvent('warn', 'tun-watchdog', `VPN server probe failed (${watchdogFailures}/3)`, { host, port, label })
    }
  }, 5000)
}

// Quick TCP reachability probe (2s timeout). Used to verify the upstream proxy
// (e.g. Happ on 127.0.0.1:10808) is actually accepting connections BEFORE we
// rewrite system routing — otherwise the TUN would blackhole all traffic.
export function probeTcp(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port })
    let done = false
    const finish = (ok: boolean) => {
      if (done) return
      done = true
      socket.destroy()
      resolve(ok)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('error', () => finish(false))
    socket.once('timeout', () => finish(false))
  })
}

const PROXY_PUBLIC_IP_CHECKS = [
  // Two endpoints, raced. We only need one good answer to clear the happy
  // path; the cross-check below is only triggered when the first answer is
  // suspicious (matches the direct IP), in which case we wait for the
  // second endpoint too. Dropped 2ip.ru — it's slower (~1-2s extra) and
  // not needed for the cross-check now that the first hit decides.
  { label: 'ipify', url: 'https://api.ipify.org' },
  { label: 'ifconfig', url: 'https://ifconfig.me/ip' }
]

function isPrivateIpv4(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  )
}

function extractPublicIpv4(text: string): string | null {
  const matches = String(text).match(/(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)/g) ?? []
  for (const ip of matches) {
    const parts = ip.split('.').map((part) => Number(part))
    if (parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && !isPrivateIpv4(ip)) {
      return ip
    }
  }
  return null
}

function curlProxyUrl(host: string, port: number, proxyType: 'socks5' | 'http'): string {
  const h = isIP(host) === 6 && !host.startsWith('[') ? `[${host}]` : host
  return `${proxyType === 'socks5' ? 'socks5h' : 'http'}://${h}:${port}`
}

async function curlText(args: string[], timeoutMs = 12000): Promise<string> {
  const { stdout } = await execFile('curl.exe', args, {
    windowsHide: true,
    timeout: timeoutMs,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })
  return stdout
}

async function fetchPublicIpDirect(): Promise<string | null> {
  if (process.platform !== 'win32') return null
  try {
    return extractPublicIpv4(await curlText(['-4', '-L', '-sS', '--max-time', '8', '--connect-timeout', '6', 'https://api.ipify.org']))
  } catch {
    return null
  }
}

async function waitForDirectIpGrace(directIpPromise: Promise<string | null>, timeoutMs: number): Promise<{ ip: string | null; ready: boolean }> {
  let timer: NodeJS.Timeout | null = null
  try {
    return await Promise.race([
      directIpPromise.then(ip => ({ ip, ready: true })),
      new Promise<{ ip: string | null; ready: false }>((resolve) => {
        timer = setTimeout(() => resolve({ ip: null, ready: false }), timeoutMs)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function validateProxyFullTunnel(
  host: string,
  port: number,
  proxyType: 'socks5' | 'http'
): Promise<{ ok: boolean; message?: string; directIp: string | null; proxyIps: Array<{ label: string; ip: string | null; error?: string }> }> {
  if (process.platform !== 'win32') return { ok: true, directIp: null, proxyIps: [] }

  const proxyUrl = curlProxyUrl(host, port, proxyType)
  // Run the direct-IP probe and the per-proxy probes IN PARALLEL. Direct
  // and through-proxy paths are completely independent, so back-to-back
  // sequencing was just adding a curl-handshake worth of latency.
  const directIpPromise = fetchPublicIpDirect()

  // Race the two through-proxy probes — first non-empty answer wins. Drop
  // max-time from 14s to 6s now that we only have to clear "any" probe to
  // make a happy-path decision.
  const probeOne = (check: { label: string; url: string }): Promise<{ label: string; ip: string | null; error?: string }> =>
    curlText(['-4', '-L', '-sS', '--max-time', '6', '--connect-timeout', '4', '--proxy', proxyUrl, check.url], 7000)
      .then((body) => ({ label: check.label, ip: extractPublicIpv4(body) }))
      .catch((err: any) => ({ label: check.label, ip: null, error: err?.message || String(err) }))

  const probePromises = PROXY_PUBLIC_IP_CHECKS.map(probeOne)

  // First successful (non-empty IP) answer wins. We can't use Promise.race
  // directly because the "loser" of a race here might still resolve LATER
  // with a useful answer — we only want to early-finish on a positive result.
  const firstHit: { label: string; ip: string | null; error?: string } = await new Promise((resolve) => {
    let pending = probePromises.length
    let settled = false
    for (const p of probePromises) {
      p.then((row) => {
        if (settled) return
        if (row.ip) {
          settled = true
          resolve(row)
          return
        }
        pending -= 1
        if (pending === 0 && !settled) {
          settled = true
          // Nothing returned an IP — surface the first row so the caller
          // gets a meaningful error structure.
          resolve(row)
        }
      })
    }
  })

  // Happy path: first probe returned an IP. Check against directIp — but
  // don't BLOCK on directIp if it hasn't resolved yet. If the proxy IP is
  // non-empty, the proxy is working (it returned a public IP). The direct
  // IP comparison is only needed to detect a "split proxy" where the proxy
  // returns the user's real IP — that's a security check, not a gating
  // check. We can start the tunnel and compare later.
  if (firstHit.ip) {
    // Give the direct-IP probe a short grace window. A zero-timeout race made
    // this cross-check practically unreachable on normal networks, masking
    // proxies that simply return the user's direct public IP.
    const directIpResult = await waitForDirectIpGrace(directIpPromise, 1200)
    if (directIpResult.ready && directIpResult.ip && firstHit.ip === directIpResult.ip) {
      // Proxy returned the same IP as direct — suspicious, fall through to full check
    } else {
      // Either directIp isn't ready yet (proxy is faster = good sign) or
      // the IPs differ (proxy is tunnelling). Either way, proceed.
      return { ok: true, directIp: directIpResult.ip, proxyIps: [firstHit] }
    }
  }

  // Suspicious path: wait for all probes + direct IP for full cross-check
  const [directIp, ...allRows] = await Promise.all([directIpPromise, ...probePromises])
  const proxyIps = allRows

  const seen = [...new Set(proxyIps.map((row) => row.ip).filter((ip): ip is string => Boolean(ip)))]
  if (seen.length >= 2) {
    return {
      ok: false,
      directIp,
      proxyIps,
      message:
        `Upstream proxy ${host}:${port} работает как split/direct proxy: разные сайты через него видят разные IP (${proxyIps.map((row) => `${row.label}=${row.ip ?? 'нет ответа'}`).join(', ')}). ` +
        'Включите в Happ режим Global/Proxy без обхода RU/локальных сайтов, иначе часть трафика будет выходить с провайдерского IP.'
    }
  }

  if (directIp && seen.length === 1 && seen[0] === directIp) {
    return {
      ok: false,
      directIp,
      proxyIps,
      message:
        `Upstream proxy ${host}:${port} не меняет внешний IP (${directIp}). ` +
        'Hard mode не будет запущен, потому что выбранный proxy ведёт напрямую, а не через VPN.'
    }
  }

  return { ok: true, directIp, proxyIps }
}

async function getProxyOwnerProcesses(host: string, port: number): Promise<Array<{ name: string; path: string | null }>> {
  if (process.platform !== 'win32') return []

  const safeHost = host.replace(/'/g, "''")
  const script = [
    `$hostName='${safeHost}';`,
    `$port=${port};`,
    "$addresses=@($hostName,'127.0.0.1','::1','0.0.0.0','::');",
    'Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |',
    'Where-Object { $addresses -contains $_.LocalAddress } |',
    'ForEach-Object {',
    '  $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -ErrorAction SilentlyContinue;',
    '  if ($p) { [pscustomobject]@{ ProcessName=$p.Name; Path=$p.ExecutablePath; Id=$p.ProcessId } }',
    '} | ConvertTo-Json -Compress'
  ].join(' ')

  try {
    const stdout = await runPowerShell(script, 8000)
    const raw = stdout.trim()
    if (!raw) return []
    const parsed = JSON.parse(raw)
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    return rows.map((row: any) => ({
      name: normalizeProcessName(String(row.ProcessName || '')) || '',
      path: row.Path ? String(row.Path) : null
    })).filter((row) => row.name)
  } catch (err: any) {
    logEvent('warn', 'tun', 'failed to detect proxy owner process', { host, port, error: err.message || String(err) })
    return []
  }
}

// Read the user's IP/CIDR kill-switch exceptions straight from the
// granular-kill-switch store. We read the store directly (same pattern
// serverGroups uses for the picker store) instead of importing
// granularKillSwitch, which would create a circular import. Returns only the
// `ip`-typed exception values; the firewall layer validates each one before
// use, so a malformed entry here is harmless.
function readGranularKillSwitchIpExceptions(): string[] {
  try {
    const exceptions = granularKillSwitchStore.get('killSwitchExceptions', []) as Array<{ type?: string; value?: string }>
    if (!Array.isArray(exceptions)) return []
    return exceptions
      .filter((e) => e && e.type === 'ip' && typeof e.value === 'string' && e.value.trim())
      .map((e) => String(e.value).trim())
  } catch {
    return []
  }
}

// Detect another active VPN/TUN adapter (Happ TUN, WireGuard, OpenVPN, …).
// Returns the interface name if found. We refuse to start in that case so we
// don't rip apart the user's working tunnel with our own auto_route.
// Our own adapter uses TUN_IPV4_PREFIX (and a legacy 172.19.0.x prefix) — anything else matching VPN patterns is foreign.
//
// Uses os.networkInterfaces() which returns raw adapter names as Windows knows them
// (e.g. 'happ-tun', 'wg0', 'WireGuard Tunnel'). Locale-independent, no external process.
export function detectForeignTun(): string | null {
  const vpnNameRx = /wintun|\btun\b|wireguard|\bwg\d*\b|openvpn|tap-windows|happ|hiddify|singbox|v2ray|xray/i
  const nics = networkInterfaces()
  for (const [name, addrs] of Object.entries(nics)) {
    if (!addrs) continue
    if (!vpnNameRx.test(name)) continue
    for (const a of addrs) {
      if (a.family !== 'IPv4' || a.internal) continue
      if (isOwnTunAddress(a.address)) continue // our own TUN
      return `${name} (${a.address})`
    }
  }
  return null
}

async function prepareRuntime(
  upstream: string | { outbound: Record<string, any>; proxyType?: 'socks5' | 'http'; clientDevice?: ClientDevice },
  proxyType: 'socks5' | 'http',
  directProcessNames: string[],
  options: {
    stealthMode?: boolean
    publicWifiCompatibility?: boolean
    smartRuSplit?: boolean
    smartRuMapsDirect?: boolean
    smartRuDirectDnsSources?: PhysicalAdapterDnsSource[]
  } = {}
): Promise<{ singbox: string; config: string }> {
  const runtimeDir = getTunRuntimeDir()
  await mkdir(runtimeDir, { recursive: true })

  const singboxSrc = getBundledResource('sing-box.exe')
  const wintunSrc = getBundledResource('wintun.dll')
  const cronetSrc = getBundledResource(CRONET_DLL_NAME)
  const singboxDst = join(runtimeDir, RUNTIME_EXE_NAME)
  const wintunDst = join(runtimeDir, 'wintun.dll')
  const cronetDst = join(runtimeDir, CRONET_DLL_NAME)
  const configPath = join(runtimeDir, 'sing-box.json')
  const logPath = join(runtimeDir, 'sing-box.log')
  const logPrevPath = join(runtimeDir, 'sing-box.prev.log')

  // Kick the OS port picks off FIRST so they overlap with the file IO below.
  // pickFreeLocalPort is a couple of bind/close round-trips which the kernel
  // can satisfy concurrently while we're stat-ing the bundled resources.
  // generateSingboxConfig falls back to randomLocalPort if no override is
  // supplied, so direct callers (e.g. tests) still work.
  //
  // We resolve BOTH the mixed-direct-in port AND the clash_api controller
  // port through the OS, because either one landing inside a Windows
  // Hyper-V/WSL excluded port range makes sing-box fail to bind (WSAEACCES)
  // and exit at startup. The clash port is resolved second with the direct
  // port excluded so the two never collide.
  const portsPromise = (async () => {
    let directPort: number | undefined
    let clashPort: number | undefined
    try {
      directPort = await pickFreeLocalPort()
    } catch (err) {
      logEvent('warn', 'tun', 'pickFreeLocalPort (direct) failed — falling back to random port', err)
    }
    try {
      clashPort = await pickFreeLocalPort(directPort ? [directPort] : [])
    } catch (err) {
      logEvent('warn', 'tun', 'pickFreeLocalPort (clash) failed — falling back to random port', err)
    }
    return { directPort, clashPort }
  })()

  // Rotate previous log so each run has a clean slate; previous one kept as .prev.log.
  try {
    await stat(logPath)
    await rename(logPath, logPrevPath).catch(() => undefined)
  } catch {
    // no existing log — nothing to rotate
  }

  // Copy binaries to a writable runtime dir (Program Files is read-only for normal users;
  // also ensures sing-box.exe, libcronet.dll and wintun.dll are in the same directory).
  // copyResourceIfStale skips the ~30 MB sing-box.exe copy when an identical
  // file already exists in the runtime dir — by far the common case after
  // first install.
  await access(singboxSrc)
  await access(wintunSrc)
  await access(cronetSrc)
  const [singboxCopied, wintunCopied, cronetCopied] = await Promise.all([
    copyResourceIfStale(singboxSrc, singboxDst),
    copyResourceIfStale(wintunSrc, wintunDst),
    copyResourceIfStale(cronetSrc, cronetDst)
  ])
  logEvent('debug', 'tun', 'runtime binaries staged', {
    singbox: singboxCopied ? 'copied' : 'reused',
    wintun: wintunCopied ? 'copied' : 'reused',
    cronet: cronetCopied ? 'copied' : 'reused'
  })

  // Smart-RU split: stage the bundled .srs rule-sets into the runtime dir so
  // sing-box loads them with `type: local` (no network at startup). This is a
  // hard reliability requirement: a `remote` rule-set whose initial download
  // fails is FATAL in sing-box — the core refuses to start, TUN never comes
  // up, the kill-switch is skipped, and the user's REAL IP leaks while the UI
  // still shows "Подключено". If ANY rule-set file can't be staged we DROP the
  // ruleSetDir (leaving it undefined) so generateSingboxConfig emits no
  // rule_set at all and the tunnel still starts — everything just tunnels via
  // proxy-out (safe default) instead of splitting. A routing nicety must never
  // be able to take down the core "hide my IP" function.
  let smartRuRuleSetDir: string | undefined
  if (options.smartRuSplit === true) {
    try {
      const source = await getPreferredSmartRouteRuleSetSourceDir()
      const staged = await Promise.all(
        smartRouteLocalRuleSetFiles().map(async (file) => {
          const src = join(source.dir, file)
          const dst = join(runtimeDir, file)
          await access(src) // throws if the file isn't bundled → caught below
          await copyResourceIfStale(src, dst)
          return true
        })
      )
      if (staged.length > 0 && staged.every(Boolean)) {
        smartRuRuleSetDir = runtimeDir
        logEvent('debug', 'tun', 'smart-RU rule-sets staged (local)', {
          dir: runtimeDir,
          source: source.source,
          managedComplete: source.managedComplete,
          files: smartRouteLocalRuleSetFiles()
        })
      }
    } catch (err) {
      logEvent('warn', 'tun', 'smart-RU rule-sets could not be staged — starting WITHOUT split-routing (all traffic via VPN)', err)
      smartRuRuleSetDir = undefined
    }
  }

  // Pre-resolve the mixed-direct-in port AND the clash_api port via the OS
  // so we never land inside a Windows Hyper-V/WSL excluded port range
  // (which causes sing-box to fail bind with WSAEACCES).
  const { directPort: directProxyPortOverride, clashPort: clashPortOverride } = await portsPromise

  const config = generateSingboxConfig(upstream, proxyType, directProcessNames, {
    ...options,
    // If staging failed, smartRuRuleSetDir is undefined. Force the whole
    // feature OFF for this run (rather than letting generateSingboxConfig fall
    // back to the dangerous `remote` download path) so the tunnel still starts
    // and everything safely egresses via proxy-out.
    smartRuSplit: options.smartRuSplit === true && smartRuRuleSetDir !== undefined,
    smartRuRuleSetDir,
    directProxyPortOverride,
    clashPortOverride
  })
  await writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8')

  return { singbox: singboxDst, config: configPath }
}

// ─── Post-trial failover ────────────────────────────────────────────────────
//
// When sing-box can't keep the active key alive AND that key was part of a
// subscription whose panel has expired (status === 'expired'), the most
// likely cause isn't a bug in our pipeline — it's that the provider finally
// revoked server-side access for that specific key. The keys NEXT to it in
// the same group very often still work, because providers revoke per-user
// quotas and not the entire pool at once.
//
// Instead of giving up and dropping the kill-switch, we walk the rest of the
// group, ping each candidate via keyHealthChecker, and switch the active
// profile to the first one that answers TLS. The user just sees a banner
// saying "we moved you to the next live key" and traffic resumes.
//
// This intentionally does NOT engage for healthy subscriptions: those go
// through the normal restart-with-backoff path, because the right answer
// there is "wait a moment and try the same server again", not "rotate keys".
export async function attemptPostTrialFailover(): Promise<{ tried: number; succeeded: boolean; newProfileId?: string }> {
  if (postTrialFailoverInProgress) {
    return { tried: 0, succeeded: false }
  }
  postTrialFailoverInProgress = true
  const generation = recoveryCancelGeneration
  const cancelled = () => userInitiatedStop || stopInProgress || generation !== recoveryCancelGeneration
  try {
    // Lazy-import the health checker via dynamic ESM `import()` so the
    // bundler still resolves it (unlike `require()` which electron-vite
    // tree-shook in production and broke "Проверить ключи").
    let checkProfileHealth: ((profile: any) => Promise<{ online: boolean; latencyMs: number | null; reason?: string }>) | null = null
    try {
      const mod = await import('./keyHealthChecker')
      checkProfileHealth = mod.checkProfileHealth
    } catch (err) {
      logEvent('warn', 'tun', 'post-trial failover: failed to load dependencies', err)
      return { tried: 0, succeeded: false }
    }
    if (!checkProfileHealth) {
      return { tried: 0, succeeded: false }
    }

    const profiles: any[] = serverPickerStore.get('profiles', []) || []
    const activeId: string | null = serverPickerStore.get('activeProfileId', null) || null
    if (!Array.isArray(profiles) || !activeId) {
      return { tried: 0, succeeded: false }
    }
    const activeProfile = profiles.find(p => p && p.id === activeId)
    if (!activeProfile) {
      return { tried: 0, succeeded: false }
    }

    const activeGroupId: string | null = activeProfile.groupId ?? null
    if (!activeGroupId) {
      return { tried: 0, succeeded: false }
    }

    const groups: any[] = serverGroupsStore.get('groups', []) || []
    const group = Array.isArray(groups) ? groups.find(g => g && g.id === activeGroupId) : null
    if (!group || group.status !== 'expired') {
      // Failover only makes sense for post-trial groups. Healthy subscriptions
      // get the existing restart-with-backoff path.
      return { tried: 0, succeeded: false }
    }

    const candidates: any[] = profiles
      .filter(p => p && p.groupId === activeGroupId && p.id !== activeId && p.enabled !== false)
      .sort((a: any, b: any) => {
        // Most-recently-seen-in-subscription first: those are the keys the
        // panel was happy with most recently, so the odds they still work
        // are slightly better.
        const ax = Number(a.lastSeenInSubscriptionAt ?? 0)
        const bx = Number(b.lastSeenInSubscriptionAt ?? 0)
        return bx - ax
      })

    if (!candidates.length) {
      logEvent('info', 'tun', 'post-trial failover: no sibling keys to try', {
        groupId: activeGroupId,
        from: activeId
      })
      return { tried: 0, succeeded: false }
    }

    let tried = 0
    for (const candidate of candidates) {
      if (cancelled()) {
        logEvent('info', 'tun', 'post-trial failover cancelled')
        return { tried, succeeded: false }
      }
      tried += 1
      let result: { online: boolean; latencyMs: number | null; reason?: string }
      try {
        result = await checkProfileHealth(candidate)
      } catch (err) {
        logEvent('warn', 'tun', 'post-trial failover: probe threw', err)
        continue
      }
      if (!result.online) continue
      if (cancelled()) {
        logEvent('info', 'tun', 'post-trial failover cancelled before promotion')
        return { tried, succeeded: false }
      }

      // Promote the candidate to active BEFORE we restart so the next
      // start() picks it up via lastStartOptions / the renderer state.
      try {
        serverPickerStore.set('activeProfileId', candidate.id)
      } catch (err) {
        logEvent('warn', 'tun', 'post-trial failover: failed to set active profile', err)
      }

      logEvent('info', 'tun', 'post-trial failover: switching to next live key', {
        from: activeId,
        to: candidate.id,
        group: activeGroupId,
        latencyMs: result.latencyMs
      })

      const candidateName = typeof candidate.name === 'string' && candidate.name.trim() ? candidate.name.trim() : 'другой ключ'
      notifyStatus(`post-trial-failover:${candidateName}`)
      notify(
        'warn',
        'Сервер сменился',
        `Активный ключ перестал отвечать. Переключились на «${candidateName}» — другой ключ из той же подписки. Подписка-источник истекла, но этот ключ ещё живой.`,
        'profileRotation'
      ).catch(() => undefined)

      // Re-arm the tunnel with the candidate's outbound. We reuse the prefs
      // from the last successful start so the user doesn't have to re-tick
      // kill-switch / lockdown / stealth mode toggles.
      try {
        if (cancelled()) {
          logEvent('info', 'tun', 'post-trial failover cancelled before restart')
          return { tried, succeeded: false }
        }
        const settings: any = settingsStore.get()
        const outbound = candidate.outbound && typeof candidate.outbound === 'object' ? candidate.outbound : null
        if (!outbound) {
          logEvent('warn', 'tun', 'post-trial failover: candidate has no outbound', { candidate: candidate.id })
          return { tried, succeeded: false }
        }
        const startResult = await tunController.start({
          mode: 'directVpn',
          vpnProfile: { name: candidateName, protocol: candidate.protocol, outbound },
          enableFirewallKillSwitch: lastStartOptions?.enableFirewallKillSwitch ?? settings.firewallKillSwitch === true,
          enableAdapterLockdown: lastStartOptions?.enableAdapterLockdown ?? settings.strictAdapterLockdown === true,
          publicWifiCompatibility: lastStartOptions?.publicWifiCompatibility ?? settings.publicWifiCompatibility,
          stealthMode: lastStartOptions?.stealthMode ?? settings.stealthMode === true
        })
        if (!startResult.success) {
          logEvent('warn', 'tun', 'post-trial failover: start failed', { error: startResult.error })
          continue
        }
      } catch (err) {
        logEvent('warn', 'tun', 'post-trial failover: start threw', err)
        continue
      }

      return { tried, succeeded: true, newProfileId: candidate.id }
    }

    logEvent('info', 'tun', 'post-trial failover: no live sibling found', {
      groupId: activeGroupId,
      tried
    })
    return { tried, succeeded: false }
  } finally {
    postTrialFailoverInProgress = false
  }
}

export const tunController = {
  async start(proxyAddrOrOpts: string | StartOptions): Promise<{ success: boolean; error?: string; warning?: string | null }> {
    if (currentStatus.running) {
      return { success: false, error: 'TUN уже запущен' }
    }
    if (startInProgress) {
      return { success: false, error: 'Запуск защиты уже выполняется' }
    }
    if (stopInProgress) {
      return { success: false, error: 'Остановка защиты ещё выполняется — подождите' }
    }
    startInProgress = true
    const finishStart = <T extends { success: boolean; error?: string; warning?: string | null }>(result: T): T => {
      startInProgress = false
      return result
    }

    // Phase timing: lightweight, in-process, written to the diagnostic dump.
    // `phases` preserves the old cumulative checkpoints; `phaseDurations`
    // shows the actual wall-clock cost of each expensive step.
    const phases: Record<string, number> = {}
    const phaseDurations: Record<string, Record<string, unknown>> = {}
    const tStart = Date.now()
    const mark = (name: string) => { phases[name] = Date.now() - tStart }
    const phaseStart = () => Date.now()
    const endPhase = (name: string, startedAt: number, meta: Record<string, unknown> = {}) => {
      const endedAt = Date.now()
      phases[name] = endedAt - tStart
      phaseDurations[name] = {
        startMs: startedAt - tStart,
        endMs: endedAt - tStart,
        durationMs: endedAt - startedAt,
        ...meta
      }
    }
    const timeAsync = async <T>(name: string, fn: () => Promise<T>, meta: Record<string, unknown> = {}): Promise<T> => {
      const startedAt = phaseStart()
      try {
        const result = await fn()
        endPhase(name, startedAt, meta)
        return result
      } catch (err) {
        endPhase(name, startedAt, { ...meta, failed: true })
        throw err
      }
    }
    const timePromise = <T>(name: string, promise: Promise<T>, meta: Record<string, unknown> = {}): Promise<T> => {
      const startedAt = phaseStart()
      return promise.then(
        (result) => {
          endPhase(name, startedAt, meta)
          return result
        },
        (err) => {
          endPhase(name, startedAt, { ...meta, failed: true })
          throw err
        }
      )
    }

    // A new start() always reopens the auto-restart window. If a pending
    // restart timer is still ticking from a crash recovery, cancel it — the
    // user (or the recovery loop) is taking matters into their own hands.
    userInitiatedStop = false
    clearRestartTimers()

    const startOptions: StartOptions =
      typeof proxyAddrOrOpts === 'string'
        ? { mode: 'localProxy', proxyAddr: proxyAddrOrOpts, proxyType: 'socks5' }
        : { mode: 'localProxy', ...proxyAddrOrOpts }
    const mode = startOptions.mode ?? 'localProxy'
    const proxyAddr = startOptions.proxyAddr ?? ''
    const proxyType: 'socks5' | 'http' =
      startOptions.proxyType ?? 'socks5'
    const vpnProfile = startOptions.vpnProfile
    const requestedKillSwitch =
      startOptions.enableFirewallKillSwitch === true
    const wantKillSwitch = requestedKillSwitch
    const wantAdapterLockdown =
      startOptions.enableAdapterLockdown === true
    const publicWifiCompatibility =
      startOptions.publicWifiCompatibility ?? settingsStore.get().publicWifiCompatibility
    recordForensicTunEvent('tun-start-requested', {
      mode,
      proxyType,
      proxyAddr: mode === 'localProxy' ? proxyAddr : null,
      vpnProfileName: vpnProfile?.name ?? null,
      vpnProtocol: vpnProfile?.protocol ?? null,
      wantKillSwitch,
      wantAdapterLockdown
    })

    // Smart RU split-routing flags, read from settings on every start so
    // toggling the UI takes effect on the next (re)connect. Passed through
    // prepareRuntime → generateSingboxConfig. mapsDirect is meaningless
    // unless the master switch is on, so gate it.
    const smartRuSplit = settingsStore.get().smartRuSplit === true
    const smartRuMapsDirect = smartRuSplit && settingsStore.get().smartRuMapsDirect === true
    // Kick off DNS sources lookup IN PARALLEL with foreign-tun detection
    // below — they're independent. Result is consumed by prepareRuntime.
    const dnsSourcesPromise = smartRuSplit
      ? getPhysicalAdapterDnsSources().catch((err) => {
        logEvent('warn', 'tun', 'failed to read physical adapter DNS sources for smart-RU', err)
        return [] as PhysicalAdapterDnsSource[]
      })
      : Promise.resolve([] as PhysicalAdapterDnsSource[])

    if (mode === 'localProxy' && !proxyAddr) {
      return finishStart({ success: false, error: 'Не указан upstream proxy' })
    }
    if (mode === 'directVpn' && !vpnProfile) {
      return finishStart({ success: false, error: 'Не выбран Direct VPN профиль' })
    }

    // ---------- Pre-flight 1: detect another VPN/TUN ----------
    // We no longer abort here: Happ often exposes both a local proxy and its own TUN.
    // Instead we exclude known Happ core processes from this TUN to avoid proxy loops.
    const foreignPreflightStarted = phaseStart()
    const foreign = detectForeignTun()
    endPhase('foreign-tun-preflight', foreignPreflightStarted, { found: Boolean(foreign) })
    if (foreign) {
      const message =
        `Уже активен другой системный туннель: ${foreign}. Второй TUN поверх него не запускается, ` +
        'потому что так чаще всего ломаются DNS и интернет. Оставьте текущий VPN/TUN включенным или выключите TUN в VPN-клиенте и оставьте только локальный proxy.'
      logEvent('warn', 'tun', 'start refused because another TUN/VPN is already active', { foreign, mode, proxyAddr, proxyType })
      return finishStart({ success: false, error: message })
    }
    mark('preflight')
    const warning = null

    // Split-tunnel "direct" app rules — these processes must bypass the VPN
    // (route through direct-out). Without merging them into directProcessNames
    // here, the split-tunnel feature has no effect at all: getDirectProcessNames
    // was never wired into config generation. Lazy import avoids the
    // tunController↔splitTunneling circular dependency.
    let splitTunnelDirectNames: string[] = []
    const splitTunnelStarted = phaseStart()
    try {
      const { splitTunneling } = await import('./splitTunneling')
      splitTunnelDirectNames = splitTunneling.getDirectProcessNames()
    } catch (err) {
      logEvent('debug', 'tun', 'could not read split-tunnel direct names', err)
    } finally {
      endPhase('split-tunnel-rules', splitTunnelStarted, { count: splitTunnelDirectNames.length })
    }

    // Adapter lockdown can run while we validate the proxy and prepare the
    // runtime. It does not depend on the proxy address, the sing-box config,
    // or the TUN interface — it only needs TUN_IPV4_RESOLVER (a constant).
    // Starting it HERE (before the proxy probe + full-tunnel check) lets its
    // ~5-9s of elevated PowerShell overlap with the ~3-8s of proxy validation,
    // saving ~3-5s on the critical path. We still await it before declaring
    // the tunnel up (inside the sing-box poller success handler).
    let adapterLockdownEngaged = false
    let adapterLockdownWarning: string | null = null
    logEvent('info', 'tun', 'adapter lockdown decision', {
      wantAdapterLockdown,
      publicWifiCompatibility,
      reason: wantAdapterLockdown
        ? 'strictAdapterLockdown is ON in settings - will apply'
        : 'strictAdapterLockdown is OFF in settings - will not apply'
    })
    const adapterLockdownPromise: Promise<void> | null = wantAdapterLockdown
      ? (async () => {
        try {
          const lock = await timeAsync(
            'adapter-lockdown',
            () => applyPhysicalAdapterLockdown(TUN_IPV4_RESOLVER, {
              forceDns: true
            }),
            { forceDns: true, parallel: true }
          )
          logEvent('info', 'tun', 'adapter lockdown result', {
            applied: lock.applied,
            adapters: lock.adapters,
            warnings: lock.warnings
          })
          if (lock.applied) {
            adapterLockdownEngaged = true
            if (lock.warnings.length > 0) {
              adapterLockdownWarning = `Lockdown with warnings: ${lock.warnings.join('; ')}`
              await rollbackPhysicalAdapterLockdownIfApplied('adapter lockdown warnings before start').catch(() => undefined)
              adapterLockdownEngaged = false
              throw new Error(adapterLockdownWarning)
            }
            return
          }
          adapterLockdownWarning = `Lockdown did not apply: ${lock.warnings.join('; ') || 'no physical adapters'}`
          logEvent('warn', 'tun', 'physical adapter lockdown did not apply', lock)
          throw new Error(adapterLockdownWarning)
        } catch (err: any) {
          if (!adapterLockdownWarning) {
            adapterLockdownWarning = `Lockdown failed: ${err?.message ?? String(err)}`
          }
          logEvent('warn', 'tun', 'physical adapter lockdown threw', err)
          throw err
        }
      })()
      : null
    adapterLockdownPromise?.catch(() => undefined)

    const rollbackEarlyAdapterLockdown = async (reason: string) => {
      if (!adapterLockdownPromise) return
      await adapterLockdownPromise.catch(() => undefined)
      if (adapterLockdownEngaged) {
        await rollbackPhysicalAdapterLockdownIfApplied(reason).catch(err =>
          logEvent('warn', 'tun', 'early adapter lockdown rollback failed', err)
        )
        adapterLockdownEngaged = false
      }
    }

    let proxyOwnerProcessNames: string[] = [...splitTunnelDirectNames]
    let proxyOwnerProgramPaths: string[] = []
    // directVpn can prepare runtime immediately. localProxy waits until the
    // full-tunnel validation passes, so a bad upstream cannot write a broken
    // runtime config before we reject the start.
    let runtimePromise: Promise<{ singbox: string; config: string }> | null = null
    // Await DNS sources before branching into mode-specific logic — both
    // localProxy and directVpn paths need smartRouteRuntimeOpts.
    const smartRuDirectDnsSources = await dnsSourcesPromise
    const smartRouteRuntimeOpts = { smartRuSplit, smartRuMapsDirect, smartRuDirectDnsSources }
    if (mode === 'localProxy') {
      // ---------- Pre-flight 2: proxy must actually be listening ----------
      // If Happ is closed or in TUN mode, port 10808 isn't listening — without this check
      // sing-box would start TUN, hijack all routes, and then 100% of traffic would blackhole.
      let parsedProxy: { host: string; port: number }
      try {
        parsedProxy = parseProxyAddress(proxyAddr)
      } catch (err: any) {
        await rollbackEarlyAdapterLockdown('proxy address parse failed after adapter lockdown')
        return finishStart({ success: false, error: err.message || String(err) })
      }

      const { host, port } = parsedProxy
      // Race the TCP probe with the PowerShell owner-process lookup.
      // getProxyOwnerProcesses is a ~1s PowerShell pipeline. Skip it
      // entirely when the kill-switch is OFF — the owner paths are only
      // used for kill-switch allow rules. Run them IN PARALLEL via
      // Promise.all so the PS spawn overlaps with the TCP connect.
      const proxyProbeStarted = phaseStart()
      const [proxyOwnerProcesses, proxyAlive] = await Promise.all([
        wantKillSwitch
          ? getProxyOwnerProcesses(host, port).catch(() => [] as Array<{ name: string; path: string | null }>)
          : Promise.resolve([] as Array<{ name: string; path: string | null }>),
        probeTcp(host, port, 2000)
      ])
      endPhase('proxy-listen-and-owner-lookup', proxyProbeStarted, {
        proxyAlive,
        ownerProcessCount: proxyOwnerProcesses.length
      })
      if (!proxyAlive) {
        logEvent('error', 'tun', 'start refused because upstream proxy is not reachable', { proxyAddr, proxyType })
        await rollbackEarlyAdapterLockdown('proxy not reachable after adapter lockdown')
        return finishStart({
          success: false,
          error:
            `Прокси ${proxyAddr} недоступен. Убедитесь, что Happ запущен в режиме Proxy ` +
            `и слушает порт ${port}.`
        })
      }
      logEvent('info', 'tun', 'upstream proxy is reachable', { proxyAddr, proxyType })

      proxyOwnerProcessNames = uniqueProcessNames([
        ...splitTunnelDirectNames,
        ...proxyOwnerProcesses.map((process) => process.name)
      ])
      proxyOwnerProgramPaths = [...new Set(proxyOwnerProcesses.map((process) => process.path).filter((path): path is string => Boolean(path)))]
      if (proxyOwnerProcesses.length > 0) {
        logEvent('info', 'tun', 'detected local proxy owner process for direct-out exclusion', {
          proxyAddr,
          processNames: proxyOwnerProcessNames,
          processPaths: proxyOwnerProgramPaths
        })
      }

      // Run the slower full-tunnel check before preparing runtime files.
      const proxyFullTunnel = await timeAsync(
        'proxy-full-tunnel-check',
        () => validateProxyFullTunnel(host, port, proxyType),
        { proxyType }
      )
      logEvent(proxyFullTunnel.ok ? 'info' : 'error', 'tun', 'upstream proxy full-tunnel check', proxyFullTunnel)
      if (!proxyFullTunnel.ok) {
        await rollbackEarlyAdapterLockdown('proxy full-tunnel check failed after adapter lockdown')
        return finishStart({ success: false, error: proxyFullTunnel.message || 'Upstream proxy не прошёл проверку полного туннеля' })
      }
      mark('proxy-validated')
    } else {
      logEvent('info', 'tun', 'starting Direct VPN profile', {
        protocol: vpnProfile?.protocol,
        name: vpnProfile?.name
      })
      // Direct VPN mode has no validation step — we can start prepareRuntime
      // immediately from the vpnProfile we already have in hand.
      if (vpnProfile) {
        runtimePromise = timePromise('prepare-runtime', prepareRuntime(
          { outbound: vpnProfile.outbound, proxyType, clientDevice: vpnProfile.clientDevice },
          proxyType,
          proxyOwnerProcessNames,
          {
            stealthMode: startOptions.stealthMode === true,
            publicWifiCompatibility,
            ...smartRouteRuntimeOpts
          }
        ), { mode })
      }
      mark('proxy-validated')
    }

    // Kill only VPNTE-owned runtime binaries. Never kill generic sing-box.exe elsewhere:
    // Happ may use its own sing-box/xray core.
    const runtimeCleanupStarted = phaseStart()
    if (await isSingboxRunning()) {
      await killOwnedRuntimeProcesses()
      if (!(await waitForOwnedRuntimeToExit())) {
        endPhase('owned-runtime-cleanup', runtimeCleanupStarted, { failed: true, previousRuntimeRunning: true })
        // Same harmless-throwaway dance as on validate failure: the eager
        // prepareRuntime is already running, drop its rejection on the floor
        // so it doesn't bubble as an unhandled rejection.
        if (runtimePromise) runtimePromise.catch(() => undefined)
        await rollbackEarlyAdapterLockdown('owned runtime cleanup failed after adapter lockdown')
        return finishStart({ success: false, error: 'Не удалось остановить предыдущий vpnte-sing-box.exe. Завершите его в Диспетчере задач и повторите.' })
      }
    } else {
      // Process is NOT running — nothing to kill. Previously this called
      // killRuntimeProcess which spawned elevated PowerShell to kill a
      // non-existent process, wasting ~250-700ms. Skip it entirely.
      logEvent('debug', 'tun', 'no stale sing-box process running — skipping kill')
    }
    endPhase('owned-runtime-cleanup', runtimeCleanupStarted)

    // Smart stale-cleanup gate: only walk the per-alias cleanup loop when at
    // least one of our well-known TUN aliases is currently present. After a
    // clean shutdown there's nothing to remove and the elevated PowerShell
    // round-trip just adds 1-3s for no reason. fastTunPresenceProbe is a
    // single ~150ms PowerShell call.
    //
    // We kick the cleanup off BUT DON'T AWAIT IT YET — it can run in
    // parallel with the sing-box config-check, since the cleanup never
    // touches our newly-copied binary or config in userData.
    const cleanupPromise: Promise<void> = timeAsync('stale-tun-cleanup', async () => {
      const needsCleanup = await fastTunPresenceProbe()
      if (needsCleanup) {
        await removeStaleTunInterface()
      } else {
        logEvent('debug', 'tun', 'skipping stale TUN cleanup — no aliases present')
      }
    })

    // Wait for runtime preparation now and run the sing-box config check in
    // parallel with the stale-cleanup that's still in flight above. localProxy
    // starts preparation here, after validation; directVpn usually started it
    // earlier.
    let runtime: { singbox: string; config: string }
    try {
      if (!runtimePromise) {
        runtimePromise = timePromise('prepare-runtime', prepareRuntime(
          mode === 'directVpn' && vpnProfile
            ? { outbound: vpnProfile.outbound, proxyType, clientDevice: vpnProfile.clientDevice }
            : proxyAddr,
          proxyType,
          proxyOwnerProcessNames,
          {
            stealthMode: startOptions.stealthMode === true,
            publicWifiCompatibility,
            ...smartRouteRuntimeOpts
          }
        ), { mode, fallback: true })
      }
      runtime = await runtimePromise
      // Run sing-box check in parallel with the stale-cleanup. Both are
      // independent and the check is the longer of the two on a clean box.
      await Promise.all([
        timeAsync('singbox-config-check', () =>
          execFile(runtime.singbox, ['check', '-c', runtime.config], {
            windowsHide: true,
            timeout: 10000,
            encoding: 'utf8',
            maxBuffer: 1024 * 1024
          })
        ),
        cleanupPromise
      ])
    } catch (err: any) {
      // Make sure we don't leave the cleanup dangling as an unhandled rejection.
      cleanupPromise.catch(() => undefined)
      await rollbackEarlyAdapterLockdown('runtime prepare failed after adapter lockdown')
      logEvent('error', 'tun', 'failed to prepare TUN runtime', err)
      return finishStart({ success: false, error: `Не удалось подготовить TUN-окружение: ${err.stderr || err.message || err}` })
    }
    mark('stale-cleanup-done')
    mark('runtime-ready')

    const runtimeDir = dirname(runtime.singbox)

    // Firewall kill-switch via DefaultOutboundAction=Block. Program-based Allow
    // rules for sing-box and proxy owner processes override the default Block,
    // so VPN traffic flows while everything else is blocked.
    // We DEFER engaging it until after sing-box has actually started AND the
    // TUN adapter is Up — otherwise the -InterfaceAlias <TUN_ADAPTER_ALIAS> rule
    // fails silently (the alias doesn't exist yet), traffic to the TUN gets
    // caught by DefaultOutboundAction=Block, and the user loses internet.
    // The actual enableKillSwitch() call happens in the polling success path
    // below, after waitForTunInterface().
    let killSwitchEngaged = false
    let killSwitchWarning: string | null = null

    // Adapter lockdown is NOT awaited here — it runs in parallel with sing-box
    // startup. The lockdown modifies physical adapters (IPv6 off, DNS pin) and
    // does not affect sing-box's ability to create the TUN. We await it inside
    // the poller success handler instead, overlapping the ~3-5s lockdown with
    // sing-box's ~0.5s startup + TUN wait. If lockdown fails there, we tear
    // down sing-box at that point.
    mark('lockdown-kicked-off')
    // sudo-prompt's callback fires on child exit. For a long-running daemon we:
    // 1. Fire-and-forget the sudo.exec call, using its callback to mark "stopped" on exit.
    // 2. Poll tasklist for sing-box.exe to determine if it actually started.
    return new Promise((resolve) => {
      let resolved = false
      const finish = (result: { success: boolean; error?: string; warning?: string | null }) => {
        if (resolved) return
        resolved = true
        startInProgress = false
        resolve(result)
      }

      // Wrap command so it runs in the runtime dir (so wintun.dll resolves correctly).
      const cmd = `cmd /c cd /d "${runtimeDir}" && "${runtime.singbox}" run -c "${runtime.config}"`

      const onExit = (error?: Error | null, stderr?: string) => {
        // This fires only when sing-box exits (or UAC is denied).
        const wasRunning = currentStatus.running
        stopProxyWatchdog()
        currentStatus = {
          running: false,
          mode,
          proxyAddr: null,
          proxyType: null,
          vpnProfileName: null,
          vpnProtocol: null,
          pid: null,
          warning: null,
          proxyReachable: true,
          startedAt: null,
          restartAttempt
        }
        if (!resolved) {
          const msg = error?.message || (stderr ? String(stderr) : 'sing-box не запустился')
          const combined = `${error?.message ?? ''} ${stderr ?? ''}`
          // sing-box can fail to bind the mixed-direct-in inbound when the
          // randomly-picked port falls inside a Windows Hyper-V/WSL excluded
          // port range. In real diagnostics this surfaced as WSAEACCES on
          // port 53771. We pre-resolve via pickFreeLocalPort now, but the OS
          // can still race and reserve a port between our probe and the bind.
          // Treat it as a transient failure and try ONCE with a fresh port.
          const isPortAccessForbidden =
            /WSAEACCES/i.test(combined) ||
            /An attempt was made to access a socket in a way forbidden/i.test(combined)
          const canRetryPortBind =
            isPortAccessForbidden && !userInitiatedStop && restartAttempt === 0
          logEvent('error', 'tun', 'sing-box exited before startup completed', { message: msg, stderr })
          recordForensicTunEvent('sing-box-start-failed', {
            message: msg,
            stderr,
            canRetryPortBind,
            restartAttempt
          })
          if (canRetryPortBind) {
            logEvent(
              'warn',
              'tun',
              'sing-box hit Windows excluded port range — picking new port and retrying',
              { stderr }
            )
            // Burn one auto-restart slot so we never loop indefinitely on a
            // persistent bind failure. The retry is fire-and-forget; if it
            // also fails we surface that error to the user via finish().
            restartAttempt = 1
          }
          // sing-box never came up. Tear down the kill-switch unconditionally
          // — otherwise the user is locked out of the internet for no reason.
          // We use disableKillSwitchIfActive (self-checks) instead of gating
          // on killSwitchEngaged, because the kill-switch may have completed
          // in the parallel IIFE before this onExit fires, but before
          // killSwitchEngaged is set in the success path.
          // Skip the teardown when we are about to retry: the next attempt
          // benefits from the rules already being in place.
          if (!canRetryPortBind) {
            disableKillSwitchIfActive('sing-box never started').catch(err =>
              logEvent('warn', 'tun', 'kill-switch disable after start failure failed', err)
            )
          }
          // Same for the adapter lockdown: it must always come down on a failed
          // start, otherwise the user has IPv6 disabled + ISP DNS overridden
          // for no reason.
          if (adapterLockdownEngaged && !canRetryPortBind) {
            rollbackPhysicalAdapterLockdownIfApplied('sing-box never started').catch(err =>
              logEvent('warn', 'tun', 'adapter lockdown rollback after start failure failed', err)
            )
          }
          if (canRetryPortBind) {
            const retryOpts = startOptions
            // Schedule the retry on next tick so the current start() call
            // unwinds cleanly (startInProgress cleared, callbacks fired) before
            // we kick off another full attempt.
            restartTimer = setTimeout(() => {
              restartTimer = null
              if (userInitiatedStop || stopInProgress) {
                logEvent('info', 'tun', 'WSAEACCES retry cancelled by stop')
                return
              }
              tunController.start(retryOpts).then((res) => {
                if (!res.success) {
                  logEvent('error', 'tun', 'WSAEACCES retry failed', { error: res.error })
                  notify('error', 'Не удалось запустить защиту', res.error || 'Неизвестная ошибка', 'connectionError')
                }
              }).catch((err) => {
                logEvent('error', 'tun', 'WSAEACCES retry threw', err)
              })
            }, 250)
            notifyStatus('restarting:1/1')
          } else {
            notifyStatus('stopped')
          }
          finish({ success: false, error: msg })
        } else if (error || stderr) {
          // A force-kill on user-initiated stop makes the child exit with a
          // non-zero "Command failed" error + empty stderr. That's expected,
          // not a fault — don't cry ERROR for it (it polluted the diagnostics
          // "errors:" summary and alarmed the user). Real unexpected crashes
          // (userInitiatedStop === false) still log at error.
          logEvent(userInitiatedStop ? 'info' : (error ? 'error' : 'warn'), 'tun', 'sing-box process exited', { error: error?.message, stderr, userInitiatedStop })
          recordForensicTunEvent(userInitiatedStop ? 'sing-box-exited-after-user-stop' : 'sing-box-process-exited', {
            error: error?.message,
            stderr,
            userInitiatedStop
          })
        } else {
          logEvent('info', 'tun', 'sing-box process exited')
          recordForensicTunEvent('sing-box-process-exited')
        }
        // sing-box died unexpectedly while we believed TUN was up. Three things to do:
        //  1. Restore proxy baseline (if applied) so we don't leave the user with
        //     no-VPN AND no-original-proxy-config.
        //  2. INTENTIONALLY KEEP the firewall kill-switch in place. Removing it
        //     here would defeat the purpose of "all traffic through VPN": the
        //     entire reason it exists is to block fall-through to the physical
        //     adapter when the daemon dies. The user must explicitly press Stop
        //     (or the daemon must come back up) to drop the rules.
        //  3. Roll back the physical adapter lockdown (IPv6 disable + DNS override
        //     to 172.19.0.2) IF auto-restart is NOT going to happen. Without a
        //     running TUN, the lockdown is actively harmful: DNS points to a
        //     non-existent resolver and IPv6 is broken. If auto-restart IS
        //     scheduled, we leave the lockdown in place — start() is idempotent
        //     and will skip it when the manifest already exists.
        if (wasRunning) {
          try {
            if (userInitiatedStop) {
            logEvent('info', 'tun', 'sing-box exited after user stop')
            return
          }

          rollbackTunNetworkBaselineIfApplied('sing-box exited').catch(err =>
            logEvent('warn', 'tun', 'baseline auto-rollback after sing-box exit failed', err)
          )

          // Decide whether to auto-recover. We only restart if (a) the user
          // didn't ask for a stop, (b) the autoRestartOnCrash setting is on,
          // (c) we have memory of the start params, and (d) we haven't burned
          // through all retries.
          const settings = settingsStore.get()
          const canAutoRestart =
            !userInitiatedStop &&
            settings.autoRestartOnCrash &&
            lastStartOptions !== null &&
            restartAttempt < RESTART_BACKOFF_MS.length

          if (canAutoRestart && lastStartOptions) {
            // Auto-restart is scheduled — keep adapter lockdown in place so the
            // restarted sing-box immediately has clean adapters. start() will
            // call applyPhysicalAdapterLockdown() which is idempotent when the
            // manifest already exists.
            const attempt = restartAttempt + 1
            const delay = RESTART_BACKOFF_MS[restartAttempt]
            restartAttempt = attempt
            logEvent('warn', 'tun', 'sing-box crashed — scheduling auto-restart', {
              attempt,
              maxAttempts: RESTART_BACKOFF_MS.length,
              delayMs: delay
            })
            recordForensicTunEvent('sing-box-crashed-auto-restart-scheduled', {
              attempt,
              maxAttempts: RESTART_BACKOFF_MS.length,
              delayMs: delay
            })
            notify('warn', 'sing-box упал', `Перезапуск через ${Math.round(delay / 1000)} с (попытка ${attempt}/${RESTART_BACKOFF_MS.length}).`, 'connectionError')
            // Surface the restart attempt to the renderer so the hero card can
            // say "Перезапускаем защиту…" instead of "Файрвол блокирует".
            notifyStatus(`restarting:${attempt}/${RESTART_BACKOFF_MS.length}`)

            clearRestartTimers()
            const optsSnapshot = lastStartOptions
            restartTimer = setTimeout(() => {
              restartTimer = null
              if (userInitiatedStop || stopInProgress) {
                logEvent('info', 'tun', 'auto-restart cancelled — user initiated stop', { attempt })
                return
              }
              tunController.start(optsSnapshot).then((res) => {
                if (!res.success) {
                  logEvent('error', 'tun', 'auto-restart attempt failed', { attempt, error: res.error })
                  notify('error', 'Не удалось перезапустить защиту', res.error || 'Неизвестная ошибка', 'connectionError')
                  if (killSwitchEngaged) notifyStatus('killswitch-active')
                  else notifyStatus('stopped')
                }
              }).catch((err) => {
                logEvent('error', 'tun', 'auto-restart attempt threw', err)
                notify('error', 'Не удалось перезапустить защиту', err?.message || String(err), 'connectionError')
                notifyStatus('stopped')
              })
            }, delay)
            return
          }

          // No auto-restart coming — roll back the adapter lockdown NOW.
          // Without a running TUN, having DNS pointed at 172.19.0.2 and IPv6
          // disabled on physical adapters will completely break the user's
          // internet. This is the root cause of the "DNS сломался" bug.
          if (adapterLockdownEngaged) {
            rollbackPhysicalAdapterLockdownIfApplied('sing-box exited — no auto-restart').catch(err =>
              logEvent('warn', 'tun', 'adapter lockdown rollback after sing-box crash failed', err)
            )
            repairOrphanedPhysicalAdapterDns('sing-box exited — safety repair').catch(err =>
              logEvent('warn', 'tun', 'orphaned DNS repair after sing-box crash failed', err)
            )
          }

          if (restartAttempt >= RESTART_BACKOFF_MS.length) {
            // Before giving up, try post-trial failover: if the active key
            // belongs to an "expired" group, the panel is gone but sibling
            // keys may still tunnel. attemptPostTrialFailover() bails fast
            // when the group is healthy / not expired, so the regular path
            // is unaffected. Fire-and-forget: it publishes its own
            // notifyStatus events, and a successful start() inside it will
            // naturally reset restartAttempt = 0.
            attemptPostTrialFailover()
              .then((res) => {
                if (res.succeeded) {
                  logEvent('info', 'tun', 'post-trial failover handled exhausted retries', res)
                  return
                }
                // Failover declined or every sibling was dead — fall back
                // to the original give-up path: announce stop, drop the
                // kill-switch so the user gets internet back, and tell the
                // UI we're done trying.
                logEvent('error', 'tun', 'auto-restart gave up — too many failures', {
                  attempts: restartAttempt,
                  failoverTried: res.tried
                })
                recordForensicTunEvent('sing-box-auto-restart-exhausted', {
                  attempts: restartAttempt,
                  failoverTried: res.tried
                })
                notify('error', 'Защита остановилась', 'Превышено число попыток перезапуска. Включите защиту вручную.', 'connectionError')
                disableKillSwitchIfActive('auto-restart exhausted — restoring internet').catch(err =>
                  logEvent('warn', 'tun', 'kill-switch disable after exhausted retries failed', err)
                )
                notifyStatus('stopped')
              })
              .catch((err) => {
                logEvent('error', 'tun', 'post-trial failover threw', err)
                disableKillSwitchIfActive('post-trial failover threw — restoring internet').catch(e =>
                  logEvent('warn', 'tun', 'kill-switch disable after failover throw failed', e)
                )
                notifyStatus('stopped')
              })
            // Done with this onExit invocation. Don't fall through to the
            // killSwitchEngaged branch below — the failover handler owns
            // the recovery path now.
            return
          }

          if (killSwitchEngaged && restartAttempt < RESTART_BACKOFF_MS.length) {
            logEvent(
              'warn',
              'tun',
              'sing-box exited unexpectedly — keeping firewall kill-switch active'
            )
            recordForensicTunEvent('sing-box-exited-killswitch-active', {
              restartAttempt,
              maxAttempts: RESTART_BACKOFF_MS.length
            })
            notify('warn', 'sing-box упал', 'Файрвол блокирует трафик, чтобы не было утечки IP. Включите защиту заново.', 'connectionError')
            try {
              import('electron').then(({ BrowserWindow }) => {
                BrowserWindow.getAllWindows().forEach(win => {
                  try { if (win.isMinimized()) win.restore(); win.show(); win.focus() } catch {}
                })
              }).catch(() => undefined)
            } catch {}
            notifyStatus('killswitch-active')
            return
          }
          notify('warn', 'Защита остановилась', 'sing-box завершил работу.', 'vpnDisconnect')
          notifyStatus('stopped')
        } catch (onExitErr) {
          logEvent('error', 'tun', 'onExit handler threw — performing emergency cleanup', onExitErr)
          rollbackTunNetworkBaselineIfApplied('onExit emergency').catch(() => undefined)
          disableKillSwitchIfActive('onExit emergency').catch(() => undefined)
          rollbackPhysicalAdapterLockdownIfApplied('onExit emergency').catch(() => undefined)
          repairOrphanedPhysicalAdapterDns('onExit emergency').catch(() => undefined)
          notifyStatus('stopped')
        }
        }
      }

      const launchStarted = phaseStart()
      mark('singbox-spawned')
      isProcessElevated().then((elevated) => {
        if (resolved) return
        if (elevated) {
          execFileCb(
            runtime.singbox,
            ['run', '-c', runtime.config],
            { cwd: runtimeDir, windowsHide: true, maxBuffer: 1024 * 1024 },
            (error, _stdout, stderr) => onExit(error, stderr)
          )
        } else {
          sudo.exec(cmd, { name: 'VPN Tunnel Enforcer' }, (error, _stdout, stderr) => onExit(error, String(stderr || '')))
        }
        endPhase('singbox-launch-submit', launchStarted, { elevated })
      }).catch((error) => {
        if (resolved) return
        endPhase('singbox-launch-submit', launchStarted, { failed: true })
        onExit(error)
      })

      // Poll for sing-box.exe presence.
      let attempts = 0
      const maxAttempts = 30 // 30 * 250ms = 7.5s (same ceiling, finer granularity)
      let successHandled = false
      const processWaitStarted = phaseStart()
      const poller = setInterval(async () => {
        if (resolved || successHandled) {
          clearInterval(poller)
          return
        }
        attempts++
        const running = await isSingboxRunning()
        if (running) {
          if (successHandled) return
          successHandled = true
          clearInterval(poller)
          endPhase('wait-singbox-process', processWaitStarted, { attempts })

          // Await the adapter lockdown NOW — it was kicked off ~3-4s ago and
          // is very likely already done by this point. If it hasn't finished
          // yet, we overlap the remaining few hundred ms with the TUN wait
          // below. If lockdown fails, we must tear down sing-box since we
          // already launched it.
          if (adapterLockdownPromise) {
            try {
              await timeAsync('adapter-lockdown-await', () => adapterLockdownPromise!)
              mark('lockdown-done')
            } catch {
              // Lockdown failed after sing-box started — kill it and abort.
              await killOwnedRuntimeProcesses()
              await rollbackEarlyAdapterLockdown('lockdown failed after sing-box started')
              finish({ success: false, error: adapterLockdownWarning || 'Adapter lockdown failed' })
              return
            }
          }

          // Engage the firewall kill-switch NOW, after sing-box is up. The
          // kill-switch installs an Allow rule scoped to -InterfaceAlias
          // TUN_ADAPTER_ALIAS, and Windows Firewall validates that alias when the
          // rule is created. If we engage too early the rule fails silently,
          // DefaultOutboundAction=Block kicks in, and traffic to the TUN dies.
          //
          // We also need the adapter present for the route-metric tweak below,
          // so wait for it unconditionally — this is a couple of hundred ms in
          // the steady-state and prevents a leak window where Wi-Fi outranks
          // our TUN on the default-route tiebreak.
          // Run waitForTunInterface and the kill-switch IN PARALLEL. The
          // kill-switch PS script now internally polls for the TUN adapter
          // before creating the -InterfaceAlias rule, so it no longer needs
          // the JS-side wait to complete first. This overlaps the ~2-3s
          // kill-switch PS script with the ~300-3000ms TUN wait, saving
          // ~2-3s on the critical path.
          //
          // The TUN metric set (netsh, ~20ms) runs after waitForTunInterface
          // completes — it's negligible and needs the adapter present.
          const parallelStarted = phaseStart()

          // Kick off the kill-switch immediately (if enabled and not already
          // active). The script handles TUN adapter polling internally.
          let killSwitchPromise: Promise<{ engaged: boolean; warning: string | null }> | null = null
          if (wantKillSwitch) {
            killSwitchPromise = (async () => {
              if (await isKillSwitchActive()) {
                logEvent('info', 'tun', 'kill-switch already active — reusing existing rules')
                return { engaged: true, warning: null }
              }
              const ks = await enableKillSwitch({
                singboxExePath: runtime.singbox,
                proxyOwnerProgramPaths,
                extraAllowedRemoteCidrs: readGranularKillSwitchIpExceptions()
              })
              if (ks.success) {
                logEvent('info', 'tun', 'kill-switch engaged (parallel with TUN wait)')
                recordForensicTunEvent('kill-switch-engaged', {
                  reason: 'parallel-with-tun-wait',
                  singboxExePath: runtime.singbox
                })
                return { engaged: true, warning: null }
              }
              logEvent('warn', 'tun', 'firewall kill-switch failed — continuing without it', ks)
              return { engaged: false, warning: `Kill-switch не включился: ${ks.message}. VPN работает без дополнительной защиты от утечек.` }
            })().catch(err => {
              logEvent('warn', 'tun', 'kill-switch promise rejected', err)
              return { engaged: false, warning: `Kill-switch error: ${err?.message || String(err)}` }
            })
          }

          // Wait for the TUN adapter (JS-side) in parallel with the kill-switch.
          const tunReady = await timeAsync('wait-tun-interface', () => waitForTunInterface(5000))

          // Lock in our TUN's InterfaceMetric as soon as the adapter is up.
          // This is a ~20ms netsh call and is independent of the kill-switch.
          if (tunReady) {
            await timeAsync('tun-interface-metric-set', () => applyLowTunInterfaceMetric())

            // Diagnostic readback only — background, non-blocking.
            const readbackStarted = phaseStart()
            const script = `(Get-NetIPInterface -InterfaceAlias '${TUN_ADAPTER_ALIAS}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty InterfaceMetric)`
            void runPowerShell(script, 4000)
              .then(out => {
                endPhase('tun-interface-metric-readback', readbackStarted, { background: true })
                const metric = parseInt(String(out).trim(), 10)
                if (Number.isFinite(metric) && metric > 50) {
                  logEvent('warn', 'tun', `TUN InterfaceMetric is high (${metric}) — possible route-priority leak`, { metric })
                }
              })
              .catch(err => {
                endPhase('tun-interface-metric-readback', readbackStarted, { background: true, failed: true })
                logEvent('debug', 'tun', 'TUN InterfaceMetric readback failed', {
                  error: err?.message || String(err)
                })
              })
          }

          // Collect the kill-switch result (it was started in parallel above
          // and is likely already done by now, since the TUN wait + metric
          // set took at least a few hundred ms).
          if (killSwitchPromise) {
            const ksResult = await timeAsync('firewall-kill-switch-await', () => killSwitchPromise!)
            endPhase('firewall-kill-switch', parallelStarted, {
              engaged: ksResult.engaged,
              parallel: true
            })
            if (ksResult.engaged) {
              killSwitchEngaged = true
            } else {
              if (!tunReady) {
                logEvent(
                  'warn',
                  'tun',
                  `${TUN_ADAPTER_ALIAS} did not reach Status=Up before kill-switch allow-rule polling completed`
                )
              }
              killSwitchWarning = ksResult.warning
            }
          } else {
            endPhase('firewall-kill-switch', parallelStarted, { skipped: true, reason: 'disabled' })
          }

          const combinedWarning = [warning, killSwitchWarning].filter(Boolean).join(' | ') || null
          currentStatus = {
            running: true,
            mode,
            proxyAddr,
            proxyType,
            vpnProfileName: vpnProfile?.name ?? null,
            vpnProtocol: vpnProfile?.protocol ?? null,
            pid: null,
            warning: combinedWarning,
            proxyReachable: true,
            startedAt: Date.now(),
            restartAttempt
          }
          mark('tun-running')
          if (mode === 'localProxy') {
            startProxyWatchdog(proxyAddr)
          } else if (mode === 'directVpn' && vpnProfile?.outbound) {
            // Direct VPN mode had NO server-health watchdog — so when the VLESS
            // server stopped responding mid-session (real case: wsarecv "host
            // failed to respond" storm), nothing detected it. DNS-through-the-
            // tunnel then timed out for 15s+, the IP-check fell back to showing
            // the real IP, and the user saw confusing "leak"/error states with
            // no clear "сервер не отвечает". Now we probe the VLESS server's
            // host:port the same way and emit proxy-down so the UI can say so.
            const vhost = vpnProfile.outbound.server
            const vport = Number(vpnProfile.outbound.server_port)
            if (typeof vhost === 'string' && vhost && Number.isInteger(vport) && vport > 0 && vport <= 65535) {
              startServerWatchdog(vhost, vport, vpnProfile.name || vhost)
            }
          }
          logEvent('info', 'tun', 'TUN started', {
            mode,
            proxyAddr,
            proxyType,
            vpnProtocol: vpnProfile?.protocol,
            warning: combinedWarning,
            killSwitch: killSwitchEngaged,
            restartAttempt
          })
          recordForensicTunEvent('tun-started', {
            mode,
            proxyAddr: mode === 'localProxy' ? proxyAddr : null,
            proxyType,
            vpnProfileName: vpnProfile?.name ?? null,
            vpnProtocol: vpnProfile?.protocol ?? null,
            warning: combinedWarning,
            killSwitch: killSwitchEngaged,
            restartAttempt
          })
          // Phase timing summary — gold for the diagnostic dump. If TUN
          // startup ever regresses, the phase deltas in this single log line
          // will pinpoint which step got slower.
          logEvent('info', 'tun', 'start timing', {
            phases,
            phaseDurations,
            totalMs: Date.now() - tStart
          })

          // Remember the start params so we can replay them after a crash.
          // Mark the run as "user-initiated" while we hold the line —
          // userInitiatedStop is cleared on success so an unexpected exit
          // from here on is treated as a crash (and triggers auto-restart).
          lastStartOptions = {
            mode,
            proxyAddr,
            proxyType,
            vpnProfile,
            enableFirewallKillSwitch: wantKillSwitch,
            enableAdapterLockdown: wantAdapterLockdown,
            publicWifiCompatibility
          }
          if (!stopInProgress) {
            userInitiatedStop = false
          }

          // If the run survives STABLE_RESET_MS we consider it healthy again
          // and zero the retry counter. Without this, the user would burn
          // through all 3 retries across days/weeks of operation.
          clearRestartTimers()
          stableTimer = setTimeout(() => {
            stableTimer = null
            if (currentStatus.running && restartAttempt > 0) {
              logEvent('info', 'tun', 'TUN stable — resetting restart attempt counter', {
                hadAttempts: restartAttempt
              })
              restartAttempt = 0
              currentStatus = { ...currentStatus, restartAttempt: 0 }
            }
          }, STABLE_RESET_MS)

          if (restartAttempt > 0) {
            notify('info', 'Защита восстановлена', `Подключение к VPN-серверу восстановлено после попытки ${restartAttempt}.`, 'vpnConnect')
          } else if (!combinedWarning) {
            notify('info', 'Защита включена', 'Весь трафик идёт через VPN.', 'vpnConnect')
          }

          notifyStatus('running')
          // Start the runtime watchdog for a foreign VPN/TUN appearing
          // mid-session. The watcher emits its own 'competing-tun:<name>'
          // status events through the existing status callback bus so the
          // renderer can show a banner without polling.
          startCompetingTunWatch((s) => notifyStatus(s))
          finish({ success: true, warning: combinedWarning })
        } else if (attempts >= maxAttempts) {
          clearInterval(poller)
          if (!resolved) {
            endPhase('wait-singbox-process', processWaitStarted, { failed: true, attempts })
            logEvent('info', 'tun', 'start timing', {
              phases,
              phaseDurations,
              totalMs: Date.now() - tStart,
              failedAt: 'wait-singbox-process'
            })
            logEvent('error', 'tun', 'sing-box did not start within timeout', { proxyAddr, proxyType })
            recordForensicTunEvent('sing-box-start-timeout', { proxyAddr, proxyType, attempts })
            // sing-box never reported running. Drop the kill-switch we installed
            // pre-flight so the user isn't stuck offline because of UAC denial.
            if (killSwitchEngaged) {
              disableKillSwitch('sing-box did not start within timeout').catch(err =>
                logEvent('warn', 'tun', 'kill-switch disable after timeout failed', err)
              )
            }
            if (adapterLockdownEngaged) {
              rollbackPhysicalAdapterLockdownIfApplied('sing-box did not start within timeout').catch(err =>
                logEvent('warn', 'tun', 'adapter lockdown rollback after timeout failed', err)
              )
            }
            finish({
              success: false,
              error: 'sing-box не стартовал за 7 секунд. Проверьте UAC-подтверждение и журнал.'
            })
          }
        }
      }, 250)
    })
  },

  async stop(): Promise<{ success: boolean; error?: string; warning?: string }> {
    // If start() is mid-flight, wait for it to finish before stopping.
    // Without this, stop() kills sing-box while start() is still polling
    // for it, leaving the app in an inconsistent state.
    if (startInProgress) {
      logEvent('info', 'tun', 'stop() called while start() in progress — waiting for start to finish')
      // Give start() up to 2s to complete, then proceed anyway
      for (let i = 0; i < 20 && startInProgress; i++) {
        await new Promise(r => setTimeout(r, 100))
      }
    }
    stopInProgress = true
    let leakMonitorSuspended = false
    let leakMonitorResumed = false
    const resumeLeakMonitor = () => {
      if (!leakMonitorSuspended || leakMonitorResumed) return
      ipMonitor.resume()
      leakMonitorResumed = true
    }
    try {
    // Mark this as a user-initiated stop BEFORE we kill sing-box, so the
    // exit handler doesn't kick off auto-restart. Also clear any pending
    // restart timer from a previous crash so we don't fight ourselves.
    userInitiatedStop = true
    recoveryCancelGeneration += 1
    recordForensicTunEvent('tun-stop-requested', {
      wasRunning: currentStatus.running,
      mode: currentStatus.mode ?? null,
      restartAttempt
    })
    lastStartOptions = null
    restartAttempt = 0
    clearRestartTimers()

    // Status contract for the renderer:
    //   'stopping'         — user just pressed Stop; cleanup is in flight.
    //                        Renderer should suppress "VPN unreachable" toasts
    //                        from ipMonitor and similar during this window.
    //   'stopped'          — cleanup finished, traffic is back to normal.
    //   'running'          — TUN is up and traffic is flowing.
    //   'killswitch-active'— TUN is down but the firewall is still blocking
    //                        leaks while we wait for retry / user action.
    //   'restarting:N/M'   — auto-restart attempt N of M is scheduled.
    //   'proxy-down'       — upstream proxy stopped responding; TUN still up.
    notifyStatus('stopping')

    // Defense-in-depth: silence the false-positive leak path before any
    // rollback runs. The renderer-side stoppingNowRef + ipMonitor IPC bridge
    // already guard against the same race, but doing it here means the
    // suppression takes effect even if the renderer hasn't received the
    // status event yet (or isn't running, e.g. during shutdown).
    ipMonitor.suspend()
    leakMonitorSuspended = true
    cancelLeakSelfTest()
    stopCompetingTunWatch()

    const cleanupErrors: string[] = []
    const rememberCleanupError = (label: string, err: unknown) => {
      const message = (err as Error)?.message || String(err)
      cleanupErrors.push(`${label}: ${message}`)
      logEvent('warn', 'tun', `${label} after stop failed`, err)
    }

    stopProxyWatchdog()
    try {
      await killOwnedRuntimeProcesses()
      if (!(await waitForOwnedRuntimeToExit())) {
        cleanupErrors.push('runtime process stop: vpnte-sing-box.exe is still running')
        logEvent('warn', 'tun', 'runtime process still running after stop')
      }
    } catch (err) {
      rememberCleanupError('runtime process stop', err)
    }

    currentStatus = {
      running: false,
      mode: 'localProxy',
      proxyAddr: null,
      proxyType: null,
      vpnProfileName: null,
      vpnProtocol: null,
      pid: null,
      warning: null,
      proxyReachable: true,
      startedAt: null,
      restartAttempt: 0
    }
    // sing-box is gone — the clash API socket is no longer listening.
    // Clear the cached port/secret so url-availability checks know to
    // tell callers "VPN is off" instead of returning ECONNREFUSED.
    clashApiInfo = null
    directProxyPort = null
    logEvent('info', 'tun', 'TUN stopped')
    recordForensicTunEvent('tun-stopped', {
      cleanupErrors
    })

    // Every cleanup step is independent. A failed taskkill or baseline rollback
    // must not prevent us from removing firewall/DNS changes; that is exactly how
    // the app can leave Windows with "VPN off, internet broken".
    try {
      const baseline = await rollbackTunNetworkBaselineIfApplied('TUN stopped')
      if (!baseline.success) {
        cleanupErrors.push(`baseline auto-rollback: ${baseline.message}`)
        logEvent('warn', 'tun', 'baseline auto-rollback after stop failed', baseline)
      }
    } catch (err) {
      rememberCleanupError('baseline auto-rollback', err)
    }

    try {
      const killSwitch = await disableKillSwitchIfActive('TUN stopped')
      if (!killSwitch.success) {
        cleanupErrors.push(`kill-switch disable: ${killSwitch.message}`)
        logEvent('warn', 'tun', 'kill-switch disable after stop failed', killSwitch)
      }
    } catch (err) {
      rememberCleanupError('kill-switch disable', err)
    }

    try {
      await rollbackPhysicalAdapterLockdownIfApplied('TUN stopped')
    } catch (err) {
      rememberCleanupError('adapter lockdown rollback', err)
    }

    try {
      await repairOrphanedPhysicalAdapterDns('TUN stopped safety repair')
    } catch (err) {
      rememberCleanupError('orphaned DNS repair', err)
    }

    if (cleanupErrors.length > 0) {
      // Resume leak detection even on a partial-cleanup failure. Suspending
      // it without ever resuming (the bug this fixes) meant a single failed
      // teardown step left leak monitoring OFF until the next app restart —
      // exactly when the user most needs it, because teardown already went
      // wrong. Resume here so the periodic monitor can re-evaluate against a
      // fresh baseline.
      resumeLeakMonitor()
      const warning = cleanupErrors.join(' | ')
      notify('warn', 'Защита отключена с предупреждениями', warning, 'vpnDisconnect')
      notifyStatus('stopped')
      return { success: true, warning }
    }

    // Cleanup finished — let the leak-detector run again. The next tunnel
    // start (or a manual recheck) will set a fresh vpnIp baseline.
    resumeLeakMonitor()
    notify('info', 'Защита выключена', 'Трафик идёт по обычному маршруту.', 'vpnDisconnect')
    notifyStatus('stopped')

    return { success: true }
    } finally {
      resumeLeakMonitor()
      stopInProgress = false
    }
  },

  async isFirewallKillSwitchActive(): Promise<boolean> {
    return isKillSwitchActive()
  },

  /**
   * Restart the tunnel reusing the last successful start options. Used by
   * split-tunnel / config hot-reload: the config (process route rules, DNS
   * profile, etc.) is regenerated on the next start(), so a stop→start cycle
   * with the SAME options applies the change without disconnecting the user
   * permanently.
   *
   * No-op (returns success) when the tunnel isn't running or when we have no
   * memory of how it was started. Snapshots lastStartOptions BEFORE stop()
   * (which clears it) and replays it.
   */
  async restartWithLastOptions(reason: string): Promise<{ success: boolean; error?: string }> {
    if (!currentStatus.running) {
      return { success: true }
    }
    const snapshot = lastStartOptions
    if (!snapshot) {
      logEvent('warn', 'tun', 'restartWithLastOptions: no last options — leaving tunnel as-is', { reason })
      return { success: false, error: 'no last start options' }
    }
    logEvent('info', 'tun', `restarting tunnel to apply config change: ${reason}`)
    const stopped = await this.stop()
    if (!stopped.success) {
      return { success: false, error: stopped.error }
    }
    // Brief pause so the runtime fully releases the TUN adapter before we
    // recreate it — mirrors the delay the old split-tunnel hot-reload used.
    await new Promise((resolve) => setTimeout(resolve, 500))
    return this.start(snapshot)
  },

  async disableFirewallKillSwitch(reason: string): Promise<{ success: boolean; message: string; skipped?: boolean }> {
    return disableKillSwitchIfActive(reason)
  },

  getStatus(): TunStatus {
    return { ...currentStatus }
  },

  onStatusChange(callback: (status: string) => void) {
    statusCallbacks.push(callback)
  }
}
