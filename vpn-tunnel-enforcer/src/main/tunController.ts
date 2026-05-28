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
  isPhysicalAdapterLockdownApplied,
  repairOrphanedPhysicalAdapterDns,
  rollbackPhysicalAdapterLockdownIfApplied
} from './physicalAdapterLockdown'
import type { VpnProfile } from './vpnProfiles'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_ADDRESS_CIDR, TUN_IPV6_ADDRESS_CIDR, TUN_IPV4_RESOLVER, TUN_IPV4_PREFIX, isOwnTunAddress, ALL_KNOWN_ALIASES } from './tunAdapter'
import { ipMonitor } from './ipMonitor'
import { cancelLeakSelfTest } from './leakSelfTest'
import { startCompetingTunWatch, stopCompetingTunWatch } from './competingTunDetector'

const exec = promisify(execCb)
const execFile = promisify(execFileCb)

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
function pickFreeLocalPort(exclude: number[] = []): Promise<number> {
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
  // 32 hex chars = 128 bits. Generated per run; never persisted.
  const bytes = new Uint8Array(16)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
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

// Auto-restart bookkeeping. We remember the last successful start params so we
// can replay them after an unexpected sing-box crash without asking the user.
// Cleared on a user-initiated stop so we don't try to "recover" from a
// deliberate shutdown.
let lastStartOptions: StartOptions | null = null
let restartAttempt = 0
let restartTimer: ReturnType<typeof setTimeout> | null = null
let stableTimer: ReturnType<typeof setTimeout> | null = null
// Set to true while inside `stop()` (and right after `start()` returns failure)
// so the onExit handler doesn't kick off a recovery loop.
let userInitiatedStop = false
const RESTART_BACKOFF_MS = [2000, 5000, 10000] as const
const STABLE_RESET_MS = 30000


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
const PROXY_CORE_PROCESS_NAMES = [
  'Happ.exe',
  'happd.exe',
  'xray.exe',
  'v2ray.exe',
  'sing-box.exe',
  'singbox.exe',
  'mihomo.exe',
  'clash.exe',
  'clash-meta.exe',
  'clash-verge.exe',
  'hiddify.exe',
  'Hiddify.exe',
  'nekoray.exe',
  'nekobox.exe',
  'shadowsocks.exe',
  'ss-local.exe',
  'trojan.exe',
  'outline.exe',
  'Outline.exe',
  'wireguard.exe',
  'openvpn.exe'
]

export function getTunRuntimeDir(): string {
  return join(app.getPath('userData'), 'tun-runtime')
}

function getBundledResource(name: string): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, name)
  }
  return join(app.getAppPath(), 'resources', name)
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

const DNS_STRATEGY = 'ipv4_only'
const BOOTSTRAP_DNS_TAG = 'dns-bootstrap'

function isDomainServer(server: unknown): boolean {
  if (typeof server !== 'string') return false
  const trimmed = server.trim()
  if (!trimmed) return false
  const unbracketed = trimmed.startsWith('[') && trimmed.endsWith(']')
    ? trimmed.slice(1, -1)
    : trimmed
  return isIP(unbracketed) === 0
}

function sanitizeProxyOutbound(outbound: Record<string, any>): { outbound: Record<string, any>; needsBootstrapDns: boolean } {
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

  const needsBootstrapDns = isDomainServer(result.server)
  if (needsBootstrapDns) {
    result.domain_resolver = {
      server: BOOTSTRAP_DNS_TAG,
      strategy: existingStrategy || legacyStrategy || DNS_STRATEGY
    }
  }

  return { outbound: result, needsBootstrapDns }
}

export function generateSingboxConfig(
  upstream: string | { outbound: Record<string, any>; proxyType?: 'socks5' | 'http' },
  proxyType: 'socks5' | 'http' = 'socks5',
  directProcessNames: string[] = [],
  options: { stealthMode?: boolean; directProxyPortOverride?: number } = {}
): object {
  // Stealth mode (TSPU/DPI bypass) toggles two knobs:
  //   1. TUN MTU 1500 → 1280 — encrypted payload sizes drift away from
  //      values DPI signature databases pattern-match for VPN traffic, and
  //      1280 is the IPv6-min-MTU floor so it always negotiates cleanly.
  //   2. tls.record_fragment on the proxy outbound (when the outbound has
  //      regular TLS, NOT Reality — Reality has its own ClientHello
  //      mimicry and fragmenting on top can break the auth handshake).
  //      record_fragment is the cheaper of the two TLS fragmenting modes
  //      offered by sing-box 1.12+; the docs explicitly recommend it as
  //      the first thing to try.
  const stealthMode = options.stealthMode === true
  const tunMtu = stealthMode ? 1280 : 1500
  const isDirectVpn = typeof upstream !== 'string'
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

  // Apply TLS record-fragmentation when stealthMode is on AND the outbound
  // has plain TLS (NOT Reality). Reality embeds auth in the structure of
  // the ClientHello that mimics the camouflage target — fragmenting on top
  // would scramble that and break Reality auth on the server side.
  if (stealthMode && proxyOutbound.tls && typeof proxyOutbound.tls === 'object') {
    const tls = proxyOutbound.tls as Record<string, any>
    const realityEnabled = tls.reality && typeof tls.reality === 'object'
      && tls.reality.enabled !== false
    if (!realityEnabled) {
      tls.record_fragment = true
    }
  }

  const logPath = join(getTunRuntimeDir(), 'sing-box.log').replace(/\\/g, '/')
  const privateRanges = [
    '127.0.0.0/8',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '169.254.0.0/16',
    '224.0.0.0/4',
    '::1/128',
    'fc00::/7',
    'fe80::/10',
    'ff00::/8'
  ]

  // Allocate a fresh clash-API port+secret for this run. Bound to
  // 127.0.0.1 so it is only reachable from the same machine, and the
  // secret is mandatory — anyone running another userland process on
  // the box still cannot probe outbounds without knowing the token.
  const clashPort = randomLocalPort()
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

  return {
    log: { level: 'debug', timestamp: true, output: logPath },
    dns: {
      // sing-box 1.13.x rejects `detour: direct-out` on DNS servers when the
      // direct outbound has no explicit override/bind options ("detour to an
      // empty direct outbound makes no sense"). The recommended replacement
      // for bootstrap DNS (resolving the proxy hostname before the tunnel
      // is up) is `type: local` — sing-box delegates the lookup to the
      // platform native resolver, which still uses the physical interface
      // because we ask it before strict_route hijacks the system DNS.
      servers: [
        { type: 'tls', tag: 'dns-remote', server: '1.1.1.1', detour: 'proxy-out' },
        { type: 'tls', tag: 'dns-backup', server: '8.8.8.8', detour: 'proxy-out' },
        ...(needsBootstrapDns
          ? [{ type: 'local', tag: BOOTSTRAP_DNS_TAG }]
          : [])
      ],
      strategy: DNS_STRATEGY
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        interface_name: TUN_ADAPTER_ALIAS,
        address: [TUN_IPV4_ADDRESS_CIDR, TUN_IPV6_ADDRESS_CIDR],
        mtu: tunMtu,
        auto_route: true,
        strict_route: true,
        route_address: ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'],
        stack: 'system'
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
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        { ip_cidr: privateRanges, outbound: 'direct-out' },
        { ip_cidr: ['::/0'], outbound: 'block-out' },
        // HTTP proxy outbound has no UDP transport at all, so every UDP packet
        // (QUIC/HTTP3, gaming, raw DNS that escaped hijack) would silently time
        // out. Explicitly block UDP/443 so browsers fail fast on QUIC and fall
        // back to TCP TLS instead of waiting for QUIC to time out on each load.
        ...(proxyType === 'http'
          ? [{ network: 'udp', port: 443, outbound: 'block-out' }]
          : []),
        // VLESS+Reality with `network: tcp` cannot carry UDP at all — sing-box
        // would otherwise let UDP fall through to `final: proxy-out` and stall
        // until the per-flow timeout. Blocking all UDP up front fails fast and,
        // more importantly, prevents UDP-only protocols (QUIC, gaming) from
        // looking "open" while actually being a leak/blackhole. We only insert
        // this for tcp-only outbounds; UDP-capable outbounds keep UDP routed.
        ...(typeof proxyOutbound.network === 'string' && proxyOutbound.network === 'tcp'
          ? [{ network: 'udp', outbound: 'block-out' }]
          : [])
      ],
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
      }
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
  const { stdout } = await exec(command, {
    windowsHide: true,
    timeout,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })
  return stdout
}

async function isSingboxRunning(): Promise<boolean> {
  try {
    const runtimeExe = join(getTunRuntimeDir(), RUNTIME_EXE_NAME)
    const stdout = await runPowerShell(`
$p=${psQuote(runtimeExe)}
@(Get-CimInstance Win32_Process -Filter "Name='${RUNTIME_EXE_NAME}'" -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath -eq $p }).Count
`, 5000)
    return parseInt(String(stdout).trim() || '0', 10) > 0
  } catch {
    return false
  }
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function killRuntimeProcess(imageName: string, executablePath: string): Promise<void> {
  const command =
    'powershell -NoProfile -ExecutionPolicy Bypass -Command ' +
    `"Get-CimInstance Win32_Process -Filter \\\"Name='${imageName}'\\\" | ` +
    `Where-Object { $_.ExecutablePath -eq ${psQuote(executablePath)} } | ` +
    `ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"`

  return execElevated(command, { timeout: 15000 }).then(() => undefined).catch(() => undefined)
}

async function killOwnedRuntimeProcesses(): Promise<void> {
  const runtimeDir = getTunRuntimeDir()
  await killRuntimeProcess(RUNTIME_EXE_NAME, join(runtimeDir, RUNTIME_EXE_NAME))
  await killRuntimeProcess('sing-box.exe', join(runtimeDir, 'sing-box.exe'))
  await killRuntimeProcess('sing-box.exe', getBundledResource('sing-box.exe'))
}

async function waitForOwnedRuntimeToExit(timeoutMs = 3000): Promise<boolean> {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (!(await isSingboxRunning())) return true
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  return !(await isSingboxRunning())
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
    try {
      const stdout = await runPowerShell(
        `(Get-NetAdapter -Name '${TUN_ADAPTER_ALIAS}' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Measure-Object).Count`,
        3000
      )
      if (parseInt(String(stdout).trim() || '0', 10) > 0) {
        return true
      }
    } catch {
      // Fall through and retry — Get-NetAdapter occasionally fails transiently.
    }
    await new Promise(r => setTimeout(r, 200))
  }
  return false
}

async function removeStaleTunInterface(): Promise<void> {
  if (process.platform !== 'win32') return
  // Sweep over BOTH the live alias (TUN_ADAPTER_ALIAS) AND the legacy
  // 'VPNTE-TUN' name shipped by older builds. Without the legacy pass an
  // upgrading user could end up with two ghost adapters fighting over the
  // default route.
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
        Write-Host '__VPNTE_DONE__ disabled'
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
  { label: 'ipify', url: 'https://api.ipify.org' },
  { label: 'myip', url: 'https://api.myip.com' },
  { label: '2ip', url: 'https://2ip.ru' }
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

async function validateProxyFullTunnel(
  host: string,
  port: number,
  proxyType: 'socks5' | 'http'
): Promise<{ ok: boolean; message?: string; directIp: string | null; proxyIps: Array<{ label: string; ip: string | null; error?: string }> }> {
  if (process.platform !== 'win32') return { ok: true, directIp: null, proxyIps: [] }

  const proxyUrl = curlProxyUrl(host, port, proxyType)
  const directIp = await fetchPublicIpDirect()
  const proxyIps: Array<{ label: string; ip: string | null; error?: string }> = []
  for (const check of PROXY_PUBLIC_IP_CHECKS) {
    try {
      const body = await curlText(['-4', '-L', '-sS', '--max-time', '10', '--connect-timeout', '6', '--proxy', proxyUrl, check.url], 14000)
      proxyIps.push({ label: check.label, ip: extractPublicIpv4(body) })
    } catch (err: any) {
      proxyIps.push({ label: check.label, ip: null, error: err?.message || String(err) })
    }
  }

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
  upstream: string | { outbound: Record<string, any>; proxyType?: 'socks5' | 'http' },
  proxyType: 'socks5' | 'http',
  directProcessNames: string[],
  options: { stealthMode?: boolean } = {}
): Promise<{ singbox: string; config: string }> {
  const runtimeDir = getTunRuntimeDir()
  await mkdir(runtimeDir, { recursive: true })

  const singboxSrc = getBundledResource('sing-box.exe')
  const wintunSrc = getBundledResource('wintun.dll')
  const singboxDst = join(runtimeDir, RUNTIME_EXE_NAME)
  const wintunDst = join(runtimeDir, 'wintun.dll')
  const configPath = join(runtimeDir, 'sing-box.json')
  const logPath = join(runtimeDir, 'sing-box.log')
  const logPrevPath = join(runtimeDir, 'sing-box.prev.log')

  // Rotate previous log so each run has a clean slate; previous one kept as .prev.log.
  try {
    await stat(logPath)
    await rename(logPath, logPrevPath).catch(() => undefined)
  } catch {
    // no existing log — nothing to rotate
  }

  // Copy binaries to a writable runtime dir (Program Files is read-only for normal users;
  // also ensures sing-box.exe and wintun.dll are in the same directory).
  await access(singboxSrc)
  await access(wintunSrc)
  await copyFile(singboxSrc, singboxDst)
  await copyFile(wintunSrc, wintunDst)

  // Pre-resolve the mixed-direct-in port via the OS so we never land inside a
  // Windows Hyper-V/WSL excluded port range (which causes sing-box to fail
  // bind with WSAEACCES). generateSingboxConfig falls back to randomLocalPort
  // if no override is supplied, so direct callers (e.g. tests) still work.
  let directProxyPortOverride: number | undefined
  try {
    directProxyPortOverride = await pickFreeLocalPort()
  } catch (err) {
    logEvent('warn', 'tun', 'pickFreeLocalPort failed — falling back to random port', err)
  }

  const config = generateSingboxConfig(upstream, proxyType, directProcessNames, {
    ...options,
    directProxyPortOverride
  })
  await writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8')

  return { singbox: singboxDst, config: configPath }
}

export const tunController = {
  async start(proxyAddrOrOpts: string | StartOptions): Promise<{ success: boolean; error?: string; warning?: string | null }> {
    if (currentStatus.running) {
      return { success: false, error: 'TUN уже запущен' }
    }
    if (startInProgress) {
      return { success: false, error: 'Запуск защиты уже выполняется' }
    }
    startInProgress = true
    const finishStart = <T extends { success: boolean; error?: string; warning?: string | null }>(result: T): T => {
      startInProgress = false
      return result
    }

    // A new start() always reopens the auto-restart window. If a pending
    // restart timer is still ticking from a crash recovery, cancel it — the
    // user (or the recovery loop) is taking matters into their own hands.
    userInitiatedStop = false
    if (restartTimer) {
      clearTimeout(restartTimer)
      restartTimer = null
    }

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

    if (mode === 'localProxy' && !proxyAddr) {
      return finishStart({ success: false, error: 'Не указан upstream proxy' })
    }
    if (mode === 'directVpn' && !vpnProfile) {
      return finishStart({ success: false, error: 'Не выбран Direct VPN профиль' })
    }

    // ---------- Pre-flight 1: detect another VPN/TUN ----------
    // We no longer abort here: Happ often exposes both a local proxy and its own TUN.
    // Instead we exclude known Happ core processes from this TUN to avoid proxy loops.
    const foreign = detectForeignTun()
    if (foreign) {
      const message =
        `Уже активен другой системный туннель: ${foreign}. Второй TUN поверх него не запускается, ` +
        'потому что так чаще всего ломаются DNS и интернет. Оставьте текущий VPN/TUN включенным или выключите TUN в VPN-клиенте и оставьте только локальный proxy.'
      logEvent('warn', 'tun', 'start refused because another TUN/VPN is already active', { foreign, mode, proxyAddr, proxyType })
      return finishStart({ success: false, error: message })
    }
    const warning = null

    let proxyOwnerProcessNames: string[] = []
    let proxyOwnerProgramPaths: string[] = []
    if (mode === 'localProxy') {
      // ---------- Pre-flight 2: proxy must actually be listening ----------
      // If Happ is closed or in TUN mode, port 10808 isn't listening — without this check
      // sing-box would start TUN, hijack all routes, and then 100% of traffic would blackhole.
      let parsedProxy: { host: string; port: number }
      try {
        parsedProxy = parseProxyAddress(proxyAddr)
      } catch (err: any) {
        return finishStart({ success: false, error: err.message || String(err) })
      }

      const { host, port } = parsedProxy
      const proxyAlive = await probeTcp(host, port, 2000)
      if (!proxyAlive) {
        logEvent('error', 'tun', 'start refused because upstream proxy is not reachable', { proxyAddr, proxyType })
        return finishStart({
          success: false,
          error:
            `Прокси ${proxyAddr} недоступен. Убедитесь, что Happ запущен в режиме Proxy ` +
            `и слушает порт ${port}.`
        })
      }
      logEvent('info', 'tun', 'upstream proxy is reachable', { proxyAddr, proxyType })

      const proxyFullTunnel = await validateProxyFullTunnel(host, port, proxyType)
      logEvent(proxyFullTunnel.ok ? 'info' : 'error', 'tun', 'upstream proxy full-tunnel check', proxyFullTunnel)
      if (!proxyFullTunnel.ok) {
        return finishStart({ success: false, error: proxyFullTunnel.message || 'Upstream proxy не прошёл проверку полного туннеля' })
      }

      const proxyOwnerProcesses = await getProxyOwnerProcesses(host, port)
      proxyOwnerProcessNames = uniqueProcessNames(proxyOwnerProcesses.map((process) => process.name))
      proxyOwnerProgramPaths = [...new Set(proxyOwnerProcesses.map((process) => process.path).filter((path): path is string => Boolean(path)))]
      if (proxyOwnerProcesses.length > 0) {
        logEvent('info', 'tun', 'detected local proxy owner process for direct-out exclusion', {
          proxyAddr,
          processNames: proxyOwnerProcessNames,
          processPaths: proxyOwnerProgramPaths
        })
      }
    } else {
      logEvent('info', 'tun', 'starting Direct VPN profile', {
        protocol: vpnProfile?.protocol,
        name: vpnProfile?.name
      })
    }

    // Kill only VPNTE-owned runtime binaries. Never kill generic sing-box.exe elsewhere:
    // Happ may use its own sing-box/xray core.
    if (await isSingboxRunning()) {
      await killOwnedRuntimeProcesses()
      if (!(await waitForOwnedRuntimeToExit())) {
        return finishStart({ success: false, error: 'Не удалось остановить предыдущий vpnte-sing-box.exe. Завершите его в Диспетчере задач и повторите.' })
      }
    } else {
      await killRuntimeProcess('sing-box.exe', join(getTunRuntimeDir(), 'sing-box.exe'))
    }
    await removeStaleTunInterface()

    let runtime: { singbox: string; config: string }
    try {
      runtime = await prepareRuntime(
        mode === 'directVpn' && vpnProfile
          ? { outbound: vpnProfile.outbound, proxyType }
          : proxyAddr,
        proxyType,
        proxyOwnerProcessNames,
        { stealthMode: startOptions.stealthMode === true }
      )
      await exec(`"${runtime.singbox}" check -c "${runtime.config}"`)
    } catch (err: any) {
      logEvent('error', 'tun', 'failed to prepare TUN runtime', err)
      return finishStart({ success: false, error: `Не удалось подготовить TUN-окружение: ${err.stderr || err.message || err}` })
    }

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

    // Adapter lockdown: disable IPv6 + force DNS to TUN on every physical
    // adapter. This is the only thing that catches DNS-over-HTTPS leaks (a
    // browser that bypasses NRPT) and IPv6 default-route leaks (a browser
    // that prefers a physical adapter's IPv6 default route over our TUN's
    // split-default IPv6 routes). Reverted on stop (and on crash recovery).
    let adapterLockdownEngaged = false
    let adapterLockdownWarning: string | null = null
    logEvent('info', 'tun', 'adapter lockdown decision', {
      wantAdapterLockdown,
      publicWifiCompatibility,
      reason: wantAdapterLockdown
        ? 'strictAdapterLockdown is ON in settings — will apply'
        : 'strictAdapterLockdown is OFF in settings — will not apply'
    })
    if (wantAdapterLockdown) {
      try {
        const lock = await applyPhysicalAdapterLockdown(TUN_IPV4_RESOLVER, {
          forceDns: !publicWifiCompatibility
        })
        logEvent('info', 'tun', 'adapter lockdown result', {
          applied: lock.applied,
          adapters: lock.adapters,
          warnings: lock.warnings
        })
        if (lock.applied) {
          adapterLockdownEngaged = true
          if (lock.warnings.length > 0) {
            adapterLockdownWarning = `Lockdown с замечаниями: ${lock.warnings.join('; ')}`
            if (killSwitchEngaged) await disableKillSwitch('adapter lockdown warnings before start').catch(() => undefined)
            await rollbackPhysicalAdapterLockdownIfApplied('adapter lockdown warnings before start').catch(() => undefined)
            return finishStart({ success: false, error: adapterLockdownWarning })
          }
        } else {
          adapterLockdownWarning = `Lockdown не применился: ${lock.warnings.join('; ') || 'нет физических адаптеров'}`
          logEvent('warn', 'tun', 'physical adapter lockdown did not apply', lock)
          if (killSwitchEngaged) await disableKillSwitch('adapter lockdown did not apply before start').catch(() => undefined)
          return finishStart({ success: false, error: adapterLockdownWarning })
        }
      } catch (err: any) {
        adapterLockdownWarning = `Lockdown упал: ${err?.message ?? String(err)}`
        logEvent('warn', 'tun', 'physical adapter lockdown threw', err)
        if (killSwitchEngaged) await disableKillSwitch('adapter lockdown threw before start').catch(() => undefined)
        return finishStart({ success: false, error: adapterLockdownWarning })
      }
    }

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
          // sing-box never came up. Tear down the kill-switch we just installed
          // — otherwise the user is locked out of the internet for no reason.
          // Skip the teardown when we are about to retry: the next attempt
          // benefits from the rules already being in place.
          if (killSwitchEngaged && !canRetryPortBind) {
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
            setTimeout(() => {
              tunController.start(retryOpts).then((res) => {
                if (!res.success) {
                  logEvent('error', 'tun', 'WSAEACCES retry failed', { error: res.error })
                  notify('error', 'Не удалось запустить защиту', res.error || 'Неизвестная ошибка')
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
          logEvent(error ? 'error' : 'warn', 'tun', 'sing-box process exited', { error: error?.message, stderr })
        } else {
          logEvent('info', 'tun', 'sing-box process exited')
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
            notify('warn', 'sing-box упал', `Перезапуск через ${Math.round(delay / 1000)} с (попытка ${attempt}/${RESTART_BACKOFF_MS.length}).`)
            // Surface the restart attempt to the renderer so the hero card can
            // say "Перезапускаем защиту…" instead of "Файрвол блокирует".
            notifyStatus(`restarting:${attempt}/${RESTART_BACKOFF_MS.length}`)

            clearRestartTimers()
            const optsSnapshot = lastStartOptions
            restartTimer = setTimeout(() => {
              restartTimer = null
              tunController.start(optsSnapshot).then((res) => {
                if (!res.success) {
                  logEvent('error', 'tun', 'auto-restart attempt failed', { attempt, error: res.error })
                  notify('error', 'Не удалось перезапустить защиту', res.error || 'Неизвестная ошибка')
                  if (killSwitchEngaged) notifyStatus('killswitch-active')
                  else notifyStatus('stopped')
                }
              }).catch((err) => {
                logEvent('error', 'tun', 'auto-restart attempt threw', err)
                notify('error', 'Не удалось перезапустить защиту', err?.message || String(err))
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
            logEvent('error', 'tun', 'auto-restart gave up — too many failures', {
              attempts: restartAttempt
            })
            notify('error', 'Защита остановилась', 'Превышено число попыток перезапуска. Включите защиту вручную.')
            // All retries burned through. The VPN is not coming back without
            // user intervention. Keeping the kill-switch active at this point
            // would permanently lock out the user's internet for no benefit,
            // so we disable it (idempotent — does nothing if already off) and
            // restore connectivity.
            disableKillSwitchIfActive('auto-restart exhausted — restoring internet').catch(err =>
              logEvent('warn', 'tun', 'kill-switch disable after exhausted retries failed', err)
            )
          }

          if (killSwitchEngaged && restartAttempt < RESTART_BACKOFF_MS.length) {
            logEvent(
              'warn',
              'tun',
              'sing-box exited unexpectedly — keeping firewall kill-switch active'
            )
            notify('warn', 'sing-box упал', 'Файрвол блокирует трафик, чтобы не было утечки IP. Включите защиту заново.')
            // Tell the UI traffic is now firewall-blocked, not just "stopped".
            notifyStatus('killswitch-active')
            return
          }
          notify('warn', 'Защита остановилась', 'sing-box завершил работу.')
          notifyStatus('stopped')
        }
      }

      isProcessElevated().then((elevated) => {
        if (elevated) {
          execCb(cmd, { windowsHide: true, maxBuffer: 1024 * 1024 }, (error, _stdout, stderr) => onExit(error, stderr))
        } else {
          sudo.exec(cmd, { name: 'VPN Tunnel Enforcer' }, (error, _stdout, stderr) => onExit(error, String(stderr || '')))
        }
      }).catch((error) => onExit(error))

      // Poll for sing-box.exe presence.
      let attempts = 0
      const maxAttempts = 15 // 15 * 500ms = 7.5s
      let successHandled = false
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

          // Engage the firewall kill-switch NOW, after sing-box is up. The
          // kill-switch installs an Allow rule scoped to -InterfaceAlias
          // TUN_ADAPTER_ALIAS, and Windows Firewall validates that alias when the
          // rule is created. If we engage too early the rule fails silently,
          // DefaultOutboundAction=Block kicks in, and traffic to the TUN dies.
          if (wantKillSwitch) {
            const tunReady = await waitForTunInterface(5000)
            if (!tunReady) {
              logEvent(
                'warn',
                'tun',
                `${TUN_ADAPTER_ALIAS} did not reach Status=Up within 5s — skipping kill-switch to avoid blocking traffic`
              )
              killSwitchWarning =
                'TUN-адаптер не поднялся за 5 с — kill-switch пропущен, чтобы не блокировать интернет.'
            } else if (await isKillSwitchActive()) {
              // Auto-restart path: rules left in place by the previous run are
              // still doing their job, no need to reinstall (which would also
              // briefly drop and re-add allow rules). Just take ownership.
              killSwitchEngaged = true
              logEvent('info', 'tun', 'kill-switch already active — reusing existing rules')
            } else {
              const ks = await enableKillSwitch({
                singboxExePath: runtime.singbox,
                proxyOwnerProgramPaths
              })
              if (ks.success) {
                killSwitchEngaged = true
                logEvent('info', 'tun', 'kill-switch engaged after TUN interface came up')
              } else {
                logEvent(
                  'warn',
                  'tun',
                  'firewall kill-switch failed to engage after TUN came up — continuing without it',
                  ks
                )
                killSwitchWarning = `Kill-switch не включился: ${ks.message}. VPN работает без дополнительной защиты от утечек.`
              }
            }
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
          if (mode === 'localProxy') startProxyWatchdog(proxyAddr)
          logEvent('info', 'tun', 'TUN started', {
            mode,
            proxyAddr,
            proxyType,
            vpnProtocol: vpnProfile?.protocol,
            warning: combinedWarning,
            killSwitch: killSwitchEngaged,
            restartAttempt
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
          userInitiatedStop = false

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
            notify('info', 'Защита восстановлена', `Подключение к VPN-серверу восстановлено после попытки ${restartAttempt}.`)
          } else if (!combinedWarning) {
            notify('info', 'Защита включена', 'Весь трафик идёт через VPN.')
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
            logEvent('error', 'tun', 'sing-box did not start within timeout', { proxyAddr, proxyType })
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
      }, 500)
    })
  },

  async stop(): Promise<{ success: boolean; error?: string }> {
    // Mark this as a user-initiated stop BEFORE we kill sing-box, so the
    // exit handler doesn't kick off auto-restart. Also clear any pending
    // restart timer from a previous crash so we don't fight ourselves.
    userInitiatedStop = true
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
    notify('info', 'Защита выключена', 'Трафик идёт по обычному маршруту.')
    notifyStatus('stopped')

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
      return { success: false, error: cleanupErrors.join(' | ') }
    }

    // Cleanup finished — let the leak-detector run again. The next tunnel
    // start (or a manual recheck) will set a fresh vpnIp baseline.
    ipMonitor.resume()

    return { success: true }
  },

  async isFirewallKillSwitchActive(): Promise<boolean> {
    return isKillSwitchActive()
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
