/**
 * Key Health Checker — probes individual VPN keys to tell which ones are
 * still alive after a subscription's free trial expires.
 *
 * Strategy: TCP connect always; a TLS handshake to the outbound's
 * `server_name` ONLY when it is safe to put that name on the wire.
 *
 * SNI-leak safety (important on RU TSPU networks): a TLS ClientHello carries
 * `server_name` in plaintext. For Reality keys that name is a camouflage
 * domain (e.g. `www.microsoft.com`) — harmless to leak. For plain-TLS keys
 * it is the provider's real front, and leaking it to a DPI box can get the
 * destination IP blackholed for minutes. So we only do the TLS rung for
 * Reality outbounds (or when the probe is genuinely tunnelled); otherwise we
 * stop at the TCP connect, which carries no SNI.
 *
 * Routing note: when the tunnel is up we dial through sing-box's
 * `mixed-direct-in` SOCKS5 inbound. NOTE that inbound is routed to
 * `direct-out` (it is the local "direct proxy" for split-tunnel/diagnostics),
 * so the probe still egresses via the physical adapter — it tests "is this
 * endpoint reachable from this network", NOT "does it work through proxy-out".
 * That is the right signal for post-trial failover (we want to know if the
 * sibling server's IP answers), and routing the probe through sing-box keeps
 * it consistent with the OS routing state while TUN owns the default route.
 */

import { spawn } from 'child_process'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { Socket } from 'net'
import { tmpdir } from 'os'
import { join } from 'path'
import { connect as tlsConnect } from 'tls'
import Store from 'electron-store'
import { SocksClient } from 'socks'
import { logEvent } from './appLogger'
import { buildBootstrapRouteAttempts, type BootstrapRouteAttempt } from './bootstrapRoute'
import { settingsStore } from './settings'
import { getBundledResource, getDirectProxyPort, pickFreeLocalPort, sanitizeProxyOutbound, tunController } from './tunController'
import type { ServerProfile } from '../shared/ipc-types'

const PROBE_TIMEOUT_MS = 4000
const HY2_PROBE_TIMEOUT_MS = 8000
const HY2_PROBE_DESTINATION = { host: '1.1.1.1', port: 443 }
const HEALTH_CHECK_CONCURRENCY = 5

export interface KeyHealthResult {
  profileId: string
  online: boolean
  latencyMs: number | null
  /** 'tcp-failed' | 'tls-failed' | 'hy2-udp-blocked' | 'hy2-auth-failed' | etc. */
  reason?: string
}

interface ProbeTarget {
  host: string
  port: number
  serverName: string
  needsTls: boolean
  /**
   * True when a TLS handshake to `serverName` would put the provider's REAL
   * front domain on the wire (plain TLS). False for Reality outbounds, where
   * `server_name` is a camouflage domain that is safe to leak. We only run
   * the TLS rung when this is false, to avoid SNI-blackholing on TSPU nets.
   */
  tlsLeaksSni: boolean
}

function pickServerName(outbound: Record<string, any>, fallback: string): string {
  // sing-box layout we generate: outbound.tls.server_name (real or front
  // SNI). Reality configs round-tripped from xray may also carry
  // outbound.tls.reality.server_name. Bare server is the last resort.
  const tls = outbound.tls && typeof outbound.tls === 'object' ? outbound.tls : null
  if (tls) {
    const direct = typeof tls.server_name === 'string' && tls.server_name.trim()
    if (direct) return tls.server_name.trim()
    const reality = tls.reality && typeof tls.reality === 'object' ? tls.reality : null
    if (reality && typeof reality.server_name === 'string' && reality.server_name.trim()) {
      return reality.server_name.trim()
    }
  }
  return fallback
}

export function describeProbeTarget(profile: ServerProfile): ProbeTarget | null {
  const outbound = profile.outbound && typeof profile.outbound === 'object' ? profile.outbound : null
  // Prefer outbound's server/port — that's what sing-box would dial. The
  // top-level ServerProfile copy is a UI display cache.
  const host = outbound && typeof outbound.server === 'string' && outbound.server.trim()
    ? outbound.server.trim()
    : (typeof profile.server === 'string' ? profile.server.trim() : '')
  const port = outbound && Number.isInteger(outbound.server_port)
    ? Number(outbound.server_port)
    : (Number.isInteger(profile.port) ? Number(profile.port) : 0)
  if (!host || !port) return null

  const serverName = outbound ? pickServerName(outbound, host) : host
  // Plain shadowsocks (and rarely plain hysteria2) carry no TLS. Settle for
  // a TCP-only probe — connect success is the best we can extract without
  // sending protocol-specific bytes.
  const tls = outbound && outbound.tls && typeof outbound.tls === 'object' ? outbound.tls : null
  const needsTls = tls ? tls.enabled !== false : false
  // Reality outbounds present a camouflage SNI — safe to leak. Plain TLS
  // would leak the provider's real front, so we must NOT do a TLS handshake
  // for those over a direct (untunnelled) path.
  const isReality = Boolean(tls && tls.reality && typeof tls.reality === 'object' && tls.reality.enabled !== false)
  const tlsLeaksSni = needsTls && !isReality

  return { host, port, serverName, needsTls, tlsLeaksSni }
}

function shouldProbeViaTunnel(): { host: string; port: number } | null {
  try {
    const status = tunController.getStatus()
    if (!status.running) return null
    const port = getDirectProxyPort()
    if (!port) return null
    return { host: '127.0.0.1', port }
  } catch {
    return null
  }
}

function currentHealthProbeRoutes(): BootstrapRouteAttempt[] {
  try {
    const settings = settingsStore.get()
    return buildBootstrapRouteAttempts({
      mode: settings.bootstrapRouteMode,
      proxyAddr: settings.proxyOverride,
      proxyType: settings.proxyType
    })
  } catch {
    return buildBootstrapRouteAttempts({ mode: 'auto' })
  }
}

async function openTcpDirect(host: string, port: number, timeoutMs: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = new Socket()
    let settled = false
    const finish = (err: Error | null) => {
      if (settled) return
      settled = true
      if (err) {
        try { socket.destroy() } catch { /* ignore */ }
        reject(err)
      } else {
        resolve(socket)
      }
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(null))
    socket.once('error', err => finish(err))
    socket.once('timeout', () => finish(new Error('timeout')))
    socket.connect(port, host)
  })
}

async function openTcpViaSocks(socks: { host: string; port: number }, host: string, port: number, timeoutMs: number): Promise<Socket> {
  // SocksClient's `timeout` covers the proxy command but not the dial to
  // the proxy itself. Wrap the whole thing so we never hang forever when
  // sing-box's inbound stalls.
  const connectPromise = SocksClient.createConnection({
    proxy: { host: socks.host, port: socks.port, type: 5 },
    command: 'connect',
    destination: { host, port },
    timeout: timeoutMs
  }).then(({ socket }) => socket as Socket)

  const timeoutPromise = new Promise<Socket>((_, reject) => {
    setTimeout(() => reject(new Error('timeout')), timeoutMs)
  })

  return Promise.race([connectPromise, timeoutPromise])
}

async function openTcpViaHttpProxy(proxy: { host: string; port: number }, host: string, port: number, timeoutMs: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = new Socket()
    let settled = false
    let buffer = ''
    const finish = (err: Error | null) => {
      if (settled) return
      settled = true
      socket.removeAllListeners('data')
      if (err) {
        try { socket.destroy() } catch { /* ignore */ }
        reject(err)
      } else {
        resolve(socket)
      }
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => {
      socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nProxy-Connection: keep-alive\r\n\r\n`)
    })
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      if (!buffer.includes('\r\n\r\n')) return
      if (/^HTTP\/1\.[01] 2\d\d\b/i.test(buffer)) finish(null)
      else finish(new Error(buffer.split(/\r?\n/, 1)[0] || 'http proxy connect failed'))
    })
    socket.once('error', err => finish(err))
    socket.once('timeout', () => finish(new Error('timeout')))
    socket.connect(proxy.port, proxy.host)
  })
}

function parseProxyEndpoint(addr: string | undefined): { host: string; port: number } | null {
  if (!addr) return null
  const sep = addr.lastIndexOf(':')
  if (sep <= 0) return null
  const host = addr.slice(0, sep)
  const port = Number(addr.slice(sep + 1))
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null
  return { host, port }
}

async function openTcpForRoute(route: BootstrapRouteAttempt, host: string, port: number, timeoutMs: number): Promise<Socket> {
  if (route.kind === 'direct') return openTcpDirect(host, port, timeoutMs)
  const proxy = parseProxyEndpoint(route.proxyAddr)
  if (!proxy) throw new Error('invalid proxy endpoint')
  if (route.proxyType === 'http') return openTcpViaHttpProxy(proxy, host, port, timeoutMs)
  return openTcpViaSocks(proxy, host, port, timeoutMs)
}

function isHysteria2Profile(profile: ServerProfile): boolean {
  const outboundType = profile.outbound && typeof profile.outbound === 'object'
    ? String(profile.outbound.type || '').toLowerCase()
    : ''
  return outboundType === 'hysteria2' || String(profile.protocol || '').toLowerCase() === 'hysteria2'
}

export function classifyHysteria2ProbeFailure(logText: string, errorText = ''): string {
  const text = `${logText}\n${errorText}`.toLowerCase()
  if (!text.trim()) return 'hy2-handshake-failed'
  if (/unknown field|decode config|parse config|invalid|unsupported|missing required|check outbound/.test(text)) {
    return 'hy2-config-failed'
  }
  if (/auth|authentication|unauthori[sz]ed|password|bad key|permission denied|obfs|salamander/.test(text)) {
    return 'hy2-auth-failed'
  }
  if (/no recent network activity|handshake.*timeout|timeout|deadline exceeded|i\/o timeout|network is unreachable|host unreachable|operation timed out|udp/.test(text)) {
    return 'hy2-udp-blocked'
  }
  if (/tls|certificate|x509|server name|sni/.test(text)) {
    return 'hy2-tls-failed'
  }
  return 'hy2-handshake-failed'
}

async function waitForLocalSocks(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError: unknown = null
  while (Date.now() < deadline) {
    try {
      const socket = await openTcpDirect('127.0.0.1', port, 300)
      try { socket.destroy() } catch { /* ignore */ }
      return
    } catch (err) {
      lastError = err
      await new Promise(resolve => setTimeout(resolve, 100))
    }
  }
  throw lastError instanceof Error ? lastError : new Error('local probe inbound did not start')
}

async function readProbeLog(logPath: string): Promise<string> {
  try {
    return await readFile(logPath, 'utf8')
  } catch {
    return ''
  }
}

async function checkHysteria2Health(profile: ServerProfile): Promise<KeyHealthResult> {
  if (!profile.outbound || typeof profile.outbound !== 'object') {
    return { profileId: profile.id, online: false, latencyMs: null, reason: 'no-outbound' }
  }

  const startedAt = Date.now()
  const workDir = await mkdtemp(join(tmpdir(), 'vpnte-hy2-probe-'))
  const logPath = join(workDir, 'sing-box.log')
  const configPath = join(workDir, 'sing-box.json')
  let child: ReturnType<typeof spawn> | null = null
  let childOutput = ''

  try {
    const inboundPort = await pickFreeLocalPort()
    const { outbound, needsBootstrapDns } = sanitizeProxyOutbound({ ...profile.outbound, tag: 'proxy-out' })
    const config = {
      log: { level: 'debug', timestamp: true, output: logPath.replace(/\\/g, '/') },
      ...(needsBootstrapDns
        ? {
            dns: {
              servers: [{ type: 'local', tag: 'dns-bootstrap' }],
              strategy: 'ipv4_only'
            }
          }
        : {}),
      inbounds: [
        { type: 'mixed', tag: 'probe-in', listen: '127.0.0.1', listen_port: inboundPort }
      ],
      outbounds: [
        outbound,
        { type: 'direct', tag: 'direct-out' }
      ],
      route: {
        final: 'proxy-out',
        auto_detect_interface: true,
        ...(needsBootstrapDns ? { default_domain_resolver: 'dns-bootstrap' } : {})
      }
    }

    await writeFile(configPath, JSON.stringify(config, null, 2), 'utf8')
    child = spawn(getBundledResource('sing-box.exe'), ['run', '-c', configPath], {
      cwd: workDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    })
    child.stdout?.on('data', chunk => { childOutput += chunk.toString() })
    child.stderr?.on('data', chunk => { childOutput += chunk.toString() })
    child.on('error', err => { childOutput += `\n${err.message}` })

    await waitForLocalSocks(inboundPort, 2500)
    const socket = await openTcpViaSocks(
      { host: '127.0.0.1', port: inboundPort },
      HY2_PROBE_DESTINATION.host,
      HY2_PROBE_DESTINATION.port,
      HY2_PROBE_TIMEOUT_MS
    )
    try { socket.destroy() } catch { /* ignore */ }

    const latencyMs = Date.now() - startedAt
    logEvent('debug', 'key-health', 'HY2 probe ok', {
      profileId: profile.id,
      latencyMs,
      destination: `${HY2_PROBE_DESTINATION.host}:${HY2_PROBE_DESTINATION.port}`
    })
    return { profileId: profile.id, online: true, latencyMs }
  } catch (err: any) {
    const logText = await readProbeLog(logPath)
    const errorText = `${childOutput}\n${err?.message ?? String(err)}`
    const reason = classifyHysteria2ProbeFailure(logText, errorText)
    logEvent('debug', 'key-health', 'HY2 probe failed', {
      profileId: profile.id,
      reason,
      error: err?.message ?? String(err)
    })
    return { profileId: profile.id, online: false, latencyMs: null, reason }
  } finally {
    if (child && !child.killed) {
      try { child.kill() } catch { /* ignore */ }
    }
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined)
  }
}

async function tlsHandshake(socket: Socket, serverName: string, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false
    const finish = (err: Error | null) => {
      if (settled) return
      settled = true
      try { tls.destroy() } catch { /* ignore */ }
      try { socket.destroy() } catch { /* ignore */ }
      if (err) reject(err); else resolve()
    }
    // rejectUnauthorized:false — a successful handshake is enough proof the
    // front is serving. Reality fronts present mTLS-style real certs we'd
    // pass anyway, and non-Reality fronts often use self-signed certs that
    // cycle out of sync with the keys themselves.
    const tls = tlsConnect({ socket, servername: serverName, rejectUnauthorized: false })
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs)
    tls.once('secureConnect', () => { clearTimeout(timer); finish(null) })
    tls.once('error', err => {
      clearTimeout(timer)
      finish(err instanceof Error ? err : new Error(String(err)))
    })
  })
}

/** Probe a single ServerProfile's outbound. Always resolves; never throws. */
export async function checkProfileHealth(profile: ServerProfile): Promise<KeyHealthResult> {
  if (isHysteria2Profile(profile)) {
    return checkHysteria2Health(profile)
  }

  const target = describeProbeTarget(profile)
  if (!target) {
    return { profileId: profile.id, online: false, latencyMs: null, reason: 'no-host' }
  }

  const tunnel = shouldProbeViaTunnel()
  const start = Date.now()
  let socket: Socket | null = null
  let usedRoute: BootstrapRouteAttempt | null = null
  const errors: string[] = []
  try {
    for (const route of currentHealthProbeRoutes()) {
      const effectiveRoute: BootstrapRouteAttempt =
        route.kind === 'direct' && tunnel
          ? {
              ...route,
              id: 'direct-out',
              kind: 'localProxy',
              label: 'через sing-box direct-out',
              proxyAddr: `${tunnel.host}:${tunnel.port}`,
              proxyType: 'socks5'
            }
          : route
      try {
        socket = await openTcpForRoute(effectiveRoute, target.host, target.port, PROBE_TIMEOUT_MS)
        usedRoute = effectiveRoute
        break
      } catch (err: any) {
        errors.push(`${effectiveRoute.label}: ${err?.message ?? String(err)}`)
      }
    }
    if (!usedRoute || !socket) throw new Error(errors.join(' | ') || 'no bootstrap route succeeded')
  } catch (err: any) {
    const reason = errors.some(line => /timeout/i.test(line)) ? 'timeout' : 'tcp-failed'
    logEvent('debug', 'key-health', 'probe TCP failed', {
      profileId: profile.id, host: target.host, port: target.port,
      viaTunnel: Boolean(tunnel), route: usedRoute?.label ?? null, errors
    })
    return { profileId: profile.id, online: false, latencyMs: null, reason }
  }
  if (!socket) return { profileId: profile.id, online: false, latencyMs: null, reason: 'tcp-failed' }

  // Decide whether to run the TLS rung. We skip it when the handshake would
  // leak the provider's real front SNI over a direct path (tlsLeaksSni) —
  // a TCP connect success is then our "online" verdict. Reality keys
  // (tlsLeaksSni=false) still get the full handshake since their SNI is
  // camouflage. If a future build adds a real proxy-out probe path, the
  // `tunnel` check here can be widened to allow TLS for plain-TLS keys too.
  const runTls = target.needsTls && !target.tlsLeaksSni

  if (!runTls) {
    const latency = Date.now() - start
    try { socket?.destroy() } catch { /* ignore */ }
    logEvent('debug', 'key-health', 'probe ok (tcp-only)', {
      profileId: profile.id, host: target.host, port: target.port,
      latencyMs: latency, viaTunnel: Boolean(tunnel), route: usedRoute?.label ?? null,
      tlsSkipped: target.needsTls && target.tlsLeaksSni ? 'sni-leak-guard' : 'no-tls'
    })
    return { profileId: profile.id, online: true, latencyMs: latency }
  }

  try {
    await tlsHandshake(socket, target.serverName, PROBE_TIMEOUT_MS)
  } catch (err: any) {
    const reason = /timeout/i.test(err?.message ?? '') ? 'timeout' : 'tls-failed'
    logEvent('debug', 'key-health', 'probe TLS failed', {
      profileId: profile.id, host: target.host, port: target.port,
      serverName: target.serverName, viaTunnel: Boolean(tunnel), route: usedRoute?.label ?? null,
      error: err?.message ?? String(err)
    })
    return { profileId: profile.id, online: false, latencyMs: null, reason }
  }

  const latency = Date.now() - start
  logEvent('debug', 'key-health', 'probe ok', {
    profileId: profile.id, host: target.host, port: target.port,
    serverName: target.serverName, latencyMs: latency, viaTunnel: Boolean(tunnel), route: usedRoute?.label ?? null
  })
  return { profileId: profile.id, online: true, latencyMs: latency }
}

interface ServerPickerStoreShape { profiles?: ServerProfile[] }
interface ServerGroupsStoreShape { groups?: Array<{ id: string; status?: string; [key: string]: any }> }

let pickerStoreCache: Store<ServerPickerStoreShape> | null = null
let groupsStoreCache: Store<ServerGroupsStoreShape> | null = null

function getPickerStore(): Store<ServerPickerStoreShape> {
  if (!pickerStoreCache) pickerStoreCache = new Store<ServerPickerStoreShape>({ name: 'server-picker' })
  return pickerStoreCache
}

function getGroupsStore(): Store<ServerGroupsStoreShape> {
  if (!groupsStoreCache) groupsStoreCache = new Store<ServerGroupsStoreShape>({ name: 'server-groups' })
  return groupsStoreCache
}

/** Probe every profile in a group, max 5 in flight. */
export async function checkGroupHealth(groupId: string): Promise<{ ok: true; results: KeyHealthResult[] } | { ok: false; error: string }> {
  let group: any = null
  try {
    const groupsRaw = getGroupsStore().get('groups', []) as Array<{ id: string }>
    group = Array.isArray(groupsRaw) ? groupsRaw.find(g => g && g.id === groupId) : null
  } catch (err) {
    logEvent('warn', 'key-health', 'failed to read server-groups store', err)
    return { ok: false, error: 'Не удалось прочитать список групп' }
  }
  if (!group) return { ok: false, error: 'Группа не найдена или пуста' }

  let profiles: ServerProfile[] = []
  try {
    const all = getPickerStore().get('profiles', []) as ServerProfile[]
    profiles = Array.isArray(all)
      ? all.filter((p: any) => p && (p as any).groupId === groupId)
      : []
  } catch (err) {
    logEvent('warn', 'key-health', 'failed to read server-picker store', err)
    return { ok: false, error: 'Не удалось прочитать список ключей' }
  }
  if (!profiles.length) return { ok: false, error: 'Группа не найдена или пуста' }

  const results: KeyHealthResult[] = new Array(profiles.length)
  let cursor = 0
  const worker = async () => {
    while (true) {
      const idx = cursor++
      if (idx >= profiles.length) return
      results[idx] = await checkProfileHealth(profiles[idx])
    }
  }
  const workers = Array.from({ length: Math.min(HEALTH_CHECK_CONCURRENCY, profiles.length) }, () => worker())
  await Promise.all(workers)

  logEvent('debug', 'key-health', 'group probe finished', {
    groupId, total: profiles.length, online: results.filter(r => r.online).length
  })
  return { ok: true, results }
}
