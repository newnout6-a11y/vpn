/**
 * Key Health Checker — probes individual VPN keys to tell which ones are
 * still alive after a subscription's free trial expires.
 *
 * Strategy: launch an isolated sing-box process with the profile's complete
 * outbound and open a public TCP destination through its local SOCKS inbound.
 * This exercises the real credentials and transport (UUID/password, Reality
 * public key + short ID, TLS, WebSocket, QUIC, etc.), rather than merely
 * proving that the server port accepts TCP.
 *
 * Routing note: when the tunnel is up we dial through sing-box's
 * `mixed-direct-in` SOCKS5 inbound as a detour for the probe outbound's own
 * connection. That inbound is routed to `direct-out`, avoiding a self-loop
 * through the currently selected VPN while preserving the kill-switch.
 */

import { spawn } from 'child_process'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { Socket } from 'net'
import { tmpdir } from 'os'
import { join } from 'path'
import { connect as tlsConnect } from 'tls'
import { SocksClient } from 'socks'
import { logEvent } from './appLogger'
import { cleanupManagedChildPidDirs, removeManagedChildPidFile, writeManagedChildPidFile } from './managedChildProcess'
import { getPhysicalAdapterDnsSources } from './physicalAdapterLockdown'
import { serverPickerStore, serverGroupsStore } from './sharedStores'
import { getBundledResource, getDirectProxyPort, pickFreeLocalPort, sanitizeProxyOutbound, tunController } from './tunController'
import type { ServerProfile } from '../shared/ipc-types'

const KEY_PROBE_TIMEOUT_MS = 8000
const KEY_PROBE_DESTINATIONS = [
  { host: 'yandex.ru', port: 443, serverName: 'yandex.ru', path: '/favicon.ico' },
  { host: '1.1.1.1', port: 443, serverName: 'cloudflare-dns.com', path: '/cdn-cgi/trace' },
  { host: 'www.gstatic.com', port: 443, serverName: 'www.gstatic.com', path: '/generate_204' }
] as const
const HEALTH_CHECK_CONCURRENCY = 5
const KEY_PROBE_DIR_PREFIX = 'vpnte-key-probe-'
const KEY_PROBE_PID_FILE = 'sing-box.pid'

export interface KeyHealthResult {
  profileId: string
  online: boolean
  latencyMs: number | null
  /** 'auth-failed' | 'timeout' | 'tls-failed' | 'config-failed' | etc. */
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

async function verifyHttpsThroughSocket(
  socket: Socket,
  destination: (typeof KEY_PROBE_DESTINATIONS)[number],
  timeoutMs: number
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let settled = false
    let response = ''
    const tls = tlsConnect({
      socket,
      servername: destination.serverName,
      rejectUnauthorized: false
    })
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs)
    const finish = (error: Error | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { tls.destroy() } catch { /* ignore */ }
      try { socket.destroy() } catch { /* ignore */ }
      if (error) reject(error)
      else resolve()
    }

    tls.once('secureConnect', () => {
      tls.write(
        `GET ${destination.path} HTTP/1.1\r\n` +
        `Host: ${destination.serverName}\r\n` +
        'Connection: close\r\n\r\n'
      )
    })
    tls.on('data', chunk => {
      response += chunk.toString('latin1')
      if (/^HTTP\/1\.[01] \d{3}\b/.test(response)) finish(null)
    })
    tls.once('error', error => finish(error instanceof Error ? error : new Error(String(error))))
    tls.once('end', () => {
      if (!settled) finish(new Error('probe destination closed without HTTP response'))
    })
  })
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

export function classifyOutboundProbeFailure(protocol: string, logText: string, errorText = ''): string {
  if (protocol.toLowerCase() === 'hysteria2') {
    return classifyHysteria2ProbeFailure(logText, errorText)
  }

  const text = `${logText}\n${errorText}`.toLowerCase()
  if (/unknown field|decode config|parse config|invalid config|unsupported|missing required|check outbound/.test(text)) {
    return 'config-failed'
  }
  if (/auth|authentication|unauthori[sz]ed|bad key|wrong (?:uuid|password)|permission denied/.test(text)) {
    return 'auth-failed'
  }
  if (/tls|certificate|x509|server name|sni|reality verification/.test(text)) {
    return 'tls-failed'
  }
  if (/timeout|deadline exceeded|i\/o timeout|network is unreachable|host unreachable|operation timed out/.test(text)) {
    return 'timeout'
  }
  return 'handshake-failed'
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

export function buildKeyProbeConfig(
  profile: ServerProfile,
  inboundPort: number,
  options: {
    directProxy?: { host: string; port: number } | null
    physicalInterface?: string | null
    logPath?: string
  } = {}
): Record<string, any> {
  if (!profile.outbound || typeof profile.outbound !== 'object') {
    throw new Error('profile has no outbound')
  }

  const rawOutbound = { ...profile.outbound, tag: 'proxy-out' }
  delete rawOutbound.detour
  if (options.directProxy) rawOutbound.detour = 'probe-direct-out'
  else if (options.physicalInterface) rawOutbound.bind_interface = options.physicalInterface

  const { outbound, needsBootstrapDns } = sanitizeProxyOutbound(rawOutbound)
  const directOutbound = options.directProxy
    ? {
        type: 'socks',
        tag: 'probe-direct-out',
        server: options.directProxy.host,
        server_port: options.directProxy.port,
        version: '5'
      }
    : { type: 'direct', tag: 'probe-direct-out' }

  return {
    log: {
      level: 'debug',
      timestamp: true,
      ...(options.logPath ? { output: options.logPath.replace(/\\/g, '/') } : {})
    },
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
    outbounds: [outbound, directOutbound],
    route: {
      final: 'proxy-out',
      auto_detect_interface: true,
      ...(needsBootstrapDns ? { default_domain_resolver: 'dns-bootstrap' } : {})
    }
  }
}

async function checkOutboundHealth(profile: ServerProfile): Promise<KeyHealthResult> {
  if (!profile.outbound || typeof profile.outbound !== 'object') {
    return { profileId: profile.id, online: false, latencyMs: null, reason: 'no-outbound' }
  }

  const startedAt = Date.now()
  await cleanupManagedChildPidDirs(tmpdir(), KEY_PROBE_DIR_PREFIX, KEY_PROBE_PID_FILE, 'key-health-probe', (message, details) => {
    logEvent('warn', 'key-health', message, details)
  })
  const workDir = await mkdtemp(join(tmpdir(), KEY_PROBE_DIR_PREFIX))
  const logPath = join(workDir, 'sing-box.log')
  const configPath = join(workDir, 'sing-box.json')
  const pidPath = join(workDir, KEY_PROBE_PID_FILE)
  let child: ReturnType<typeof spawn> | null = null
  let childOutput = ''

  try {
    const inboundPort = await pickFreeLocalPort()
    const directProxy = shouldProbeViaTunnel()
    const physicalAdapter = directProxy
      ? null
      : (await getPhysicalAdapterDnsSources().catch(() => []))[0] ?? null
    const config = buildKeyProbeConfig(profile, inboundPort, {
      directProxy,
      physicalInterface: physicalAdapter?.alias,
      logPath
    })

    await writeFile(configPath, JSON.stringify(config, null, 2), 'utf8')
    child = spawn(getBundledResource('sing-box.exe'), ['run', '-c', configPath], {
      cwd: workDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    })
    await writeManagedChildPidFile(pidPath, {
      owner: 'key-health-probe',
      pid: child.pid ?? 0,
      exePath: getBundledResource('sing-box.exe'),
      configPath,
      createdAt: Date.now()
    }).catch((err) => {
      logEvent('warn', 'key-health', 'failed to write key probe pidfile', err)
    })
    child.stdout?.on('data', chunk => { childOutput += chunk.toString() })
    child.stderr?.on('data', chunk => { childOutput += chunk.toString() })
    child.on('error', err => { childOutput += `\n${err.message}` })

    await waitForLocalSocks(inboundPort, 2500)
    const destination = await Promise.any(KEY_PROBE_DESTINATIONS.map(async candidate => {
      const socket = await openTcpViaSocks(
        { host: '127.0.0.1', port: inboundPort },
        candidate.host,
        candidate.port,
        KEY_PROBE_TIMEOUT_MS
      )
      await verifyHttpsThroughSocket(socket, candidate, KEY_PROBE_TIMEOUT_MS)
      return candidate
    }))

    const latencyMs = Date.now() - startedAt
    logEvent('debug', 'key-health', 'outbound probe ok', {
      profileId: profile.id,
      protocol: profile.protocol,
      latencyMs,
      destination: `${destination.host}:${destination.port}`,
      bootstrap: directProxy ? 'tun-direct-out' : physicalAdapter?.alias || 'system-direct'
    })
    return { profileId: profile.id, online: true, latencyMs }
  } catch (err: any) {
    const logText = await readProbeLog(logPath)
    const aggregateErrors = err instanceof AggregateError
      ? err.errors.map(error => error instanceof Error ? error.message : String(error)).join(' | ')
      : ''
    const errorText = `${childOutput}\n${err?.message ?? String(err)}\n${aggregateErrors}`
    const reason = classifyOutboundProbeFailure(profile.protocol, logText, errorText)
    logEvent('debug', 'key-health', 'outbound probe failed', {
      profileId: profile.id,
      protocol: profile.protocol,
      reason,
      error: err?.message ?? String(err)
    })
    return { profileId: profile.id, online: false, latencyMs: null, reason }
  } finally {
    if (child && !child.killed) {
      try { child.kill() } catch { /* ignore */ }
    }
    await removeManagedChildPidFile(pidPath, child?.pid)
    await rm(workDir, { recursive: true, force: true }).catch(() => undefined)
  }
}

/** Probe a single ServerProfile's outbound. Always resolves; never throws. */
export async function checkProfileHealth(profile: ServerProfile): Promise<KeyHealthResult> {
  if (!profile.outbound || typeof profile.outbound !== 'object') {
    return { profileId: profile.id, online: false, latencyMs: null, reason: 'no-outbound' }
  }
  return checkOutboundHealth(profile)
}

function getPickerStore() {
  return serverPickerStore
}

function getGroupsStore() {
  return serverGroupsStore
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
      ? all.filter((p: any) => p && (p as any).groupId === groupId && !(p as any).removedFromSubscriptionAt)
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

  // Persist only the reachability verdict. Health-probe latency is not a
  // geographical ping, so it must not overwrite ServerProfile.ping.
  const checkedAt = Date.now()
  const resultByProfileId = new Map(results.map(result => [result.profileId, result]))
  const allProfiles = getPickerStore().get('profiles', []) as ServerProfile[]
  if (Array.isArray(allProfiles)) {
    getPickerStore().set('profiles', allProfiles.map(profile => {
      const result = resultByProfileId.get(profile.id)
      return result
        ? {
            ...profile,
            status: result.online ? 'online' as const : 'offline' as const,
            lastChecked: checkedAt,
            healthStatus: result.online ? 'online' as const : 'offline' as const,
            healthCheckedAt: checkedAt,
            healthLatencyMs: result.latencyMs,
            healthReason: result.reason
          }
        : profile
    }))
  }

  logEvent('debug', 'key-health', 'group probe finished', {
    groupId, total: profiles.length, online: results.filter(r => r.online).length
  })
  return { ok: true, results }
}
