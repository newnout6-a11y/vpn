/**
 * Native Xray-core Engine — runs a managed vpnte-xray.exe process on loopback
 * SOCKS5 to handle protocols/inbounds (especially modern REALITY) that reject sing-box.
 *
 * In Direct VPN mode with proxyEngine: "auto" or "xray", sing-box continues to
 * manage the Wintun TUN adapter, DNS, smart-RU split routing, and firewall kill-switch,
 * while proxy-out points to this local SOCKS port.
 */

import { spawn, type ChildProcess } from 'child_process'
import { isIP, Socket } from 'net'
import { promises as dns } from 'dns'
import { join } from 'path'
import { readFile, writeFile } from 'fs/promises'
import { logEvent } from './appLogger'
import {
  writeManagedChildPidFile,
  removeManagedChildPidFile
} from './managedChildProcess'
import {
  getTunRuntimeDir,
  getBundledResource,
  pickFreeLocalPort,
  copyResourceIfStale,
  type SingBoxOutboundFault
} from './tunController'
import { clientFingerprintForDevice } from './vpnProfiles'
import type { ClientDevice } from '../shared/ipc-types'

export const XRAY_RUNTIME_EXE_NAME = 'vpnte-xray.exe'
const XRAY_PID_FILE = 'xray.pid'
const SOCKS_PROBE_TIMEOUT_MS = 3500

export interface XrayOutboundOptions {
  clientDevice?: ClientDevice | null
  stealthMode?: boolean
  resolvedIp?: string | null
  dialerProxy?: string
}

export interface StartXrayOptions extends XrayOutboundOptions {
  portOverride?: number
}

export interface XrayEngineStatus {
  running: boolean
  socksPort: number | null
  pid: number | null
  startedAt: number | null
  resolvedIp: string | null
}

interface XrayState {
  running: boolean
  proc: ChildProcess | null
  socksPort: number | null
  exePath: string | null
  configPath: string | null
  logPath: string | null
  startedAt: number | null
  resolvedIp: string | null
}

let activeXrayState: XrayState = {
  running: false,
  proc: null,
  socksPort: null,
  exePath: null,
  configPath: null,
  logPath: null,
  startedAt: null,
  resolvedIp: null
}

export function getXrayRuntimeExePath(): string {
  return join(getTunRuntimeDir(), XRAY_RUNTIME_EXE_NAME)
}

export function getXrayStatus(): XrayEngineStatus {
  return {
    running: activeXrayState.running,
    socksPort: activeXrayState.socksPort,
    pid: activeXrayState.proc?.pid ?? null,
    startedAt: activeXrayState.startedAt,
    resolvedIp: activeXrayState.resolvedIp
  }
}

/**
 * Maps a sing-box outbound configuration into an Xray-core OutboundObject.
 */
export function toXrayOutbound(
  sbOutbound: Record<string, any>,
  options: XrayOutboundOptions = {}
): Record<string, any> {
  const type = String(sbOutbound.type || '').toLowerCase()
  const server = String(sbOutbound.server || '').trim()
  const port = Number(sbOutbound.server_port || 443)
  const address = options.resolvedIp || server

  const tls = sbOutbound.tls && typeof sbOutbound.tls === 'object' && sbOutbound.tls.enabled !== false
    ? sbOutbound.tls
    : null
  const reality = tls && tls.reality && typeof tls.reality === 'object' && tls.reality.enabled !== false
    ? tls.reality
    : null

  let fingerprint = 'chrome'
  if (options.clientDevice) {
    fingerprint = clientFingerprintForDevice(options.clientDevice)
  } else if (tls?.utls && typeof tls.utls === 'object' && typeof tls.utls.fingerprint === 'string' && tls.utls.fingerprint) {
    fingerprint = tls.utls.fingerprint
  }

  const transport = sbOutbound.transport && typeof sbOutbound.transport === 'object'
    ? sbOutbound.transport
    : null
  const transportType = transport ? String(transport.type || '').toLowerCase() : ''

  let network = 'tcp'
  const streamSettings: Record<string, any> = {}

  if (transportType === 'ws') {
    network = 'ws'
    const headers: Record<string, string> = {}
    const hostHeader = transport.headers?.Host || transport.headers?.host || transport.host || tls?.server_name || server
    if (hostHeader) {
      headers.Host = String(hostHeader)
    }
    const wsSettings: Record<string, any> = {
      path: transport.path || '/',
      headers
    }
    if (Number.isInteger(transport.max_early_data) && transport.max_early_data > 0) {
      wsSettings.maxEarlyData = transport.max_early_data
      if (typeof transport.early_data_header_name === 'string' && transport.early_data_header_name) {
        wsSettings.earlyDataHeaderName = transport.early_data_header_name
      }
    }
    streamSettings.wsSettings = wsSettings
  } else if (transportType === 'grpc') {
    network = 'grpc'
    streamSettings.grpcSettings = {
      serviceName: transport.service_name || '',
      multiMode: Boolean(transport.idle_timeout)
    }
  } else if (transportType === 'httpupgrade') {
    network = 'httpupgrade'
    streamSettings.httpupgradeSettings = {
      path: transport.path || '/',
      host: transport.host || tls?.server_name || server
    }
  } else if (transportType === 'http') {
    network = 'http'
    streamSettings.httpSettings = {
      path: transport.path || '/',
      host: Array.isArray(transport.host) && transport.host.length
        ? transport.host.map(String)
        : transport.host ? [String(transport.host)] : undefined
    }
  } else if (transportType === 'xhttp' || transportType === 'splithttp') {
    network = 'xhttp'
    streamSettings.xhttpSettings = {
      path: transport.path || '/',
      host: transport.host || tls?.server_name || server
    }
  }

  streamSettings.network = network

  if (reality) {
    streamSettings.security = 'reality'
    streamSettings.realitySettings = {
      serverName: tls.server_name || server,
      publicKey: reality.public_key || '',
      shortId: reality.short_id || '',
      fingerprint,
      spiderX: reality.spider_x || ''
    }
  } else if (tls) {
    streamSettings.security = 'tls'
    streamSettings.tlsSettings = {
      serverName: tls.server_name || server,
      alpn: Array.isArray(tls.alpn) && tls.alpn.length ? tls.alpn : ['h2', 'http/1.1'],
      fingerprint,
      allowInsecure: tls.insecure === true
    }
  } else {
    streamSettings.security = 'none'
  }

  if (options.dialerProxy) {
    streamSettings.sockopt = {
      ...(streamSettings.sockopt || {}),
      dialerProxy: options.dialerProxy
    }
  }

  const outboundObj: Record<string, any> = {
    tag: 'proxy',
    protocol: type,
    streamSettings
  }

  switch (type) {
    case 'vless': {
      const user: Record<string, any> = {
        id: String(sbOutbound.uuid || ''),
        encryption: sbOutbound.encryption || 'none'
      }
      // Critical safeguard: flow (xtls-rprx-vision) is only valid on pure TCP with TLS/REALITY.
      // If present on WebSocket/gRPC/xhttp, Xray rejects the configuration.
      if (network === 'tcp' && (reality || tls) && sbOutbound.flow) {
        user.flow = sbOutbound.flow
      }
      outboundObj.settings = {
        vnext: [
          {
            address,
            port,
            users: [user]
          }
        ]
      }
      break
    }
    case 'vmess': {
      outboundObj.settings = {
        vnext: [
          {
            address,
            port,
            users: [
              {
                id: String(sbOutbound.uuid || ''),
                alterId: Number(sbOutbound.alter_id ?? 0),
                security: sbOutbound.security || 'auto'
              }
            ]
          }
        ]
      }
      break
    }
    case 'trojan': {
      outboundObj.settings = {
        servers: [
          {
            address,
            port,
            password: String(sbOutbound.password || '')
          }
        ]
      }
      break
    }
    case 'shadowsocks': {
      outboundObj.settings = {
        servers: [
          {
            address,
            port,
            method: String(sbOutbound.method || 'chacha20-ietf-poly1305'),
            password: String(sbOutbound.password || ''),
            uot: sbOutbound.uot !== false
          }
        ]
      }
      break
    }
    default:
      throw new Error(`Unsupported Xray protocol: ${type}`)
  }

  return outboundObj
}

/**
 * Builds the complete JSON configuration for an Xray runtime process.
 */
export function buildXrayConfig(
  xrayOutbound: Record<string, any>,
  socksPort: number,
  options: { logPath?: string } = {}
): Record<string, any> {
  const logOutput = options.logPath
    ? options.logPath.replace(/\\/g, '/')
    : join(getTunRuntimeDir(), 'xray.log').replace(/\\/g, '/')

  return {
    log: {
      loglevel: 'warning',
      access: '',
      error: logOutput
    },
    inbounds: [
      {
        tag: 'in',
        listen: '127.0.0.1',
        port: socksPort,
        protocol: 'socks',
        settings: {
          udp: true
        },
        sniffing: {
          enabled: true,
          destOverride: ['tls', 'http', 'quic']
        }
      }
    ],
    outbounds: [
      { ...xrayOutbound, tag: 'proxy' },
      { tag: 'direct', protocol: 'freedom' },
      { tag: 'block', protocol: 'blackhole' }
    ],
    routing: {
      rules: [
        {
          type: 'field',
          ip: [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '100.64.0.0/10'
          ],
          outboundTag: 'direct'
        },
        { type: 'field', network: 'tcp,udp', outboundTag: 'proxy' }
      ]
    }
  }
}

/**
 * Builds an isolated Xray probe config for keyHealthChecker.
 */
export function buildXrayProbeConfig(
  sbOutbound: Record<string, any>,
  socksPort: number,
  options: {
    directProxy?: { host: string; port: number } | null
    clientDevice?: ClientDevice | null
    logPath?: string
    resolvedIp?: string | null
  } = {}
): Record<string, any> {
  const dialerProxyTag = options.directProxy ? 'probe-direct-out' : undefined
  const xrayOutbound = toXrayOutbound(sbOutbound, {
    clientDevice: options.clientDevice,
    resolvedIp: options.resolvedIp,
    dialerProxy: dialerProxyTag
  })

  const baseConfig = buildXrayConfig(xrayOutbound, socksPort, { logPath: options.logPath })

  if (options.directProxy) {
    baseConfig.outbounds.push({
      tag: 'probe-direct-out',
      protocol: 'socks',
      settings: {
        servers: [
          {
            address: options.directProxy.host,
            port: options.directProxy.port
          }
        ]
      }
    })
  }

  return baseConfig
}

/**
 * Pre-resolves hostname to IPv4 address to prevent circular DNS deadlock when
 * adapter lockdown is active.
 */
export async function resolveServerAddress(server: string): Promise<string | null> {
  const trimmed = String(server || '').trim()
  if (!trimmed) return null
  if (isIP(trimmed) === 4) return trimmed
  if (isIP(trimmed) === 6) return null // IPv4-only TUN routing

  try {
    const ips = await dns.resolve4(trimmed)
    if (ips.length > 0 && ips[0]) return ips[0]
  } catch {}

  try {
    const lookup = await dns.lookup(trimmed, { family: 4 })
    if (lookup?.address && isIP(lookup.address) === 4) return lookup.address
  } catch {}

  return null
}

/**
 * Stages the bundled xray.exe binary into the writable tun-runtime folder.
 */
export async function stageXrayRuntime(): Promise<string> {
  const dst = getXrayRuntimeExePath()
  const src = getBundledResource('xray.exe')
  await copyResourceIfStale(src, dst)
  return dst
}

async function waitForLocalSocks(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError: unknown = null
  while (Date.now() < deadline) {
    try {
      await new Promise<void>((resolve, reject) => {
        const socket = new Socket()
        socket.setTimeout(250)
        socket.once('connect', () => {
          socket.destroy()
          resolve()
        })
        socket.once('error', (err) => {
          socket.destroy()
          reject(err)
        })
        socket.once('timeout', () => {
          socket.destroy()
          reject(new Error('timeout'))
        })
        socket.connect(port, '127.0.0.1')
      })
      return
    } catch (err) {
      lastError = err
      await new Promise((r) => setTimeout(r, 100))
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`Xray SOCKS5 port ${port} did not respond within ${timeoutMs}ms`)
}

/**
 * Starts the managed Xray process for Direct VPN mode.
 */
export async function startXray(
  sbOutbound: Record<string, any>,
  options: StartXrayOptions = {}
): Promise<{ socksPort: number; exePath: string; resolvedIp: string | null }> {
  await stopXray('preparing fresh start')

  const runtimeDir = getTunRuntimeDir()
  const exePath = await stageXrayRuntime()
  const configPath = join(runtimeDir, 'xray.json')
  const logPath = join(runtimeDir, 'xray.log')
  const pidPath = join(runtimeDir, XRAY_PID_FILE)

  const server = String(sbOutbound.server || '')
  let resolvedIp = options.resolvedIp || null
  if (!resolvedIp && isIP(server) === 0) {
    resolvedIp = await resolveServerAddress(server)
  }

  const socksPort = options.portOverride ?? (await pickFreeLocalPort())

  const xrayOutbound = toXrayOutbound(sbOutbound, {
    clientDevice: options.clientDevice,
    stealthMode: options.stealthMode,
    resolvedIp
  })

  const config = buildXrayConfig(xrayOutbound, socksPort, { logPath })
  await writeFile(configPath, JSON.stringify(config, null, 2), 'utf8')

  // Run preflight test: xray run -test -c <config>
  await new Promise<void>((resolve, reject) => {
    const testProc = spawn(exePath, ['run', '-test', '-c', configPath], {
      cwd: runtimeDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let stderr = ''
    let stdout = ''
    testProc.stdout?.on('data', (c) => { stdout += c.toString() })
    testProc.stderr?.on('data', (c) => { stderr += c.toString() })
    testProc.on('error', reject)
    testProc.on('exit', (code) => {
      if (code === 0) {
        resolve()
      } else {
        const errDetails = (stderr || stdout || `exit code ${code}`).trim()
        reject(new Error(`xray run -test preflight failed: ${errDetails}`))
      }
    })
  })

  const child = spawn(exePath, ['run', '-c', configPath], {
    cwd: runtimeDir,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  })

  const pid = child.pid ?? 0
  await writeManagedChildPidFile(pidPath, {
    owner: 'xray-engine',
    pid,
    exePath,
    configPath,
    createdAt: Date.now()
  }).catch((err) => {
    logEvent('warn', 'xray', 'failed to write xray pidfile', err)
  })

  let childStderr = ''
  child.stderr?.on('data', (chunk) => {
    childStderr += chunk.toString()
  })

  child.once('exit', (code, signal) => {
    logEvent(code === 0 ? 'info' : 'warn', 'xray', 'xray process exited', { code, signal, stderr: childStderr.slice(-500) })
    if (activeXrayState.proc === child) {
      activeXrayState = {
        running: false,
        proc: null,
        socksPort: null,
        exePath: null,
        configPath: null,
        logPath: null,
        startedAt: null,
        resolvedIp: null
      }
    }
  })

  try {
    await waitForLocalSocks(socksPort, SOCKS_PROBE_TIMEOUT_MS)
  } catch (probeErr) {
    try { child.kill() } catch {}
    await removeManagedChildPidFile(pidPath, pid)
    throw new Error(`xray-движок запустился, но локальный SOCKS-порт ${socksPort} не отвечает: ${(probeErr as Error).message}`)
  }

  activeXrayState = {
    running: true,
    proc: child,
    socksPort,
    exePath,
    configPath,
    logPath,
    startedAt: Date.now(),
    resolvedIp
  }

  logEvent('info', 'xray', 'xray engine started successfully', {
    socksPort,
    pid,
    resolvedIp
  })

  return { socksPort, exePath, resolvedIp }
}

/**
 * Stops the managed Xray process.
 */
export async function stopXray(reason = 'stopped'): Promise<void> {
  const { proc } = activeXrayState
  const pidPath = join(getTunRuntimeDir(), XRAY_PID_FILE)

  if (proc && !proc.killed) {
    try {
      proc.kill()
    } catch (err) {
      logEvent('warn', 'xray', 'error killing xray process', err)
    }
  }

  await removeManagedChildPidFile(pidPath, proc?.pid).catch(() => undefined)

  activeXrayState = {
    running: false,
    proc: null,
    socksPort: null,
    exePath: null,
    configPath: null,
    logPath: null,
    startedAt: null,
    resolvedIp: null
  }

  logEvent('info', 'xray', 'xray engine stopped', { reason })
}

/**
 * Scans the tail of the live xray.log for persistent outbound faults.
 */
export async function readRecentXrayOutboundFault(
  logPath: string = join(getTunRuntimeDir(), 'xray.log')
): Promise<SingBoxOutboundFault | null> {
  try {
    const raw = await readFile(logPath, 'utf8')
    const lines = raw.split(/\r?\n/).slice(-500)
    let reality = 0
    let tls = 0
    let unreachable = 0

    for (const line of lines) {
      if (!/\[(Warning|Error)\]/i.test(line)) continue
      if (/reality verification failed|reality.*invalid connection|bad reality/i.test(line)) {
        reality++
      } else if (/\b(tls|x509|certificate|bad certificate|handshake failure|remote error)\b/i.test(line)) {
        tls++
      } else if (/\b(connection refused|i\/o timeout|no route to host|network is unreachable|context deadline exceeded|dial tcp|connection ends)\b/i.test(line)) {
        unreachable++
      }
    }

    if (reality >= 2) return 'reality-key-mismatch'
    if (tls >= 2) return 'tls-handshake-failed'
    if (unreachable >= 2) return 'upstream-unreachable'
    return null
  } catch {
    return null
  }
}
