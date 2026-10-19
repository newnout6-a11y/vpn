/**
 * Routing self-test — prove, end-to-end, that traffic is actually being split
 * the way the config claims:
 *
 *   - VPN path:    a request captured by the TUN → proxy-out → should report
 *                  the VPN exit IP.
 *   - Direct path: a request through sing-box's `mixed-direct-in` SOCKS port
 *                  (hard-routed to direct-out) → should report the user's REAL
 *                  ISP IP.
 *
 * If those two IPs DIFFER, the tunnel is genuinely routing — the split is real,
 * not cosmetic. If they're EQUAL, either the VPN isn't actually carrying
 * traffic (leak) or both paths egress the same way (misconfig). This is the
 * single most trustworthy "does it work" check we can do without a second
 * machine.
 *
 * When smart RU split-routing is enabled we add a second assertion: a
 * representative RU domain (gosuslugi.ru — every RU ISP whitelists it) must,
 * via the SMART (TUN) path, egress with the REAL IP, while a neutral foreign
 * check via the same TUN path egresses with the VPN IP. Same path, different
 * destinations → proves per-site routing, not just "tunnel up".
 *
 * The IP-echo endpoints used here are deliberately PLAIN-TEXT IPv4 echoes, and
 * we use a couple so one being down/blocked doesn't fail the test.
 */

import axios from 'axios'
import { SocksClient } from 'socks'
import { logEvent } from './appLogger'
import { tunController, getDirectProxyPort } from './tunController'
import { settingsStore } from './settings'
import { ipcMain } from 'electron'
import { randomUUID } from 'node:crypto'
import { IpcFault } from '../shared/ipc-result'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'
import { runRequesterOperation } from './requesterOperation'

function assertActive(signal?: AbortSignal): void {
  if (signal?.aborted) throw new IpcFault('cancelled')
}

export interface RoutingSelfTestResult {
  ranAt: number
  /** Tunnel was up when the test ran. */
  tunnelActive: boolean
  /** IP seen when egressing through the VPN (proxy-out via TUN). */
  vpnIp: string | null
  /** IP seen when egressing directly (direct-out via SOCKS). */
  directIp: string | null
  /** True when vpnIp and directIp are both known and differ. */
  splitWorks: boolean
  /** Smart-route check (only when the feature is on). */
  smartRu: {
    enabled: boolean
    /** Egress IP for a known RU host through the smart (TUN) path. */
    ruHostIp: string | null
    /** True when the RU host egressed with the REAL (direct) IP. */
    ruGoesDirect: boolean | null
  }
  verdict: 'ok' | 'partial' | 'leak' | 'tunnel-off' | 'inconclusive'
  message: string
}

// Plain-text IPv4 echoes. ipify and ifconfig.me both return just the IP as the
// body (ipify with /, ifconfig.me/ip), no JSON parsing fuss.
const IP_ECHO_HOSTS = [
  { host: 'api.ipify.org', path: '/', port: 80 },
  { host: 'ifconfig.me', path: '/ip', port: 80 }
]

const RU_IP_ECHO_URLS = [
  'https://yandex.ru/internet/',
  'https://internet.yandex.ru/'
] as const

const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g

function extractIpv4(text: string): string | null {
  for (const match of String(text || '').matchAll(IPV4_RE)) {
    const candidate = match[1]
    const octets = candidate.split('.').map(part => Number(part))
    if (octets.length === 4 && octets.every(part => Number.isInteger(part) && part >= 0 && part <= 255)) {
      return candidate
    }
  }
  return null
}

/** Egress IP through the VPN: a normal Node request, captured by the TUN and
 *  dispatched via proxy-out. */
async function vpnEgressIp(signal?: AbortSignal): Promise<string | null> {
  for (const ep of IP_ECHO_HOSTS) {
    assertActive(signal)
    try {
      const resp = await axios.get(`http://${ep.host}${ep.path}`, {
        signal,
        timeout: 8000,
        responseType: 'text',
        transformResponse: (d) => d,
        headers: { Connection: 'close' }
      })
      assertActive(signal)
      const ip = extractIpv4(String(resp.data))
      if (ip) return ip
    } catch {
      assertActive(signal)
      /* try next */
    }
  }
  return null
}

/** Egress IP through direct-out: HTTP GET tunneled over the local SOCKS port
 *  that sing-box hard-routes to direct-out (the physical NIC). */
async function directEgressIp(socksPort: number, destHost: string, destPath: string, signal?: AbortSignal): Promise<string | null> {
  assertActive(signal)
  let socket: import('net').Socket | undefined
  try {
    const conn = await SocksClient.createConnection({
      proxy: { host: '127.0.0.1', port: socksPort, type: 5 },
      command: 'connect',
      timeout: 8000,
      destination: { host: destHost, port: 80 }
    })
    socket = conn.socket
  } catch {
    assertActive(signal)
    return null
  }
  const sock = socket
  return new Promise<string | null>((resolve) => {
    let buffer = ''
    let done = false
    let result: string | null = null
    const finish = (ip: string | null) => {
      if (done) return
      done = true
      result = ip
      try { sock.destroy() } catch { /* ignore */ }
    }
    const abort = () => finish(null)
    sock.once('close', () => {
      signal?.removeEventListener('abort', abort)
      const value = done ? result : extractIpv4(buffer.split('\r\n\r\n')[1] || '')
      done = true
      resolve(value)
    })
    sock.once('error', () => finish(null))
    sock.once('timeout', () => finish(null))
    signal?.addEventListener('abort', abort, { once: true })
    // SOCKS negotiation cannot be interrupted by its API. A late socket is
    // destroyed without sending a request and remains owned until actual close.
    if (signal?.aborted) return abort()
    sock.setTimeout(8000)
    sock.on('data', (chunk: Buffer) => {
      if (done || signal?.aborted) return
      buffer += chunk.toString('utf-8')
      const body = buffer.split('\r\n\r\n')[1]
      if (body && extractIpv4(body)) finish(extractIpv4(body))
    })
    try { sock.write(`GET ${destPath} HTTP/1.1\r\nHost: ${destHost}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n`) }
    catch { finish(null) }
  })
}

/**
 * Pure verdict derivation, exported for testing. Given the measured IPs and
 * whether smart-route is on, produce the verdict + message.
 */
export function deriveRoutingVerdict(input: {
  tunnelActive: boolean
  vpnIp: string | null
  directIp: string | null
  smartEnabled: boolean
  ruHostIp: string | null
}): { verdict: RoutingSelfTestResult['verdict']; message: string; splitWorks: boolean; ruGoesDirect: boolean | null } {
  if (!input.tunnelActive) {
    return { verdict: 'tunnel-off', message: 'Защита выключена — проверять маршрутизацию нечего.', splitWorks: false, ruGoesDirect: null }
  }
  if (!input.vpnIp || !input.directIp) {
    return {
      verdict: 'inconclusive',
      message: 'Не удалось измерить оба IP (часть эхо-серверов не ответила). Повторите проверку.',
      splitWorks: false,
      ruGoesDirect: null
    }
  }
  const splitWorks = input.vpnIp !== input.directIp
  if (!splitWorks) {
    // VPN IP == direct IP means the tunnel isn't actually changing the egress.
    return {
      verdict: 'leak',
      message: `Через VPN и напрямую виден ОДИН и тот же IP (${input.vpnIp}). Туннель не меняет внешний адрес — это утечка или прокси ведёт напрямую.`,
      splitWorks: false,
      ruGoesDirect: null
    }
  }

  // Smart-route assertion.
  if (input.smartEnabled) {
    if (!input.ruHostIp) {
      return {
        verdict: 'partial',
        message: `Туннель работает (VPN ${input.vpnIp} ≠ прямой ${input.directIp}), но Smart-RU runtime-проверка не завершена: нет надежного РФ echo через TUN. Правила маршрутизации проверяются конфиг-тестами, но этот live self-test подтверждает только общий VPN/direct split.`,
        splitWorks: true,
        ruGoesDirect: null
      }
    }
    const ruGoesDirect = input.ruHostIp === input.directIp
    if (ruGoesDirect) {
      return {
        verdict: 'ok',
        message: `Всё работает как надо: зарубежные сайты идут через VPN (${input.vpnIp}), а РФ-сайты — напрямую с вашим реальным IP (${input.directIp}). Умный режим РФ действительно разделяет трафик.`,
        splitWorks: true,
        ruGoesDirect: true
      }
    }
    return {
      verdict: 'partial',
      message: `Туннель работает, но РФ-хост вышел через VPN (${input.ruHostIp}), а не напрямую (${input.directIp}). Возможно, списки РФ-доменов ещё качаются — повторите через минуту.`,
      splitWorks: true,
      ruGoesDirect: false
    }
  }

  return {
    verdict: 'ok',
    message: `Туннель работает: через VPN виден ${input.vpnIp}, напрямую — ${input.directIp}. Внешний адрес действительно меняется.`,
    splitWorks: true,
    ruGoesDirect: null
  }
}

/**
 * Run the full routing self-test. Safe to call any time; returns a structured
 * result for measured failures; cancellation/deadline use the typed taxonomy.
 */
export async function runRoutingSelfTest(options: { signal?: AbortSignal; onOperation?: (lease: OperationLease) => void } = {}): Promise<RoutingSelfTestResult> {
  return operations.run('routing-check', lease => {
    options.onOperation?.(lease)
    return runRoutingSelfTestOwned(lease)
  }, { signal: options.signal, resource: `routing-check:${randomUUID()}` })
}

async function runRoutingSelfTestOwned(lease: OperationLease): Promise<RoutingSelfTestResult> {
  lease.assertActive()
  const tunnelActive = tunController.getStatus().running
  const settings = settingsStore.get()
  const smartEnabled = settings.smartRuSplit === true
  const disableGeoLookup = settings.disableGeoLookup === true
  const base: RoutingSelfTestResult = {
    ranAt: Date.now(),
    tunnelActive,
    vpnIp: null,
    directIp: null,
    splitWorks: false,
    smartRu: { enabled: smartEnabled, ruHostIp: null, ruGoesDirect: null },
    verdict: 'tunnel-off',
    message: ''
  }

  if (!tunnelActive) {
    const v = deriveRoutingVerdict({ tunnelActive, vpnIp: null, directIp: null, smartEnabled, ruHostIp: null })
    return lease.commit(() => ({ ...base, verdict: v.verdict, message: v.message }))
  }

  const socksPort = getDirectProxyPort()

  // VPN egress (Node → TUN → proxy-out) and direct egress (SOCKS → direct-out)
  // in parallel.
  const [vpnIp, directIp] = await Promise.all([
    lease.wait(vpnEgressIp(lease.signal)),
    socksPort ? lease.wait(directEgressIp(socksPort, 'api.ipify.org', '/', lease.signal)) : Promise.resolve(null)
  ])
  lease.assertActive()

  // Smart-route check: keep this honest. A real proof needs an RU-domain IP
  // echo reached through the normal TUN path. Reusing the direct SOCKS path
  // only proves direct-out works and used to create false "smart RU ok"
  // confidence, so we return null when no reliable runtime echo is available.
  let ruHostIp: string | null = null
  if (smartEnabled && !disableGeoLookup) {
    ruHostIp = await lease.wait(ruEgressIp(lease.signal))
  }
  lease.assertActive()

  const v = deriveRoutingVerdict({ tunnelActive, vpnIp, directIp, smartEnabled, ruHostIp })

  const result: RoutingSelfTestResult = {
    ...base,
    vpnIp,
    directIp,
    splitWorks: v.splitWorks,
    smartRu: { enabled: smartEnabled, ruHostIp, ruGoesDirect: v.ruGoesDirect },
    verdict: v.verdict,
    message: v.message
  }

  return lease.commit(() => {
    logEvent('info', 'routing-self-test', 'completed', {
      verdict: result.verdict,
      splitWorks: result.splitWorks,
      smartEnabled,
      // Log only the last octet for privacy.
      vpnIpTail: vpnIp ? vpnIp.split('.').slice(-1)[0] : null,
      directIpTail: directIp ? directIp.split('.').slice(-1)[0] : null,
      smartRuEchoSkipped: smartEnabled && disableGeoLookup
    })

    return result
  })
}

export async function ruEgressIp(signal?: AbortSignal): Promise<string | null> {
  for (const url of RU_IP_ECHO_URLS) {
    assertActive(signal)
    try {
      const resp = await axios.get(url, {
        signal,
        timeout: 8000,
        responseType: 'text',
        transformResponse: (d) => d,
        headers: { Connection: 'close' }
      })
      assertActive(signal)
      const ip = extractIpv4(String(resp.data))
      if (ip) return ip
    } catch {
      assertActive(signal)
      /* try next */
    }
  }
  return null
}

export function registerRoutingSelfTestHandlers(): void {
  ipcMain.handle('run-routing-self-test', (event, requestId?: string) =>
    runRequesterOperation(event.sender, requestId, (signal, onOperation) => runRoutingSelfTest({ signal, onOperation })))
}
