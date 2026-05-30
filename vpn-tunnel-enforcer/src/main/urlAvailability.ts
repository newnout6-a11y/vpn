/**
 * URL Availability — paste a link, find out whether it's reachable from
 * inside the user's network and whether VPN actually helps.
 *
 * Two parallel measurements when the tunnel is active:
 *   1. "Через VPN" — the same TCP/TLS/HTTP probe a browser would do once
 *      sing-box has captured the kernel route. Full breakdown (DNS, TCP,
 *      TLS, HTTP) because the request walks Node's regular http stack and
 *      we own every layer.
 *   2. "Без VPN" — issued via the localhost clash API's
 *      /proxies/direct-out/delay endpoint, which makes sing-box itself
 *      dial the URL through its `direct-out` outbound (= physical NIC, no
 *      tunnel). This gives us a "what would happen if I disconnected
 *      right now" comparison without actually disconnecting. The clash
 *      API only returns a latency number, so the direct side carries
 *      less detail than the tunnel side — but that's enough to tell
 *      "blocked / works".
 *
 * When the tunnel is OFF we only do the direct path natively (full
 * breakdown — no clash API needed since nothing is hijacking our
 * sockets).
 *
 * The verdict + recommendation are produced from the combination of
 * both measurements so the UI can show "works only with VPN", "works
 * only without VPN", "blocked everywhere", etc.
 */

import { ipcMain, BrowserWindow } from 'electron'
import { Socket } from 'net'
import { connect as tlsConnect, type TLSSocket } from 'tls'
import { promises as dns } from 'dns'
import axios from 'axios'
import Store from 'electron-store'
import { randomUUID } from 'crypto'
import { logEvent } from './appLogger'
import { tunController, getDirectProxyPort } from './tunController'
import { getClashApiInfo } from './tunController'
import {
  scoreSinglePage,
  compareRenders,
  type PageSignal,
  type GeoBlockVerdict
} from './geoBlockDetect'

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PathReport {
  /** True if the URL was reachable along this path. */
  available: boolean
  /** End-to-end wall-clock ms (DNS + TCP + TLS + HTTP). null if unreachable. */
  totalMs: number | null
  /** Why it failed, if it did. Human-readable for the UI. */
  errorStage: 'dns' | 'tcp' | 'tls' | 'http' | 'api' | null
  errorMessage: string | null
  /** Full per-stage breakdown. Only populated for the native path. */
  dns: {
    resolved: boolean
    ips: string[]
    ms: number | null
    /** True if the resolver returned 0.0.0.0 / a known RKN landing IP. */
    poisoned: boolean
  } | null
  tcp: { connected: boolean; ms: number | null } | null
  tls: { handshakeOk: boolean; ms: number | null; cipher: string | null; protocol: string | null } | null
  http: { status: number | null; ms: number | null; server: string | null } | null
  /** ASN/geo of the resolved IP, best-effort. */
  asn: { country: string; org: string } | null
  /** Set to true if the website returned 200 OK but the HTML body contains GeoBlock markers (e.g. Gemini). */
  geoBlocked?: boolean
  /** How the measurement was taken — useful for telling apart full probe
   *  results from "clash API delay only" approximations. */
  source: 'native' | 'clash-direct-out'
}

export interface UrlAvailabilityResult {
  id: string
  url: string
  testedAt: number
  tunnelActive: boolean
  /** Full report through the tunnel (when VPN is on). null otherwise. */
  tunnel: PathReport | null
  /** Report without the tunnel — native when VPN off, clash-direct when on. */
  direct: PathReport | null
  /** High-level conclusion. */
  verdict:
    | 'works-both'
    | 'works-only-with-vpn'
    | 'works-only-without-vpn'
    | 'blocked-everywhere'
    | 'unknown'
  /** Human-readable next step for the user. */
  recommendation: string
}

// ─── Store: history of recent checks ─────────────────────────────────────────

interface AvailabilityStore {
  history: UrlAvailabilityResult[]
}

const store = new Store<AvailabilityStore>({
  name: 'url-availability',
  defaults: { history: [] }
})

const MAX_HISTORY = 50
const PROBE_TIMEOUT_MS = 8000

// ─── URL helpers ─────────────────────────────────────────────────────────────

interface ParsedUrl {
  raw: string
  host: string
  port: number
  scheme: 'http' | 'https'
  path: string
}

/**
 * Be tolerant: users will paste "youtube.com", "https://www.youtube.com",
 * "youtube.com/feed/trending", etc. We pick https on bare hostnames and
 * the leading slash for the path.
 */
export function parseUrlForProbe(input: string): ParsedUrl | null {
  const trimmed = input.trim()
  if (!trimmed) return null
  // If the user typed an explicit scheme other than http/https (ftp://, ws://,
  // ssh://, etc.), reject — we only know how to probe HTTP-like targets.
  const explicitScheme = trimmed.match(/^([a-z][a-z0-9+.-]*):\/\//i)
  if (explicitScheme && !/^https?$/i.test(explicitScheme[1])) return null
  let normalized = trimmed
  if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`
  try {
    const u = new URL(normalized)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    const scheme = u.protocol === 'https:' ? 'https' : 'http'
    const port = u.port ? parseInt(u.port, 10) : (scheme === 'https' ? 443 : 80)
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null
    return {
      raw: trimmed,
      host: u.hostname,
      port,
      scheme,
      path: u.pathname + u.search
    }
  } catch {
    return null
  }
}

// ─── DNS-poisoning heuristics ────────────────────────────────────────────────

/** IPs RKN's "site blocked" landing pages historically resolve to.
 *  Not exhaustive — but catches the most common "0.0.0.0" + a few RKN
 *  honeypots. False positives are OK: we just mark it as suspect.
 */
const POISONED_IPS = new Set<string>([
  '0.0.0.0',
  '127.0.0.1',
  // Some RKN landing IPs (publicly documented).
  '109.207.10.100',
  '95.213.255.114',
  '178.176.106.249'
])

function isPoisonedIp(ip: string): boolean {
  return POISONED_IPS.has(ip)
}

// ─── Per-stage native probes (run from Node, captured by TUN if active) ───────

async function probeDns(host: string): Promise<PathReport['dns']> {
  // Already an IP literal — skip resolution entirely.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) {
    return { resolved: true, ips: [host], ms: 0, poisoned: false }
  }
  const start = Date.now()
  try {
    const v4 = await dns.resolve4(host).catch(() => [] as string[])
    const v6 = await dns.resolve6(host).catch(() => [] as string[])
    const ips = [...v4, ...v6]
    if (!ips.length) {
      return { resolved: false, ips: [], ms: Date.now() - start, poisoned: false }
    }
    const poisoned = ips.some(isPoisonedIp)
    return { resolved: true, ips, ms: Date.now() - start, poisoned }
  } catch {
    return { resolved: false, ips: [], ms: Date.now() - start, poisoned: false }
  }
}

function probeTcp(host: string, port: number): Promise<{ connected: boolean; ms: number | null; error?: string }> {
  return new Promise((resolve) => {
    const socket = new Socket()
    const start = Date.now()
    let done = false
    const finish = (value: { connected: boolean; ms: number | null; error?: string }) => {
      if (done) return
      done = true
      socket.removeAllListeners()
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(PROBE_TIMEOUT_MS)
    socket.once('connect', () => finish({ connected: true, ms: Date.now() - start }))
    socket.once('timeout', () => finish({ connected: false, ms: null, error: 'timeout' }))
    socket.once('error', (err: Error) => finish({ connected: false, ms: null, error: err.message }))
    socket.connect(port, host)
  })
}

function probeTls(
  host: string,
  port: number
): Promise<{ handshakeOk: boolean; ms: number | null; cipher: string | null; protocol: string | null; error?: string }> {
  return new Promise((resolve) => {
    const start = Date.now()
    let done = false
    let socket: TLSSocket
    const finish = (value: { handshakeOk: boolean; ms: number | null; cipher: string | null; protocol: string | null; error?: string }) => {
      if (done) return
      done = true
      try { socket?.removeAllListeners(); socket?.destroy() } catch {}
      resolve(value)
    }
    try {
      socket = tlsConnect({
        host,
        port,
        servername: host,
        // Treat a self-signed / mismatched cert as "TLS handshake worked"
        // — the site is reachable, even if the cert is funky. We surface
        // the cipher/protocol either way.
        rejectUnauthorized: false,
        timeout: PROBE_TIMEOUT_MS
      })
      socket.once('secureConnect', () => {
        const cipher = socket.getCipher()?.name ?? null
        const protocol = socket.getProtocol() ?? null
        finish({ handshakeOk: true, ms: Date.now() - start, cipher, protocol })
      })
      socket.once('timeout', () => finish({ handshakeOk: false, ms: null, cipher: null, protocol: null, error: 'timeout' }))
      socket.once('error', (err: Error) => finish({ handshakeOk: false, ms: null, cipher: null, protocol: null, error: err.message }))
    } catch (err: any) {
      finish({ handshakeOk: false, ms: null, cipher: null, protocol: null, error: err?.message || String(err) })
    }
  })
}

async function probeHttp(
  parsed: ParsedUrl
): Promise<{ status: number | null; ms: number | null; server: string | null; error?: string }> {
  const start = Date.now()
  try {
    // HEAD first because we don't care about the body — but a lot of
    // CDNs return 405 on HEAD, in which case we fall back to a tiny
    // ranged GET.
    let resp = await axios.head(parsed.raw, {
      timeout: PROBE_TIMEOUT_MS,
      validateStatus: () => true,
      maxRedirects: 3
    }).catch(err => ({ err }) as any)

    if (resp.err || resp.status === 405 || resp.status === 501) {
      resp = await axios.get(parsed.raw, {
        timeout: PROBE_TIMEOUT_MS,
        validateStatus: () => true,
        maxRedirects: 3,
        headers: { Range: 'bytes=0-0' }
      }).catch(err => ({ err }) as any)
    }

    if (resp.err) {
      return { status: null, ms: null, server: null, error: resp.err?.message || String(resp.err) }
    }
    return {
      status: resp.status,
      ms: Date.now() - start,
      server: resp.headers?.server ?? null
    }
  } catch (err: any) {
    return { status: null, ms: null, server: null, error: err?.message || String(err) }
  }
}

async function fetchAsn(ip: string): Promise<PathReport['asn']> {
  if (!ip || isPoisonedIp(ip)) return null
  try {
    const resp = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 5000 })
    if (resp.data && !resp.data.error) {
      return {
        country: (resp.data.country_name || resp.data.country || '').toString().trim() || 'неизвестно',
        org: (resp.data.org || resp.data.asn || '').toString().trim() || 'неизвестно'
      }
    }
  } catch {
    // ipapi rate limits — silent fallback.
  }
  return null
}

// ─── Full native probe (used for the "tunnel" path always, and for the
//      "direct" path when VPN is off) ────────────────────────────────────────

async function probeNative(parsed: ParsedUrl): Promise<PathReport> {
  const totalStart = Date.now()
  const dnsRes = await probeDns(parsed.host)
  if (!dnsRes || !dnsRes.resolved || dnsRes.poisoned) {
    return {
      available: false,
      totalMs: Date.now() - totalStart,
      errorStage: 'dns',
      errorMessage: dnsRes?.poisoned
        ? `DNS вернул подозрительный IP (${dnsRes.ips.join(', ')}) — похоже на DNS-блокировку.`
        : 'Имя не разрешается в IP.',
      dns: dnsRes,
      tcp: null,
      tls: null,
      http: null,
      asn: null,
      source: 'native'
    }
  }

  const firstIp = dnsRes.ips[0]
  const asn = await fetchAsn(firstIp).catch(() => null)

  const tcpRes = await probeTcp(parsed.host, parsed.port)
  if (!tcpRes.connected) {
    return {
      available: false,
      totalMs: Date.now() - totalStart,
      errorStage: 'tcp',
      errorMessage: `TCP-соединение не открылось: ${tcpRes.error || 'неизвестно'}.`,
      dns: dnsRes,
      tcp: { connected: false, ms: null },
      tls: null,
      http: null,
      asn,
      source: 'native'
    }
  }

  let tlsRes: PathReport['tls'] = null
  if (parsed.scheme === 'https') {
    const tls = await probeTls(parsed.host, parsed.port)
    tlsRes = {
      handshakeOk: tls.handshakeOk,
      ms: tls.ms,
      cipher: tls.cipher,
      protocol: tls.protocol
    }
    if (!tls.handshakeOk) {
      return {
        available: false,
        totalMs: Date.now() - totalStart,
        errorStage: 'tls',
        errorMessage: `TLS-handshake не прошёл: ${tls.error || 'неизвестно'}. Возможна DPI-блокировка по SNI.`,
        dns: dnsRes,
        tcp: { connected: true, ms: tcpRes.ms },
        tls: tlsRes,
        http: null,
        asn,
        source: 'native'
      }
    }
  }

  const httpRes = await probeHttp(parsed)
  // HTTP-level availability. Note: a 200 does NOT mean "usable here" — geo
  // blocks return healthy 200s with an "unavailable in your country" body.
  // That determination is made later via the rendered-page signal (single or
  // differential). Here we only judge the transport: anything that returned a
  // status below 500 reached the origin. 451 (legal block) is an explicit
  // geo/legal denial, so we mark it unavailable right away.
  let availableHttp = httpRes.status != null && httpRes.status < 500 && httpRes.status !== 451
  if (httpRes.status === 451) {
    return {
      available: false,
      totalMs: Date.now() - totalStart,
      errorStage: 'http',
      errorMessage: 'Сайт ответил 451 (заблокирован по юридическим причинам / гео-блок).',
      dns: dnsRes,
      tcp: { connected: true, ms: tcpRes.ms },
      tls: tlsRes,
      http: { status: httpRes.status, ms: httpRes.ms, server: httpRes.server },
      asn,
      geoBlocked: true,
      source: 'native'
    }
  }

  return {
    available: availableHttp,
    totalMs: Date.now() - totalStart,
    errorStage: availableHttp ? null : 'http',
    errorMessage: availableHttp
      ? null
      : `HTTP-запрос не вернул осмысленного ответа: ${httpRes.error ?? `статус ${httpRes.status}`}.`,
    dns: dnsRes,
    tcp: { connected: true, ms: tcpRes.ms },
    tls: tlsRes,
    http: { status: httpRes.status, ms: httpRes.ms, server: httpRes.server },
    asn,
    source: 'native'
  }
}

// ─── Direct probe via clash API (only when VPN is up) ────────────────────────

/**
 * Use the running sing-box's clash API to ask the `direct-out` outbound
 * to fetch the URL. The endpoint returns a single integer latency in ms
 * or an error JSON. We can't get the per-stage breakdown this way, but
 * we get the "would this work without the VPN" answer.
 */
async function probeViaClashApi(parsed: ParsedUrl): Promise<PathReport> {
  const info = getClashApiInfo()
  if (!info) {
    return {
      available: false,
      totalMs: null,
      errorStage: 'api',
      errorMessage: 'sing-box clash API недоступен.',
      dns: null,
      tcp: null,
      tls: null,
      http: null,
      asn: null,
      source: 'clash-direct-out'
    }
  }

  const start = Date.now()
  try {
    // The delay endpoint dispatches the request through the named
    // outbound. We pick a low timeout so a hung request doesn't block
    // the UI; the user can re-run with VPN off if they want the full
    // detailed direct-side report.
    const resp = await axios.get(
      `http://127.0.0.1:${info.port}/proxies/direct-out/delay`,
      {
        params: { url: parsed.raw, timeout: PROBE_TIMEOUT_MS },
        headers: { Authorization: `Bearer ${info.secret}` },
        timeout: PROBE_TIMEOUT_MS + 1000,
        validateStatus: () => true
      }
    )
    if (resp.status >= 200 && resp.status < 300 && typeof resp.data?.delay === 'number') {
      // Transport reached the origin via direct-out. Geo-block determination
      // is done at the orchestration level using rendered-page signals, so we
      // report "available" here and let checkUrl downgrade it if the rendered
      // direct page turns out to be a geo-block.
      return {
        available: true,
        totalMs: resp.data.delay,
        errorStage: null,
        errorMessage: null,
        dns: null,
        tcp: null,
        tls: null,
        http: { status: 200, ms: resp.data.delay, server: null },
        asn: null,
        source: 'clash-direct-out'
      }
    }
    // sing-box returns 400/500 with { message: ... } on failure.
    return {
      available: false,
      totalMs: Date.now() - start,
      errorStage: 'http',
      errorMessage: resp.data?.message
        ? `direct-out не достал URL: ${resp.data.message}`
        : `direct-out вернул ${resp.status}`,
      dns: null,
      tcp: null,
      tls: null,
      http: { status: resp.status, ms: null, server: null },
      asn: null,
      source: 'clash-direct-out'
    }
  } catch (err: any) {
    return {
      available: false,
      totalMs: null,
      errorStage: 'api',
      errorMessage: `clash API ошибка: ${err?.message || String(err)}`,
      dns: null,
      tcp: null,
      tls: null,
      http: null,
      asn: null,
      source: 'clash-direct-out'
    }
  }
}

// ─── Verdict + recommendation ────────────────────────────────────────────────

export function deriveVerdict(
  tunnel: PathReport | null,
  direct: PathReport | null
): { verdict: UrlAvailabilityResult['verdict']; recommendation: string } {
  // Tunnel off — only direct measurement was taken.
  if (!tunnel && direct) {
    if (direct.available) {
      if (direct.http?.status === 403 || direct.http?.status === 401) {
        return {
          verdict: 'works-only-with-vpn',
          recommendation: 'Сам сайт запрещает доступ (отдаёт ошибку доступа 403). Скорее всего, он блокирует пользователей по IP. Включите VPN.'
        }
      }
      return {
        verdict: 'works-both',
        recommendation: 'Провайдер не блокирует сайт (сеть работает). Если сайт всё равно недоступен или пишет «Not supported in your country», значит он сам запрещает доступ по IP — включите VPN.'
      }
    }
    return {
      verdict: 'works-only-with-vpn',
      recommendation: 'Сайт недоступен без VPN. Включите защиту и проверьте ещё раз.'
    }
  }
  // Both reports present.
  if (tunnel && direct) {
    const t = tunnel.available
    const d = direct.available
    // Strongest signal: the differential geo-block detector flagged the direct
    // (local) side while the tunnel side renders fine. This is the definitive
    // "works only with VPN because the SITE geo-blocks RU" case — independent
    // of HTTP status and language.
    if (t && direct.geoBlocked) {
      return {
        verdict: 'works-only-with-vpn',
        recommendation: 'Сайт сам блокирует доступ из вашего региона (контент «недоступен в вашей стране»), хотя сеть его не режет. Через VPN он открывается — оставьте защиту включённой.'
      }
    }
    // Even the VPN exit is geo-blocked (e.g. server in a country the site also
    // blocks). Tell the user to switch server location.
    if (tunnel.geoBlocked) {
      return {
        verdict: d && !direct.geoBlocked ? 'works-only-without-vpn' : 'blocked-everywhere',
        recommendation: 'Сайт блокирует и страну VPN-сервера. Попробуйте сервер в другой стране (например, не в той, что сейчас).'
      }
    }
    if (t && d) {
      // Geo-block heuristic: VPN gets 200 OK, direct gets 403 Forbidden.
      // This means the ISP/RKN is NOT blocking the site, but the destination
      // server is actively refusing Russian IPs.
      if (
        (tunnel.http?.status === 200 || tunnel.http?.status === 301 || tunnel.http?.status === 302 || tunnel.http?.status === 307) &&
        (direct.http?.status === 403 || direct.http?.status === 401)
      ) {
        return {
          verdict: 'works-only-with-vpn',
          recommendation: 'Сам сайт запрещает доступ без VPN (отдаёт ошибку доступа 403). Оставьте защиту включённой.'
        }
      }

      return {
        verdict: 'works-both',
        recommendation: 'Провайдер не блокирует сайт (сеть работает). Если сайт всё равно недоступен или пишет «Not supported in your country», значит он сам запрещает доступ из РФ — в таком случае включите VPN.'
      }
    }
    if (t && !d) {
      return {
        verdict: 'works-only-with-vpn',
        recommendation: 'Сайт работает только через VPN — провайдер блокирует его напрямую. Оставьте защиту включённой.'
      }
    }
    if (!t && d) {
      return {
        verdict: 'works-only-without-vpn',
        recommendation: 'Сайт работает только без VPN (типично для российских сервисов). Добавьте его в исключения или временно отключите защиту.'
      }
    }
    return {
      verdict: 'blocked-everywhere',
      recommendation: 'Сайт не отвечает ни через VPN, ни напрямую. Возможно, он сейчас лежит или его блокируют по содержимому (а не по сети) — попробуйте другой сервер.'
    }
  }
  return {
    verdict: 'unknown',
    recommendation: 'Не удалось завершить проверку.'
  }
}

// ─── Geo-block orchestration ─────────────────────────────────────────────────

/** Stamp geoBlocked + downgrade availability on the relevant report(s) using
 *  rendered-page signals. Mutates the passed report objects in place. */
async function applyGeoBlock(
  parsed: ParsedUrl,
  tunnel: PathReport | null,
  direct: PathReport | null,
  tunRunning: boolean
): Promise<void> {
  // Only bother when at least one side reached the origin (transport OK) —
  // there's nothing to "render" through a dead path.
  const directReachable = !!direct && (direct.available || direct.http?.status != null)
  const tunnelReachable = !!tunnel && (tunnel.available || tunnel.http?.status != null)

  if (tunRunning) {
    // Render foreign (TUN) and local (direct-out SOCKS) in parallel.
    const dpPort = getDirectProxyPort()
    const [foreignSig, localSig] = await Promise.all([
      tunnelReachable ? probePageSignal(parsed.raw, undefined) : Promise.resolve(null),
      directReachable && dpPort
        ? probePageSignal(parsed.raw, `socks5://127.0.0.1:${dpPort}`)
        : Promise.resolve(null)
    ])

    // Differential: if we have both renders, this is the strong signal for the
    // LOCAL (direct) side — "works abroad, blocked at home".
    if (foreignSig && localSig) {
      const diff = compareRenders(foreignSig, localSig)
      if (diff.blocked && direct) {
        direct.available = false
        direct.geoBlocked = true
        direct.errorStage = 'http'
        direct.errorMessage = geoBlockMessage(diff)
      }
      // The foreign (tunnel) side: a single-page check catches the rare case
      // where even the VPN exit is geo-blocked (e.g. wrong-country server).
      const foreignVerdict = scoreSinglePage(foreignSig)
      if (foreignVerdict.blocked && tunnel) {
        tunnel.available = false
        tunnel.geoBlocked = true
        tunnel.errorStage = 'http'
        tunnel.errorMessage = geoBlockMessage(foreignVerdict)
      }
      return
    }

    // Fallbacks when one render is missing: single-page score each side we got.
    if (localSig && direct) {
      const v = scoreSinglePage(localSig)
      if (v.blocked) {
        direct.available = false
        direct.geoBlocked = true
        direct.errorStage = 'http'
        direct.errorMessage = geoBlockMessage(v)
      }
    }
    if (foreignSig && tunnel) {
      const v = scoreSinglePage(foreignSig)
      if (v.blocked) {
        tunnel.available = false
        tunnel.geoBlocked = true
        tunnel.errorStage = 'http'
        tunnel.errorMessage = geoBlockMessage(v)
      }
    }
    return
  }

  // Tunnel OFF — only the local (direct) render exists; single-page scoring.
  if (directReachable && direct) {
    const sig = await probePageSignal(parsed.raw, 'direct://')
    if (sig) {
      const v = scoreSinglePage(sig)
      if (v.blocked) {
        direct.available = false
        direct.geoBlocked = true
        direct.errorStage = 'http'
        direct.errorMessage = geoBlockMessage(v)
      }
    }
  }
}

function geoBlockMessage(v: GeoBlockVerdict): string {
  const why = v.reasons.length ? ` (${v.reasons.slice(0, 2).join('; ')})` : ''
  return `Сайт загрузился, но сам запретил доступ для вашего региона (Geo-Block)${why}.`
}

// ─── Public entry point ──────────────────────────────────────────────────────

export async function checkUrl(input: string): Promise<UrlAvailabilityResult> {
  const parsed = parseUrlForProbe(input)
  if (!parsed) {
    throw new Error('Не удалось разобрать ссылку. Введите URL вида example.com или https://example.com/path.')
  }

  const tunRunning = tunController.getStatus().running

  logEvent('info', 'url-availability', 'starting check', {
    host: parsed.host,
    port: parsed.port,
    tunnelActive: tunRunning
  })

  // Run both probes in parallel when VPN is on. The "native" probe goes
  // through TUN (=tunnel side), the clash-API probe goes through direct-out
  // (=what-would-be-without-VPN). When VPN is off, native IS the direct
  // side and we skip the clash call.
  let tunnel: PathReport | null = null
  let direct: PathReport | null = null
  if (tunRunning) {
    const [t, d] = await Promise.all([
      probeNative(parsed),
      probeViaClashApi(parsed)
    ])
    tunnel = t
    direct = d
  } else {
    direct = await probeNative(parsed)
  }

  // ─── Geo-block determination via rendered-page signals ──────────────────
  // A transport-level "available" (200/connect) does NOT mean usable here: the
  // site may serve a healthy 200 whose content says "not available in your
  // country". We render the page through each exit and decide:
  //   - tunnel ON  → render through BOTH exits (foreign via TUN, local via the
  //     direct-out SOCKS port) and run the LANGUAGE-INDEPENDENT differential.
  //   - tunnel OFF → only the local render exists; fall back to single-page
  //     scoring (weaker, but the only option without a foreign reference).
  // Only HTTPS/HTTP pages that reached the origin are worth rendering.
  try {
    await applyGeoBlock(parsed, tunnel, direct, tunRunning)
  } catch (err) {
    logEvent('debug', 'url-availability', 'geo-block detection skipped', {
      error: (err as Error)?.message
    })
  }

  const { verdict, recommendation } = deriveVerdict(tunnel, direct)
  const result: UrlAvailabilityResult = {
    id: randomUUID(),
    url: parsed.raw,
    testedAt: Date.now(),
    tunnelActive: tunRunning,
    tunnel,
    direct,
    verdict,
    recommendation
  }

  // Append to history (LRU, MAX_HISTORY entries).
  const history = store.get('history') as UrlAvailabilityResult[]
  history.unshift(result)
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY
  store.set('history', history)

  logEvent('info', 'url-availability', 'check finished', {
    host: parsed.host,
    verdict,
    tunnelOk: tunnel?.available ?? null,
    directOk: direct?.available ?? null
  })

  return result
}

export function getHistory(): UrlAvailabilityResult[] {
  return (store.get('history') as UrlAvailabilityResult[]) ?? []
}

export function clearHistory(): void {
  store.set('history', [])
}

// ─── IPC ─────────────────────────────────────────────────────────────────────

export function registerUrlAvailabilityHandlers(): void {
  ipcMain.handle('url-availability:check', async (_event, url: string) => {
    return checkUrl(url)
  })
  ipcMain.handle('url-availability:history', async () => {
    return getHistory()
  })
  ipcMain.handle('url-availability:clear-history', async () => {
    clearHistory()
  })
}

/**
 * Render a URL in an offscreen, sandboxed browser through a given proxy and
 * extract a structured PageSignal (final URL, title, innerText sample+length).
 * This replaces the old boolean regex probe: the heavy lifting (deciding
 * "blocked") moved to the pure, tested geoBlockDetect module, which can do a
 * language-independent differential comparison between two renders.
 *
 * Returns null when the page couldn't be rendered at all (load failure /
 * timeout) — the caller treats that as "no signal" rather than "not blocked".
 */
export async function probePageSignal(url: string, proxyRules?: string): Promise<PageSignal | null> {
  return new Promise((resolve) => {
    let mainStatus: number | null = null
    const win = new BrowserWindow({
      show: false,
      webPreferences: {
        offscreen: true,
        nodeIntegration: false,
        contextIsolation: true,
        // Arbitrary, possibly-hostile third-party pages. Sandbox hard.
        sandbox: true,
        webSecurity: true
      }
    })

    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

    let settled = false
    const finish = (sig: PageSignal | null) => {
      if (settled) return
      settled = true
      clearTimeout(timeoutId)
      try { if (!win.isDestroyed()) win.destroy() } catch { /* ignore */ }
      resolve(sig)
    }

    const timeoutId = setTimeout(() => finish(null), 12000)

    win.webContents.session
      .setProxy({ proxyRules: proxyRules || 'direct://' })
      .catch(() => {})

    // Capture the main-frame HTTP status. did-navigate fires with the response
    // code for the top-level document.
    win.webContents.on(
      'did-navigate',
      (_e, _url, httpResponseCode) => {
        if (typeof httpResponseCode === 'number' && httpResponseCode > 0) {
          mainStatus = httpResponseCode
        }
      }
    )

    const extract = async () => {
      // Let SPAs settle a touch before sampling.
      await new Promise((r) => setTimeout(r, 1500))
      if (win.isDestroyed()) return finish(null)
      try {
        const data = await win.webContents.executeJavaScript(
          `(() => {
             const text = (document.body && document.body.innerText) || '';
             return {
               finalUrl: location.href,
               title: document.title || '',
               textLength: text.length,
               textSample: text.slice(0, 8000)
             };
           })()`
        )
        finish({
          requestedUrl: url,
          finalUrl: typeof data?.finalUrl === 'string' ? data.finalUrl : null,
          title: typeof data?.title === 'string' ? data.title : null,
          textSample: (typeof data?.textSample === 'string' ? data.textSample : '').toLowerCase(),
          textLength: Number.isFinite(data?.textLength) ? Number(data.textLength) : 0,
          httpStatus: mainStatus
        })
      } catch {
        finish(null)
      }
    }

    win.webContents.on('did-finish-load', () => { void extract() })
    // did-fail-load fires for the main frame on hard failures; for a geo-block
    // that still renders an HTML page did-finish-load fires instead. If the
    // main frame genuinely failed we still try to sample (some block pages
    // report a failure code but render content).
    win.webContents.on('did-fail-load', (_e, errorCode, _desc, _validatedUrl, isMainFrame) => {
      if (isMainFrame && errorCode !== -3 /* ABORTED is benign */) {
        // Give the renderer a beat in case a body was still painted.
        setTimeout(() => { if (!settled) void extract() }, 500)
      }
    })

    win.loadURL(url).catch(() => { /* finish via timeout/fail-load */ })
  })
}

/**
 * Back-compat boolean wrapper around the new signal probe + single-page
 * scorer. Kept for any caller that just wants "is this one render blocked".
 */
export async function probeBrowserGeoBlock(url: string, proxyRules?: string): Promise<boolean> {
  const sig = await probePageSignal(url, proxyRules)
  if (!sig) return false
  return scoreSinglePage(sig).blocked
}
