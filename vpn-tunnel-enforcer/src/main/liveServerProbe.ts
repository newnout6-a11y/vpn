import { ipcMain } from 'electron'
import { promises as dnsPromises } from 'dns'
import * as net from 'net'
import * as tls from 'tls'
import * as http from 'http'
import * as https from 'https'
import * as crypto from 'crypto'
import { spawn } from 'child_process'
import axios from 'axios'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'
import { serverPicker } from './serverPicker'
import { tunController } from './tunController'
import { normalizeServerPort } from '../shared/portValidation'
import {
  liveServerHistory,
  computeHistoryDiff,
  sanitizeLiveCheckForStorage
} from './liveServerHistory'
import type {
  AsnInfo,
  DnsDiagnostics,
  HttpProbeResult,
  InfrastructureHints,
  LiveCheckFinding,
  LiveLatencyStats,
  LivePortScanItem,
  LiveServerCheck,
  LiveServerCheckOptions,
  LiveTlsCertInfo,
  ReachabilityDiagnostics,
  RouteDiagnostics
} from '../shared/ipc-types'

export const LIVE_PROBE_THRESHOLDS = {
  HIGH_LATENCY_WARNING_MS: 250,
  HIGH_LATENCY_ERROR_MS: 500,
  HIGH_JITTER_WARNING_MS: 40,
  PACKET_LOSS_WARNING: 0.1,
  PACKET_LOSS_ERROR: 0.5,
  TLS_EXPIRING_WARNING_DAYS: 30,
  TLS_EXPIRING_ERROR_DAYS: 7,
  PORT_SCAN_CONCURRENCY: 3,
  MAX_REDIRECTS: 3,
  MAX_HTTP_BODY_BYTES: 8192,
  DNS_LOOKUP_TIMEOUT_MS: 2500,
  TCP_CONNECT_TIMEOUT_MS: 1500,
  TLS_HANDSHAKE_TIMEOUT_MS: 3500,
  HTTP_PROBE_TIMEOUT_MS: 3500,
  TRACEROUTE_TIMEOUT_MS: 3500
} as const

export const RESTRICTED_PORTS = [80, 443, 8080, 8443, 2053, 2083, 2087, 2096] as const

const SERVICE_HINTS: Record<number, string> = {
  80: 'HTTP',
  443: 'HTTPS',
  8080: 'HTTP-alt',
  8443: 'HTTPS-alt',
  2053: 'Cloudflare-TLS',
  2083: 'Cloudflare-TLS',
  2087: 'Cloudflare-TLS',
  2096: 'Cloudflare-TLS'
}

// In-memory ASN cache with 10-minute TTL to reduce external geo queries
const asnCache = new Map<string, { data: AsnInfo; expiresAt: number }>()

// Active checks registry mapped by unique requestId
const activeControllers = new Map<string, AbortController>()

/**
 * Normalizes host and port from various formats (IPv4, bracketed IPv6, domain:port).
 */
export function normalizeHostAndPort(
  rawHost: string,
  rawPort?: number
): { host: string; port: number; isIp: boolean; isIpv6: boolean } {
  let host = (rawHost || '').trim()
  let port = normalizeServerPort(rawPort, 443)!

  if (host.startsWith('[') && host.includes(']')) {
    const endBracket = host.indexOf(']')
    const inside = host.slice(1, endBracket)
    const after = host.slice(endBracket + 1)
    host = inside
    if (after.startsWith(':')) {
      const parsedPort = Number(after.slice(1))
      if (Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
        port = parsedPort
      }
    }
  } else if (!host.includes('::') && host.includes(':')) {
    const parts = host.split(':')
    if (parts.length === 2) {
      host = parts[0]
      const parsedPort = Number(parts[1])
      if (Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
        port = parsedPort
      }
    }
  }

  const ipFamily = net.isIP(host)
  const isIp = ipFamily !== 0
  const isIpv6 = ipFamily === 6

  return { host, port, isIp, isIpv6 }
}

/**
 * Stage 2: DNS Diagnostics (parallel A/AAAA, CNAME chain, reverse DNS)
 */
export async function probeDns(
  host: string,
  mode: 'basic' | 'extended' = 'basic',
  signal?: AbortSignal
): Promise<{ dns: DnsDiagnostics; reverseDns: string[] }> {
  const started = Date.now()
  const ipFamily = net.isIP(host)

  // Direct IP entered: skip forward DNS
  if (ipFamily !== 0) {
    const reverseDnsList: string[] = []
    try {
      if (!signal?.aborted) {
        const rev = await Promise.race([
          dnsPromises.reverse(host),
          new Promise<string[]>((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS)
          )
        ]).catch(() => [])
        if (Array.isArray(rev)) reverseDnsList.push(...rev)
      }
    } catch {}

    return {
      dns: {
        status: 'ok',
        durationMs: Date.now() - started,
        a: ipFamily === 4 ? [host] : [],
        aaaa: ipFamily === 6 ? [host] : [],
        cnameChain: []
      },
      reverseDns: reverseDnsList
    }
  }

  if (signal?.aborted) {
    return {
      dns: {
        status: 'skipped',
        durationMs: 0,
        error: 'Cancelled',
        a: [],
        aaaa: [],
        cnameChain: []
      },
      reverseDns: []
    }
  }

  const aRecords: string[] = []
  const aaaaRecords: string[] = []
  const cnameChain: string[] = []
  const timings: { aMs?: number; aaaaMs?: number; cnameMs?: number } = {}
  let minTtl: number | undefined
  let primaryError: string | undefined

  // 1. Parallel A and AAAA resolution
  const queryA = async () => {
    const aStart = Date.now()
    try {
      const resA = await Promise.race([
        dnsPromises.resolve4(host, { ttl: true }),
        new Promise<Array<{ address: string; ttl: number }>>((_, reject) =>
          setTimeout(() => reject(new Error('A query timeout')), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS)
        )
      ]).catch((err) => {
        primaryError = err?.message || 'A query failed'
        return [] as Array<{ address: string; ttl: number }>
      })

      timings.aMs = Date.now() - aStart
      for (const r of resA) {
        if (r?.address && !aRecords.includes(r.address)) {
          aRecords.push(r.address)
          if (typeof r.ttl === 'number') {
            minTtl = minTtl === undefined ? r.ttl : Math.min(minTtl, r.ttl)
          }
        }
      }
    } catch (err: any) {
      timings.aMs = Date.now() - aStart
      if (!primaryError) primaryError = err?.message
    }
  }

  const queryAAAA = async () => {
    if (signal?.aborted) return
    const aaaaStart = Date.now()
    try {
      const resAAAA = await Promise.race([
        dnsPromises.resolve6(host, { ttl: true }),
        new Promise<Array<{ address: string; ttl: number }>>((_, reject) =>
          setTimeout(() => reject(new Error('AAAA query timeout')), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS)
        )
      ]).catch(() => [] as Array<{ address: string; ttl: number }>)

      timings.aaaaMs = Date.now() - aaaaStart
      for (const r of resAAAA) {
        if (r?.address && !aaaaRecords.includes(r.address)) {
          aaaaRecords.push(r.address)
          if (typeof r.ttl === 'number') {
            minTtl = minTtl === undefined ? r.ttl : Math.min(minTtl, r.ttl)
          }
        }
      }
    } catch {
      timings.aaaaMs = Date.now() - aaaaStart
    }
  }

  await Promise.all([queryA(), queryAAAA()])

  // 2. Resolve CNAME chain (max depth 5, checking signal in loop)
  if (!signal?.aborted) {
    const cnameStart = Date.now()
    let currentTarget = host
    const visited = new Set<string>([host.toLowerCase()])
    for (let depth = 0; depth < 5; depth++) {
      if (signal?.aborted) break
      try {
        const cnames = await Promise.race([
          dnsPromises.resolveCname(currentTarget),
          new Promise<string[]>((_, reject) =>
            setTimeout(() => reject(new Error('CNAME timeout')), 1000)
          )
        ]).catch(() => [] as string[])

        if (cnames.length === 0) break
        const nextTarget = cnames[0]
        cnameChain.push(nextTarget)
        const lower = nextTarget.toLowerCase()
        if (visited.has(lower)) break
        visited.add(lower)
        currentTarget = nextTarget
      } catch {
        break
      }
    }
    timings.cnameMs = Date.now() - cnameStart
  }

  // 3. Reverse DNS for all resolved unique IPs
  const allIps = [...new Set([...aRecords, ...aaaaRecords])]
  const reverseDnsList: string[] = []
  if (!signal?.aborted && allIps.length > 0) {
    const reversePromises = allIps.map(async (ip) => {
      if (signal?.aborted) return []
      try {
        const rev = await Promise.race([
          dnsPromises.reverse(ip),
          new Promise<string[]>((_, reject) =>
            setTimeout(() => reject(new Error('reverse timeout')), 1200)
          )
        ]).catch(() => [] as string[])
        return rev
      } catch {
        return [] as string[]
      }
    })
    const revResults = await Promise.allSettled(reversePromises)
    for (const r of revResults) {
      if (r.status === 'fulfilled' && Array.isArray(r.value)) {
        for (const name of r.value) {
          if (name && !reverseDnsList.includes(name)) reverseDnsList.push(name)
        }
      }
    }
  }

  const durationMs = Date.now() - started
  const hasRecords = aRecords.length > 0 || aaaaRecords.length > 0

  return {
    dns: {
      status: hasRecords ? 'ok' : 'error',
      durationMs,
      error: hasRecords ? undefined : (primaryError || 'DNS lookup failed: no records'),
      a: aRecords,
      aaaa: aaaaRecords,
      cnameChain,
      ttl: minTtl,
      timings
    },
    reverseDns: reverseDnsList
  }
}

/**
 * Stage 3: Real TLS Probe
 * Verifies certificate identity against host or SNI, preserves authorization state, passes ALPN.
 */
export async function probeTls(
  host: string,
  port: number,
  sniHostname?: string,
  signal?: AbortSignal
): Promise<LiveTlsCertInfo> {
  const started = Date.now()
  if (signal?.aborted) {
    return {
      status: 'skipped',
      durationMs: 0,
      error: 'Cancelled'
    }
  }

  const identityTarget = sniHostname || host
  const isTargetIp = net.isIP(identityTarget) !== 0

  return new Promise<LiveTlsCertInfo>((resolve) => {
    let finished = false
    const finish = (result: LiveTlsCertInfo) => {
      if (finished) return
      finished = true
      socket?.destroy()
      resolve(result)
    }

    const abortHandler = () => {
      finish({
        status: 'skipped',
        durationMs: Date.now() - started,
        error: 'Cancelled'
      })
    }

    if (signal) {
      signal.addEventListener('abort', abortHandler, { once: true })
    }

    const timer = setTimeout(() => {
      finish({
        status: 'error',
        durationMs: Date.now() - started,
        error: 'TLS handshake timeout'
      })
    }, LIVE_PROBE_THRESHOLDS.TLS_HANDSHAKE_TIMEOUT_MS)

    let socket: tls.TLSSocket | null = null

    try {
      // RFC 6066: servername must only be sent for DNS hostnames, not IP addresses
      const servername = sniHostname
        ? (net.isIP(sniHostname) === 0 ? sniHostname : undefined)
        : (isTargetIp ? undefined : identityTarget)

      socket = tls.connect(
        {
          host,
          port,
          servername,
          rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1'],
          timeout: LIVE_PROBE_THRESHOLDS.TLS_HANDSHAKE_TIMEOUT_MS
        },
        () => {
          clearTimeout(timer)
          try {
            const cert = socket?.getPeerCertificate(true)
            if (!cert || Object.keys(cert).length === 0) {
              finish({
                status: 'error',
                durationMs: Date.now() - started,
                error: 'No peer certificate returned'
              })
              return
            }

            const protocol = socket?.getProtocol() || undefined
            const cipher = socket?.getCipher()?.name || undefined
            const alpn = (socket as any)?.alpnProtocol || undefined
            const authorized = socket?.authorized === true
            const authorizationError = socket?.authorizationError ? String(socket.authorizationError) : undefined

            // Verify identity against identityTarget (works for both domain and IP against SANs)
            let hostnameVerified = false
            let verifyError: string | undefined
            try {
              const checkErr = tls.checkServerIdentity(identityTarget, cert)
              if (checkErr) {
                hostnameVerified = false
                verifyError = checkErr.message
              } else {
                hostnameVerified = true
              }
            } catch (err: any) {
              hostnameVerified = false
              verifyError = err?.message || 'Hostname check failed'
            }

            // Parse SANs
            const sans: string[] = []
            if (cert.subjectaltname && typeof cert.subjectaltname === 'string') {
              for (const part of cert.subjectaltname.split(',')) {
                const trimmed = part.trim()
                if (trimmed.startsWith('DNS:')) {
                  sans.push(trimmed.slice(4))
                } else if (trimmed.startsWith('IP Address:')) {
                  sans.push(trimmed.slice(11))
                } else if (trimmed) {
                  sans.push(trimmed)
                }
              }
            }

            // Expiry calculation
            let daysRemaining: number | undefined
            if (cert.valid_to) {
              const toTime = new Date(cert.valid_to).getTime()
              if (!isNaN(toTime)) {
                daysRemaining = Math.round((toTime - Date.now()) / (1000 * 60 * 60 * 24))
              }
            }

            const formatCertField = (val: unknown): string | undefined => {
              if (!val) return undefined
              if (Array.isArray(val)) return val.join(', ')
              if (typeof val === 'string') return val
              return String(val)
            }
            const subject = formatCertField(cert.subject?.CN) || (cert.subject ? JSON.stringify(cert.subject) : undefined)
            const issuer = formatCertField(cert.issuer?.O) || formatCertField(cert.issuer?.CN) || (cert.issuer ? JSON.stringify(cert.issuer) : undefined)
            const fingerprint = cert.fingerprint256 || undefined

            finish({
              status: 'ok',
              durationMs: Date.now() - started,
              hostnameVerified,
              authorized,
              authorizationError,
              error: verifyError,
              subject,
              issuer,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              fingerprint,
              sans,
              protocol,
              cipher,
              alpn,
              alpnProtocol: alpn
            })
          } catch (err: any) {
            finish({
              status: 'error',
              durationMs: Date.now() - started,
              error: `Certificate parsing error: ${err?.message || err}`
            })
          }
        }
      )

      socket.on('error', (err: any) => {
        clearTimeout(timer)
        finish({
          status: 'error',
          durationMs: Date.now() - started,
          error: err?.message || 'TLS connection error'
        })
      })

      socket.on('timeout', () => {
        clearTimeout(timer)
        finish({
          status: 'error',
          durationMs: Date.now() - started,
          error: 'TLS socket timeout'
        })
      })
    } catch (err: any) {
      clearTimeout(timer)
      finish({
        status: 'error',
        durationMs: Date.now() - started,
        error: err?.message || 'TLS initialization error'
      })
    }
  })
}

/**
 * Stage 4: HTTP/HTTPS Diagnostic Probe
 * Passes Host authority and TLS SNI, enforces overall deadline, bounded 8KB body.
 */
export async function probeHttp(
  connectIp: string,
  port: number,
  isTls: boolean,
  authorityHost?: string,
  signal?: AbortSignal
): Promise<HttpProbeResult> {
  const started = Date.now()
  if (signal?.aborted) {
    return {
      status: 'skipped',
      durationMs: 0,
      error: 'Cancelled',
      targetPort: port,
      isTls,
      confidence: 'low'
    }
  }

  const requester = isTls ? https : http
  const overallDeadline = Date.now() + LIVE_PROBE_THRESHOLDS.HTTP_PROBE_TIMEOUT_MS

  const executeRequest = (
    method: 'HEAD' | 'GET',
    reqPath: string,
    redirectCount = 0
  ): Promise<HttpProbeResult> => {
    return new Promise<HttpProbeResult>((resolve) => {
      let resolved = false
      const done = (res: HttpProbeResult) => {
        if (resolved) return
        resolved = true
        resolve(res)
      }

      if (signal?.aborted || Date.now() >= overallDeadline) {
        done({
          status: 'skipped',
          durationMs: Date.now() - started,
          error: signal?.aborted ? 'Cancelled' : 'HTTP overall deadline exceeded',
          targetPort: port,
          isTls,
          confidence: 'low'
        })
        return
      }

      const hostHeaderValue = authorityHost
        ? (port === (isTls ? 443 : 80) ? authorityHost : `${authorityHost}:${port}`)
        : (port === (isTls ? 443 : 80) ? connectIp : `${connectIp}:${port}`)

      const servername = (authorityHost && net.isIP(authorityHost) === 0) ? authorityHost : undefined

      const remainingTime = Math.max(500, overallDeadline - Date.now())

      const req = requester.request(
        {
          host: connectIp,
          port,
          path: reqPath,
          method,
          servername,
          timeout: remainingTime,
          rejectUnauthorized: false,
          headers: {
            Host: hostHeaderValue,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VPNTE-Diagnostics/1.0',
            Accept: '*/*'
          }
        },
        (res) => {
          let bytesReceived = 0
          const statusCode = res.statusCode || 0
          const serverHeader = Array.isArray(res.headers['server'])
            ? res.headers['server'].join(', ')
            : (res.headers['server'] || undefined)
          const viaHeader = Array.isArray(res.headers['via'])
            ? res.headers['via'].join(', ')
            : (res.headers['via'] || undefined)
          const contentType = Array.isArray(res.headers['content-type'])
            ? res.headers['content-type'].join(', ')
            : (res.headers['content-type'] || undefined)

          // Sanitize Location: strip query and credentials
          let locationHeader: string | undefined
          if (res.headers['location'] && typeof res.headers['location'] === 'string') {
            try {
              const parsed = new URL(res.headers['location'], `${isTls ? 'https' : 'http'}://${connectIp}:${port}`)
              locationHeader = `${parsed.protocol}//${parsed.host}${parsed.pathname}`
            } catch {
              locationHeader = res.headers['location'].split('?')[0].split('#')[0]
            }
          }

          // Follow redirect if 3xx and within limit
          if ([301, 302, 307, 308].includes(statusCode) && locationHeader && redirectCount < LIVE_PROBE_THRESHOLDS.MAX_REDIRECTS) {
            res.destroy()
            try {
              const nextUrl = new URL(locationHeader)
              if (nextUrl.hostname === connectIp && Number(nextUrl.port || (isTls ? 443 : 80)) === port) {
                executeRequest('HEAD', nextUrl.pathname, redirectCount + 1).then(done)
                return
              }
            } catch {}
          }

          // If 405 Method Not Allowed on HEAD, retry once with GET
          if (statusCode === 405 && method === 'HEAD') {
            res.destroy()
            executeRequest('GET', reqPath, redirectCount).then(done)
            return
          }

          // Bounded response body reading: max 8 KB
          res.on('data', (chunk: Buffer) => {
            bytesReceived += chunk.length
            if (bytesReceived >= LIVE_PROBE_THRESHOLDS.MAX_HTTP_BODY_BYTES) {
              res.destroy()
            }
          })

          res.on('end', () => {
            done({
              status: 'ok',
              durationMs: Date.now() - started,
              statusCode,
              protocol: res.httpVersion ? `HTTP/${res.httpVersion}` : undefined,
              serverHeader,
              viaHeader,
              locationHeader,
              contentType,
              bodySize: bytesReceived,
              targetPort: port,
              isTls,
              confidence: 'low'
            })
          })

          res.on('close', () => {
            done({
              status: 'ok',
              durationMs: Date.now() - started,
              statusCode,
              protocol: res.httpVersion ? `HTTP/${res.httpVersion}` : undefined,
              serverHeader,
              viaHeader,
              locationHeader,
              contentType,
              bodySize: bytesReceived,
              targetPort: port,
              isTls,
              confidence: 'low'
            })
          })
        }
      )

      req.on('timeout', () => {
        req.destroy()
        done({
          status: 'error',
          durationMs: Date.now() - started,
          error: 'HTTP request timeout',
          targetPort: port,
          isTls,
          confidence: 'low'
        })
      })

      req.on('error', (err: any) => {
        done({
          status: 'error',
          durationMs: Date.now() - started,
          error: err?.message || 'HTTP request error',
          targetPort: port,
          isTls,
          confidence: 'low'
        })
      })

      if (signal) {
        signal.addEventListener('abort', () => {
          req.destroy()
          done({
            status: 'skipped',
            durationMs: Date.now() - started,
            error: 'Cancelled',
            targetPort: port,
            isTls,
            confidence: 'low'
          })
        }, { once: true })
      }

      req.end()
    })
  }

  return executeRequest('HEAD', '/')
}

/**
 * Measure a single TCP connect to host:port
 */
function probeTcpSingle(
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<{ ok: boolean; durationMs: number; error?: string }> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve({ ok: false, durationMs: 0, error: 'Cancelled' })
      return
    }

    const start = Date.now()
    const socket = new net.Socket()
    let resolved = false

    const finish = (ok: boolean, err?: string) => {
      if (resolved) return
      resolved = true
      socket.destroy()
      resolve({ ok, durationMs: Date.now() - start, error: err })
    }

    if (signal) {
      signal.addEventListener('abort', () => finish(false, 'Cancelled'), { once: true })
    }

    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false, 'ETIMEDOUT'))
    socket.once('error', (e: any) => finish(false, e?.code || e?.message || 'Error'))
    socket.connect(port, host)
  })
}

/**
 * Stage 5: Reachability, Latency & Stability Probe
 * Measures TCP connect failure rate, records pathType, counts only actual attempted samples.
 */
export async function probeReachabilityAndLatency(
  host: string,
  port: number,
  mode: 'basic' | 'extended' = 'basic',
  signal?: AbortSignal
): Promise<{ reachability: ReachabilityDiagnostics; latency: LiveLatencyStats | undefined }> {
  const started = Date.now()
  const samplesTarget = mode === 'extended' ? 10 : 5
  const timeoutPerSample = LIVE_PROBE_THRESHOLDS.TCP_CONNECT_TIMEOUT_MS
  const deadline = Date.now() + (mode === 'extended' ? 9000 : 6000)

  const durations: number[] = []
  let lostCount = 0
  let attemptedCount = 0
  let primaryError: string | undefined

  for (let i = 0; i < samplesTarget; i++) {
    if (signal?.aborted) break
    const remainingTime = deadline - Date.now()
    if (remainingTime <= 0) break

    attemptedCount++
    const probe = await probeTcpSingle(host, port, Math.min(timeoutPerSample, remainingTime), signal)
    if (probe.ok) {
      durations.push(probe.durationMs)
    } else {
      lostCount++
      if (!primaryError && probe.error) primaryError = probe.error
    }

    // Inter-sample spacing (60ms) if not at end
    if (i < samplesTarget - 1 && Date.now() + 60 < deadline && !signal?.aborted) {
      await new Promise((r) => setTimeout(r, 60))
    }
  }

  const tcpReachable = durations.length > 0
  const pathType = tunController.getStatus().running ? 'tun' : 'direct'

  const reachability: ReachabilityDiagnostics = {
    status: tcpReachable ? 'ok' : 'error',
    durationMs: Date.now() - started,
    tcpReachable,
    port,
    error: tcpReachable ? undefined : (primaryError || 'Connection refused or timed out')
  }

  if (attemptedCount === 0 || durations.length === 0) {
    return { reachability, latency: undefined }
  }

  durations.sort((a, b) => a - b)
  const min = durations[0]
  const max = durations[durations.length - 1]
  const avg = Math.round(durations.reduce((sum, d) => sum + d, 0) / durations.length)
  const midIndex = Math.floor(durations.length / 2)
  const median = durations.length % 2 === 0
    ? Math.round((durations[midIndex - 1] + durations[midIndex]) / 2)
    : durations[midIndex]

  const variance = durations.reduce((sum, d) => sum + (d - avg) ** 2, 0) / durations.length
  const jitter = Math.round(Math.sqrt(variance))
  const loss = Number((lostCount / attemptedCount).toFixed(2))

  const latency: LiveLatencyStats = {
    min,
    avg,
    median,
    max,
    jitter,
    loss,
    connectionFailureRate: loss,
    samples: durations,
    samplesAttempted: attemptedCount,
    pathType,
    method: 'tcp'
  }

  return { reachability, latency }
}

/**
 * Stage 6: Bounded Port Scanner with concurrency limit 3
 */
export async function probePorts(
  host: string,
  knownPort: number,
  mode: 'basic' | 'extended' = 'basic',
  signal?: AbortSignal
): Promise<LivePortScanItem[]> {
  const portsToScan: number[] = []

  if (mode === 'basic') {
    portsToScan.push(knownPort)
    if (knownPort !== 443) portsToScan.push(443)
  } else {
    const set = new Set<number>([...RESTRICTED_PORTS, knownPort])
    portsToScan.push(...set)
  }

  const results: LivePortScanItem[] = []
  const concurrency = LIVE_PROBE_THRESHOLDS.PORT_SCAN_CONCURRENCY

  let index = 0
  const workers = Array.from({ length: concurrency }).map(async () => {
    while (index < portsToScan.length) {
      if (signal?.aborted) break
      const currentPort = portsToScan[index++]
      const probe = await probeTcpSingle(host, currentPort, 1200, signal)

      let state: LivePortScanItem['state'] = 'closed'
      if (probe.ok) {
        state = 'open'
      } else if (probe.error === 'ETIMEDOUT') {
        state = 'timeout'
      } else if (probe.error?.includes('REFUSED')) {
        state = 'closed'
      } else {
        state = 'filtered'
      }

      results.push({
        port: currentPort,
        open: probe.ok,
        state,
        service: SERVICE_HINTS[currentPort]
      })
    }
  })

  await Promise.all(workers)
  return results.sort((a, b) => a.port - b.port)
}

/**
 * Stage 7: Route Diagnostics (Hop estimation via tracert, no fake MTU)
 */
export async function probeRoute(targetIp: string, signal?: AbortSignal): Promise<RouteDiagnostics> {
  const started = Date.now()
  if (process.platform !== 'win32' || !targetIp) {
    return {
      status: 'unavailable',
      durationMs: 0,
      error: 'Platform does not support native win32 traceroute',
      mtuStatus: 'unavailable'
    }
  }

  if (signal?.aborted) {
    return {
      status: 'skipped',
      durationMs: 0,
      error: 'Cancelled',
      mtuStatus: 'skipped'
    }
  }

  return new Promise<RouteDiagnostics>((resolve) => {
    let resolved = false
    const finish = (result: RouteDiagnostics) => {
      if (resolved) return
      resolved = true
      resolve(result)
    }

    try {
      const child = spawn('tracert', ['-d', '-h', '8', '-w', '400', targetIp], {
        windowsHide: true
      })

      let output = ''
      child.stdout.on('data', (d) => {
        output += d.toString()
      })

      const timer = setTimeout(() => {
        try { child.kill() } catch {}
        finish({
          status: 'unavailable',
          durationMs: Date.now() - started,
          error: 'Traceroute timed out',
          mtuStatus: 'unavailable'
        })
      }, LIVE_PROBE_THRESHOLDS.TRACEROUTE_TIMEOUT_MS)

      if (signal) {
        signal.addEventListener('abort', () => {
          clearTimeout(timer)
          try { child.kill() } catch {}
          finish({
            status: 'skipped',
            durationMs: Date.now() - started,
            error: 'Cancelled',
            mtuStatus: 'skipped'
          })
        }, { once: true })
      }

      child.on('close', (code) => {
        clearTimeout(timer)
        const durationMs = Date.now() - started
        if (code !== 0 && !output) {
          finish({
            status: 'unavailable',
            durationMs,
            error: 'Traceroute execution error',
            mtuStatus: 'unavailable'
          })
          return
        }

        // Parse hop lines
        const hopLines = output
          .split(/\r?\n/)
          .filter(line => /^\s*\d+\s+/.test(line))
          .map(line => line.trim())

        const reachedTarget = output.toLowerCase().includes('complete') ||
          hopLines.some(line => line.includes(targetIp))

        finish({
          status: hopLines.length > 0 ? 'ok' : 'unavailable',
          durationMs,
          hops: hopLines.length > 0 ? hopLines.length : undefined,
          reachedTarget,
          hopDetails: hopLines.slice(0, 8),
          routeMethod: 'tracert',
          mtuStatus: 'unavailable'
        })
      })

      child.on('error', (err) => {
        clearTimeout(timer)
        finish({
          status: 'unavailable',
          durationMs: Date.now() - started,
          error: err.message,
          mtuStatus: 'unavailable'
        })
      })
    } catch (err: any) {
      finish({
        status: 'unavailable',
        durationMs: Date.now() - started,
        error: err?.message || 'Failed to spawn traceroute',
        mtuStatus: 'unavailable'
      })
    }
  })
}

/**
 * Stage 8: Infrastructure Hints & ASN
 * Passes signal to axios, and strictly scopes egress country comparison to active profile.
 */
export async function probeInfrastructure(
  host: string,
  primaryIp: string,
  profileId?: string,
  endpointCountry?: string,
  disableGeoLookup?: boolean,
  signal?: AbortSignal
): Promise<InfrastructureHints> {
  let asnInfo: AsnInfo | undefined

  if (!disableGeoLookup && primaryIp && net.isIP(primaryIp) !== 0) {
    const cached = asnCache.get(primaryIp)
    if (cached && cached.expiresAt > Date.now()) {
      asnInfo = cached.data
    } else if (!signal?.aborted) {
      try {
        const resp = await axios.get(`https://ipapi.co/${primaryIp}/json/`, {
          timeout: 4000,
          signal
        })
        if (resp.data && !resp.data.error) {
          asnInfo = {
            asn: resp.data.asn || 'unknown',
            org: resp.data.org || 'unknown',
            network: resp.data.network || '',
            country: resp.data.country_name || resp.data.country || ''
          }
          asnCache.set(primaryIp, { data: asnInfo, expiresAt: Date.now() + 10 * 60 * 1000 })
        }
      } catch {}
    }
  }

  // Active tunnel status: ONLY associate egress with this profile if it is the currently connected profile
  const tunRunning = tunController.getStatus().running
  let egressCountry: string | undefined
  let egressIp: string | undefined
  let activeTunnelMatchesProfile = false

  if (tunRunning) {
    try {
      const active = serverPicker.getActiveProfile()
      if (active && profileId && active.id === profileId) {
        activeTunnelMatchesProfile = true
        egressCountry = active.country
        egressIp = active.egressIp
      }
    } catch {}
  }

  // Find shared CIDR /24 among other configured profiles
  const sharedCidrWithProfiles: string[] = []
  if (primaryIp && primaryIp.includes('.')) {
    const subnet24 = primaryIp.split('.').slice(0, 3).join('.') + '.'
    try {
      const allProfiles = serverPicker.getProfiles()
      for (const p of allProfiles) {
        if (p.server && p.server !== host) {
          if (p.resolvedIp && p.resolvedIp.startsWith(subnet24)) {
            sharedCidrWithProfiles.push(p.name || p.server)
          }
        }
      }
    } catch {}
  }

  return {
    status: 'ok',
    asn: asnInfo,
    egressIp,
    egressCountry,
    endpointCountry: asnInfo?.country || endpointCountry,
    activeTunnelMatchesProfile,
    sharedCidrWithProfiles: sharedCidrWithProfiles.length > 0 ? sharedCidrWithProfiles : undefined
  }
}

/**
 * Stage 11: Findings Evaluator
 */
export function evaluateLiveCheckFindings(
  check: Partial<LiveServerCheck>,
  previousCheck: LiveServerCheck | null = null
): LiveCheckFinding[] {
  const findings: LiveCheckFinding[] = []

  // 1. DNS Findings
  const resolvedIps = [...(check.dns?.a || []), ...(check.dns?.aaaa || [])]
  if (resolvedIps.length > 1) {
    findings.push({
      code: 'DNS_MULTI_IP',
      severity: 'info',
      title: 'Несколько IP-адресов в DNS',
      detail: `Хост резолвится в ${resolvedIps.length} адресов: ${resolvedIps.join(', ')}`,
      evidence: { ipCount: resolvedIps.length }
    })
  }

  if (previousCheck) {
    const prevIps = [...(previousCheck.dns?.a || []), ...(previousCheck.dns?.aaaa || [])]
    const currentIpsSorted = [...resolvedIps].sort().join(',')
    const prevIpsSorted = [...prevIps].sort().join(',')
    if (currentIpsSorted && prevIpsSorted && currentIpsSorted !== prevIpsSorted) {
      findings.push({
        code: 'DNS_CHANGED',
        severity: 'info',
        title: 'Изменились IP-адреса DNS',
        detail: `IP изменился с ${prevIps.join(', ') || '—'} на ${resolvedIps.join(', ')}`,
        evidence: { currentIps: resolvedIps.join(','), previousIps: prevIps.join(',') }
      })
    }
  }

  // Reverse DNS mismatch
  if (check.reverseDns && check.reverseDns.length > 0 && check.host && net.isIP(check.host) === 0) {
    const hostDomain = check.host.toLowerCase()
    const matchesDomain = check.reverseDns.some(r => r.toLowerCase().endsWith(hostDomain) || hostDomain.endsWith(r.toLowerCase()))
    if (!matchesDomain) {
      findings.push({
        code: 'REVERSE_DNS_MISMATCH',
        severity: 'info',
        title: 'Reverse DNS указывает на другой домен',
        detail: `rDNS: ${check.reverseDns.join(', ')}, ожидался хост ${check.host}`,
        evidence: { host: check.host, rDns: check.reverseDns.join(',') }
      })
    }
  }

  // 2. TLS Findings
  if (check.tls && check.tls.status === 'ok') {
    if (check.tls.daysRemaining !== undefined) {
      if (check.tls.daysRemaining <= LIVE_PROBE_THRESHOLDS.TLS_EXPIRING_ERROR_DAYS) {
        findings.push({
          code: 'TLS_EXPIRING',
          severity: 'error',
          title: 'TLS сертификат истекает или истёк',
          detail: `Сертификат действителен ещё ${check.tls.daysRemaining} дн. (до ${check.tls.validTo})`,
          evidence: { daysRemaining: check.tls.daysRemaining }
        })
      } else if (check.tls.daysRemaining <= LIVE_PROBE_THRESHOLDS.TLS_EXPIRING_WARNING_DAYS) {
        findings.push({
          code: 'TLS_EXPIRING',
          severity: 'warning',
          title: 'TLS сертификат скоро истекает',
          detail: `Сертификат истекает через ${check.tls.daysRemaining} дн.`,
          evidence: { daysRemaining: check.tls.daysRemaining }
        })
      }
    }

    if (check.tls.hostnameVerified === false) {
      findings.push({
        code: 'TLS_SAN_MISMATCH',
        severity: 'warning',
        title: 'Имя хоста отсутствует в SAN сертификата',
        detail: `Сертификат выдан для [${check.tls.sans?.slice(0, 5).join(', ') || check.tls.subject}], проверялся ${check.host}`,
        evidence: { host: check.host || '' }
      })
    }

    if (previousCheck?.tls?.fingerprint && check.tls.fingerprint) {
      if (previousCheck.tls.fingerprint !== check.tls.fingerprint) {
        findings.push({
          code: 'TLS_FINGERPRINT_CHANGED',
          severity: 'warning',
          title: 'Fingerprint TLS сертификата изменился',
          detail: `Отпечаток сертификата изменился с момента предыдущей проверки`,
          evidence: {
            currentFingerprint: check.tls.fingerprint,
            previousFingerprint: previousCheck.tls.fingerprint
          }
        })
      }
    }
  }

  // 3. HTTP Findings
  if (check.http && check.http.status === 'ok') {
    if (check.http.locationHeader) {
      findings.push({
        code: 'HTTP_REDIRECT',
        severity: 'info',
        title: 'HTTP перенаправление',
        detail: `Ответ HTTP ${check.http.statusCode} перенаправляет на ${check.http.locationHeader}`,
        evidence: { location: check.http.locationHeader, statusCode: check.http.statusCode || 0 }
      })
    }
    if (check.http.statusCode && check.http.statusCode >= 500) {
      findings.push({
        code: 'HTTP_UNEXPECTED_STATUS',
        severity: 'warning',
        title: 'Сервер вернул ошибку HTTP 5xx',
        detail: `HTTP статус: ${check.http.statusCode}`,
        evidence: { statusCode: check.http.statusCode }
      })
    }
  }

  // 4. Port Findings
  const openPorts = (check.openPorts || []).filter(p => p.open)
  if (openPorts.length > 0) {
    findings.push({
      code: 'PORT_OPEN',
      severity: 'info',
      title: 'Обнаружены открытые порты',
      detail: `Открытые порты: ${openPorts.map(p => `${p.port}${p.service ? ` (${p.service})` : ''}`).join(', ')}`,
      evidence: { openPortsCount: openPorts.length }
    })
  }

  // 5. Latency, Jitter & Loss Findings
  if (check.latency) {
    if (check.latency.loss >= LIVE_PROBE_THRESHOLDS.PACKET_LOSS_ERROR) {
      findings.push({
        code: 'PACKET_LOSS',
        severity: 'error',
        title: 'Высокая доля отказов TCP подключений',
        detail: `Не удалось установить соединение в ${Math.round(check.latency.loss * 100)}% попыток`,
        evidence: { lossPct: Math.round(check.latency.loss * 100) }
      })
    } else if (check.latency.loss >= LIVE_PROBE_THRESHOLDS.PACKET_LOSS_WARNING) {
      findings.push({
        code: 'PACKET_LOSS',
        severity: 'warning',
        title: 'Отказы TCP подключений при проверке задержки',
        detail: `Не удалось установить соединение в ${Math.round(check.latency.loss * 100)}% попыток`,
        evidence: { lossPct: Math.round(check.latency.loss * 100) }
      })
    }

    if (check.latency.avg >= LIVE_PROBE_THRESHOLDS.HIGH_LATENCY_ERROR_MS) {
      findings.push({
        code: 'LATENCY_HIGH',
        severity: 'error',
        title: 'Критически высокая задержка',
        detail: `Средний RTT составляет ${check.latency.avg} ms`,
        evidence: { avgMs: check.latency.avg }
      })
    } else if (check.latency.avg >= LIVE_PROBE_THRESHOLDS.HIGH_LATENCY_WARNING_MS) {
      findings.push({
        code: 'LATENCY_HIGH',
        severity: 'warning',
        title: 'Повышенная задержка до сервера',
        detail: `Средний RTT: ${check.latency.avg} ms`,
        evidence: { avgMs: check.latency.avg }
      })
    }

    if (check.latency.jitter >= LIVE_PROBE_THRESHOLDS.HIGH_JITTER_WARNING_MS) {
      findings.push({
        code: 'JITTER_HIGH',
        severity: 'warning',
        title: 'Нестабильное соединение (высокий джиттер)',
        detail: `Флуктуация RTT (jitter): ${check.latency.jitter} ms`,
        evidence: { jitterMs: check.latency.jitter }
      })
    }
  }

  // 6. Infrastructure & ASN Findings
  if (previousCheck?.asn?.asn && check.asn?.asn && previousCheck.asn.asn !== check.asn.asn) {
    findings.push({
      code: 'ASN_CHANGED',
      severity: 'warning',
      title: 'Сменилась автономная система (ASN)',
      detail: `ASN изменился с ${previousCheck.asn.asn} на ${check.asn.asn} (${check.asn.org})`,
      evidence: { currentAsn: check.asn.asn, previousAsn: previousCheck.asn.asn }
    })
  }

  if (check.infrastructure?.sharedCidrWithProfiles && check.infrastructure.sharedCidrWithProfiles.length > 0) {
    findings.push({
      code: 'CIDR_SHARED_WITH_PROFILE',
      severity: 'info',
      title: 'Общая подсеть с другими серверами',
      detail: `Сервер находится в одной /24 подсети с: ${check.infrastructure.sharedCidrWithProfiles.slice(0, 3).join(', ')}`,
      evidence: { sharedCount: check.infrastructure.sharedCidrWithProfiles.length }
    })
  }

  // Only compare egress country if active tunnel matches this profile!
  if (
    check.infrastructure?.activeTunnelMatchesProfile === true &&
    check.infrastructure?.egressCountry &&
    check.infrastructure?.endpointCountry
  ) {
    const egCountry = check.infrastructure.egressCountry.toLowerCase().trim()
    const epCountry = check.infrastructure.endpointCountry.toLowerCase().trim()
    if (egCountry && epCountry && egCountry !== epCountry) {
      findings.push({
        code: 'EGRESS_COUNTRY_MISMATCH',
        severity: 'warning',
        title: 'Несовпадение страны выхода и сервера',
        detail: `Egress трафика: ${check.infrastructure.egressCountry}, страна сервера: ${check.infrastructure.endpointCountry}`,
        evidence: { egress: check.infrastructure.egressCountry, endpoint: check.infrastructure.endpointCountry }
      })
    }
  }

  return findings
}

/**
 * Main Live Server Check runner
 * Wraps overall timeout, isolates sub-probe failures, attaches diff before saving.
 */
export async function runLiveServerCheck(
  options: LiveServerCheckOptions,
  signal?: AbortSignal
): Promise<LiveServerCheck> {
  const startedAt = new Date().toISOString()
  const startTs = Date.now()
  const checkId = crypto.randomUUID()
  const requestId = options.requestId || checkId

  // Look up profile if profileId was supplied
  let host = options.host || ''
  let port = options.port
  let endpointCountry: string | undefined
  let sniHostname: string | undefined

  if (options.profileId) {
    try {
      const allProfiles = serverPicker.getProfiles()
      const found = allProfiles.find(p => p.id === options.profileId)
      if (found) {
        if (!host) host = found.server
        if (!port) port = found.port
        endpointCountry = found.country
        if (found.outbound?.tls?.server_name) {
          sniHostname = found.outbound.tls.server_name
        }
      }
    } catch {}
  }

  const normalized = normalizeHostAndPort(host, port)
  host = normalized.host
  port = normalized.port
  const mode = options.mode === 'extended' ? 'extended' : 'basic'
  const disableGeoLookup = settingsStore.get().disableGeoLookup === true

  logEvent('info', 'live-server-probe', `Starting live check for ${host}:${port}`, {
    mode,
    checkId,
    requestId,
    profileId: options.profileId,
    disableGeoLookup
  })

  // Create deadline controller to enforce an overall timeout on the entire check
  const totalTimeoutMs = mode === 'extended' ? 22000 : 14000
  const deadlineController = new AbortController()

  const overallTimer = setTimeout(() => {
    deadlineController.abort(new Error('Live check overall deadline exceeded'))
  }, totalTimeoutMs)

  const abortForwarder = () => {
    deadlineController.abort()
  }

  if (signal) {
    if (signal.aborted) {
      deadlineController.abort()
    } else {
      signal.addEventListener('abort', abortForwarder, { once: true })
    }
  }

  const checkSignal = deadlineController.signal

  try {
    // 1. DNS Probe
    const dnsRes = await probeDns(host, mode, checkSignal)
    const primaryIp = dnsRes.dns.a[0] || dnsRes.dns.aaaa[0] || host

    // 2. Parallel Probes isolated with Promise.allSettled
    const isTlsPort = [443, 8443, 2053, 2083, 2087, 2096, 4433].includes(port)
    const isTlsApplicable = isTlsPort || sniHostname !== undefined

    const [reachabilitySettled, tlsSettled, httpSettled, portsSettled, routeSettled, infraSettled] =
      await Promise.allSettled([
        probeReachabilityAndLatency(primaryIp, port, mode, checkSignal),
        isTlsApplicable
          ? probeTls(primaryIp, port, sniHostname || (net.isIP(host) === 0 ? host : undefined), checkSignal)
          : Promise.resolve<LiveTlsCertInfo | undefined>(undefined),
        probeHttp(primaryIp, isTlsPort ? port : 80, isTlsPort, host, checkSignal),
        probePorts(primaryIp, port, mode, checkSignal),
        mode === 'extended' ? probeRoute(primaryIp, checkSignal) : Promise.resolve<RouteDiagnostics | undefined>(undefined),
        probeInfrastructure(host, primaryIp, options.profileId, endpointCountry, disableGeoLookup, checkSignal)
      ])

    const reachabilityRes = reachabilitySettled.status === 'fulfilled'
      ? reachabilitySettled.value
      : { reachability: { status: 'error' as const, durationMs: 0, error: 'Probe crashed', tcpReachable: false, port }, latency: undefined }

    const tlsRes = tlsSettled.status === 'fulfilled' ? tlsSettled.value : undefined
    const httpRes = httpSettled.status === 'fulfilled' ? httpSettled.value : undefined
    const openPortsRes = portsSettled.status === 'fulfilled' ? portsSettled.value : undefined
    const routeRes = routeSettled.status === 'fulfilled' ? routeSettled.value : undefined
    const infraRes = infraSettled.status === 'fulfilled'
      ? infraSettled.value
      : { status: 'ok' as const, endpointCountry }

    // Get previous successful check for diff & findings
    const previousCheck = liveServerHistory.getPreviousSuccessfulCheck(options.profileId, host)

    const partialCheck: Partial<LiveServerCheck> = {
      id: checkId,
      requestId,
      profileId: options.profileId,
      host,
      port,
      mode,
      startedAt,
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - startTs,
      cancelled: checkSignal.aborted || false,
      error: checkSignal.aborted ? 'Live check was cancelled' : undefined,
      dns: dnsRes.dns,
      reverseDns: dnsRes.reverseDns.length > 0 ? dnsRes.reverseDns : undefined,
      asn: infraRes.asn,
      reachability: reachabilityRes.reachability,
      latency: reachabilityRes.latency,
      tls: tlsRes,
      http: httpRes,
      openPorts: openPortsRes,
      route: routeRes,
      infrastructure: infraRes
    }

    // Attach diff to infrastructure hints BEFORE saving to disk!
    if (previousCheck && partialCheck.infrastructure) {
      const diff = computeHistoryDiff(partialCheck as LiveServerCheck, previousCheck)
      if (diff) {
        partialCheck.infrastructure.changesFromPrevious = {
          ipChanged: diff.ipChanged,
          asnChanged: diff.asnChanged,
          tlsCertChanged: diff.tlsCertChanged,
          countryChanged: diff.countryChanged,
          portsChanged: diff.portsChanged,
          latencySpike: diff.latencySpike
        }
      }
    }

    // Evaluate Findings
    const findings = evaluateLiveCheckFindings(partialCheck, previousCheck)
    partialCheck.findings = findings

    const finalCheck = partialCheck as LiveServerCheck

    // Save to history (diff is already attached)
    liveServerHistory.addCheck(finalCheck)

    return sanitizeLiveCheckForStorage(finalCheck)
  } finally {
    clearTimeout(overallTimer)
    if (signal) {
      signal.removeEventListener('abort', abortForwarder)
    }
  }
}

/**
 * Stage 10: Register Live Server Probe IPC Handlers
 */
export function registerLiveServerProbeIpcHandlers(): void {
  ipcMain.handle('server:live-check', async (_event, options: LiveServerCheckOptions) => {
    if (!options || typeof options !== 'object') {
      throw new TypeError('options must be an object')
    }

    const requestId = options.requestId || crypto.randomUUID()
    const controller = new AbortController()
    activeControllers.set(requestId, controller)

    try {
      const result = await runLiveServerCheck({ ...options, requestId }, controller.signal)
      return result
    } finally {
      if (activeControllers.get(requestId) === controller) {
        activeControllers.delete(requestId)
      }
    }
  })

  ipcMain.handle('server:live-check-cancel', async (_event, requestId?: string) => {
    if (requestId) {
      const ctrl = activeControllers.get(requestId)
      if (ctrl) {
        ctrl.abort()
        activeControllers.delete(requestId)
        return { cancelled: true }
      }
      return { cancelled: false, reason: 'not_found' }
    }
    return { cancelled: false, reason: 'missing_request_id' }
  })

  ipcMain.handle(
    'server:live-check-history',
    async (_event, filter?: { profileId?: string; host?: string }) => {
      return liveServerHistory.getHistory(filter)
    }
  )
}
