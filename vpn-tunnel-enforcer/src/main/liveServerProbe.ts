import { ipcMain } from 'electron'
import { promises as dnsPromises } from 'dns'
import * as net from 'net'
import * as tls from 'tls'
import * as http from 'http'
import * as https from 'https'
import * as crypto from 'crypto'
import { spawn } from 'child_process'
import { tmpdir } from 'os'
import { join } from 'path'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { SocksClient } from 'socks'
import axios from 'axios'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'
import { serverPicker } from './serverPicker'
import { tunController, getBundledResource, getDirectProxyPort, pickFreeLocalPort } from './tunController'
import { ALL_KNOWN_ALIASES } from './tunAdapter'
import { getPhysicalAdapterDnsSources } from './physicalAdapterLockdown'
import { resolveProxyEngine } from './proxyEngine'
import { buildXrayProbeConfig } from './xrayEngine'
import {
  buildKeyProbeConfig,
  classifyOutboundProbeFailure,
  parseCloudflareTrace,
  waitForLocalSocks,
  openTcpViaSocks,
  verifyHttpsThroughSocket
} from './keyHealthChecker'
import {
  cleanupManagedChildPidDirs,
  writeManagedChildPidFile,
  removeManagedChildPidFile
} from './managedChildProcess'
import { Address6 } from 'ip-address'
import { normalizeServerPort } from '../shared/portValidation'
import {
  liveServerHistory,
  computeHistoryDiff,
  sanitizeLiveCheckForStorage
} from './liveServerHistory'
import type {
  AsnInfo,
  DnsDiagnostics,
  DnsRecordEntry,
  DnsResolverComparison,
  EgressReflectorResult,
  HttpProbeResult,
  InfrastructureHints,
  LiveCheckFinding,
  LiveCheckProgress,
  LiveCheckStage,
  LiveEgressResult,
  LiveLatencyStats,
  LivePortScanItem,
  LiveServerCheck,
  LiveServerCheckOptions,
  LiveTlsCertInfo,
  PathDiagnostics,
  PmtuDiagnostics,
  ReachabilityDiagnostics,
  RouteDiagnostics,
  ServerProfile,
  TunnelHandshakeResult
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

// Each query owns its resolver: timeout/cancellation never cancels another check.
async function dnsQuery<T>(run: (resolver: InstanceType<typeof dnsPromises.Resolver>) => Promise<T>, timeout: number, signal?: AbortSignal): Promise<T> {
  const resolver = new dnsPromises.Resolver()
  return new Promise((resolve, reject) => {
    let finished = false
    const finish = (error?: Error, result?: T) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      if (error) { resolver.cancel(); reject(error) } else resolve(result as T)
    }
    const abort = () => finish(new Error('Cancelled'))
    const timer = setTimeout(() => finish(new Error('DNS query timeout')), timeout)
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) { abort(); return }
    try { run(resolver).then(value => finish(undefined, value), error => finish(error)) }
    catch (error: any) { finish(error) }
  })
}

export function isPublicFqdn(host: string): boolean {
  if (!host || net.isIP(host) !== 0) return false
  const trimmed = host.trim().toLowerCase()
  if (!trimmed.includes('.')) return false
  if (
    trimmed === 'localhost' ||
    trimmed.endsWith('.local') ||
    trimmed.endsWith('.lan') ||
    trimmed.endsWith('.internal') ||
    trimmed.endsWith('.home.arpa') ||
    trimmed.endsWith('.corp') ||
    trimmed.endsWith('.home')
  ) {
    return false
  }
  return true
}

export async function queryDoH(
  resolverId: 'google-doh' | 'cloudflare-doh',
  resolverName: string,
  urlBase: string,
  host: string,
  signal?: AbortSignal,
  headers?: Record<string, string>
): Promise<DnsResolverComparison> {
  const started = Date.now()
  const recs: DnsRecordEntry[] = []
  let adFlag: boolean | undefined
  let rcode: number | undefined
  let truncated: boolean | undefined

  try {
    const fetchWithTimeout = async (type: 'A' | 'AAAA') => {
      const url = `${urlBase}?name=${encodeURIComponent(host)}&type=${type}`
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(new Error('timeout')), 3000)
      const onOuterAbort = () => ctrl.abort(signal?.reason || new Error('cancelled'))
      if (signal) {
        if (signal.aborted) ctrl.abort(signal.reason)
        else signal.addEventListener('abort', onOuterAbort, { once: true })
      }
      try {
        const resp = await fetch(url, {
          headers: {
            Accept: 'application/dns-json',
            ...headers
          },
          signal: ctrl.signal
        })
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status} ${resp.statusText}`)
        }
        return (await resp.json()) as {
          Status?: number
          AD?: boolean
          TC?: boolean
          Answer?: Array<{ name: string; type: number; TTL: number; data: string }>
        }
      } finally {
        clearTimeout(timer)
        signal?.removeEventListener('abort', onOuterAbort)
      }
    }

    const [resA, resAAAA] = await Promise.allSettled([
      fetchWithTimeout('A'),
      fetchWithTimeout('AAAA')
    ])

    let anySuccess = false
    let lastErr = ''

    if (resA.status === 'fulfilled') {
      anySuccess = true
      const data = resA.value
      rcode = data.Status
      adFlag = data.AD
      truncated = data.TC
      if (Array.isArray(data.Answer)) {
        for (const ans of data.Answer) {
          if (!ans?.data) continue
          const cleanName = (ans.name || host).replace(/\.$/, '')
          const recType = ans.type === 28 ? 'AAAA' : ans.type === 5 ? 'CNAME' : 'A'
          recs.push({
            name: cleanName,
            type: recType,
            value: ans.data.replace(/\.$/, ''),
            ttl: typeof ans.TTL === 'number' ? ans.TTL : undefined,
            observedAt: new Date().toISOString(),
            resolverId,
            transport: 'doh'
          })
        }
      }
    } else {
      lastErr = resA.reason?.message || 'A lookup failed'
    }

    if (resAAAA.status === 'fulfilled') {
      anySuccess = true
      const data = resAAAA.value
      if (rcode === undefined) rcode = data.Status
      if (adFlag === undefined) adFlag = data.AD
      if (truncated === undefined) truncated = data.TC
      if (Array.isArray(data.Answer)) {
        for (const ans of data.Answer) {
          if (!ans?.data) continue
          const cleanName = (ans.name || host).replace(/\.$/, '')
          const recType = ans.type === 28 ? 'AAAA' : ans.type === 5 ? 'CNAME' : 'A'
          if (!recs.some(r => r.type === recType && r.value === ans.data.replace(/\.$/, ''))) {
            recs.push({
              name: cleanName,
              type: recType,
              value: ans.data.replace(/\.$/, ''),
              ttl: typeof ans.TTL === 'number' ? ans.TTL : undefined,
              observedAt: new Date().toISOString(),
              resolverId,
              transport: 'doh'
            })
          }
        }
      }
    }

    return {
      resolverId,
      resolverName,
      endpoint: urlBase,
      status: anySuccess ? 'ok' : 'error',
      durationMs: Date.now() - started,
      authenticatedData: adFlag,
      records: recs,
      truncated,
      rcode,
      error: anySuccess ? undefined : lastErr
    }
  } catch (err: any) {
    return {
      resolverId,
      resolverName,
      endpoint: urlBase,
      status: err?.name === 'AbortError' || err?.message === 'timeout' ? 'timeout' : 'error',
      durationMs: Date.now() - started,
      records: [],
      error: err?.message || 'DoH lookup failed'
    }
  }
}

/**
 * Stage 2: DNS Diagnostics (parallel A/AAAA, CNAME chain, TTL tracking, DoH multi-resolver comparison)
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
        const rev = await dnsQuery(resolver => resolver.reverse(host), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS, signal).catch(() => [])
        if (Array.isArray(rev)) reverseDnsList.push(...rev)
      }
    } catch {}

    const directRecord: DnsRecordEntry = {
      name: host,
      type: ipFamily === 4 ? 'A' : 'AAAA',
      value: host,
      observedAt: new Date().toISOString(),
      resolverId: 'system',
      transport: 'system'
    }

    return {
      dns: {
        status: 'ok',
        durationMs: Date.now() - started,
        a: ipFamily === 4 ? [host] : [],
        aaaa: ipFamily === 6 ? [host] : [],
        cnameChain: [],
        records: [directRecord],
        resolvers: [
          {
            resolverId: 'system',
            resolverName: 'Системный резолвер (Direct IP)',
            endpoint: 'OS/Direct',
            status: 'ok',
            durationMs: 0,
            records: [directRecord]
          }
        ]
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
        cnameChain: [],
        records: [],
        resolvers: []
      },
      reverseDns: []
    }
  }

  const aRecords: string[] = []
  const aaaaRecords: string[] = []
  const cnameChain: string[] = []
  const dnsRecords: DnsRecordEntry[] = []
  const timings: { aMs?: number; aaaaMs?: number; cnameMs?: number } = {}
  let minTtl: number | undefined
  let primaryError: string | undefined

  // 1. Parallel A and AAAA resolution (System Resolver)
  const queryA = async () => {
    const aStart = Date.now()
    try {
      const resA = await dnsQuery(resolver => resolver.resolve4(host, { ttl: true }), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS, signal).catch((err) => {
        primaryError = err?.message || 'A query failed'
        return [] as Array<{ address: string; ttl: number }>
      })

      timings.aMs = Date.now() - aStart
      for (const r of resA) {
        if (r?.address) {
          if (!aRecords.includes(r.address)) aRecords.push(r.address)
          dnsRecords.push({
            name: host,
            type: 'A',
            value: r.address,
            ttl: typeof r.ttl === 'number' ? r.ttl : undefined,
            observedAt: new Date().toISOString(),
            resolverId: 'system',
            transport: 'system'
          })
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
      const resAAAA = await dnsQuery(resolver => resolver.resolve6(host, { ttl: true }), LIVE_PROBE_THRESHOLDS.DNS_LOOKUP_TIMEOUT_MS, signal).catch(() => [] as Array<{ address: string; ttl: number }>)

      timings.aaaaMs = Date.now() - aaaaStart
      for (const r of resAAAA) {
        if (r?.address) {
          if (!aaaaRecords.includes(r.address)) aaaaRecords.push(r.address)
          dnsRecords.push({
            name: host,
            type: 'AAAA',
            value: r.address,
            ttl: typeof r.ttl === 'number' ? r.ttl : undefined,
            observedAt: new Date().toISOString(),
            resolverId: 'system',
            transport: 'system'
          })
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
        const cnames = await dnsQuery(resolver => resolver.resolveCname(currentTarget), 1000, signal).catch(() => [] as string[])

        if (cnames.length === 0) break
        const nextTarget = cnames[0]
        cnameChain.push(nextTarget)
        dnsRecords.push({
          name: currentTarget,
          type: 'CNAME',
          value: nextTarget,
          observedAt: new Date().toISOString(),
          resolverId: 'system',
          transport: 'system'
        })
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

  // 3. Multi-resolver Comparison (Google DoH & Cloudflare DoH in extended mode)
  const resolverComparisons: DnsResolverComparison[] = []
  const hasRecords = aRecords.length > 0 || aaaaRecords.length > 0

  resolverComparisons.push({
    resolverId: 'system',
    resolverName: 'Системный резолвер (OS/Hosts)',
    endpoint: 'OS/System',
    status: hasRecords ? 'ok' : 'error',
    durationMs: timings.aMs || 0,
    records: dnsRecords.filter(r => r.resolverId === 'system'),
    error: hasRecords ? undefined : primaryError
  })

  const discrepancies: string[] = []

  if (mode === 'extended' && isPublicFqdn(host) && !signal?.aborted) {
    const [googleRes, cfRes] = await Promise.allSettled([
      queryDoH('google-doh', 'Google Public DNS (DoH)', 'https://dns.google/resolve', host, signal),
      queryDoH('cloudflare-doh', 'Cloudflare DNS (DoH)', 'https://cloudflare-dns.com/dns-query', host, signal, { Accept: 'application/dns-json' })
    ])

    if (googleRes.status === 'fulfilled') {
      resolverComparisons.push(googleRes.value)
      dnsRecords.push(...googleRes.value.records)
    }
    if (cfRes.status === 'fulfilled') {
      resolverComparisons.push(cfRes.value)
      dnsRecords.push(...cfRes.value.records)
    }

    // Check for discrepancies between resolvers
    const systemIps = new Set(dnsRecords.filter(r => r.resolverId === 'system' && (r.type === 'A' || r.type === 'AAAA')).map(r => r.value))
    const dohIps = new Set(dnsRecords.filter(r => r.transport === 'doh' && (r.type === 'A' || r.type === 'AAAA')).map(r => r.value))

    if (systemIps.size > 0 && dohIps.size > 0) {
      const hasOverlap = [...systemIps].some(ip => dohIps.has(ip))
      if (!hasOverlap) {
        discrepancies.push(
          `Системный DNS ([${[...systemIps].join(', ')}]) не совпадает с публичными DoH ([${[...dohIps].join(', ')}]) (возможно split-horizon DNS или CDN)`
        )
      }
    }

    const googleIps = dnsRecords.filter(r => r.resolverId === 'google-doh' && (r.type === 'A' || r.type === 'AAAA')).map(r => r.value)
    const cfIps = dnsRecords.filter(r => r.resolverId === 'cloudflare-doh' && (r.type === 'A' || r.type === 'AAAA')).map(r => r.value)
    if (googleIps.length > 0 && cfIps.length > 0) {
      const overlap = googleIps.some(ip => cfIps.includes(ip))
      if (!overlap) {
        discrepancies.push(
          `Google DoH ([${googleIps.join(', ')}]) и Cloudflare DoH ([${cfIps.join(', ')}]) вернули разные адреса (GeoDNS/Anycast)`
        )
      }
    }
  }

  // 4. Reverse DNS for all resolved unique IPs
  const allIps = [...new Set([...aRecords, ...aaaaRecords])]
  const reverseDnsList: string[] = []
  if (!signal?.aborted && allIps.length > 0) {
    const reversePromises = allIps.map(async (ip) => {
      if (signal?.aborted) return []
      try {
        const rev = await dnsQuery(resolver => resolver.reverse(ip), 1200, signal).catch(() => [] as string[])
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

  return {
    dns: {
      status: hasRecords ? 'ok' : 'error',
      durationMs,
      error: hasRecords ? undefined : (primaryError || 'DNS lookup failed: no records'),
      a: aRecords,
      aaaa: aaaaRecords,
      cnameChain,
      ttl: minTtl,
      records: dnsRecords,
      resolvers: resolverComparisons,
      discrepancies: discrepancies.length > 0 ? discrepancies : undefined,
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
      clearTimeout(timer)
      signal?.removeEventListener('abort', abortHandler)
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
  connectIp: string, port: number, isTls: boolean,
  authorityHost?: string, signal?: AbortSignal, sniHostname?: string
): Promise<HttpProbeResult> {
  const started = Date.now()
  const authority = authorityHost || connectIp
  const bracket = (host: string) => net.isIP(host) === 6 ? `[${host}]` : host
  const origin = new URL(`${isTls ? 'https' : 'http'}://${bracket(authority)}:${port}/`)
  return new Promise(resolve => {
    let finished = false
    let req: http.ClientRequest | undefined
    let response: http.IncomingMessage | undefined
    const finish = (result: Partial<HttpProbeResult>) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      req?.destroy()
      response?.destroy()
      resolve({ status: 'error', durationMs: Date.now() - started, targetPort: port,
        isTls, confidence: 'low', ...result })
    }
    const abort = () => finish({ status: 'skipped', error: 'Cancelled' })
    const timer = setTimeout(() => finish({ error: 'HTTP overall deadline exceeded' }), LIVE_PROBE_THRESHOLDS.HTTP_PROBE_TIMEOUT_MS)
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) { abort(); return }
    const execute = (method: 'HEAD' | 'GET', url: URL, redirects: number) => {
      if (finished) return
      const tlsName = sniHostname || authority
      try {
        const current = (isTls ? https : http).request({
          host: connectIp, port, path: url.pathname + url.search, method,
          servername: net.isIP(tlsName) === 0 ? tlsName : undefined,
          rejectUnauthorized: false,
          headers: { Host: origin.host, 'User-Agent': 'VPNTE-Diagnostics/1.0', Accept: '*/*' }
        }, res => {
          if (finished || req !== current) { res.destroy(); return }
          response = res
          const statusCode = res.statusCode || 0
          let location: URL | undefined
          try { if (res.headers.location) location = new URL(res.headers.location, url) } catch {}
          const follow = (nextMethod: 'HEAD' | 'GET', next: URL, count: number) => {
            req = undefined
            response = undefined
            res.destroy()
            current.destroy()
            execute(nextMethod, next, count)
          }
          if ([301, 302, 303, 307, 308].includes(statusCode) && location &&
              location.origin === origin.origin && !location.username && !location.password &&
              redirects < LIVE_PROBE_THRESHOLDS.MAX_REDIRECTS) {
            follow(method, location, redirects + 1); return
          }
          if (statusCode === 405 && method === 'HEAD') { follow('GET', url, redirects); return }
          let bytes = 0
          const header = (key: string) => {
            const value = res.headers[key]
            return Array.isArray(value) ? value.join(', ') : value
          }
          const complete = () => finish({ status: 'ok', statusCode, protocol: `HTTP/${res.httpVersion}`,
            serverHeader: header('server'), viaHeader: header('via'), contentType: header('content-type'),
            locationHeader: location ? `${location.protocol}//${location.host}${location.pathname}` : undefined,
            bodySize: bytes })
          res.on('data', (chunk: Buffer) => {
            bytes = Math.min(bytes + chunk.length, LIVE_PROBE_THRESHOLDS.MAX_HTTP_BODY_BYTES)
            if (bytes >= LIVE_PROBE_THRESHOLDS.MAX_HTTP_BODY_BYTES) complete()
          })
          res.on('end', complete)
          res.on('error', err => finish({ error: err.message }))
          res.on('aborted', () => finish({ error: 'HTTP response interrupted' }))
        })
        req = current
        current.on('error', err => { if (req === current) finish({ error: err.message }) })
        current.end()
      } catch (err: any) { finish({ error: err.message }) }
    }
    execute('HEAD', origin, 0)
  })
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
      signal?.removeEventListener('abort', abortHandler)
      socket.destroy()
      resolve({ ok, durationMs: Date.now() - start, error: err })
    }

    const abortHandler = () => finish(false, 'Cancelled')
    signal?.addEventListener('abort', abortHandler, { once: true })

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
  const pathType = 'os-selected' as const

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
    tunRunning: tunController.getStatus().running,
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

  return new Promise<RouteDiagnostics>(resolve => {
    let output = ''
    let finished = false
    let child: ReturnType<typeof spawn> | undefined
    let timer: ReturnType<typeof setTimeout> | undefined
    const canonical = (ip: string) => net.isIP(ip) === 6 ? new Address6(ip).canonicalForm() : ip
    const finish = (status: RouteDiagnostics['status'], error?: string, commandFinished = false) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      const lines = output.split(/\r?\n/).filter(line => /^\s*\d+\s+/.test(line)).map(line => line.trim()).slice(0, 8)
      const reachedTarget = lines.some(line => line.split(/\s+/).some(token => {
        const ip = token.replace(/^\[|\]$/g, '')
        return net.isIP(ip) !== 0 && canonical(ip) === canonical(targetIp)
      }))
      if (!commandFinished) { try { child?.kill() } catch {} }
      resolve({ status, error, durationMs: Date.now() - started, hops: lines.length || undefined,
        hopDetails: lines, reachedTarget, commandFinished, partial: !reachedTarget,
        routeMethod: 'tracert', mtuStatus: 'unavailable' })
    }
    const abort = () => finish('skipped', 'Cancelled')
    try {
      child = spawn('tracert', ['-d', '-h', '8', '-w', '400', targetIp], { windowsHide: true })
      child.stdout?.on('data', data => { output = (output + data.toString()).slice(0, 65536) })
      child.on('close', code => finish(code === 0 ? 'ok' : 'error', code === 0 ? undefined : 'Traceroute execution error', true))
      child.on('error', err => finish('error', err.message))
      timer = setTimeout(() => finish('unavailable', 'Traceroute timed out'), LIVE_PROBE_THRESHOLDS.TRACEROUTE_TIMEOUT_MS)
      signal?.addEventListener('abort', abort, { once: true })
      if (signal?.aborted) abort()
    } catch (err: any) { finish('error', err.message) }
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
  let infrastructureError: string | undefined
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
      } catch (err: any) { infrastructureError = err?.message || 'ASN lookup failed' }
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
    status: signal?.aborted ? 'skipped' : infrastructureError ? 'error' : 'ok',
    error: infrastructureError,
    asn: asnInfo,
    egressIp,
    egressCountry,
    egressSource: egressIp || egressCountry ? 'profile-cache' : undefined,
    egressObservedAt: null,
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
    check.infrastructure.egressSource !== 'profile-cache' &&
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

  // 7. DNS Discrepancy Findings
  if (check.dns?.discrepancies && check.dns.discrepancies.length > 0) {
    for (const disc of check.dns.discrepancies) {
      findings.push({
        code: 'DNS_RESOLVER_DISCREPANCY',
        severity: 'info',
        title: 'Расхождение ответов DNS резолверов',
        detail: disc,
        evidence: { host: check.host || '' }
      })
    }
  }

  // 8. Handshake & Tunnel Service Findings
  if (check.handshake && check.handshake.status !== 'ok' && check.handshake.status !== 'skipped') {
    findings.push({
      code: 'TUNNEL_HANDSHAKE_FAILED',
      severity: 'error',
      title: 'Сбой рукопожатия туннеля',
      detail: `Протокол ${check.handshake.protocol || 'VPN'} не прошёл проверку: ${check.handshake.error || check.handshake.status}`,
      evidence: { protocol: check.handshake.protocol || '', status: check.handshake.status }
    })
  }

  // 9. Egress vs Endpoint Findings
  if (check.egress && check.egress.status === 'ok') {
    if (check.egress.underlayPath === 'direct') {
      findings.push({
        code: 'DIRECT_UNDERLAY_LEAK',
        severity: 'error',
        title: 'Утечка прямого провайдера (Direct Underlay)',
        detail: 'Выходной IP совпадает с прямым подключением без защитного туннелирования!',
        evidence: { exit: check.egress.exitIpv4 || check.egress.exitIpv6 || '' }
      })
    }
    if (check.egress.exitIpv4 && check.egress.matchesEndpoint === false) {
      findings.push({
        code: 'EGRESS_DIFFERS_FROM_ENDPOINT',
        severity: 'info',
        title: 'Выходной IP отличается от IP подключения',
        detail: `Endpoint: ${check.egress.endpointIp || check.host}, фактический Egress: ${check.egress.exitIpv4} (${check.egress.country || '—'})`,
        evidence: { endpoint: check.egress.endpointIp || '', exit: check.egress.exitIpv4 }
      })
    }
  }

  // 10. PMTU Findings
  if (check.pmtu?.status === 'blackhole_suspected') {
    findings.push({
      code: 'PMTU_BLACKHOLE_SUSPECTED',
      severity: 'warning',
      title: 'Подозрение на PMTU Blackhole',
      detail: check.pmtu.detail || 'Большие пакеты отбрасываются без ICMP ответа',
      evidence: { destination: check.pmtu.destination, status: check.pmtu.status }
    })
  }
  if (check.pmtu?.pmtu && check.pmtu.pmtu < 1300) {
    findings.push({
      code: 'LOW_PMTU',
      severity: 'warning',
      title: 'Низкий MTU канала',
      detail: `Обнаружен MTU ${check.pmtu.pmtu} байт. Это может приводить к повышенной фрагментации пакетов.`,
      evidence: { pmtu: check.pmtu.pmtu }
    })
  }

  return findings
}

/**
 * Execute a PowerShell script safely with timeout and AbortSignal support via base64 EncodedCommand
 */
export function execPs(
  script: string,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    let finished = false
    let child: any = null
    const timer = setTimeout(() => {
      finish(new Error('PowerShell command timeout'))
    }, timeoutMs)

    const abortHandler = () => {
      finish(new Error('Cancelled'))
    }

    const finish = (err?: Error, res?: { stdout: string; stderr: string }) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abortHandler)
      if (child) {
        try { child.kill() } catch {}
      }
      if (err) reject(err)
      else resolve(res || { stdout: '', stderr: '' })
    }

    if (signal) {
      if (signal.aborted) {
        finish(new Error('Cancelled'))
        return
      }
      signal.addEventListener('abort', abortHandler, { once: true })
    }

    try {
      const encoded = Buffer.from(script, 'utf16le').toString('base64')
      child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      })
      let stdout = ''
      let stderr = ''
      child.stdout?.on('data', (d: Buffer) => { stdout += d.toString('utf8') })
      child.stderr?.on('data', (d: Buffer) => { stderr += d.toString('utf8') })
      child.on('error', (err: any) => finish(err))
      child.on('close', () => {
        finish(undefined, { stdout, stderr })
      })
    } catch (err: any) {
      finish(err)
    }
  })
}

/**
 * Stage 8: Tunnel Handshake & Fresh Egress Probe
 * Spawns an isolated ephemeral proxy instance, verifies end-to-end handshake,
 * and requests exit IPs from dual independent reflectors.
 */
export async function probeTunnelHandshakeAndEgress(
  profile?: ServerProfile | null,
  endpointIp?: string,
  signal?: AbortSignal
): Promise<{ handshake: TunnelHandshakeResult; egress: LiveEgressResult }> {
  const started = Date.now()
  if (!profile || !profile.outbound || typeof profile.outbound !== 'object') {
    return {
      handshake: {
        status: 'skipped',
        durationMs: 0,
        protocol: profile?.protocol,
        error: 'Профиль не выбран или не имеет конфигурации outbound'
      },
      egress: {
        status: 'skipped',
        durationMs: 0,
        reflectors: [],
        error: 'Проверка egress пропущена: профиль не настроен'
      }
    }
  }

  if (signal?.aborted) {
    return {
      handshake: {
        status: 'skipped',
        durationMs: 0,
        protocol: profile.protocol,
        error: 'Cancelled'
      },
      egress: {
        status: 'skipped',
        durationMs: 0,
        reflectors: [],
        error: 'Cancelled'
      }
    }
  }

  const workDirPrefix = 'vpnte-live-handshake-'
  const pidFileName = 'engine.pid'
  let workDir: string | null = null
  let child: any = null
  let logText = ''

  try {
    await cleanupManagedChildPidDirs(tmpdir(), workDirPrefix, pidFileName, 'live-handshake-probe', () => {})
    workDir = await mkdtemp(join(tmpdir(), workDirPrefix))
    const logPath = join(workDir, 'engine.log')
    const pidPath = join(workDir, pidFileName)
    const inboundPort = await pickFreeLocalPort()

    const tunStatus = tunController.getStatus()
    let directProxy: { host: string; port: number } | null = null
    if (tunStatus.running && tunStatus.proxyAddr) {
      const directPort = getDirectProxyPort()
      if (directPort) directProxy = { host: '127.0.0.1', port: directPort }
    }
    const physicalAdapter = directProxy
      ? null
      : (await getPhysicalAdapterDnsSources().catch(() => []))[0] ?? null

    const proxyEngineSetting = settingsStore.get().proxyEngine ?? 'auto'
    const engine = resolveProxyEngine(profile.outbound, proxyEngineSetting)
    const isXray = engine === 'xray'
    const probeExe = isXray ? getBundledResource('xray.exe') : getBundledResource('sing-box.exe')

    if (!probeExe) {
      return {
        handshake: {
          status: 'skipped',
          durationMs: Date.now() - started,
          protocol: profile.protocol,
          error: 'Бинарный файл движка (sing-box/xray) не найден'
        },
        egress: {
          status: 'skipped',
          durationMs: 0,
          reflectors: [],
          error: 'Движок туннеля не найден'
        }
      }
    }

    const probeConfigPath = join(workDir, isXray ? 'xray.json' : 'sing-box.json')
    const config = isXray
      ? buildXrayProbeConfig(profile.outbound, inboundPort, {
          directProxy,
          clientDevice: profile.clientDevice,
          logPath
        })
      : buildKeyProbeConfig(profile, inboundPort, {
          directProxy,
          physicalInterface: physicalAdapter?.alias,
          logPath
        })

    await writeFile(probeConfigPath, JSON.stringify(config, null, 2), 'utf8')

    child = spawn(probeExe, ['run', '-c', probeConfigPath], {
      cwd: workDir,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    })

    await writeManagedChildPidFile(pidPath, {
      owner: 'live-handshake-probe',
      pid: child.pid ?? 0,
      exePath: probeExe,
      configPath: probeConfigPath,
      createdAt: Date.now()
    }).catch(() => {})

    child.stdout?.on('data', (d: Buffer) => { logText += d.toString() })
    child.stderr?.on('data', (d: Buffer) => { logText += d.toString() })

    // Wait for inbound port
    await waitForLocalSocks(inboundPort, 2500)

    // Handshake check: connect via local socks inbound to Cloudflare
    const socket = await openTcpViaSocks({ host: '127.0.0.1', port: inboundPort }, '1.1.1.1', 443, 4000)
    const cfTrace = await verifyHttpsThroughSocket(socket, {
      host: '1.1.1.1',
      port: 443,
      serverName: 'cloudflare-dns.com',
      path: '/cdn-cgi/trace'
    }, 4000)

    const handshakeMs = Date.now() - started
    const handshake: TunnelHandshakeResult = {
      status: 'ok',
      durationMs: handshakeMs,
      protocol: profile.protocol,
      evidence: {
        transport: profile.outbound.type || profile.protocol,
        alpn: profile.outbound.tls?.alpn?.[0],
        inboundPort
      }
    }

    // Now Egress check using dual reflectors
    const egressStarted = Date.now()
    const reflectorResults: EgressReflectorResult[] = []

    if (cfTrace.egressIp) {
      reflectorResults.push({
        source: 'cloudflare-trace',
        ip: cfTrace.egressIp,
        family: net.isIP(cfTrace.egressIp) === 6 ? 6 : 4,
        country: cfTrace.country,
        durationMs: handshakeMs,
        status: 'ok'
      })
    }

    // Reflector 2: ipify over socks
    try {
      const ipifyStart = Date.now()
      const ipifySocket = await openTcpViaSocks({ host: '127.0.0.1', port: inboundPort }, 'api.ipify.org', 443, 3500)
      const ipifyTrace = await verifyHttpsThroughSocket(ipifySocket, {
        host: 'api.ipify.org',
        port: 443,
        serverName: 'api.ipify.org',
        path: '/?format=text'
      }, 3500)
      if (ipifyTrace.egressIp) {
        reflectorResults.push({
          source: 'ipify',
          ip: ipifyTrace.egressIp,
          family: 4,
          durationMs: Date.now() - ipifyStart,
          status: 'ok'
        })
      }
    } catch {}

    const exitIpv4 = reflectorResults.find(r => r.family === 4)?.ip || (cfTrace.egressIp && net.isIP(cfTrace.egressIp) === 4 ? cfTrace.egressIp : undefined)
    const exitIpv6 = reflectorResults.find(r => r.family === 6)?.ip || (cfTrace.egressIp && net.isIP(cfTrace.egressIp) === 6 ? cfTrace.egressIp : undefined)
    const country = cfTrace.country

    const egress: LiveEgressResult = {
      status: reflectorResults.length > 0 ? 'ok' : 'partial',
      durationMs: Date.now() - egressStarted,
      exitIpv4,
      exitIpv6,
      country,
      reflectors: reflectorResults,
      endpointIp,
      matchesEndpoint: exitIpv4 && endpointIp ? exitIpv4 === endpointIp : undefined,
      underlayPath: tunStatus.running ? 'nested' : 'direct'
    }

    return { handshake, egress }
  } catch (err: any) {
    let diskLogs = ''
    if (workDir) {
      try {
        diskLogs = await readFile(join(workDir, 'engine.log'), 'utf8')
      } catch {}
    }
    const combinedLogs = `${logText}\n${diskLogs}`
    const classified = classifyOutboundProbeFailure(profile.protocol, combinedLogs, err?.message || '')
    let handshakeStatus: TunnelHandshakeResult['status'] = 'transport_failed'
    if (classified.includes('auth')) handshakeStatus = 'auth_failed'
    else if (classified === 'timeout') handshakeStatus = 'timeout'

    return {
      handshake: {
        status: handshakeStatus,
        durationMs: Date.now() - started,
        protocol: profile.protocol,
        error: err?.message || classified,
        evidence: {
          transport: profile.outbound.type || profile.protocol,
          detail: classified
        }
      },
      egress: {
        status: 'skipped',
        durationMs: 0,
        reflectors: [],
        error: `Рукопожатие завершилось ошибкой (${classified})`
      }
    }
  } finally {
    if (child) {
      try { child.kill('SIGKILL') } catch {}
    }
    if (workDir) {
      await rm(workDir, { recursive: true, force: true }).catch(() => {})
    }
  }
}

/**
 * Stage 9: Windows Path Confirmation (inspects Windows routing table for TUN vs direct adapter)
 */
export async function probePathConfirmation(
  destinationIp: string,
  signal?: AbortSignal
): Promise<PathDiagnostics> {
  const started = Date.now()
  if (process.platform !== 'win32' || !destinationIp || net.isIP(destinationIp) === 0) {
    return {
      status: 'skipped',
      durationMs: 0,
      destination: destinationIp || '',
      isTunInterface: false,
      evidenceKind: 'os-unverified'
    }
  }

  try {
    const script = `Find-NetRoute -RemoteIPAddress "${destinationIp}" -ErrorAction SilentlyContinue | Select-Object -First 1 InterfaceIndex, InterfaceAlias, IPAddress, NextHop | ConvertTo-Json`
    const { stdout } = await execPs(script, 3000, signal)
    if (!stdout.trim()) {
      return {
        status: 'error',
        durationMs: Date.now() - started,
        destination: destinationIp,
        isTunInterface: false,
        evidenceKind: 'net-route',
        error: 'Таблица маршрутизации не вернула активный маршрут'
      }
    }

    const parsed = JSON.parse(stdout)
    const alias = parsed.InterfaceAlias || ''
    const isTun = ALL_KNOWN_ALIASES.some(a => alias.toLowerCase().includes(a.toLowerCase()))

    return {
      status: 'ok',
      durationMs: Date.now() - started,
      destination: destinationIp,
      activeInterfaceIndex: typeof parsed.InterfaceIndex === 'number' ? parsed.InterfaceIndex : undefined,
      activeInterfaceAlias: alias,
      activeLocalIp: parsed.IPAddress || undefined,
      nextHop: parsed.NextHop || undefined,
      isTunInterface: isTun,
      evidenceKind: 'net-route'
    }
  } catch (err: any) {
    return {
      status: 'error',
      durationMs: Date.now() - started,
      destination: destinationIp,
      isTunInterface: false,
      evidenceKind: 'net-route',
      error: err?.message || 'Сбой проверки маршрута Windows'
    }
  }
}

/**
 * Stage 10: Path MTU (PMTU) Discovery
 * Queries interface MTU and executes ICMP ping ladder with DontFragment (DF) flag.
 */
export async function probePmtu(
  destinationIp: string,
  interfaceIndex?: number,
  interfaceAlias?: string,
  signal?: AbortSignal
): Promise<PmtuDiagnostics> {
  const started = Date.now()
  const ipVer = net.isIP(destinationIp)
  const family: 4 | 6 = ipVer === 6 ? 6 : 4

  if (process.platform !== 'win32' || !destinationIp || ipVer === 0) {
    return {
      status: 'skipped',
      durationMs: 0,
      destination: destinationIp || '',
      family,
      method: 'fallback',
      detail: 'Определение PMTU доступно только для прямых IP-адресов на Windows'
    }
  }

  // 1. Interface MTU via Get-NetIPInterface
  let ifMtu: number | undefined
  if (interfaceIndex) {
    try {
      const script = `Get-NetIPInterface -InterfaceIndex ${interfaceIndex} -AddressFamily IPv${family} -ErrorAction SilentlyContinue | Select-Object -First 1 NlMtu | ConvertTo-Json`
      const { stdout } = await execPs(script, 2000, signal)
      if (stdout.trim()) {
        const parsed = JSON.parse(stdout)
        if (typeof parsed.NlMtu === 'number' && parsed.NlMtu > 0) {
          ifMtu = parsed.NlMtu
        }
      }
    } catch {}
  }

  // 2. Ladder ICMP probe with DF flag
  try {
    const script = `
$ip = [System.Net.IPAddress]::Parse('${destinationIp}')
$p = New-Object System.Net.NetworkInformation.Ping
$opt = New-Object System.Net.NetworkInformation.PingOptions(64, $true)
$ctrlBuf = New-Object byte[] 32
$ctrl = $p.Send($ip, 700, $ctrlBuf, $opt)
if ($ctrl.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) {
  [PSCustomObject]@{ Status = 'icmp_blocked'; Detail = $ctrl.Status.ToString() } | ConvertTo-Json
  exit 0
}
$ladder = @(1472, 1464, 1372, 1252)
$best = 0
$tooBigCount = 0
$timeoutCount = 0
foreach ($sz in $ladder) {
  $buf = New-Object byte[] $sz
  $reply = $p.Send($ip, 700, $buf, $opt)
  if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
    $best = $sz
    break
  } elseif ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::PacketTooBig) {
    $tooBigCount++
  } else {
    $timeoutCount++
  }
}
[PSCustomObject]@{ Status = 'ok'; BestPayload = $best; TooBigCount = $tooBigCount; TimeoutCount = $timeoutCount } | ConvertTo-Json
`
    const { stdout } = await execPs(script, 4500, signal)
    if (stdout.trim()) {
      const parsed = JSON.parse(stdout)
      if (parsed.Status === 'icmp_blocked') {
        return {
          status: 'icmp_blocked',
          durationMs: Date.now() - started,
          destination: destinationIp,
          family,
          interfaceAlias,
          method: ifMtu ? 'interface-nlmtu' : 'fallback',
          pmtu: ifMtu,
          detail: 'ICMP echo заблокирован узлом или сетью; показан MTU сетевого адаптера'
        }
      }

      if (parsed.Status === 'ok') {
        if (parsed.BestPayload === 1472) {
          return {
            status: 'lower_bound',
            durationMs: Date.now() - started,
            destination: destinationIp,
            family,
            interfaceAlias,
            method: 'icmp-df',
            pmtu: 1500,
            minTested: 1280,
            maxTested: 1500,
            detail: 'PMTU не менее 1500 байт (пакет 1500B с DF принят)'
          }
        }
        if (parsed.BestPayload > 0) {
          const totalMtu = parsed.BestPayload + 28
          return {
            status: 'ok',
            durationMs: Date.now() - started,
            destination: destinationIp,
            family,
            interfaceAlias,
            method: 'icmp-df',
            pmtu: totalMtu,
            minTested: 1280,
            maxTested: 1500,
            detail: `Подтверждённый PMTU ${totalMtu} байт (payload ${parsed.BestPayload}B + 28B IP/ICMP)`
          }
        }
        if (parsed.TimeoutCount > 0 && parsed.TooBigCount === 0) {
          return {
            status: 'blackhole_suspected',
            durationMs: Date.now() - started,
            destination: destinationIp,
            family,
            interfaceAlias,
            method: ifMtu ? 'interface-nlmtu' : 'fallback',
            pmtu: ifMtu,
            detail: 'Подозрение на PMTU Blackhole: большие пакеты отбрасываются без ICMP PacketTooBig'
          }
        }
      }
    }
  } catch (err: any) {
    if (ifMtu) {
      return {
        status: 'ok',
        durationMs: Date.now() - started,
        destination: destinationIp,
        family,
        interfaceAlias,
        method: 'interface-nlmtu',
        pmtu: ifMtu,
        detail: `MTU локального интерфейса ${ifMtu} байт`
      }
    }
  }

  return {
    status: ifMtu ? 'ok' : 'skipped',
    durationMs: Date.now() - started,
    destination: destinationIp,
    family,
    interfaceAlias,
    method: ifMtu ? 'interface-nlmtu' : 'fallback',
    pmtu: ifMtu,
    detail: ifMtu ? `MTU локального интерфейса ${ifMtu} байт` : 'PMTU не удалось определить'
  }
}

/**
 * Main Live Server Check runner
 * Wraps overall timeout, coordinates 11 diagnostic stages, emits progress updates.
 */
export async function runLiveServerCheck(
  options: LiveServerCheckOptions,
  signal?: AbortSignal,
  onProgress?: (progress: LiveCheckProgress) => void
): Promise<LiveServerCheck> {
  const startedAt = new Date().toISOString()
  const startTs = Date.now()
  const checkId = crypto.randomUUID()
  const requestId = options.requestId || checkId

  // Look up profile if profileId was supplied
  let host = options.host || ''
  let port = options.port
  let endpointCountry: string | undefined
  let profileTlsEnabled: boolean | undefined
  let sniHostname: string | undefined
  let matchedProfile: ServerProfile | null = null

  if (options.profileId) {
    try {
      const allProfiles = serverPicker.getProfiles()
      const found = allProfiles.find(p => p.id === options.profileId)
      if (found) {
        matchedProfile = found
        if (!host) host = found.server
        if (!port) port = found.port
        endpointCountry = found.country
        profileTlsEnabled = found.outbound?.tls?.enabled
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
  const totalTimeoutMs = mode === 'extended' ? 45000 : 25000
  const deadlineController = new AbortController()

  const overallTimer = setTimeout(() => {
    deadlineController.abort(new Error('Live check overall deadline exceeded'))
  }, totalTimeoutMs)

  const abortForwarder = () => {
    deadlineController.abort(new Error('Live check was cancelled'))
  }

  if (signal) {
    if (signal.aborted) {
      deadlineController.abort(new Error('Live check was cancelled'))
    } else {
      signal.addEventListener('abort', abortForwarder, { once: true })
    }
  }

  const checkSignal = deadlineController.signal

  const totalStages = 11
  let completedStages = 0
  let sequence = 0

  const reportStage = (
    stage: LiveCheckStage,
    status: 'running' | 'completed' | 'failed' | 'skipped',
    detail?: string
  ) => {
    if (status === 'completed' || status === 'failed' || status === 'skipped') {
      completedStages++
    }
    try {
      onProgress?.({
        requestId,
        sequence: ++sequence,
        stage,
        status,
        completedStages,
        totalStages,
        elapsedMs: Date.now() - startTs,
        detail
      })
    } catch {}
  }

  try {
    // 1. DNS Probe
    reportStage('dns', 'running')
    const dnsRes = await probeDns(host, mode, checkSignal)
    reportStage('dns', dnsRes.dns.status === 'ok' ? 'completed' : dnsRes.dns.status === 'skipped' ? 'skipped' : 'failed')
    const primaryIp = dnsRes.dns.a[0] || dnsRes.dns.aaaa[0] || host

    // 2. Reachability, TLS, HTTP, Ports, Route, Infrastructure Probes
    const isTlsPort = [443, 8443, 2053, 2083, 2087, 2096, 4433].includes(port)
    const isTlsApplicable = profileTlsEnabled ?? (isTlsPort || sniHostname !== undefined)

    reportStage('reachability', 'running')
    reportStage('tls', 'running')
    reportStage('http', 'running')
    reportStage('ports', 'running')
    if (mode === 'extended') reportStage('route', 'running')
    else reportStage('route', 'skipped')
    reportStage('infrastructure', 'running')

    const [reachabilitySettled, tlsSettled, httpSettled, portsSettled, routeSettled, infraSettled] =
      await Promise.allSettled([
        probeReachabilityAndLatency(primaryIp, port, mode, checkSignal),
        isTlsApplicable
          ? probeTls(primaryIp, port, sniHostname || (net.isIP(host) === 0 ? host : undefined), checkSignal)
          : Promise.resolve<LiveTlsCertInfo | undefined>(undefined),
        probeHttp(primaryIp, port, isTlsApplicable, host, checkSignal, sniHostname),
        probePorts(primaryIp, port, mode, checkSignal),
        mode === 'extended' ? probeRoute(primaryIp, checkSignal) : Promise.resolve<RouteDiagnostics | undefined>(undefined),
        probeInfrastructure(host, primaryIp, options.profileId, endpointCountry, disableGeoLookup, checkSignal)
      ])

    const reachabilityRes = reachabilitySettled.status === 'fulfilled'
      ? reachabilitySettled.value
      : { reachability: { status: 'error' as const, durationMs: 0, error: 'Probe crashed', tcpReachable: false, port }, latency: undefined }
    reportStage('reachability', reachabilityRes.reachability.status === 'ok' ? 'completed' : 'failed')

    const tlsRes: LiveTlsCertInfo | undefined = tlsSettled.status === 'fulfilled' ? tlsSettled.value : { status: 'error', durationMs: 0, error: 'TLS probe failed' }
    reportStage('tls', tlsRes ? (tlsRes.status === 'ok' ? 'completed' : 'failed') : 'skipped')

    const httpRes: HttpProbeResult = httpSettled.status === 'fulfilled' ? httpSettled.value : { status: 'error', durationMs: 0, error: 'HTTP probe failed', confidence: 'low' }
    reportStage('http', httpRes.status === 'ok' ? 'completed' : 'failed')

    const openPortsRes = portsSettled.status === 'fulfilled' ? portsSettled.value : undefined
    reportStage('ports', portsSettled.status === 'fulfilled' ? 'completed' : 'failed')

    const routeRes: RouteDiagnostics | undefined = routeSettled.status === 'fulfilled' ? routeSettled.value : { status: 'error', durationMs: 0, error: 'Route probe failed' }
    if (mode === 'extended') {
      reportStage('route', routeRes?.status === 'ok' ? 'completed' : 'failed')
    }

    const infraRes: InfrastructureHints = infraSettled.status === 'fulfilled'
      ? infraSettled.value
      : { status: 'error', endpointCountry, error: 'Infrastructure probe failed' }
    reportStage('infrastructure', infraRes.status === 'ok' ? 'completed' : 'failed')

    // 3. Tunnel Handshake & Fresh Egress Probes
    reportStage('handshake', 'running')
    reportStage('egress', 'running')
    const { handshake: handshakeRes, egress: egressRes } = await probeTunnelHandshakeAndEgress(
      matchedProfile,
      primaryIp,
      checkSignal
    )
    reportStage('handshake', handshakeRes.status === 'ok' ? 'completed' : handshakeRes.status === 'skipped' ? 'skipped' : 'failed')
    reportStage('egress', egressRes.status === 'ok' ? 'completed' : egressRes.status === 'skipped' ? 'skipped' : 'failed')

    // 4. Windows Path Confirmation & PMTU Probes
    reportStage('path', 'running')
    const pathRes = await probePathConfirmation(primaryIp, checkSignal)
    reportStage('path', pathRes.status === 'ok' ? 'completed' : pathRes.status === 'skipped' ? 'skipped' : 'failed')

    reportStage('pmtu', 'running')
    const pmtuRes = await probePmtu(
      primaryIp,
      pathRes.activeInterfaceIndex,
      pathRes.activeInterfaceAlias,
      checkSignal
    )
    reportStage('pmtu', pmtuRes.status === 'ok' || pmtuRes.status === 'lower_bound' ? 'completed' : pmtuRes.status === 'skipped' ? 'skipped' : 'failed')

    // Get previous successful check for diff & findings
    const previousCheck = liveServerHistory.getPreviousSuccessfulCheck(options.profileId, host, port)

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
      error: checkSignal.aborted ? (checkSignal.reason?.message || 'Live check was cancelled') : undefined,
      dns: dnsRes.dns,
      reverseDns: dnsRes.reverseDns.length > 0 ? dnsRes.reverseDns : undefined,
      asn: infraRes.asn,
      reachability: reachabilityRes.reachability,
      latency: reachabilityRes.latency,
      tls: tlsRes,
      http: httpRes,
      openPorts: openPortsRes,
      portsError: portsSettled.status === 'rejected' ? 'Port probe failed' : undefined,
      route: routeRes,
      infrastructure: infraRes,
      handshake: handshakeRes,
      egress: egressRes,
      pathDiagnostics: pathRes,
      pmtu: pmtuRes
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
    const owner = _event.sender?.id ?? 0
    const key = `${owner}:${requestId}`
    if (activeControllers.has(key)) throw new Error('Duplicate live check requestId')
    if ([...activeControllers.keys()].filter(k => k.startsWith(`${owner}:`)).length >= 4) throw new Error('Too many active live checks')
    const controller = new AbortController()
    const onDestroyed = () => controller.abort()
    _event.sender?.once('destroyed', onDestroyed)
    activeControllers.set(key, controller)

    try {
      const result = await runLiveServerCheck(
        { ...options, requestId },
        controller.signal,
        (progress) => {
          if (_event.sender && !_event.sender.isDestroyed()) {
            _event.sender.send('server:live-check-progress', progress)
          }
        }
      )
      return result
    } finally {
      _event.sender?.removeListener('destroyed', onDestroyed)
      if (activeControllers.get(key) === controller) {
        activeControllers.delete(key)
      }
    }
  })

  ipcMain.handle('server:live-check-cancel', async (_event, requestId?: string) => {
    if (requestId) {
      const key = `${_event.sender?.id ?? 0}:${requestId}`
      const ctrl = activeControllers.get(key)
      if (ctrl) {
        ctrl.abort()
        activeControllers.delete(key)
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
