import type { ServerProbeResult, LatencyStats, PortScanResult, TlsCertInfo } from '../shared/diagnostics'
export type { ServerProbeResult, LatencyStats, PortScanResult, TlsCertInfo } from '../shared/diagnostics'
import type { AsnInfo } from '../shared/ipc-types'
export type { AsnInfo } from '../shared/ipc-types'
import { ipcMain } from 'electron'
import { randomUUID } from 'node:crypto'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'
import { runRequesterOperation } from './requesterOperation'
import { IpcFault } from '../shared/ipc-result'
import { promises as dns } from 'dns'
import { BlockList, Socket, isIP } from 'net'
import axios from 'axios'
import { logEvent } from './appLogger'
import { tunController } from './tunController'
import { settingsStore } from './settings'
import { normalizeServerPort } from '../shared/portValidation'

export interface ProbeServerOptions {
  disableGeoLookup?: boolean
  signal?: AbortSignal
  onOperation?: (lease: OperationLease) => void
}

const COMMON_PORTS = [22, 80, 443, 8080, 8443, 3128, 1080, 8388, 4433, 8081, 8888, 53, 21, 25, 110, 143, 587, 993, 995]
const SERVICE_HINTS: Record<number, string> = {
  22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
  3128: 'Squid proxy', 1080: 'SOCKS', 8388: 'Shadowsocks', 4433: 'TLS-alt',
  53: 'DNS', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 587: 'SMTP-Submission',
  993: 'IMAPS', 995: 'POP3S'
}
const DNS_LOOKUP_TIMEOUT_MS = 2500

function assertProbeActive(signal?: AbortSignal): void {
  if (signal?.aborted) throw new IpcFault('cancelled')
}

// Each raw DNS query owns a bounded resolver until its actual settlement.
async function dnsQuery(run: (resolver: InstanceType<typeof dns.Resolver>) => Promise<string[]>, signal?: AbortSignal): Promise<string[]> {
  assertProbeActive(signal)
  const resolver = new dns.Resolver({ timeout: DNS_LOOKUP_TIMEOUT_MS, tries: 1 })
  const abort = () => resolver.cancel()
  let expired = false
  const timer = setTimeout(() => { expired = true; abort() }, DNS_LOOKUP_TIMEOUT_MS)
  signal?.addEventListener('abort', abort, { once: true })
  try {
    assertProbeActive(signal)
    const result = await run(resolver).catch(() => [] as string[])
    assertProbeActive(signal)
    return expired ? [] : result
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort) }
}

// Destruction starts cleanup; only close releases the raw socket promise.
function probePort(host: string, port: number, timeoutMs = 1500, signal?: AbortSignal): Promise<{ open: boolean; ms: number | null }> {
  assertProbeActive(signal)
  const safePort = normalizeServerPort(port)
  if (!safePort) return Promise.resolve({ open: false, ms: null })
  return new Promise(resolve => {
    const socket = new Socket(), startedAt = Date.now()
    let finished = false, result: { open: boolean; ms: number | null } = { open: false, ms: null }
    const finish = (value: boolean) => {
      if (finished) return
      finished = true; result = { open: value, ms: value ? Date.now() - startedAt : null }; socket.destroy()
    }
    const abort = () => finish(false)
    socket.once('close', () => {
      signal?.removeEventListener('abort', abort)
      socket.removeAllListeners()
      resolve(result)
    })
    socket.once('error', () => finish(false))
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    else {
      try { socket.setTimeout(timeoutMs); socket.connect(safePort, host) }
      catch { finish(false) }
    }
  })
}

// Measure only the validated address, never a second hostname resolution.
async function measureLatency(host: string, port = 443, samples = 5, signal?: AbortSignal): Promise<LatencyStats> {
  const safePort = normalizeServerPort(port, 443)!
  const results: number[] = []
  let lost = 0
  const deadline = Date.now() + 7000
  for (let i = 0; i < samples; i++) {
    assertProbeActive(signal)
    const remaining = deadline - Date.now()
    if (remaining <= 0) { lost += samples - i; break }
    const sample = await probePort(host, safePort, Math.min(3000, Math.max(500, remaining)), signal)
    assertProbeActive(signal)
    if (sample.open) results.push(sample.ms!)
    else lost++
    if (i < samples - 1 && Date.now() + 80 < deadline) {
      await new Promise<void>(resolve => {
        const done = () => { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve() }
        const timer = setTimeout(done, 80)
        signal?.addEventListener('abort', done, { once: true })
        if (signal?.aborted) done()
      })
    }
  }
  assertProbeActive(signal)
  if (!results.length) return { min: 0, avg: 0, max: 0, jitter: 0, loss: 1, samples: [] }
  const min = Math.min(...results), max = Math.max(...results)
  const avg = results.reduce((a, b) => a + b, 0) / results.length
  const variance = results.reduce((sum, x) => sum + (x - avg) ** 2, 0) / results.length
  return { min, avg: Math.round(avg), max, jitter: Math.round(Math.sqrt(variance)), loss: lost / samples, samples: results }
}

// Resolve hostname to IPs (both v4 and v6)
export async function resolveHost(rawHost: string, signal?: AbortSignal): Promise<string[]> {
  assertProbeActive(signal)
  let host = rawHost.trim()
  if (host.startsWith('[') && host.includes(']')) {
    host = host.slice(1, host.indexOf(']'))
  } else if (!host.includes('::') && host.includes(':')) {
    host = host.split(':')[0]
  }

  // If host is already an IP, return it as is
  if (isIP(host) !== 0) {
    return [host]
  }
  const results = await Promise.allSettled([
    dnsQuery(resolver => resolver.resolve4(host), signal),
    dnsQuery(resolver => resolver.resolve6(host), signal)
  ])
  assertProbeActive(signal)
  return results.flatMap(result => result.status === 'fulfilled' ? result.value : [])
}


// Reverse DNS lookup
async function reverseDnsLookup(ip: string, signal?: AbortSignal): Promise<string | null> {
  const names = await dnsQuery(resolver => resolver.reverse(ip), signal)
  return names.length > 0 ? names[0] : null
}

// Get ASN info from ipapi.co with ipwho.is fallback
async function getAsnInfo(ip: string, signal?: AbortSignal): Promise<AsnInfo | null> {
  assertProbeActive(signal)
  try {
    const resp = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 6000, signal })
    assertProbeActive(signal)
    if (resp.data && !resp.data.error) {
      return {
        asn: resp.data.asn || 'unknown',
        org: resp.data.org || 'unknown',
        network: resp.data.network || '',
        country: resp.data.country_name || resp.data.country || ''
      }
    }
  } catch { assertProbeActive(signal) }
  try {
    const fb = await axios.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 6000, signal })
    assertProbeActive(signal)
    if (fb.data && fb.data.success !== false) {
      const d = fb.data
      const rawAsn = d.connection?.asn
        ? (String(d.connection.asn).startsWith('AS') ? String(d.connection.asn) : `AS${d.connection.asn}`)
        : 'unknown'
      return {
        asn: rawAsn,
        org: d.connection?.isp || d.connection?.org || 'unknown',
        network: '',
        country: d.country || ''
      }
    }
  } catch { assertProbeActive(signal) }
  return null
}

// Scan ports.
//
// Restricted to the *known* port of the profile. Scanning a fan of common
// ports (22/80/443/8080/3128/etc.) on a VPN endpoint is an obvious DPI
// signal — censorship boxes don't even need a signature, the port-fan
// pattern itself triggers throttling. We only check that the actual VPN
// port is reachable; everything else is unused diagnostic noise that hurt
// users far more than it helped them.
async function scanPorts(host: string, knownPort?: number, signal?: AbortSignal): Promise<PortScanResult[]> {
  const port = normalizeServerPort(knownPort, 443)!
  const { open } = await probePort(host, port, 1000, signal)
  if (!open) return []
  return [{ port, open, service: SERVICE_HINTS[port] }]
}

// Get TLS certificate info from a host:port.
//
// IMPORTANT: We intentionally do NOT send a TLS ClientHello to the
// requested host. The hosts probed here are VPN endpoints (vless/trojan
// fronts on :443) — sending a ClientHello with their server_name leaks
// that hostname to the local DPI in clear text. Russian TSPU and similar
// censorship boxes pattern-match SNIs against a database of known VPN
// fronts and start throttling/blackholing the IP for several minutes
// after a single such request. Reported by users as "the diagnostic
// page killed my internet for 10 minutes".
//
// We have no useful information to gain from probing the cert anyway —
// VPN fronts deliberately camouflage with a real domain's certificate
// (Reality), so the cert tells us nothing about the actual VPN backend.
//
// The function is kept for backwards compatibility with the IPC schema
// but always resolves null. Future versions can re-enable it for
// genuinely user-supplied hosts (custom Tahoe/SS endpoints), but never
// for our own picker entries.
function getTlsCert(_host: string, _port: number): Promise<TlsCertInfo | null> {
  return Promise.resolve(null)
}

// HTTP banner from port 80.
//
// Disabled for the same reason as getTlsCert: probing VPN endpoints with
// raw HTTP requests is a clean fingerprint for DPI ("client just hit
// :80 on a VPN backend"). The banner string isn't actionable anyway —
// these endpoints rarely have any meaningful Server header, and the few
// that do are camouflaged.
async function getHttpBanner(_host: string, _port = 80): Promise<string | null> {
  return null
}

// Main probe entry point
export async function probeServer(host: string, knownPort?: number, options: ProbeServerOptions = {}): Promise<ServerProbeResult> {
  return operations.run('server-probe', lease => {
    options.onOperation?.(lease)
    return probeServerOwned(host, knownPort, options, lease)
  }, { signal: options.signal, resource: `server-probe:${randomUUID()}` })
}

async function probeServerOwned(host: string, knownPort: number | undefined, options: ProbeServerOptions, lease: OperationLease): Promise<ServerProbeResult> {
  lease.assertActive()
  const disableGeoLookup = options.disableGeoLookup === true
  const safePort = normalizeServerPort(knownPort, 443)!
  logEvent('info', 'server-probe', `probing ${host}`, { knownPort: safePort, disableGeoLookup })

  const resolvedIps = await lease.wait(resolveHost(host, lease.signal))
  lease.assertActive()
  if (!resolvedIps.length || resolvedIps.some(ip => !isIP(ip))) throw new IpcFault('network')
  if (resolvedIps.some(ip => isPrivateProbeAddress(ip))) throw new IpcFault('permission')
  const primaryIp = resolvedIps[0]
  const tunRunning = tunController.getStatus().running

  // When TUN is active, TCP probes go through the tunnel — latency would be
  // tunnel RTT, not direct RTT. Skip latency measurement to avoid misleading
  // values (the active server self-loops, others show tunnel RTT as "direct").
  const [reverseDns, asn, latency, openPorts, tlsCert, httpBanner] = await Promise.all([
    lease.wait(reverseDnsLookup(primaryIp, lease.signal)),
    disableGeoLookup ? Promise.resolve(null) : lease.wait(getAsnInfo(primaryIp, lease.signal)),
    tunRunning ? Promise.resolve(null as LatencyStats | null) : lease.wait(measureLatency(primaryIp, safePort, 5, lease.signal)),
    lease.wait(scanPorts(primaryIp, safePort, lease.signal)),
    getTlsCert(host, [443, 8443, 4433].includes(safePort) ? safePort : 443),
    getHttpBanner(host, 80)
  ])

  return lease.commit(() => ({
    host,
    resolvedIps,
    reverseDns,
    asn,
    latency: latency !== null && latency.samples.length > 0 ? latency : null,
    openPorts,
    tlsCert,
    httpBanner
  }))
}

const privateProbeAddresses = new BlockList()
for (const [address, prefix] of [['0.0.0.0', 8], ['127.0.0.0', 8], ['10.0.0.0', 8],
  ['192.168.0.0', 16], ['172.16.0.0', 12], ['169.254.0.0', 16]] as const) {
  privateProbeAddresses.addSubnet(address, prefix, 'ipv4')
}
privateProbeAddresses.addAddress('::', 'ipv6')
privateProbeAddresses.addAddress('::1', 'ipv6')
privateProbeAddresses.addSubnet('fc00::', 7, 'ipv6')
privateProbeAddresses.addSubnet('fe80::', 10, 'ipv6')
function isPrivateProbeAddress(ip: string): boolean {
  // Node also matches IPv4-mapped IPv6 against IPv4 subnets.
  const family = isIP(ip)
  return family !== 0 && privateProbeAddresses.check(ip, family === 6 ? 'ipv6' : 'ipv4')
}

export function registerServerProbeIpcHandlers(): void {
  ipcMain.handle('server:probe', (event, host: string, knownPort?: number, requestId?: string) =>
    runRequesterOperation(event.sender, requestId, async (signal, onOperation) => {
      if (typeof host !== 'string' || !host.trim()) return null
      const normalizedHost = host.trim().replace(/^\[|\]$/g, '').toLowerCase()
      if (normalizedHost === 'localhost' || normalizedHost.endsWith('.localhost') || (isIP(normalizedHost) !== 0 && isPrivateProbeAddress(normalizedHost))) {
        throw new IpcFault('permission')
      }
      const safePort = normalizeServerPort(knownPort) ?? undefined
      return probeServer(normalizedHost, safePort, {
        disableGeoLookup: settingsStore.get().disableGeoLookup === true, signal, onOperation
      })
    }))
}
