import { ipcMain } from 'electron'
import { promises as dns } from 'dns'
import { Socket } from 'net'
import axios from 'axios'
import { logEvent } from './appLogger'

export interface ServerProbeResult {
  host: string
  resolvedIps: string[]
  reverseDns: string | null
  asn: AsnInfo | null
  latency: LatencyStats | null
  openPorts: PortScanResult[]
  tlsCert: TlsCertInfo | null
  httpBanner: string | null
}

export interface AsnInfo {
  asn: string
  org: string
  network: string
  country: string
}

export interface LatencyStats {
  min: number
  avg: number
  max: number
  jitter: number   // stddev
  loss: number     // 0..1 (packets lost / total)
  samples: number[]
}

export interface PortScanResult {
  port: number
  open: boolean
  service?: string  // best guess (ssh, http, https, etc.)
}

export interface TlsCertInfo {
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  fingerprint: string
  sans: string[]
  protocol: string  // TLSv1.2, TLSv1.3
  cipher: string
}

const COMMON_PORTS = [22, 80, 443, 8080, 8443, 3128, 1080, 8388, 4433, 8081, 8888, 53, 21, 25, 110, 143, 587, 993, 995]
const SERVICE_HINTS: Record<number, string> = {
  22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
  3128: 'Squid proxy', 1080: 'SOCKS', 8388: 'Shadowsocks', 4433: 'TLS-alt',
  53: 'DNS', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 587: 'SMTP-Submission',
  993: 'IMAPS', 995: 'POP3S'
}

// Probe a single TCP port with short timeout
function probePort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket()
    let resolved = false
    const finish = (result: boolean) => {
      if (resolved) return
      resolved = true
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    socket.connect(port, host)
  })
}

// Measure latency via TCP connect timing (port 443 default — usually open)
async function measureLatency(host: string, port = 443, samples = 5): Promise<LatencyStats> {
  const results: number[] = []
  let lost = 0
  for (let i = 0; i < samples; i++) {
    const start = Date.now()
    const ok = await probePort(host, port, 3000)
    if (ok) results.push(Date.now() - start)
    else lost++
    // small delay between probes
    await new Promise(r => setTimeout(r, 80))
  }
  if (results.length === 0) {
    return { min: 0, avg: 0, max: 0, jitter: 0, loss: 1, samples: [] }
  }
  const min = Math.min(...results)
  const max = Math.max(...results)
  const avg = results.reduce((a, b) => a + b, 0) / results.length
  const variance = results.reduce((sum, x) => sum + (x - avg) ** 2, 0) / results.length
  const jitter = Math.sqrt(variance)
  return { min, avg: Math.round(avg), max, jitter: Math.round(jitter), loss: lost / samples, samples: results }
}

// Resolve hostname to IPs (both v4 and v6)
async function resolveHost(host: string): Promise<string[]> {
  const ips: string[] = []
  // If host is already an IP, return it as is
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) {
    return [host]
  }
  try {
    const v4 = await dns.resolve4(host).catch(() => [] as string[])
    const v6 = await dns.resolve6(host).catch(() => [] as string[])
    ips.push(...v4, ...v6)
  } catch {}
  return ips
}

// Reverse DNS lookup
async function reverseDnsLookup(ip: string): Promise<string | null> {
  try {
    const names = await dns.reverse(ip)
    return names.length > 0 ? names[0] : null
  } catch {
    return null
  }
}

// Get ASN info from ipapi.co (free, no auth)
async function getAsnInfo(ip: string): Promise<AsnInfo | null> {
  try {
    const resp = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 6000 })
    if (resp.data && !resp.data.error) {
      return {
        asn: resp.data.asn || 'unknown',
        org: resp.data.org || 'unknown',
        network: resp.data.network || '',
        country: resp.data.country_name || resp.data.country || ''
      }
    }
  } catch {}
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
async function scanPorts(host: string, knownPort?: number): Promise<PortScanResult[]> {
  const port = knownPort && knownPort > 0 ? knownPort : 443
  const open = await probePort(host, port, 1000)
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
export async function probeServer(host: string, knownPort?: number): Promise<ServerProbeResult> {
  logEvent('info', 'server-probe', `probing ${host}`, { knownPort })

  const resolvedIps = await resolveHost(host)
  const primaryIp = resolvedIps[0] || host

  // Run all probes in parallel
  const [reverseDns, asn, latency, openPorts, tlsCert, httpBanner] = await Promise.all([
    reverseDnsLookup(primaryIp),
    getAsnInfo(primaryIp),
    measureLatency(host, knownPort && knownPort > 0 ? knownPort : 443),
    scanPorts(host, knownPort),
    getTlsCert(host, knownPort && [443, 8443, 4433].includes(knownPort) ? knownPort : 443),
    getHttpBanner(host, 80)
  ])

  return {
    host,
    resolvedIps,
    reverseDns,
    asn,
    latency: latency.samples.length > 0 ? latency : null,
    openPorts,
    tlsCert,
    httpBanner
  }
}

export function registerServerProbeIpcHandlers(): void {
  ipcMain.handle('server:probe', async (_event, host: string, knownPort?: number) => {
    return probeServer(host, knownPort)
  })
}
