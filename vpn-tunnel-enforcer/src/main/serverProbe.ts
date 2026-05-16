import { ipcMain } from 'electron'
import { promises as dns } from 'dns'
import { Socket } from 'net'
import { connect as tlsConnect } from 'tls'
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

// Scan common ports in parallel (with concurrency limit)
async function scanPorts(host: string, knownPort?: number): Promise<PortScanResult[]> {
  const portsToScan = knownPort && !COMMON_PORTS.includes(knownPort)
    ? [knownPort, ...COMMON_PORTS]
    : COMMON_PORTS

  const results: PortScanResult[] = []
  const concurrency = 8
  for (let i = 0; i < portsToScan.length; i += concurrency) {
    const batch = portsToScan.slice(i, i + concurrency)
    const batchResults = await Promise.all(
      batch.map(async (port) => ({
        port,
        open: await probePort(host, port, 1000),
        service: SERVICE_HINTS[port]
      }))
    )
    results.push(...batchResults)
  }
  return results.filter(r => r.open)  // only return open ports
}

// Get TLS certificate info from a host:port
function getTlsCert(host: string, port: number): Promise<TlsCertInfo | null> {
  return new Promise((resolve) => {
    let resolved = false
    const finish = (result: TlsCertInfo | null) => {
      if (resolved) return
      resolved = true
      try { socket.destroy() } catch {}
      resolve(result)
    }
    const socket = tlsConnect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 5000
    }, () => {
      try {
        const cert = (socket as any).getPeerCertificate(true)
        if (!cert || Object.keys(cert).length === 0) return finish(null)
        const subject = Object.entries(cert.subject || {}).map(([k, v]) => `${k}=${v}`).join(', ')
        const issuer = Object.entries(cert.issuer || {}).map(([k, v]) => `${k}=${v}`).join(', ')
        const sans: string[] = []
        if (cert.subjectaltname) {
          for (const part of String(cert.subjectaltname).split(',')) {
            const m = part.trim().match(/^(?:DNS|IP Address):(.+)$/)
            if (m) sans.push(m[1])
          }
        }
        finish({
          subject,
          issuer,
          validFrom: cert.valid_from || '',
          validTo: cert.valid_to || '',
          fingerprint: cert.fingerprint256 || cert.fingerprint || '',
          sans,
          protocol: (socket as any).getProtocol() || '',
          cipher: (socket as any).getCipher()?.name || ''
        })
      } catch {
        finish(null)
      }
    })
    socket.on('error', () => finish(null))
    socket.on('timeout', () => finish(null))
  })
}

// Get HTTP banner from port 80 (Server header)
async function getHttpBanner(host: string, port = 80): Promise<string | null> {
  try {
    const resp = await axios.head(`http://${host}:${port}/`, {
      timeout: 4000,
      validateStatus: () => true,
      maxRedirects: 0
    })
    return (resp.headers['server'] as string | undefined) || null
  } catch {
    return null
  }
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
