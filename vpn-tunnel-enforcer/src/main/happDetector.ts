import { createConnection } from 'net'
import { exec as execCb } from 'child_process'
import { readFile, readdir, stat } from 'fs/promises'
import { join } from 'path'
import { homedir } from 'os'
import { promisify } from 'util'
import axios from 'axios'
import { SocksClient } from 'socks'

export interface ProxyInfo {
  host: string
  port: number
  type: 'socks5' | 'http'
  verified: boolean
  publicIpViaProxy: string | null
}

const TYPICAL_PORTS = [2080, 1080, 10808, 10809, 7890, 7891, 8080, 1087, 1081, 20170, 20171, 9090]
const IP_CHECK_URL = 'https://api.ipify.org?format=json'
const exec = promisify(execCb)

interface ProxyCandidate {
  host: string
  port: number
  source: string
  typeHint?: 'socks5' | 'http'
}

function probePort(host: string, port: number, timeout = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port }, () => {
      socket.destroy()
      resolve(true)
    })
    socket.setTimeout(timeout)
    socket.on('timeout', () => {
      socket.destroy()
      resolve(false)
    })
    socket.on('error', () => {
      resolve(false)
    })
  })
}

async function probeSocks5(host: string, port: number): Promise<boolean> {
  try {
    await SocksClient.createConnection({
      proxy: { host, port, type: 5 },
      command: 'connect',
      destination: { host: 'api.ipify.org', port: 443 }
    })
    return true
  } catch {
    return false
  }
}

async function probeHttpProxy(host: string, port: number): Promise<boolean> {
  try {
    await axios.get(IP_CHECK_URL, {
      proxy: { host, port, protocol: 'http' },
      timeout: 5000
    })
    return true
  } catch {
    return false
  }
}

async function getPublicIpViaSocks5(host: string, port: number): Promise<string | null> {
  try {
    const { socket } = await SocksClient.createConnection({
      proxy: { host, port, type: 5 },
      command: 'connect',
      destination: { host: 'api.ipify.org', port: 80 }
    })
    return await new Promise<string | null>((resolve) => {
      let buffer = ''
      const finish = (ip: string | null) => {
        socket.destroy()
        resolve(ip)
      }
      socket.setTimeout(6000)
      socket.on('data', chunk => {
        buffer += chunk.toString('utf-8')
        const body = buffer.split('\r\n\r\n')[1]
        if (!body) return
        try {
          finish(JSON.parse(body).ip ?? null)
        } catch {
          finish(null)
        }
      })
      socket.once('error', () => finish(null))
      socket.once('timeout', () => finish(null))
      socket.write('GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
    })
  } catch {
    return null
  }
}

async function getPublicIpViaHttpProxy(host: string, port: number): Promise<string | null> {
  try {
    const resp = await axios.get(IP_CHECK_URL, {
      proxy: { host, port, protocol: 'http' },
      timeout: 8000
    })
    return resp.data?.ip || null
  } catch {
    return null
  }
}

function extractProxyCandidates(source: string, raw: string | null | undefined): ProxyCandidate[] {
  if (!raw) return []
  const candidates: ProxyCandidate[] = []
  const rx = /(?:(https?|socks5?|socks):\/\/)?(\[[0-9a-fA-F:]+\]|localhost|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+):(\d{2,5})/gi

  for (const match of raw.matchAll(rx)) {
    const scheme = match[1]?.toLowerCase()
    const host = match[2].replace(/^\[|\]$/g, '')
    const port = Number(match[3])
    if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) continue
    candidates.push({
      host: host === 'localhost' ? '127.0.0.1' : host,
      port,
      source,
      typeHint: scheme?.startsWith('socks') ? 'socks5' : scheme === 'http' || scheme === 'https' ? 'http' : undefined
    })
  }

  return candidates
}

async function getWindowsProxyCandidates(): Promise<ProxyCandidate[]> {
  if (process.platform !== 'win32') return []

  const candidates: ProxyCandidate[] = []
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
    candidates.push(...extractProxyCandidates(`env:${name}`, process.env[name]))
  }

  try {
    const { stdout, stderr } = await exec('netsh winhttp show proxy', {
      windowsHide: true,
      timeout: 8000,
      encoding: 'utf8'
    })
    candidates.push(...extractProxyCandidates('WinHTTP', stdout || stderr))
  } catch {
    // ignore, other sources can still work
  }

  try {
    const command =
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();" +
      "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction Stop;" +
      "[pscustomobject]@{ProxyEnable=$p.ProxyEnable;ProxyServer=$p.ProxyServer;AutoConfigURL=$p.AutoConfigURL} | ConvertTo-Json -Compress\""
    const { stdout } = await exec(command, { windowsHide: true, timeout: 8000, encoding: 'utf8' })
    const data = JSON.parse(stdout.trim() || '{}')
    if (Number(data.ProxyEnable) === 1) candidates.push(...extractProxyCandidates('WinINet', data.ProxyServer))
    candidates.push(...extractProxyCandidates('WinINet PAC', data.AutoConfigURL))
  } catch {
    // ignore
  }

  return candidates
}

async function getLoopbackListenerCandidates(): Promise<ProxyCandidate[]> {
  if (process.platform !== 'win32') return []

  try {
    // Behavior-based detection: return ALL user-level loopback listeners as
    // candidates. Process name is just a hint, not a filter — `verifyCandidate()`
    // probes whether each candidate actually speaks SOCKS5 or HTTP proxy
    // protocol, which is the reliable signal. We only filter out well-known
    // non-proxy ports and core OS processes to keep the candidate list small.
    const command =
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();" +
      "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | " +
      "Where-Object { $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::') } | " +
      "ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{Address=$_.LocalAddress;Port=$_.LocalPort;Process=$p.ProcessName} } | " +
      "Where-Object { ($_.Port -notin @(135,139,445,3389,5985,5986,5040,5357,49664,49665,49666,49667,49668,49669,49670,49671,49672,49673,80,443,3306,5432,6379,27017,11211,8443,8888,9000)) -and ($_.Process -notmatch '(?i)^(svchost|System|wininit|services|lsass|csrss|smss|winlogon|spoolsv|RuntimeBroker|SearchHost|SearchApp|StartMenuExperienceHost|TextInputHost|ShellExperienceHost|ApplicationFrameHost|Explorer|Taskmgr|dllhost|conhost|fontdrvhost|sihost|ctfmon|dwm|audiodg)$') -and ($_.Port -ge 1024) } | " +
      "Sort-Object Port -Unique | ConvertTo-Json -Compress\""
    const { stdout } = await exec(command, {
      windowsHide: true,
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      encoding: 'utf8'
    })
    const raw = stdout.trim()
    if (!raw) return []
    const parsed = JSON.parse(raw)
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    return rows
      .filter((row: any) => Number.isInteger(Number(row.Port)))
      .map((row: any) => ({
        host: '127.0.0.1',
        port: Number(row.Port),
        source: `listener:${row.Process || 'unknown'}`
      }))
  } catch {
    return []
  }
}

function uniqueCandidates(candidates: ProxyCandidate[]): ProxyCandidate[] {
  const seen = new Set<string>()
  const result: ProxyCandidate[] = []
  for (const candidate of candidates) {
    const key = `${candidate.host}:${candidate.port}`
    if (seen.has(key)) continue
    seen.add(key)
    result.push(candidate)
  }
  return result
}

async function verifyCandidate(candidate: ProxyCandidate): Promise<ProxyInfo | null> {
  const open = await probePort(candidate.host, candidate.port)
  if (!open) return null

  const orderedTypes: Array<'http' | 'socks5'> =
    candidate.typeHint === 'http'
      ? ['http', 'socks5']
      : candidate.typeHint === 'socks5'
        ? ['socks5', 'http']
        : ['http', 'socks5']

  for (const type of orderedTypes) {
    if (type === 'http' && await probeHttpProxy(candidate.host, candidate.port)) {
      return {
        host: candidate.host,
        port: candidate.port,
        type: 'http',
        verified: true,
        publicIpViaProxy: await getPublicIpViaHttpProxy(candidate.host, candidate.port)
      }
    }

    if (type === 'socks5' && await probeSocks5(candidate.host, candidate.port)) {
      return {
        host: candidate.host,
        port: candidate.port,
        type: 'socks5',
        verified: true,
        publicIpViaProxy: await getPublicIpViaSocks5(candidate.host, candidate.port)
      }
    }
  }

  return null
}

async function scanHappConfig(): Promise<ProxyInfo | null> {
  const appData = process.env.APPDATA || join(homedir(), 'AppData', 'Roaming')
  const localAppData = process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')

  const searchDirs = [
    join(appData, 'Happ'),
    join(localAppData, 'Happ'),
    join(appData, 'happ'),
    join(localAppData, 'happ'),
    join(appData, 'Happ VPN'),
    join(localAppData, 'Happ VPN'),
  ]

  for (const dir of searchDirs) {
    try {
      await stat(dir)
      const entries = await readdir(dir, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isFile() && (entry.name.endsWith('.json') || entry.name.endsWith('.yaml') || entry.name.endsWith('.yml') || entry.name.endsWith('.conf') || entry.name.endsWith('.ini') || entry.name.endsWith('.toml'))) {
          try {
            const content = await readFile(join(dir, entry.name), 'utf-8')
            const portMatch = content.match(/(?:port|listen|socks-port|http-port|mixed-port)['":\s]+(\d{2,5})/i)
            if (portMatch) {
              const port = parseInt(portMatch[1], 10)
              if (port > 0 && port < 65536) {
                return { host: '127.0.0.1', port, type: 'socks5', verified: false, publicIpViaProxy: null }
              }
            }
          } catch { /* skip unreadable */ }
        }
      }
    } catch { /* dir not found */ }
  }

  return null
}

export const happDetector = {
  async detect(): Promise<ProxyInfo | null> {
    // 1. Try reading Happ config
    const configProxy = await scanHappConfig()
    if (configProxy) {
      const verified = await probeSocks5(configProxy.host, configProxy.port)
      if (verified) {
        const ip = await getPublicIpViaSocks5(configProxy.host, configProxy.port)
        return { ...configProxy, verified: true, publicIpViaProxy: ip }
      }
    }

    // 2. Check existing system proxy settings and live loopback listeners from VPN/proxy apps
    const discoveredCandidates = uniqueCandidates([
      ...await getWindowsProxyCandidates(),
      ...await getLoopbackListenerCandidates()
    ])

    for (const candidate of discoveredCandidates) {
      const verified = await verifyCandidate(candidate)
      if (verified) return verified
    }

    // 3. Scan typical ports as a fallback
    const host = '127.0.0.1'
    const openPorts: number[] = []

    const probeResults = await Promise.all(
      TYPICAL_PORTS.map(async (port) => {
        const open = await probePort(host, port)
        return { port, open }
      })
    )

    for (const r of probeResults) {
      if (r.open) openPorts.push(r.port)
    }

    // 3. Probe each open port — prefer HTTP over SOCKS5 for TUN reliability
    for (const port of openPorts) {
      const isHttp = await probeHttpProxy(host, port)
      if (isHttp) {
        const ip = await getPublicIpViaHttpProxy(host, port)
        return { host, port, type: 'http', verified: true, publicIpViaProxy: ip }
      }
    }

    for (const port of openPorts) {
      const isSocks5 = await probeSocks5(host, port)
      if (isSocks5) {
        const ip = await getPublicIpViaSocks5(host, port)
        return { host, port, type: 'socks5', verified: true, publicIpViaProxy: ip }
      }
    }

    return null
  }
}
