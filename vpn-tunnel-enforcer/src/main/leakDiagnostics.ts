import axios from 'axios'
import { exec as execCb } from 'child_process'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { networkInterfaces } from 'os'
import { promisify } from 'util'
import { detectForeignTun, getTunRuntimeDir, parseProxyAddress, probeTcp } from './tunController'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

const exec = promisify(execCb)

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info'

export interface LeakCheckItem {
  id: string
  label: string
  status: CheckStatus
  value: string
  details?: string
}

export interface LeakCheckResult {
  ranAt: number
  summary: CheckStatus
  items: LeakCheckItem[]
}

interface RunLeakCheckOptions {
  proxyAddr?: string
  proxyType?: 'socks5' | 'http'
  tunRunning?: boolean
  /**
   * Connection mode. In 'directVpn' sing-box IS the tunnel core — there is no
   * separate local SOCKS/HTTP proxy to probe, so a stale proxyOverride like
   * 127.0.0.1:10808 (left over from Happ-proxy mode) must NOT be flagged red.
   */
  connectionMode?: 'localProxy' | 'directVpn'
  /**
   * Smart-RU split is ON. When set, RU-hosted public IPs egressing via
   * direct-out are EXPECTED (banks/gov/VK/Yandex see the real IP by design) —
   * so the "Direct-out приложений" check must treat them as informational, not
   * a leak.
   */
  smartRuSplit?: boolean
}

async function fetchJson(url: string, timeout = 8000): Promise<any | null> {
  try {
    const response = await axios.get(url, { timeout })
    return response.data
  } catch {
    return null
  }
}

async function getPublicIpV4(): Promise<string | null> {
  const urls = [
    'https://api.ipify.org?format=json',
    'https://api.myip.com',
    'https://ipinfo.io/json',
    'https://ifconfig.co/json'
  ]

  for (const url of urls) {
    const data = await fetchJson(url)
    const ip = data?.ip || data?.query
    if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip
  }

  try {
    const { stdout } = await exec('curl.exe -4 -sS --max-time 8 https://api.ipify.org', {
      windowsHide: true,
      timeout: 10000
    })
    const ip = stdout.trim()
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip
  } catch {
    // fall through
  }

  return null
}

async function getPublicIpV6(): Promise<string | null> {
  const data = await fetchJson('https://api6.ipify.org?format=json', 6000)
  return data?.ip ?? null
}

function getVpnLikeAdapters(): string[] {
  const vpnNameRx = /wintun|\btun\b|wireguard|\bwg\d*\b|openvpn|tap-windows|happ|hiddify|singbox|v2ray|xray/i
  const result: string[] = []
  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    if (!addrs || !vpnNameRx.test(name)) continue
    const visible = addrs
      .filter(a => !a.internal)
      .map(a => a.address)
      .join(', ')
    result.push(visible ? `${name} (${visible})` : name)
  }
  return result
}

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === '::1' ||
    /^fe80:/i.test(ip) ||
    /^fc|^fd/i.test(ip)
  )
}

async function getVpnLikeAdaptersFromWindows(): Promise<string[]> {
  if (process.platform !== 'win32') return getVpnLikeAdapters()
  try {
    const command =
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();" +
      "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match '(?i)wintun|tun|wireguard|openvpn|tap-windows|happ|singbox|sing-tun|vpn') } | " +
      "Select-Object Name,InterfaceDescription,ifIndex | ConvertTo-Json -Compress\""
    const { stdout } = await exec(command, { windowsHide: true, timeout: 8000, encoding: 'utf8' })
    const raw = stdout.trim()
    if (!raw) return []
    const parsed = JSON.parse(raw)
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    return rows.map((row: any) => `${row.Name} (${row.InterfaceDescription}, ifIndex ${row.ifIndex})`)
  } catch {
    return getVpnLikeAdapters()
  }
}

async function getDnsServers(): Promise<string> {
  if (process.platform !== 'win32') return 'Доступно только на Windows'
  try {
    const command =
      "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();" +
      "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | " +
      "Where-Object { $_.ServerAddresses.Count -gt 0 } | " +
      "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress\""
    const { stdout } = await exec(command, { windowsHide: true, timeout: 8000, encoding: 'utf8' })
    const raw = stdout.trim()
    if (!raw) return 'DNS-серверы не найдены'
    const parsed = JSON.parse(raw)
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    return rows
      .map((row: any) => `${row.InterfaceAlias}: ${(row.ServerAddresses ?? []).join(',')}`)
      .join(' | ')
  } catch (err: any) {
    return err.message || 'Не удалось прочитать DNS-серверы'
  }
}

/**
 * Map a Windows Resolve-DnsName record Type to a human label.
 *
 * ConvertTo-Json serializes the [Microsoft.DnsClient.Commands.RecordType] enum
 * to its NUMERIC value, so the diagnostics card was showing "1: 104.20.23.154"
 * (1 = A) instead of "A: 104.20.23.154". This maps the common record types
 * back to their names; unknown values fall back to "type N". Exported pure for
 * tests.
 */
export function dnsTypeName(type: number | string): string {
  if (typeof type === 'string' && /^[A-Za-z]/.test(type)) return type // already a name
  const n = Number(type)
  const map: Record<number, string> = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    65: 'HTTPS'
  }
  return map[n] ?? (Number.isFinite(n) ? `type ${n}` : String(type))
}

async function getDnsProbe(): Promise<string> {
  if (process.platform === 'win32') {
    try {
      const script = Buffer.from(
        '$ProgressPreference="SilentlyContinue";' +
        '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
        '$records=@();' +
        '$records += Resolve-DnsName example.com -Type A -QuickTimeout -ErrorAction Stop;' +
        '$records += Resolve-DnsName example.com -Type AAAA -QuickTimeout -ErrorAction SilentlyContinue;' +
        '$records | Where-Object { $_.IPAddress } | Select-Object Type,IPAddress | ConvertTo-Json -Compress',
        'utf16le'
      ).toString('base64')
      const command =
        `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${script}`
      const { stdout } = await exec(command, { windowsHide: true, timeout: 8000, encoding: 'utf8' })
      const raw = stdout.trim()
      if (!raw) return 'Resolve-DnsName: пустой ответ'
      const parsed = JSON.parse(raw)
      const rows = Array.isArray(parsed) ? parsed : [parsed]
      return rows.map((row: any) => `${dnsTypeName(row.Type)}: ${row.IPAddress}`).join(' | ')
    } catch (err: any) {
      return `DNS не отвечает: ${String(err.stderr || err.stdout || err.message || 'Resolve-DnsName failed').replace(/#< CLIXML[\s\S]*/i, 'PowerShell returned no readable result').replace(/\s+/g, ' ').trim()}`
    }
  }

  try {
    const { stdout } = await exec('nslookup example.com', { windowsHide: true, timeout: 8000 })
    const lines = stdout
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .slice(0, 8)
    return lines.join(' | ') || 'Ответ пустой'
  } catch (err: any) {
    return err.message || 'DNS probe failed'
  }
}

/**
 * A sing-box log line is BENIGN block-out noise (not a real error) when it's
 * the core refusing to open a UDP listen socket for traffic we deliberately
 * route to block-out (QUIC/HTTP3 on a tcp-only Reality outbound). Counting
 * these as errors made every healthy session look broken. Exported for tests.
 */
export function isBenignBlockLine(line: string): boolean {
  return (
    /outbound\/block\[block-out]/i.test(line) ||
    /listen packet connection using .*block-out: operation not permitted/i.test(line)
  )
}

/** Pure: extract the up-to-5 most recent REAL error lines from a sing-box log. */
export function extractRealErrors(logText: string): string[] {
  return logText
    .split(/\r?\n/)
    .filter(Boolean)
    .filter(line => /\b(fatal|error|panic|failed|timeout|refused)\b/i.test(line))
    .filter(line => !isBenignBlockLine(line))
    .slice(-5)
}

/** Pure: build the sing-box log one-line summary (counts + recent errors). */
export function summarizeSingboxLog(logText: string): string {
  const lines = logText.split(/\r?\n/).filter(Boolean)
  const errors = extractRealErrors(logText)
  // Count ANY outbound tagged proxy-out, not just socks/http. In Direct VPN
  // mode the tunnel outbound is vless/vmess/trojan/hysteria2/etc — the old
  // socks|http-only regex matched nothing and showed a misleading
  // "proxy-out: 0" even on a fully working VLESS/Reality session.
  const proxyHits = lines.filter(line => /outbound\/[a-z0-9]+\[proxy-out]/i.test(line)).length
  const directHits = lines.filter(line => /outbound\/direct\[direct-out]/i.test(line)).length
  const dnsHits = lines.filter(line => /hijack|dns/i.test(line)).length
  const parts = [`proxy-out: ${proxyHits}`, `direct-out: ${directHits}`, `dns-events: ${dnsHits}`]
  if (errors.length > 0) parts.push(`errors: ${errors.join(' | ')}`)
  return parts.join('; ')
}

async function getLogSummary(): Promise<string> {
  try {
    const log = await readFile(join(getTunRuntimeDir(), 'sing-box.log'), 'utf-8')
    return summarizeSingboxLog(log)
  } catch {
    return 'Лог sing-box пока не создан'
  }
}

async function getTunLogItem(tunRunning: boolean): Promise<LeakCheckItem> {
  const summary = await getLogSummary()
  if (!tunRunning) {
    return {
      id: 'sing-box-log',
      label: 'sing-box log',
      status: 'info',
      value: 'TUN выключен; лог исторический',
      details: summary
    }
  }

  return {
    id: 'sing-box-log',
    label: 'sing-box log',
    status: summary.includes('errors:') ? 'warn' : 'info',
    value: summary
  }
}

/**
 * Pure classifier for direct-out connections found in a sing-box log. Splits
 * public IPs that egressed direct into three buckets:
 *   - smartRu:  matched geoip-ru / geosite-category-gov-ru → RU split (expected)
 *   - allowed:  the connection's process was a VPN-core (Happ/xray) exclusion
 *   - leaked:   neither — a genuine unexplained direct-out of a public IP
 * Exported for unit testing (the IO wrapper getDirectPublicSummary just reads
 * the file and delegates here).
 */
export function classifyDirectPublic(logText: string): {
  leakedCount: number; allowedCoreCount: number; smartRuCount: number
  leakedExamples: string[]; allowedExamples: string[]; smartRuExamples: string[]
} {
  const byId = new Map<string, { allowedCore: boolean; smartRu: boolean; directIps: string[] }>()

  for (const line of logText.split(/\r?\n/)) {
    const id = line.match(/\[(\d+)\s/)?.[1]
    if (!id) continue

    const entry = byId.get(id) ?? { allowedCore: false, smartRu: false, directIps: [] }
    if (/router: match\[\d+].*process_name=\[/i.test(line)) {
      entry.allowedCore = true
    }
    // Smart-RU split: a connection routed direct because it matched the RU
    // geoip / gov-geosite rule-set. This is EXPECTED (banks/gov/VK/Yandex
    // egress with the real IP by design), NOT a leak.
    if (/router: match\[\d+].*rule_set=(geoip-ru|geosite-category-gov-ru).*=>\s*route\(direct-out\)/i.test(line)) {
      entry.smartRu = true
    }

    const direct = line.match(/outbound\/direct\[direct-out\].*?(?:to|connection to) ([0-9a-fA-F:.]+):\d+/)
    if (direct && !isPrivateIp(direct[1])) {
      entry.directIps.push(direct[1])
    }

    byId.set(id, entry)
  }

  const leaked: string[] = []
  const allowed: string[] = []
  const smartRu: string[] = []
  for (const entry of byId.values()) {
    for (const ip of entry.directIps) {
      if (entry.smartRu) smartRu.push(ip)
      else if (entry.allowedCore) allowed.push(ip)
      else leaked.push(ip)
    }
  }

  return {
    leakedCount: leaked.length,
    allowedCoreCount: allowed.length,
    smartRuCount: smartRu.length,
    leakedExamples: [...new Set(leaked)].slice(0, 5),
    allowedExamples: [...new Set(allowed)].slice(0, 5),
    smartRuExamples: [...new Set(smartRu)].slice(0, 5)
  }
}

async function getDirectPublicSummary(): Promise<{ leakedCount: number; allowedCoreCount: number; smartRuCount: number; leakedExamples: string[]; allowedExamples: string[]; smartRuExamples: string[] }> {
  try {
    const log = await readFile(join(getTunRuntimeDir(), 'sing-box.log'), 'utf-8')
    return classifyDirectPublic(log)
  } catch {
    return { leakedCount: 0, allowedCoreCount: 0, smartRuCount: 0, leakedExamples: [], allowedExamples: [], smartRuExamples: [] }
  }
}

function combineStatus(items: LeakCheckItem[]): CheckStatus {
  if (items.some(i => i.status === 'fail')) return 'fail'
  if (items.some(i => i.status === 'warn')) return 'warn'
  return 'ok'
}

export async function runLeakCheck(options: RunLeakCheckOptions = {}): Promise<LeakCheckResult> {
  const items: LeakCheckItem[] = []
  const foreignTun = detectForeignTun()
  const externalOnly = Boolean(foreignTun && !options.tunRunning)
  const isDirectVpn = options.connectionMode === 'directVpn'

  // In Direct VPN mode sing-box itself is the tunnel core — there is no local
  // SOCKS/HTTP proxy to probe. A leftover proxyOverride (e.g. 127.0.0.1:10808
  // from a previous Happ-proxy session) is meaningless here and must not be
  // probed/flagged red. Report the real architecture instead.
  if (isDirectVpn) {
    items.push({
      id: 'proxy',
      label: 'Прокси',
      status: 'info',
      value: 'Direct VPN (sing-box)',
      details: options.tunRunning
        ? 'Локальный proxy не используется — sing-box сам держит VLESS/Reality-туннель. Это нормально.'
        : 'Режим Direct VPN: локальный proxy не нужен. sing-box поднимает туннель сам.'
    })
  } else if (options.proxyAddr) {
    try {
      const { host, port } = parseProxyAddress(options.proxyAddr)
      const alive = await probeTcp(host, port, 2000)
      items.push({
        id: 'proxy',
        label: 'Прокси',
        status: alive ? 'ok' : 'fail',
        value: `${options.proxyAddr} (${options.proxyType ?? 'socks5'})`,
        details: alive ? 'TCP-порт принимает соединения' : 'Порт не отвечает, TUN через него не стартует'
      })
    } catch (err: any) {
      items.push({
        id: 'proxy',
        label: 'Прокси',
        status: 'fail',
        value: options.proxyAddr,
        details: err.message || String(err)
      })
    }
  } else {
    items.push({
      id: 'proxy',
      label: 'Прокси',
      status: externalOnly ? 'info' : 'warn',
      value: externalOnly ? 'Не нужен: внешний VPN активен' : 'Не указан',
      details: externalOnly
        ? `Найден ${foreignTun}. ${TUN_ADAPTER_ALIAS} намеренно выключен, поэтому upstream proxy сейчас не требуется.`
        : 'Диагностика не может проверить upstream proxy'
    })
  }

  const ipv4 = await getPublicIpV4()
  items.push({
    id: 'ipv4',
    label: 'Public IPv4',
    status: ipv4 ? 'ok' : 'fail',
    value: ipv4 ?? 'Нет ответа',
    details: options.tunRunning
      ? 'Должен совпадать с IP через выбранный proxy'
      : externalOnly
        ? `${TUN_ADAPTER_ALIAS} выключен, интернет идет через внешний VPN/TUN`
        : 'TUN сейчас выключен'
  })

  const ipv6 = await getPublicIpV6()
  items.push({
    id: 'ipv6',
    label: 'Public IPv6',
    status: ipv6 ? 'warn' : 'ok',
    value: ipv6 ?? 'IPv6 не доступен',
    details: ipv6
      ? 'Если это реальный провайдерский IPv6, проверьте Happ и TUN route_address'
      : 'Нет отдельного публичного IPv6 ответа'
  })

  const adapters = await getVpnLikeAdaptersFromWindows()
  items.push({
    id: 'adapters',
    label: 'TUN/VPN адаптеры',
    status: foreignTun ? externalOnly ? 'ok' : 'warn' : 'ok',
    value: adapters.length > 0 ? adapters.join('; ') : 'Не найдены',
    details: foreignTun
      ? externalOnly
        ? `Обнаружен внешний туннель: ${foreignTun}. Это текущий основной маршрут, второй TUN не нужен.`
        : `Обнаружен внешний туннель: ${foreignTun}`
      : 'Конфликтующих TUN не обнаружено'
  })

  const dnsServers = await getDnsServers()
  const dnsProbe = await getDnsProbe()
  items.push({
    id: 'dns',
    label: 'DNS',
    status: 'info',
    value: dnsServers,
    details: dnsProbe
  })

  items.push(await getTunLogItem(Boolean(options.tunRunning)))

  const directPublic = await getDirectPublicSummary()
  const suspiciousCoreDirect = directPublic.allowedCoreCount > 10 || directPublic.allowedExamples.length > 1
  // When smart-RU split is ON, RU-hosted public IPs routed direct are the
  // feature working as intended (banks/gov/VK/Yandex see the real IP) — show
  // them as informational, never a leak.
  const smartRuDirectInfo = options.smartRuSplit === true && directPublic.smartRuCount > 0
  items.push({
    id: 'direct-public',
    label: 'Direct-out приложений',
    status: directPublic.leakedCount > 0 ? 'fail' : suspiciousCoreDirect ? 'warn' : 'ok',
    value: directPublic.leakedCount > 0
      ? `${directPublic.leakedCount} записей`
      : smartRuDirectInfo
        ? `${directPublic.smartRuCount} RU-направлений (smart-RU)`
        : suspiciousCoreDirect
          ? `${directPublic.allowedCoreCount} VPN-core direct-out`
          : 'Утечек не найдено',
    details:
      directPublic.leakedCount > 0
        ? `Публичные IP ушли в direct-out без VPN-core исключения: ${directPublic.leakedExamples.join(', ')}`
        : smartRuDirectInfo
          ? `Это умная маршрутизация РФ: российские сервисы (${directPublic.smartRuExamples.join(', ')}) идут напрямую с реальным IP по правилам geoip-ru/gov-ru. Так и задумано — иностранный трафик при этом через VPN.`
        : suspiciousCoreDirect
          ? `VPN-core процесс делает direct-out к нескольким публичным IP: ${directPublic.allowedExamples.join(', ')}. Это похоже на split/direct правила upstream proxy.`
        : directPublic.allowedCoreCount > 0
          ? `Найден только разрешённый direct-out VPN-core процессов Happ/xray: ${directPublic.allowedExamples.join(', ')}`
          : 'Публичный direct-out по текущему логу не найден'
  })

  return {
    ranAt: Date.now(),
    summary: combineStatus(items),
    items
  }
}
