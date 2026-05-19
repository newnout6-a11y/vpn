import { exec as execCb, execFile as execFileCb } from 'child_process'
import { readFile, stat } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { app } from 'electron'
import { isProcessElevated } from './admin'
import { getAppLogPath, getLogDir, logEvent } from './appLogger'
import { getRoutingPlan } from './connectionPlanner'
import { runLeakCheck, type CheckStatus } from './leakDiagnostics'
import { settingsStore } from './settings'
import { redactSensitiveText, redactSettingsForDiagnostics } from './vpnProfiles'
import { runStoreDiagnostics } from './storeDiagnostics'
import { getTunRuntimeDir, parseProxyAddress, probeTcp, tunController } from './tunController'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

const exec = promisify(execCb)
const execFile = promisify(execFileCb)
const MAX_BUFFER = 1024 * 1024 * 6

export interface SystemDiagnosticItem {
  id: string
  category: string
  label: string
  status: CheckStatus
  value: string
  details?: string
}

export interface SystemDiagnosticResult {
  ranAt: number
  summary: CheckStatus
  items: SystemDiagnosticItem[]
}

function encodedPowerShell(script: string) {
  const prelude =
    '$ProgressPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

async function ps(script: string, timeout = 15000): Promise<string> {
  const { stdout, stderr } = await exec(
    `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encodedPowerShell(script)}`,
    {
      windowsHide: true,
      timeout,
      maxBuffer: MAX_BUFFER,
      encoding: 'utf8'
    }
  )
  return (stdout || stderr || '').trim()
}

function parseJson<T = any>(raw: string): T | null {
  const trimmed = raw.trim()
  if (!trimmed) return null
  try {
    return JSON.parse(trimmed) as T
  } catch {
    return null
  }
}

function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

function shortError(err: any): string {
  const stderr = typeof err?.stderr === 'string' ? err.stderr.trim() : ''
  const stdout = typeof err?.stdout === 'string' ? err.stdout.trim() : ''
  const raw = stderr || stdout || err?.message || String(err)
  return cleanPowerShellText(raw)
}

function cleanPowerShellText(raw: string): string {
  return raw
    .replace(/#< CLIXML[\s\S]*/i, 'PowerShell returned no readable result')
    .replace(/_x000D__x000A_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function item(
  id: string,
  category: string,
  label: string,
  status: CheckStatus,
  value: string,
  details?: string
): SystemDiagnosticItem {
  return { id, category, label, status, value, details }
}

function combineStatus(items: SystemDiagnosticItem[]): CheckStatus {
  const criticalCategories = new Set(['App', 'TUN', 'Proxy', 'Network', 'Internet', 'Routing'])
  if (items.some(i => i.status === 'fail' && criticalCategories.has(i.category))) return 'fail'
  if (items.some(i => i.status === 'warn')) return 'warn'
  if (items.some(i => i.status === 'fail')) return 'warn'
  return 'ok'
}

function joinRows(rows: string[], limit = 18): string {
  const visible = rows.slice(0, limit)
  const suffix = rows.length > limit ? ` | ... +${rows.length - limit} more` : ''
  return visible.join(' | ') + suffix
}

async function getLogSummary(
  path: string,
  options: { structuredApp?: boolean; includeErrors?: boolean; freshMs?: number } = {}
): Promise<{ exists: boolean; size: number; lines: number; errors: string[] }> {
  try {
    const info = await stat(path)
    const raw = await readFile(path, 'utf8')
    const lines = raw.split(/\r?\n/).filter(Boolean)
    const includeErrors = options.includeErrors !== false
    let errors: string[] = []
    if (includeErrors && options.structuredApp) {
      const now = Date.now()
      const freshMs = options.freshMs ?? 15 * 60 * 1000
      errors = lines.flatMap(line => {
        try {
          const row = JSON.parse(line)
          const ts = Date.parse(String(row.ts || ''))
          if (!Number.isFinite(ts) || now - ts > freshMs) return []
          if (row.level !== 'warn' && row.level !== 'error') return []
          const details = row.details ? ` ${JSON.stringify(row.details).slice(0, 180)}` : ''
          return [redactSensitiveText(`${row.ts} ${row.level} ${row.scope || 'app'}: ${row.message || ''}${details}`)]
        } catch {
          return []
        }
      }).slice(-8)
    } else if (includeErrors) {
      errors = lines
        .filter(line => /\b(fatal|error|panic|failed|timeout|refused|denied)\b/i.test(line))
        .map(redactSensitiveText)
        .slice(-8)
    }
    return { exists: true, size: info.size, lines: lines.length, errors }
  } catch {
    return { exists: false, size: 0, lines: 0, errors: [] }
  }
}

async function getRuntimeItems(): Promise<SystemDiagnosticItem[]> {
  const settings = settingsStore.get()
  const elevated = process.platform === 'win32' ? await isProcessElevated().catch(() => false) : false
  const tun = tunController.getStatus()

  return [
    item(
      'runtime-app',
      'App',
      'Application runtime',
      'info',
      `${process.platform}/${process.arch} Electron ${process.versions.electron || 'n/a'}`,
      [
        `appVersion=${app.getVersion()}`,
        `packaged=${app.isPackaged}`,
        `elevated=${elevated}`,
        `userData=${app.getPath('userData')}`,
        `logDir=${getLogDir()}`
      ].join(' | ')
    ),
    item(
      'runtime-settings',
      'App',
      'Current settings',
      'info',
      `proxyType=${settings.proxyType}, interval=${settings.checkInterval}ms`,
      JSON.stringify(redactSettingsForDiagnostics(settings))
    ),
    item(
      'runtime-tun-status',
      'TUN',
      'TUN status',
      tun.running ? 'ok' : 'info',
      tun.running ? `running via ${tun.proxyAddr || 'unknown'}` : 'stopped',
      JSON.stringify(tun)
    )
  ]
}

async function getBinaryItems(): Promise<SystemDiagnosticItem[]> {
  const resourceDir = app.isPackaged ? process.resourcesPath : join(app.getAppPath(), 'resources')
  const singBox = join(resourceDir, 'sing-box.exe')
  const wintun = join(resourceDir, 'wintun.dll')
  const rows: string[] = []
  let missing = false

  for (const file of [singBox, wintun]) {
    try {
      const info = await stat(file)
      rows.push(`${file} (${Math.round(info.size / 1024)} KB)`)
    } catch {
      missing = true
      rows.push(`${file} missing`)
    }
  }

  try {
    const { stdout, stderr } = await execFile(singBox, ['version'], {
      windowsHide: true,
      timeout: 5000,
      maxBuffer: MAX_BUFFER,
      encoding: 'utf8'
    })
    rows.push(`sing-box version: ${(stdout || stderr).trim().replace(/\s+/g, ' ')}`)
  } catch (err: any) {
    rows.push(`sing-box version failed: ${shortError(err)}`)
  }

  const config = join(getTunRuntimeDir(), 'sing-box.json')
  const log = join(getTunRuntimeDir(), 'sing-box.log')
  return [
    item('binaries', 'TUN', 'Bundled binaries', missing ? 'fail' : 'ok', missing ? 'missing files' : 'present', joinRows(rows, 8)),
    item('runtime-paths', 'TUN', 'Runtime files', 'info', getTunRuntimeDir(), `config=${config} | log=${log}`)
  ]
}

async function getProxyItems(): Promise<SystemDiagnosticItem[]> {
  const settings = settingsStore.get()
  const tun = tunController.getStatus()
  const proxyAddr = tun.proxyAddr || settings.proxyOverride.trim()
  const rows: string[] = []
  const plan = await getRoutingPlan().catch(() => null)

  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
    if (process.env[key]) rows.push(`env:${key}=${process.env[key]}`)
  }

  if (process.platform === 'win32') {
    try {
      const winhttp = await exec('netsh winhttp show proxy', {
        windowsHide: true,
        timeout: 8000,
        maxBuffer: MAX_BUFFER,
        encoding: 'utf8'
      })
      rows.push(`WinHTTP=${(winhttp.stdout || winhttp.stderr || '').trim().replace(/\s+/g, ' ')}`)
    } catch (err: any) {
      rows.push(`WinHTTP failed=${shortError(err)}`)
    }

    try {
      const raw = await ps(`
$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction Stop;
[pscustomobject]@{
  ProxyEnable=$p.ProxyEnable;
  ProxyServer=$p.ProxyServer;
  AutoConfigURL=$p.AutoConfigURL;
  AutoDetect=$p.AutoDetect
} | ConvertTo-Json -Compress
`)
      rows.push(`WinINet=${raw}`)
    } catch (err: any) {
      rows.push(`WinINet failed=${shortError(err)}`)
    }
  }

  if (!proxyAddr) {
    const hasExternalTunnel = Boolean(plan?.activeTunnels.some(tunnel => !tunnel.isVpnte))
    const listeners = plan?.proxyListeners ?? []
    return [item(
      'proxy-current',
      'Proxy',
      'Current proxy',
      hasExternalTunnel ? 'info' : listeners.length > 0 ? 'warn' : 'warn',
      hasExternalTunnel ? 'not needed: external VPN is active' : listeners.length > 0 ? 'detected but not selected' : 'not configured',
      joinRows([
        ...rows,
        listeners.length > 0 ? `listeners=${listeners.map(listener => `${listener.process}:${listener.host}:${listener.port}`).join(', ')}` : '',
        hasExternalTunnel ? 'Hard TUN is intentionally disabled while external VPN/TUN is active.' : ''
      ].filter(Boolean))
    )]
  }

  try {
    const parsed = parseProxyAddress(proxyAddr)
    const alive = await probeTcp(parsed.host, parsed.port, 2000)
    rows.unshift(`selected=${proxyAddr} alive=${alive}`)
    return [item('proxy-current', 'Proxy', 'Current proxy', alive ? 'ok' : 'fail', `${proxyAddr} ${alive ? 'open' : 'closed'}`, joinRows(rows))]
  } catch (err: any) {
    rows.unshift(`selected=${proxyAddr} invalid=${err.message || String(err)}`)
    return [item('proxy-current', 'Proxy', 'Current proxy', 'fail', proxyAddr, joinRows(rows))]
  }
}

async function getWindowsNetworkItems(): Promise<SystemDiagnosticItem[]> {
  if (process.platform !== 'win32') {
    return [item('windows-network', 'Network', 'Windows network', 'info', process.platform, 'Windows-only diagnostics skipped')]
  }

  const items: SystemDiagnosticItem[] = []

  try {
    const raw = await ps(`
Get-NetAdapter -ErrorAction SilentlyContinue |
  Select-Object Name,InterfaceDescription,Status,LinkSpeed,ifIndex |
  ConvertTo-Json -Compress
`, 12000)
    const rows = asArray<any>(parseJson(raw))
    const up = rows.filter(row => row.Status === 'Up')
    items.push(item(
      'adapters',
      'Network',
      'Network adapters',
      up.length > 0 ? 'ok' : 'fail',
      `${up.length}/${rows.length} up`,
      joinRows(rows.map(row => `${row.Name}:${row.Status}:${row.InterfaceDescription}:${row.LinkSpeed}`))
    ))
  } catch (err: any) {
    items.push(item('adapters', 'Network', 'Network adapters', 'fail', 'failed', shortError(err)))
  }

  try {
    const raw = await ps(`
Get-NetIPConfiguration -ErrorAction SilentlyContinue |
  ForEach-Object {
    [pscustomobject]@{
      InterfaceAlias=$_.InterfaceAlias;
      IPv4=($_.IPv4Address.IPAddress -join ',');
      IPv6=($_.IPv6Address.IPAddress -join ',');
      Gateway=($_.IPv4DefaultGateway.NextHop -join ',');
      DNS=($_.DNSServer.ServerAddresses -join ',')
    }
  } | ConvertTo-Json -Compress
`, 12000)
    const rows = asArray<any>(parseJson(raw)).filter(row => row.IPv4 || row.IPv6 || row.Gateway || row.DNS)
    items.push(item(
      'ip-config',
      'Network',
      'IP configuration',
      rows.length > 0 ? 'ok' : 'warn',
      `${rows.length} configured interfaces`,
      joinRows(rows.map(row => `${row.InterfaceAlias}: IPv4=${row.IPv4 || '-'} Gateway=${row.Gateway || '-'} DNS=${row.DNS || '-'}`), 12)
    ))
  } catch (err: any) {
    items.push(item('ip-config', 'Network', 'IP configuration', 'fail', 'failed', shortError(err)))
  }

  try {
    const raw = await ps(`
$prefixes=@('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1');
Get-NetRoute -ErrorAction SilentlyContinue |
  Where-Object { $prefixes -contains $_.DestinationPrefix } |
  Sort-Object AddressFamily,DestinationPrefix,RouteMetric |
  Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,Protocol |
  ConvertTo-Json -Compress
`, 12000)
    const rows = asArray<any>(parseJson(raw))
    const tunRoutes = rows.filter(row => String(row.InterfaceAlias || '').toLowerCase().includes('vpnte'))
    items.push(item(
      'routes',
      'Network',
      'Default/TUN routes',
      tunRoutes.length > 0 ? 'ok' : 'info',
      `${rows.length} routes, ${tunRoutes.length} VPNTE`,
      joinRows(rows.map(row => `${row.DestinationPrefix} -> ${row.InterfaceAlias} ${row.NextHop || ''} metric=${row.RouteMetric}`), 18)
    ))
  } catch (err: any) {
    items.push(item('routes', 'Network', 'Default/TUN routes', 'fail', 'failed', shortError(err)))
  }

  try {
    const raw = await ps(`
$records=@();
$records += Resolve-DnsName example.com -Type A -ErrorAction Stop;
$records += Resolve-DnsName example.com -Type AAAA -ErrorAction SilentlyContinue;
$records | Where-Object { $_.IPAddress } | Select-Object Type,IPAddress | ConvertTo-Json -Compress
`, 10000)
    const rows = asArray<any>(parseJson(raw))
    items.push(item(
      'dns-resolve',
      'Network',
      'DNS resolve',
      rows.length > 0 ? 'ok' : 'fail',
      rows.length > 0 ? `${rows.length} records` : 'no records',
      joinRows(rows.map(row => `${row.Type}:${row.IPAddress}`))
    ))
  } catch (err: any) {
    items.push(item('dns-resolve', 'Network', 'DNS resolve', 'fail', 'failed', shortError(err)))
  }

  return items
}

async function getProcessAndListenerItems(): Promise<SystemDiagnosticItem[]> {
  if (process.platform !== 'win32') {
    return [item('proxy-processes', 'Proxy', 'Proxy processes', 'info', process.platform, 'Windows-only diagnostics skipped')]
  }

  try {
    const raw = await ps(`
$rx='(?i)happ|hiddify|nekoray|nekobox|v2ray|xray|sing-box|singbox|clash|mihomo|shadowsocks|ss-local|trojan|outline|wireguard|openvpn|vpn';
$listeners=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::') } |
  ForEach-Object {
    $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;
    [pscustomobject]@{Address=$_.LocalAddress;Port=$_.LocalPort;Process=$p.ProcessName;Pid=$_.OwningProcess}
  } |
  Where-Object { ($_.Process -match $rx) -or ($_.Port -in @(1080,10808,10809,7890,7891,8080,2080,2081,1087,1081,20170,20171,9090)) } |
  Sort-Object Process,Port;
$processes=Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.ProcessName -match $rx } |
  Select-Object ProcessName,Id,Path;
[pscustomobject]@{Listeners=$listeners;Processes=$processes} | ConvertTo-Json -Compress -Depth 4
`, 12000)
    const data = parseJson<any>(raw)
    const listeners = asArray<any>(data?.Listeners)
    const processes = asArray<any>(data?.Processes)
    const listenerRows = listeners.map(row => `${row.Process || 'unknown'}:${row.Address}:${row.Port} pid=${row.Pid}`)
    const processRows = processes.map(row => `${row.ProcessName} pid=${row.Id} ${row.Path || ''}`)
    return [
      item('proxy-listeners', 'Proxy', 'Loopback proxy listeners', listeners.length > 0 ? 'ok' : 'warn', `${listeners.length} listeners`, joinRows(listenerRows, 16)),
      item('proxy-processes', 'Proxy', 'VPN/proxy processes', processes.length > 0 ? 'ok' : 'warn', `${processes.length} processes`, joinRows(processRows, 16))
    ]
  } catch (err: any) {
    return [item('proxy-listeners', 'Proxy', 'Loopback proxy listeners', 'fail', 'failed', shortError(err))]
  }
}

async function curlEndpoint(id: string, label: string, url: string): Promise<SystemDiagnosticItem> {
  try {
    const { stdout, stderr } = await execFile(
      'curl.exe',
      ['--noproxy', '*', '-L', '-sS', '-o', 'NUL', '--max-time', '12', '-w', '%{http_code}|%{remote_ip}|%{time_total}|%{errormsg}', url],
      {
        windowsHide: true,
        timeout: 15000,
        maxBuffer: MAX_BUFFER,
        encoding: 'utf8',
        env: {
          ...process.env,
          HTTP_PROXY: '',
          HTTPS_PROXY: '',
          ALL_PROXY: '',
          http_proxy: '',
          https_proxy: '',
          all_proxy: ''
        }
      }
    )
    const [codeRaw, remoteIp, timeRaw, curlError] = stdout.trim().split('|')
    const code = Number(codeRaw)
    const reachable = Boolean(remoteIp) || code > 0
    const status: CheckStatus = reachable ? (code >= 500 ? 'warn' : 'ok') : 'fail'
    return item(
      id,
      'Internet',
      label,
      status,
      reachable ? `HTTP ${code || 'n/a'} ${remoteIp || ''}`.trim() : 'no connection',
      `url=${url} | time=${timeRaw || 'n/a'}s${curlError ? ` | curl=${curlError}` : ''}${stderr ? ` | stderr=${stderr.trim()}` : ''}`
    )
  } catch (err: any) {
    return item(id, 'Internet', label, 'fail', 'no connection', `${url} | ${shortError(err)}`)
  }
}

async function getEndpointItems(): Promise<SystemDiagnosticItem[]> {
  const endpoints = [
    ['endpoint-ipv4', 'Public IPv4 endpoint', 'https://api.ipify.org'] as const,
    ['endpoint-cloudflare', 'Cloudflare', 'https://www.cloudflare.com/cdn-cgi/trace'] as const,
    ['endpoint-google', 'Google generate_204', 'https://www.google.com/generate_204'] as const,
    ['endpoint-msft', 'Microsoft connect test', 'http://www.msftconnecttest.com/connecttest.txt'] as const,
    ['endpoint-store', 'Microsoft Store edge', 'https://storeedgefd.dsx.mp.microsoft.com'] as const
  ]
  return Promise.all(endpoints.map(([id, label, url]) => curlEndpoint(id, label, url)))
}

async function getServiceItems(): Promise<SystemDiagnosticItem[]> {
  if (process.platform !== 'win32') return []
  try {
    const raw = await ps(`
$names=@('Dhcp','Dnscache','WinHttpAutoProxySvc','iphlpsvc','BFE','MpsSvc','Winmgmt','BITS','DoSvc','wuauserv');
$names | ForEach-Object {
  $s=Get-Service -Name $_ -ErrorAction SilentlyContinue;
  if ($s) { [pscustomobject]@{Name=$s.Name;Status=$s.Status.ToString();StartType=$s.StartType.ToString()} }
  else { [pscustomobject]@{Name=$_;Missing=$true} }
} | ConvertTo-Json -Compress
`, 12000)
    const rows = asArray<any>(parseJson(raw))
    const disabled = rows.filter(row => row.StartType === 'Disabled').map(row => row.Name)
    const missing = rows.filter(row => row.Missing).map(row => row.Name)
    return [item(
      'services',
      'Windows',
      'Network-related services',
      disabled.length > 0 ? 'fail' : missing.length > 0 ? 'warn' : 'ok',
      disabled.length > 0 ? `disabled: ${disabled.join(',')}` : `${rows.length - missing.length}/${rows.length} present`,
      joinRows(rows.map(row => row.Missing ? `${row.Name}:missing` : `${row.Name}:${row.Status}/${row.StartType}`), 20)
    )]
  } catch (err: any) {
    return [item('services', 'Windows', 'Network-related services', 'fail', 'failed', shortError(err))]
  }
}

async function getEventLogItem(logName: string, id: string, label: string): Promise<SystemDiagnosticItem> {
  if (process.platform !== 'win32') return item(id, 'Windows', label, 'info', process.platform, 'Windows-only diagnostics skipped')
  try {
    const raw = await ps(`
$events=Get-WinEvent -LogName '${logName.replace(/'/g, "''")}' -MaxEvents 40 -ErrorAction Stop |
  Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning' } |
  Select-Object -First 10 TimeCreated,Id,LevelDisplayName,ProviderName,Message;
$events | ConvertTo-Json -Compress
`, 12000)
    const rows = asArray<any>(parseJson(raw))
    if (rows.length === 0) return item(id, 'Windows', label, 'ok', 'no recent Error/Warning', logName)
    return item(
      id,
      'Windows',
      label,
      'warn',
      `${rows.length} Error/Warning`,
      joinRows(rows.map(row => {
        const message = String(row.Message || '').replace(/\s+/g, ' ').slice(0, 260)
        return `${row.TimeCreated || ''} #${row.Id} ${row.ProviderName || ''} ${row.LevelDisplayName}: ${message}`
      }), 10)
    )
  } catch (err: any) {
    const message = shortError(err)
    if (/NoMatchingEventsFound|Не удалось найти события/i.test(message)) {
      return item(id, 'Windows', label, 'ok', 'no recent Error/Warning', logName)
    }
    return item(id, 'Windows', label, 'info', 'not available', `${logName}: ${message}`)
  }
}

async function getLogItems(): Promise<SystemDiagnosticItem[]> {
  const tun = tunController.getStatus()
  const appLog = await getLogSummary(getAppLogPath(), { structuredApp: true, freshMs: 15 * 60 * 1000 })
  const tunLog = await getLogSummary(join(getTunRuntimeDir(), 'sing-box.log'), { includeErrors: tun.running })
  const prevTunLog = await getLogSummary(join(getTunRuntimeDir(), 'sing-box.prev.log'), { includeErrors: false })

  return [
    item(
      'app-log',
      'Logs',
      'App log',
      appLog.errors.length > 0 ? 'warn' : appLog.exists ? 'ok' : 'info',
      appLog.exists ? `${appLog.lines} lines, ${Math.round(appLog.size / 1024)} KB` : 'not created',
      appLog.errors.length > 0 ? joinRows(appLog.errors, 8) : `No fresh warn/error entries in the last 15 minutes | ${getAppLogPath()}`
    ),
    item(
      'tun-log',
      'Logs',
      'Current sing-box log',
      tun.running && tunLog.errors.length > 0 ? 'warn' : tunLog.exists ? 'info' : 'info',
      tunLog.exists
        ? tun.running
          ? `${tunLog.lines} lines, ${Math.round(tunLog.size / 1024)} KB`
          : `historical, TUN stopped: ${tunLog.lines} lines, ${Math.round(tunLog.size / 1024)} KB`
        : 'not created',
      tun.running && tunLog.errors.length > 0
        ? joinRows(tunLog.errors, 8)
        : `Not used by the current route while ${TUN_ADAPTER_ALIAS} is stopped | ${join(getTunRuntimeDir(), 'sing-box.log')}`
    ),
    item(
      'tun-prev-log',
      'Logs',
      'Previous sing-box log',
      prevTunLog.exists ? 'info' : 'info',
      prevTunLog.exists ? `${prevTunLog.lines} lines, ${Math.round(prevTunLog.size / 1024)} KB` : 'not created',
      `Historical log, not current route health | ${join(getTunRuntimeDir(), 'sing-box.prev.log')}`
    )
  ]
}

async function getRoutingItems(): Promise<SystemDiagnosticItem[]> {
  const settings = settingsStore.get()
  const tun = tunController.getStatus()
  const proxyAddr = settings.proxyOverride.trim() || tun.proxyAddr || undefined
  const checks = await runLeakCheck({
    proxyAddr,
    proxyType: tun.proxyType || settings.proxyType,
    tunRunning: tun.running
  })
  return checks.items.map(row => ({
    id: `routing-${row.id}`,
    category: 'Routing',
    label: row.label,
    status: row.status,
    value: row.value,
    details: row.details
  }))
}

async function getStoreItems(): Promise<SystemDiagnosticItem[]> {
  const store = await runStoreDiagnostics()
  return store.items.map((row: any) => ({
    id: `store-${row.id}`,
    category: 'Store',
    label: row.label,
    status: row.status,
    value: row.value,
    details: row.details
  }))
}

export async function runSystemDiagnostics(): Promise<SystemDiagnosticResult> {
  logEvent('info', 'diagnostics', 'full system diagnostics started')

  const itemGroups = await Promise.all([
    getRuntimeItems(),
    getBinaryItems(),
    getProxyItems(),
    getWindowsNetworkItems(),
    getProcessAndListenerItems(),
    getEndpointItems(),
    getServiceItems(),
    Promise.all([
      getEventLogItem('System', 'event-system', 'System event log'),
      getEventLogItem('Application', 'event-application', 'Application event log'),
      getEventLogItem('Microsoft-Windows-DNS-Client/Operational', 'event-dns-client', 'DNS Client event log')
    ]),
    getLogItems(),
    getRoutingItems(),
    getStoreItems()
  ])

  const items = itemGroups.flat()
  const result = {
    ranAt: Date.now(),
    summary: combineStatus(items),
    items
  }
  logEvent('info', 'diagnostics', 'full system diagnostics finished', {
    summary: result.summary,
    items: result.items.length
  })
  return result
}
