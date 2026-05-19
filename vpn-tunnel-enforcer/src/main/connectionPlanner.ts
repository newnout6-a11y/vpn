import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { happDetector, type ProxyInfo } from './happDetector'
import { settingsStore } from './settings'
import { parseProxyAddress, probeTcp, tunController } from './tunController'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

const exec = promisify(execCb)
const MAX_BUFFER = 1024 * 1024 * 4

export type RoutingPlanStatus = 'ready' | 'protected' | 'blocked' | 'broken'
export type RecommendedMode = 'off' | 'soft' | 'hard' | 'external'

export interface TunnelInfo {
  name: string
  description: string
  address: string
  isVpnte: boolean
}

export interface ProxyListenerInfo {
  host: string
  port: number
  process: string
  pid: number
}

export interface RoutingPlanStep {
  label: string
  before: string
  after: string
  status: 'ok' | 'warn' | 'fail' | 'info'
}

export interface RoutingPlan {
  ranAt: number
  status: RoutingPlanStatus
  recommendedMode: RecommendedMode
  title: string
  explanation: string
  before: string
  after: string
  canStartHard: boolean
  proxy: ProxyInfo | null
  activeTunnels: TunnelInfo[]
  proxyListeners: ProxyListenerInfo[]
  blockers: string[]
  steps: RoutingPlanStep[]
}

function encodedPowerShell(script: string) {
  const prelude =
    '$ProgressPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

async function ps(script: string, timeout = 10000): Promise<string> {
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
  if (!raw.trim()) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (!value) return []
  return Array.isArray(value) ? value : [value]
}

function proxyFromOverride(): ProxyInfo | null {
  const settings = settingsStore.get()
  const raw = settings.proxyOverride.trim()
  if (!raw) return null
  try {
    const { host, port } = parseProxyAddress(raw)
    return { host, port, type: settings.proxyType, verified: true, publicIpViaProxy: null }
  } catch {
    return null
  }
}

async function getActiveTunnels(): Promise<TunnelInfo[]> {
  if (process.platform !== 'win32') return []

  try {
    const raw = await ps(`
$rx='(?i)wintun|\\btun\\b|wireguard|openvpn|tap-windows|happ|hiddify|singbox|sing-tun|v2ray|xray|vpn';
Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -eq 'Up' -and ($_.Name -match $rx -or $_.InterfaceDescription -match $rx) } |
  ForEach-Object {
    $adapter=$_;
    $ips=Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress } |
      Select-Object -ExpandProperty IPAddress;
    [pscustomobject]@{
      Name=$adapter.Name;
      Description=$adapter.InterfaceDescription;
      Address=($ips -join ', ');
      IsVpnte=($adapter.Name -eq TUN_ADAPTER_ALIAS -or ($ips -join ',') -match '^172\\.19\\.')
    }
  } | ConvertTo-Json -Compress
`)
    return asArray<any>(parseJson(raw)).map(row => ({
      name: String(row.Name || ''),
      description: String(row.Description || ''),
      address: String(row.Address || ''),
      isVpnte: Boolean(row.IsVpnte)
    })).filter(row => row.name)
  } catch (err) {
    logEvent('warn', 'planner', 'failed to read active tunnel adapters', err)
    return []
  }
}

async function getProxyListeners(): Promise<ProxyListenerInfo[]> {
  if (process.platform !== 'win32') return []

  try {
    const raw = await ps(`
$rx='(?i)happ|hiddify|nekoray|nekobox|v2ray|xray|sing-box|singbox|clash|mihomo|shadowsocks|ss-local|trojan|outline|wireguard|openvpn|vpn';
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::') } |
  ForEach-Object {
    $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;
    [pscustomobject]@{Host=$_.LocalAddress;Port=$_.LocalPort;Process=$p.ProcessName;Pid=$_.OwningProcess}
  } |
  Where-Object { ($_.Process -match $rx) -or ($_.Port -in @(1080,10808,10809,7890,7891,8080,2080,2081,1087,1081,20170,20171,9090)) } |
  Sort-Object Process,Port -Unique |
  ConvertTo-Json -Compress
`)
    return asArray<any>(parseJson(raw)).map(row => ({
      host: String(row.Host || '127.0.0.1'),
      port: Number(row.Port),
      process: String(row.Process || 'unknown'),
      pid: Number(row.Pid || 0)
    })).filter(row => Number.isInteger(row.port))
  } catch (err) {
    logEvent('warn', 'planner', 'failed to read proxy listeners', err)
    return []
  }
}

async function detectProxy(): Promise<ProxyInfo | null> {
  const manual = proxyFromOverride()
  if (manual) {
    const alive = await probeTcp(manual.host, manual.port, 1500)
    return { ...manual, verified: alive }
  }
  return happDetector.detect()
}

function tunnelLabel(tunnel: TunnelInfo) {
  const address = tunnel.address ? ` ${tunnel.address}` : ''
  return `${tunnel.name}${address}`.trim()
}

export async function getRoutingPlan(): Promise<RoutingPlan> {
  const [activeTunnels, proxyListeners, proxy] = await Promise.all([
    getActiveTunnels(),
    getProxyListeners(),
    detectProxy()
  ])

  const tunStatus = tunController.getStatus()
  const vpnteTunnels = activeTunnels.filter(tunnel => tunnel.isVpnte)
  const foreignTunnels = activeTunnels.filter(tunnel => !tunnel.isVpnte)
  const blockers: string[] = []
  const steps: RoutingPlanStep[] = []

  const proxyText = proxy ? `${proxy.host}:${proxy.port} (${proxy.type})` : 'локальный proxy не найден'
  const foreignText = foreignTunnels.map(tunnelLabel).join(', ')
  const vpnteText = vpnteTunnels.map(tunnelLabel).join(', ')

  if (tunStatus.running && foreignTunnels.length > 0) {
    blockers.push(`Одновременно активны внешний TUN и ${TUN_ADAPTER_ALIAS}.`)
    steps.push({
      label: 'Убрать двойной туннель',
      before: `Сейчас включены два системных туннеля: ${foreignText} и ${vpnteText || TUN_ADAPTER_ALIAS}.`,
      after: `Приложение остановит ${TUN_ADAPTER_ALIAS}. Останется один существующий VPN/TUN, поэтому DNS перестанет петлять.`,
      status: 'fail'
    })
    return {
      ranAt: Date.now(),
      status: 'broken',
      recommendedMode: 'external',
      title: 'Найден двойной туннель',
      explanation: 'Это как раз тот сценарий, из-за которого интернет “иногда умирает”: DNS и HTTPS могут уходить в циклический маршрут.',
      before: `Было: ${foreignText} + ${TUN_ADAPTER_ALIAS}.`,
      after: `Станет: один активный туннель. ${TUN_ADAPTER_ALIAS} нужно остановить, либо выключить TUN в VPN-клиенте и оставить только proxy.`,
      canStartHard: false,
      proxy,
      activeTunnels,
      proxyListeners,
      blockers,
      steps
    }
  }

  if (foreignTunnels.length > 0) {
    steps.push({
      label: 'Использовать уже поднятый VPN',
      before: `Сейчас система уже идет через ${foreignText}.`,
      after: 'VPNTE не будет создавать второй TUN. Это безопаснее: маршрут останется один, без DNS-петли.',
      status: 'ok'
    })
    if (proxy) {
      steps.push({
        label: 'Подключать приложения через локальный proxy',
        before: `Локальный proxy найден: ${proxyText}.`,
        after: 'Для отдельных приложений можно включить мягкий режим: они будут брать этот proxy без второго TUN.',
        status: proxy.verified ? 'ok' : 'warn'
      })
    }

    return {
      ranAt: Date.now(),
      status: 'protected',
      recommendedMode: 'external',
      title: 'VPN/TUN уже включен',
      explanation: 'Hard mode здесь не нужен и будет вреден. Система уже видит активный туннель, поэтому приложение должно не плодить второй.',
      before: `Было: активный системный туннель ${foreignText}.`,
      after: 'Станет: текущий VPN остается главным маршрутом; VPNTE только показывает статус и помогает настроить приложения при необходимости.',
      canStartHard: false,
      proxy,
      activeTunnels,
      proxyListeners,
      blockers,
      steps
    }
  }

  if (!proxy) {
    blockers.push('Не найден локальный proxy. Нечего превращать в системный туннель.')
    steps.push({
      label: 'Найти proxy',
      before: 'Сейчас нет понятного локального proxy-порта.',
      after: 'Запустите VPN-клиент в режиме Proxy, после этого приложение сможет сделать системный TUN.',
      status: 'fail'
    })

    return {
      ranAt: Date.now(),
      status: 'blocked',
      recommendedMode: 'off',
      title: 'Proxy не найден',
      explanation: 'Hard mode строит системный туннель поверх локального proxy. Без proxy запускать TUN нельзя: трафик уйдет в пустоту.',
      before: 'Было: нет рабочего proxy.',
      after: 'Станет: после включения proxy появится безопасная точка входа для TUN.',
      canStartHard: false,
      proxy: null,
      activeTunnels,
      proxyListeners,
      blockers,
      steps
    }
  }

  if (!proxy.verified) {
    blockers.push(`Proxy ${proxyText} найден, но не отвечает.`)
    steps.push({
      label: 'Проверить proxy',
      before: `Сейчас выбран ${proxyText}, но порт не принимает соединения.`,
      after: 'Когда proxy начнет отвечать, VPNTE сможет направить весь интернет через него.',
      status: 'fail'
    })

    return {
      ranAt: Date.now(),
      status: 'blocked',
      recommendedMode: 'off',
      title: 'Proxy не отвечает',
      explanation: 'Запускать TUN на закрытый proxy нельзя: это сразу ломает интернет.',
      before: `Было: ${proxyText} закрыт или недоступен.`,
      after: 'Станет: после запуска proxy появится безопасный маршрут.',
      canStartHard: false,
      proxy,
      activeTunnels,
      proxyListeners,
      blockers,
      steps
    }
  }

  steps.push({
    label: 'Создать системный TUN',
    before: `Сейчас системного ${TUN_ADAPTER_ALIAS} нет, а proxy ${proxyText} работает.`,
    after: 'VPNTE создаст один системный туннель и направит обычный интернет через этот proxy.',
    status: 'ok'
  })
  steps.push({
    label: 'Оставить локальную сеть напрямую',
    before: 'Локальные адреса и localhost не должны уходить во внешний proxy.',
    after: 'Локальная сеть останется напрямую, внешний интернет пойдет через proxy.',
    status: 'ok'
  })

  return {
    ranAt: Date.now(),
    status: 'ready',
    recommendedMode: 'hard',
    title: 'Можно включать Hard mode',
    explanation: 'Конфликтующих TUN не найдено, proxy живой. Это безопасный сценарий для системного перенаправления.',
    before: `Было: интернет идет обычным маршрутом, proxy доступен на ${proxyText}.`,
    after: `Станет: внешний интернет пойдет через ${TUN_ADAPTER_ALIAS}, а proxy-core будет исключен из туннеля, чтобы не было петли.`,
    canStartHard: true,
    proxy,
    activeTunnels,
    proxyListeners,
    blockers,
    steps
  }
}
