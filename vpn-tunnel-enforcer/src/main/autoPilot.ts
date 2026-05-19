import axios from 'axios'
import { SocksClient } from 'socks'
import { getRoutingPlan, type RoutingPlan, type ProxyListenerInfo } from './connectionPlanner'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'
import { applyTunNetworkBaseline, rollbackTunNetworkBaselineIfApplied } from './systemNetwork'
import { probeTcp, tunController } from './tunController'

export interface AutoPilotStep {
  label: string
  before: string
  after: string
  status: 'ok' | 'warn' | 'fail' | 'info'
}

export interface AutoPilotResult {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail'
  mode: 'off' | 'external' | 'hard' | 'soft'
  title: string
  message: string
  changed: boolean
  steps: AutoPilotStep[]
  plan: RoutingPlan
}

interface VerifiedProxy {
  host: string
  port: number
  type: 'socks5' | 'http'
}

function listenerHost(listener: ProxyListenerInfo): string {
  if (listener.host === '::' || listener.host === '::1' || listener.host === '0.0.0.0') return '127.0.0.1'
  return listener.host || '127.0.0.1'
}

async function probeSocks5(host: string, port: number): Promise<boolean> {
  try {
    const { socket } = await SocksClient.createConnection({
      proxy: { host, port, type: 5 },
      command: 'connect',
      destination: { host: 'api.ipify.org', port: 443 },
      timeout: 5000
    })
    socket.destroy()
    return true
  } catch {
    return false
  }
}

async function probeHttp(host: string, port: number): Promise<boolean> {
  try {
    await axios.get('https://api.ipify.org?format=json', {
      proxy: { host, port, protocol: 'http' },
      timeout: 5000
    })
    return true
  } catch {
    return false
  }
}

async function verifyListener(listener: ProxyListenerInfo): Promise<VerifiedProxy | null> {
  const host = listenerHost(listener)
  const port = listener.port
  if (!await probeTcp(host, port, 1200)) return null

  const processName = listener.process.toLowerCase()
  const preferSocks = /xray|v2ray|sing|happ|hiddify|nekoray|shadowsocks|trojan/i.test(processName)
  const order: Array<'socks5' | 'http'> = preferSocks ? ['socks5', 'http'] : ['http', 'socks5']

  for (const type of order) {
    if (type === 'socks5' && await probeSocks5(host, port)) return { host, port, type }
    if (type === 'http' && await probeHttp(host, port)) return { host, port, type }
  }
  return null
}

async function pickWorkingProxy(plan: RoutingPlan): Promise<VerifiedProxy | null> {
  if (plan.proxy?.verified) {
    return { host: plan.proxy.host, port: plan.proxy.port, type: plan.proxy.type }
  }

  const preferred = [...plan.proxyListeners].sort((a, b) => {
    const score = (listener: ProxyListenerInfo) => {
      let value = 0
      if ([10808, 2080, 7890, 1080, 10809, 7891].includes(listener.port)) value += 10
      if (/xray|v2ray|sing|happ|hiddify|mihomo|clash/i.test(listener.process)) value += 5
      return -value
    }
    return score(a) - score(b)
  })

  for (const listener of preferred) {
    const verified = await verifyListener(listener)
    if (verified) return verified
  }
  return null
}

function hasVpnteTunnel(plan: RoutingPlan): boolean {
  return plan.activeTunnels.some(tunnel => tunnel.isVpnte)
}

function hasForeignTunnel(plan: RoutingPlan): boolean {
  return plan.activeTunnels.some(tunnel => !tunnel.isVpnte)
}

export async function runAutoPilot(): Promise<AutoPilotResult> {
  const steps: AutoPilotStep[] = []
  let changed = false
  let plan = await getRoutingPlan()

  logEvent('info', 'autopilot', 'started', { status: plan.status, title: plan.title })

  if (hasVpnteTunnel(plan) || tunController.getStatus().running) {
    steps.push({
      label: 'Убрать лишний туннель VPNTE',
      before: 'Найден активный VPNTE-TUN или процесс VPNTE sing-box.',
      after: 'Останавливаю только туннель VPNTE. Внешний VPN-клиент не трогаю.',
      status: 'info'
    })
    const stopped = await tunController.stop()
    changed = true
    steps[steps.length - 1].status = stopped.success ? 'ok' : 'fail'
    if (!stopped.success) {
      return {
        ranAt: Date.now(),
        summary: 'fail',
        mode: 'off',
        title: 'Не удалось остановить VPNTE-TUN',
        message: stopped.error || 'Остановка завершилась с ошибкой.',
        changed,
        steps,
        plan
      }
    }
    plan = await getRoutingPlan()
  }

  if (hasForeignTunnel(plan)) {
    steps.push({
      label: 'Оставить один системный VPN',
      before: 'Система уже имеет внешний TUN/VPN.',
      after: 'Второй TUN не создается. Приложение переходит в режим наблюдения и не ломает DNS.',
      status: 'ok'
    })
    return {
      ranAt: Date.now(),
      summary: 'ok',
      mode: 'external',
      title: 'Автопилот оставил внешний VPN',
      message: 'Интернет уже идет через существующий системный туннель. VPNTE-TUN не нужен и не будет запущен.',
      changed,
      steps,
      plan
    }
  }

  let proxy = await pickWorkingProxy(plan)
  if (proxy) {
    settingsStore.save({ proxyOverride: `${proxy.host}:${proxy.port}`, proxyType: proxy.type })
    changed = true
    steps.push({
      label: 'Запомнить рабочий proxy',
      before: plan.proxy ? `Был выбран ${plan.proxy.host}:${plan.proxy.port}.` : 'Proxy не был выбран в настройках.',
      after: `Будет использоваться ${proxy.host}:${proxy.port} (${proxy.type}).`,
      status: 'ok'
    })
    plan = await getRoutingPlan()
  } else {
    steps.push({
      label: 'Найти рабочий proxy',
      before: 'Есть listeners или настройки, но ни один proxy не прошел проверку.',
      after: 'Ничего не меняю: запуск TUN без proxy сломал бы интернет.',
      status: 'fail'
    })
    return {
      ranAt: Date.now(),
      summary: 'fail',
      mode: 'off',
      title: 'Автопилот не нашел рабочий proxy',
      message: 'Включите в VPN-клиенте режим Proxy или задайте адрес вручную. Пока безопаснее ничего не перенаправлять.',
      changed,
      steps,
      plan
    }
  }

  if (settingsStore.get().autoNetworkBaseline) {
    const baseline = await applyTunNetworkBaseline()
    changed = true
    steps.push({
      label: 'Очистить старые системные proxy',
      before: 'WinHTTP/WinINet/env proxy могли указывать на старые или мертвые адреса.',
      after: baseline.success
        ? 'Старые системные proxy сброшены, backup сохранен.'
        : `Не удалось полностью сбросить системные proxy: ${baseline.message}`,
      status: baseline.success ? 'ok' : 'warn'
    })
  }

  const start = await tunController.start({
    proxyAddr: `${proxy.host}:${proxy.port}`,
    proxyType: proxy.type,
    enableFirewallKillSwitch: settingsStore.get().firewallKillSwitch,
    enableAdapterLockdown: settingsStore.get().strictAdapterLockdown,
    stealthMode: settingsStore.get().stealthMode
  })
  changed = true
  if (!start.success) {
    // We may have applied the network baseline above; if TUN didn't come up, undo it so
    // the user is not left with both no-VPN and no-original-proxy-config.
    await rollbackTunNetworkBaselineIfApplied('autopilot start failed').catch(err =>
      logEvent('warn', 'autopilot', 'baseline rollback after start failure failed', err)
    )
  }
  steps.push({
    label: 'Включить один системный TUN',
    before: 'Внешнего TUN нет, proxy работает.',
    after: start.success
      ? 'VPNTE-TUN включен, внешний интернет идет через выбранный proxy.'
      : `VPNTE-TUN не включен: ${start.error}`,
    status: start.success ? 'ok' : 'fail'
  })

  const finalPlan = await getRoutingPlan()
  return {
    ranAt: Date.now(),
    summary: start.success ? 'ok' : 'fail',
    mode: start.success ? 'hard' : 'off',
    title: start.success ? 'Автопилот включил Hard TUN' : 'Автопилот не смог включить Hard TUN',
    message: start.success
      ? 'Безопасный сценарий применен автоматически: один TUN, один proxy, без двойного туннеля.'
      : start.error || 'Запуск TUN завершился ошибкой.',
    changed,
    steps,
    plan: finalPlan
  }
}
