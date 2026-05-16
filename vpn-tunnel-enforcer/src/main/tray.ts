import { Tray, Menu, nativeImage, BrowserWindow, app, type MenuItemConstructorOptions, type NativeImage } from 'electron'
import { existsSync } from 'fs'
import { join } from 'path'

export type TrayStatus = 'protected' | 'leak' | 'off' | 'starting' | 'proxy-down' | 'killswitch' | 'restarting'

export interface TrayState {
  status: TrayStatus
  publicIp: string | null
  proxyAddr: string | null
  downloadBps: number
  uploadBps: number
  tunRunning: boolean
  firewallKillSwitchActive: boolean
  restartingProgress: string | null
}

export interface TrayActions {
  onStart?: () => unknown | Promise<unknown>
  onStop?: () => unknown | Promise<unknown>
  onRunDiagnostics?: () => unknown | Promise<unknown>
  onOpenLogs?: () => unknown | Promise<unknown>
  onQuit?: () => unknown | Promise<unknown>
}

const defaultState: TrayState = {
  status: 'off',
  publicIp: null,
  proxyAddr: null,
  downloadBps: 0,
  uploadBps: 0,
  tunRunning: false,
  firewallKillSwitchActive: false,
  restartingProgress: null
}

let trayState: TrayState = { ...defaultState }
let trayActions: TrayActions = {}
let trayWindow: BrowserWindow | null = null

function createFallbackTrayIcon(status: TrayStatus): NativeImage {
  const color =
    status === 'protected' ? '#22c55e' :
      status === 'leak' || status === 'killswitch' ? '#ef4444' :
        status === 'starting' || status === 'proxy-down' || status === 'restarting' ? '#f59e0b' :
          '#888888'
  const size = 16
  const canvas = `data:image/svg+xml,${encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `)}`
  return nativeImage.createFromDataURL(canvas)
}

function resourceCandidates(): string[] {
  if (app.isPackaged) {
    return [
      join(process.resourcesPath, 'icon.ico'),
      join(process.resourcesPath, 'icon.png')
    ]
  }
  return [
    join(app.getAppPath(), 'resources', 'icon.ico'),
    join(app.getAppPath(), 'resources', 'icon.png'),
    join(__dirname, '../../resources/icon.ico'),
    join(__dirname, '../../resources/icon.png')
  ]
}

function createTrayIcon(status: TrayStatus): NativeImage {
  for (const candidate of resourceCandidates()) {
    if (!existsSync(candidate)) continue
    const image = nativeImage.createFromPath(candidate)
    if (!image.isEmpty()) return image.resize({ width: 16, height: 16 })
  }
  return createFallbackTrayIcon(status)
}

function statusLabel(status: TrayStatus): string {
  if (status === 'protected') return 'Защищено'
  if (status === 'leak') return 'УТЕЧКА IP'
  if (status === 'starting') return 'Запуск защиты'
  if (status === 'proxy-down') return 'VPN-сервер недоступен'
  if (status === 'killswitch') return 'Файрвол блокирует'
  if (status === 'restarting') return `Перезапуск ${trayState.restartingProgress ?? ''}`.trim()
  return 'Выключено'
}

function formatSpeed(bytesPerSecond: number): string {
  const bits = Math.max(0, bytesPerSecond * 8)
  if (bits < 1_000_000) return `${Math.round(bits / 1_000)} Kbps`
  return `${(bits / 1_000_000).toFixed(bits < 10_000_000 ? 1 : 0)} Mbps`
}

function showWindow() {
  if (!trayWindow || trayWindow.isDestroyed()) return
  trayWindow.show()
  trayWindow.focus()
}

function runAction(action?: () => unknown | Promise<unknown>) {
  if (!action) return
  Promise.resolve(action()).catch(() => undefined)
}

function buildTooltip(): string {
  const lines = [`VPN Tunnel Enforcer — ${statusLabel(trayState.status)}`]
  if (trayState.publicIp) lines.push(`IP: ${trayState.publicIp}`)
  if (trayState.proxyAddr) lines.push(`Proxy: ${trayState.proxyAddr}`)
  if (trayState.tunRunning) {
    lines.push(`↓ ${formatSpeed(trayState.downloadBps)} / ↑ ${formatSpeed(trayState.uploadBps)}`)
  }
  return lines.join('\n')
}

function buildMenu(): Menu {
  const isActive = trayState.tunRunning || trayState.status === 'proxy-down' || trayState.status === 'protected' || trayState.status === 'leak'
  const canStart = !isActive && trayState.status !== 'starting' && trayState.status !== 'restarting'
  const canStop = isActive || trayState.status === 'killswitch' || trayState.status === 'restarting'
  const template: MenuItemConstructorOptions[] = [
    { label: `Статус: ${statusLabel(trayState.status)}`, enabled: false },
    { label: trayState.publicIp ? `IP: ${trayState.publicIp}` : 'IP: неизвестен', enabled: false },
    { label: trayState.proxyAddr ? `Proxy: ${trayState.proxyAddr}` : 'Proxy: не выбран', enabled: false },
    {
      label: `Скорость: ↓ ${formatSpeed(trayState.downloadBps)} / ↑ ${formatSpeed(trayState.uploadBps)}`,
      enabled: false
    },
    { type: 'separator' },
    { label: 'Показать окно', click: showWindow },
    {
      label: 'Включить защиту',
      enabled: canStart,
      click: () => runAction(trayActions.onStart)
    },
    {
      label: 'Выключить защиту',
      enabled: canStop,
      click: () => runAction(trayActions.onStop)
    },
    {
      label: 'Проверить маршрут',
      click: () => runAction(trayActions.onRunDiagnostics)
    },
    {
      label: 'Открыть логи',
      click: () => runAction(trayActions.onOpenLogs)
    },
    { type: 'separator' },
    {
      label: 'Выход',
      click: () => runAction(trayActions.onQuit)
    }
  ]
  return Menu.buildFromTemplate(template)
}

export function createTray(mainWindow: BrowserWindow, actions: TrayActions = {}): Tray {
  trayWindow = mainWindow
  trayActions = actions
  const tray = new Tray(createTrayIcon('off'))

  tray.setToolTip(buildTooltip())
  tray.setContextMenu(buildMenu())

  tray.on('double-click', () => {
    showWindow()
  })

  return tray
}

export function updateTrayIcon(tray: Tray, status: 'protected' | 'leak' | 'off') {
  updateTrayState(tray, { status })
}

export function updateTrayState(tray: Tray, patch: Partial<TrayState>) {
  trayState = { ...trayState, ...patch }
  tray.setImage(createTrayIcon(trayState.status))
  tray.setToolTip(buildTooltip())
  tray.setContextMenu(buildMenu())
}
