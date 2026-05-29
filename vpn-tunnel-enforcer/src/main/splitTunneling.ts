/**
 * Split Tunneling Service — per-app routing via sing-box route rules.
 *
 * Responsibilities:
 * - Discover installed Windows applications (registry + common directories)
 * - Manage per-app routing rules (vpn / direct / none)
 * - Generate sing-box route rules for split tunnel configuration
 * - Hot-reload rules when TUN is active (restart sing-box with updated config)
 * - Register IPC handlers for all SplitTunnelChannels
 */

import { exec as execCb } from 'child_process'
import { ipcMain, dialog, type IpcMainInvokeEvent } from 'electron'
import { basename, extname } from 'path'
import { access } from 'fs/promises'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { tunController } from './tunController'
import type { SplitTunnelApp, SplitTunnelConfig } from '../shared/ipc-types'

const exec = promisify(execCb)

// ─── Persistent Store ────────────────────────────────────────────────────────

interface SplitTunnelStore {
  splitTunnelApps: SplitTunnelApp[]
  splitTunnelEnabled: boolean
}

const store = new Store<SplitTunnelStore>({
  name: 'split-tunnel',
  defaults: {
    splitTunnelApps: [],
    splitTunnelEnabled: true
  }
})

// ─── App Discovery ───────────────────────────────────────────────────────────

/**
 * Discovers installed Windows applications by scanning the registry Uninstall keys.
 * Returns apps with name, exe path, and icon (null for now — icon extraction is complex).
 */
export async function discoverInstalledApps(): Promise<
  Array<{ name: string; path: string; icon: string | null }>
> {
  if (process.platform !== 'win32') return []

  const registryPaths = [
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
  ]

  const apps: Array<{ name: string; path: string; icon: string | null }> = []
  const seenPaths = new Set<string>()

  for (const regPath of registryPaths) {
    try {
      const result = await queryRegistryApps(regPath)
      for (const app of result) {
        const normalizedPath = app.path.toLowerCase()
        if (!seenPaths.has(normalizedPath)) {
          seenPaths.add(normalizedPath)
          apps.push(app)
        }
      }
    } catch (err) {
      logEvent('debug', 'split-tunnel', `registry scan failed for ${regPath}`, err)
    }
  }

  return apps
}

/**
 * Queries a registry Uninstall key for installed applications.
 * Uses PowerShell to enumerate subkeys and extract DisplayName + InstallLocation/DisplayIcon.
 */
async function queryRegistryApps(
  registryPath: string
): Promise<Array<{ name: string; path: string; icon: string | null }>> {
  // PowerShell script to enumerate registry entries and extract app info
  const psScript = `
$ErrorActionPreference='SilentlyContinue'
$results=@()
$root='${registryPath.replace(/'/g, "''")}'
$hive=$root.Split('\\\\')[0]
$subPath=$root.Substring($hive.Length+1)
if($hive -eq 'HKLM'){$regHive='HKLM:'}else{$regHive='HKCU:'}
$basePath="$regHive\\$subPath"
Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
  $props=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
  if($props.DisplayName -and ($props.InstallLocation -or $props.DisplayIcon)){
    $exe=''
    if($props.InstallLocation){
      $loc=$props.InstallLocation.TrimEnd('\\')
      $exes=Get-ChildItem "$loc\\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
      if($exes){$exe=$exes.FullName}
    }
    if(-not $exe -and $props.DisplayIcon){
      $icon=$props.DisplayIcon -replace ',.*$',''
      $icon=$icon.Trim('"')
      if($icon -match '\\.exe$'){$exe=$icon}
    }
    if($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)){
      $results+=[pscustomobject]@{Name=$props.DisplayName;Path=$exe}
    }
  }
}
$results | ConvertTo-Json -Compress
`

  const { stdout } = await exec(
    `powershell -NoProfile -ExecutionPolicy Bypass -Command "${psScript.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`,
    { windowsHide: true, timeout: 15000, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  )

  const trimmed = stdout.trim()
  if (!trimmed || trimmed === 'null') return []

  try {
    const parsed = JSON.parse(trimmed)
    const rows = Array.isArray(parsed) ? parsed : [parsed]
    return rows
      .filter(
        (row: any) =>
          row &&
          typeof row.Name === 'string' &&
          row.Name.trim() &&
          typeof row.Path === 'string' &&
          row.Path.trim()
      )
      .map((row: any) => ({
        name: row.Name.trim(),
        path: row.Path.trim(),
        icon: null // Icon extraction deferred — complex Win32 API needed
      }))
  } catch {
    return []
  }
}

// ─── Rule Management ─────────────────────────────────────────────────────────

function getApps(): SplitTunnelApp[] {
  return store.get('splitTunnelApps') ?? []
}

function saveApps(apps: SplitTunnelApp[]): void {
  store.set('splitTunnelApps', apps)
}

function isEnabled(): boolean {
  return store.get('splitTunnelEnabled') ?? true
}

function getConfig(): SplitTunnelConfig {
  return {
    apps: getApps(),
    enabled: isEnabled()
  }
}

function setRule(appId: string, rule: 'vpn' | 'direct' | 'none'): void {
  const apps = getApps()
  const index = apps.findIndex((a) => a.id === appId)
  if (index === -1) {
    logEvent('warn', 'split-tunnel', `setRule: app not found`, { appId, rule })
    return
  }
  apps[index] = { ...apps[index], rule }
  saveApps(apps)
  logEvent('info', 'split-tunnel', `rule set`, { appId, name: apps[index].name, rule })
}

async function addApp(exePath: string): Promise<SplitTunnelApp> {
  // Validate the path exists
  await access(exePath)

  const name = basename(exePath, extname(exePath))
  const app: SplitTunnelApp = {
    id: randomUUID(),
    name,
    path: exePath,
    icon: null,
    rule: 'none'
  }

  const apps = getApps()
  // Check for duplicate path
  const existing = apps.find((a) => a.path.toLowerCase() === exePath.toLowerCase())
  if (existing) {
    return existing
  }

  apps.push(app)
  saveApps(apps)
  logEvent('info', 'split-tunnel', `app added`, { id: app.id, name: app.name, path: app.path })
  return app
}

function removeApp(appId: string): void {
  const apps = getApps()
  const filtered = apps.filter((a) => a.id !== appId)
  if (filtered.length === apps.length) {
    logEvent('warn', 'split-tunnel', `removeApp: app not found`, { appId })
    return
  }
  saveApps(filtered)
  logEvent('info', 'split-tunnel', `app removed`, { appId })
}

// ─── Sing-box Route Rule Generation ─────────────────────────────────────────

/**
 * Generates sing-box route rules for split tunnel configuration.
 *
 * - Apps with 'direct' rule → route through 'direct-out' (bypass VPN)
 * - Apps with 'vpn' rule → route through 'proxy-out' (force through VPN)
 * - Apps with 'none' → no special rule (follow default routing, which is proxy-out)
 *
 * Returns an array of sing-box route rule objects to be inserted into the config.
 */
export function generateSplitTunnelRouteRules(): Array<Record<string, any>> {
  if (!isEnabled()) return []

  const apps = getApps()
  const rules: Array<Record<string, any>> = []

  // Collect process names for direct routing
  const directProcessNames = apps
    .filter((a) => a.rule === 'direct')
    .map((a) => basename(a.path))

  // Collect process names for explicit VPN routing
  const vpnProcessNames = apps
    .filter((a) => a.rule === 'vpn')
    .map((a) => basename(a.path))

  if (directProcessNames.length > 0) {
    rules.push({
      process_name: directProcessNames,
      outbound: 'direct-out'
    })
  }

  if (vpnProcessNames.length > 0) {
    rules.push({
      process_name: vpnProcessNames,
      outbound: 'proxy-out'
    })
  }

  return rules
}

/**
 * Returns the list of process names that should bypass the VPN (direct routing).
 * Used by tunController when generating the sing-box config.
 */
export function getDirectProcessNames(): string[] {
  if (!isEnabled()) return []
  const apps = getApps()
  return apps.filter((a) => a.rule === 'direct').map((a) => basename(a.path))
}

/**
 * Returns the list of process names that should be explicitly routed through VPN.
 * Note: In the default sing-box config, all traffic goes through proxy-out anyway,
 * so this is mainly for documentation/explicitness. The 'vpn' rule ensures these
 * apps are routed through VPN even if the default final route changes.
 */
export function getVpnProcessNames(): string[] {
  if (!isEnabled()) return []
  const apps = getApps()
  return apps.filter((a) => a.rule === 'vpn').map((a) => basename(a.path))
}

// ─── Hot-Reload ──────────────────────────────────────────────────────────────

/**
 * When rules change while TUN is active, we need to regenerate the sing-box config
 * and restart sing-box with the new configuration.
 *
 * Sing-box does not support live config reload, so we stop and restart.
 * This is done transparently — the user sees a brief reconnection.
 */
async function hotReloadIfActive(): Promise<void> {
  const status = tunController.getStatus()
  if (!status.running) {
    logEvent('debug', 'split-tunnel', 'hot-reload skipped — TUN not running')
    return
  }

  logEvent('info', 'split-tunnel', 'hot-reloading split tunnel rules while TUN is active')

  try {
    // Restart the tunnel reusing the last start options. The new split-tunnel
    // rules are picked up via getDirectProcessNames() during config
    // regeneration on the restart. Previously this only called stop() and
    // logged "renderer should re-trigger start" — but nothing did, so changing
    // a split-tunnel rule (or removing an app) while connected silently killed
    // the VPN and left it down. restartWithLastOptions stops AND starts again.
    const result = await tunController.restartWithLastOptions('split-tunnel rule change')
    if (!result.success) {
      logEvent('warn', 'split-tunnel', 'hot-reload restart failed — tunnel may be down', {
        error: result.error
      })
    }
  } catch (err) {
    logEvent('error', 'split-tunnel', 'hot-reload failed', err)
  }
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

/**
 * Registers all split tunnel IPC handlers.
 * Should be called once during app initialization.
 */
export function registerSplitTunnelHandlers(): void {
  handleLogged('split-tunnel:get-apps', async () => {
    const storedApps = getApps()

    // If no apps stored yet, discover and populate
    if (storedApps.length === 0) {
      try {
        const discovered = await discoverInstalledApps()
        const apps: SplitTunnelApp[] = discovered.map((d) => ({
          id: randomUUID(),
          name: d.name,
          path: d.path,
          icon: d.icon,
          rule: 'none' as const
        }))
        saveApps(apps)
        return apps
      } catch (err) {
        logEvent('error', 'split-tunnel', 'app discovery failed', err)
        return []
      }
    }

    return storedApps
  })

  handleLogged('split-tunnel:set-rule', async (_event, appId: string, rule: 'vpn' | 'direct' | 'none') => {
    setRule(appId, rule)
    // Hot-reload if TUN is active
    await hotReloadIfActive()
  })

  handleLogged('split-tunnel:add-app', async (_event, exePath: string) => {
    let targetPath = exePath
    // If no path provided, open a file dialog for the user to select an exe
    if (!targetPath) {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        title: 'Select executable',
        filters: [{ name: 'Executables', extensions: ['exe'] }],
        properties: ['openFile']
      })
      if (canceled || filePaths.length === 0) return null
      targetPath = filePaths[0]
    }
    const app = await addApp(targetPath)
    return app
  })

  handleLogged('split-tunnel:remove-app', async (_event, appId: string) => {
    removeApp(appId)
    // Hot-reload if TUN is active (in case removed app had a rule)
    await hotReloadIfActive()
  })

  handleLogged('split-tunnel:get-config', async () => {
    return getConfig()
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const splitTunneling = {
  getApps,
  getConfig,
  setRule,
  addApp,
  removeApp,
  getDirectProcessNames,
  getVpnProcessNames,
  generateSplitTunnelRouteRules,
  discoverInstalledApps,
  registerHandlers: registerSplitTunnelHandlers
}
