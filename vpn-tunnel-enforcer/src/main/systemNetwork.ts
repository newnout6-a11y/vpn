import { app } from 'electron'
import { mkdir, readFile, writeFile, unlink, rename } from 'fs/promises'
import { join } from 'path'
import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { execElevated } from './admin'
import { logEvent } from './appLogger'

const exec = promisify(execCb)

export interface SystemNetworkResult {
  success: boolean
  message: string
  details?: string
  warnings?: string[]
  skipped?: boolean
}

// Presence of the manifest file is the source of truth that baseline is currently applied.
// Rollback removes the manifest. Used by tunController/main to drive idempotent auto-rollback.
export async function isBaselineApplied(): Promise<boolean> {
  return (await readManifest()) !== null
}

interface NetworkBackupManifest {
  createdAt: number
  internetSettingsBackup: string | null
  environmentBackup: string | null
  hklmConnectionsBackup: string | null
}

const INTERNET_SETTINGS = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
const USER_ENVIRONMENT = 'HKCU\\Environment'
const HKLM_CONNECTIONS = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections'

const PROXY_ENV_KEYS = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'no_proxy'
]

let baselineOpQueue: Promise<void> = Promise.resolve()

async function withBaselineOpLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = baselineOpQueue
  let release!: () => void
  baselineOpQueue = new Promise<void>((resolve) => {
    release = resolve
  })
  await previous.catch(() => undefined)
  try {
    return await operation()
  } finally {
    release()
  }
}

function backupDir() {
  // Store backups in ProgramData (survives app uninstall) instead of userData.
  return join(getProgramDataPath(), 'VPN-Tunnel-Enforcer', 'network-backups')
}

function getProgramDataPath(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (app as any).getPath('programData')
  } catch {
    return process.env.ProgramData || 'C:\\ProgramData'
  }
}

export function getTunNetworkBaselineManifestPath() {
  return join(backupDir(), 'latest-tun-network-baseline.json')
}

function manifestPath() {
  return getTunNetworkBaselineManifestPath()
}

function timestamp() {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
}

function encodedPowerShell(script: string) {
  const prelude =
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

async function ps(script: string, elevated = false, timeout = 30000) {
  const command = `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encodedPowerShell(script)}`
  if (elevated) return execElevated(command, { timeout, maxBuffer: 1024 * 1024 * 4 })
  return exec(command, {
    windowsHide: true,
    timeout,
    maxBuffer: 1024 * 1024 * 4,
    encoding: 'utf8'
  })
}

async function exportKey(key: string, file: string, elevated = false): Promise<string | null> {
  try {
    if (elevated) await execElevated(`reg export "${key}" "${file}" /y`, { timeout: 15000 })
    else await exec(`reg export "${key}" "${file}" /y`, { windowsHide: true, timeout: 15000 })
    return file
  } catch {
    return null
  }
}

function errorText(err: any): string {
  return String(err?.stderr || err?.stdout || err?.message || err || 'unknown error').replace(/\s+/g, ' ').trim()
}

function isOptionalProxyDeleteCommand(cmd: string): boolean {
  return /^reg delete /i.test(cmd) && (
    cmd.includes('"HKCU\\Environment"') ||
    cmd.includes('"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer') ||
    cmd.includes('"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoConfigURL')
  )
}

async function createBackup(): Promise<NetworkBackupManifest> {
  await mkdir(backupDir(), { recursive: true })
  const stamp = timestamp()
  const manifest: NetworkBackupManifest = {
    createdAt: Date.now(),
    internetSettingsBackup: await exportKey(INTERNET_SETTINGS, join(backupDir(), `hkcu-internet-settings-${stamp}.reg`)),
    environmentBackup: await exportKey(USER_ENVIRONMENT, join(backupDir(), `hkcu-environment-${stamp}.reg`)),
    hklmConnectionsBackup: await exportKey(HKLM_CONNECTIONS, join(backupDir(), `hklm-connections-${stamp}.reg`), true)
  }
  const tmpPath = `${manifestPath()}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`
  await writeFile(tmpPath, JSON.stringify(manifest, null, 2), 'utf-8')
  await rename(tmpPath, manifestPath())
  return manifest
}

async function readManifest(): Promise<NetworkBackupManifest | null> {
  try {
    return JSON.parse(await readFile(manifestPath(), 'utf-8')) as NetworkBackupManifest
  } catch {
    return null
  }
}

async function clearManifest(): Promise<void> {
  try {
    await unlink(manifestPath())
  } catch {
    // Already gone — fine.
  }
}

function clearCurrentProcessProxyEnv() {
  for (const key of PROXY_ENV_KEYS) {
    delete process.env[key]
  }
}

async function notifyWinInetSettingsChanged() {
  await ps(`
$sig='[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);'
$type=Add-Type -MemberDefinition $sig -Name WinInet -Namespace Native -PassThru
$null=$type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
$null=$type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
`, false, 10000).catch(() => undefined)
}

export async function applyTunNetworkBaseline(): Promise<SystemNetworkResult> {
  return withBaselineOpLock(applyTunNetworkBaselineUnlocked)
}

async function applyTunNetworkBaselineUnlocked(): Promise<SystemNetworkResult> {
  if (process.platform !== 'win32') {
    return { success: false, message: 'Сетевой baseline доступен только на Windows' }
  }

  try {
    const manifest = await createBackup()
    const warnings: string[] = []

    // Validate that at least the primary backup (HKCU Internet Settings)
    // succeeded before wiping. If the backup failed, abort — wiping
    // without a backup would permanently destroy the user's proxy settings.
    if (!manifest.internetSettingsBackup) {
      await clearManifest()
      return {
        success: false,
        message: 'Не удалось создать backup настроек. Отмена — настройки не были изменены.',
        details: 'reg export для HKCU\\Internet Settings завершился ошибкой. Проверьте права доступа.'
      }
    }

    // 1. Reset WinHTTP proxy (requires elevation)
    await execElevated('netsh winhttp reset proxy', { timeout: 10000 }).catch((err) => {
      const warning = `netsh winhttp reset proxy failed: ${errorText(err)}`
      warnings.push(warning)
      logEvent('warn', 'system-network', warning)
    })

    // 2. Clear WinINet proxy & environment vars in HKCU (fast native reg commands, no broadcasting deadlock)
    const commands = [
      'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
      'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /f',
      'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoConfigURL /f',
      'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f'
    ]
    for (const key of PROXY_ENV_KEYS) {
      commands.push(`reg delete "HKCU\\Environment" /v ${key} /f`)
    }

    await Promise.all(commands.map(async (cmd) => {
      try {
        await exec(cmd, { windowsHide: true, timeout: 5000 })
      } catch (err: any) {
        const text = errorText(err)
        if (isOptionalProxyDeleteCommand(cmd)) {
          logEvent('debug', 'system-network', 'optional proxy registry value already absent', { command: cmd, error: text })
          return
        }
        const missingValue = /reg delete/i.test(cmd) && /unable to find|cannot find|system was unable to find|не удается найти/i.test(text)
        if (missingValue) return
        const warning = `${cmd.split(' /v ')[0]} failed: ${text}`
        warnings.push(warning)
        logEvent('warn', 'system-network', 'baseline command failed', { command: cmd, error: text })
      }
    }))

    clearCurrentProcessProxyEnv()
    await notifyWinInetSettingsChanged()
    return {
      success: true,
      message: 'Сеть нормализована для TUN',
      details:
        'WinHTTP proxy сброшен, WinINet/User proxy и PAC отключены, env proxy удалены. ' +
        `Backup: ${manifestPath()}` +
        (warnings.length > 0 ? `; warnings: ${warnings.join(' | ')}` : ''),
      warnings
    }
  } catch (err: any) {
    return {
      success: false,
      message: err.message || String(err),
      details: err.stderr || err.stdout
    }
  }
}

export async function rollbackTunNetworkBaseline(): Promise<SystemNetworkResult> {
  return withBaselineOpLock(rollbackTunNetworkBaselineUnlocked)
}

async function rollbackTunNetworkBaselineUnlocked(): Promise<SystemNetworkResult> {
  if (process.platform !== 'win32') {
    return { success: false, message: 'Rollback доступен только на Windows' }
  }

  const manifest = await readManifest()
  if (!manifest) {
    return {
      success: true,
      skipped: true,
      message: 'Активный VPNTE network baseline не найден',
      details: 'Откат не требуется: VPNTE не нашёл backup/manifest изменений.'
    }
  }

  try {
    if (manifest.internetSettingsBackup) {
      await exec(`reg import "${manifest.internetSettingsBackup}"`, { windowsHide: true, timeout: 15000 })
    }
    if (manifest.environmentBackup) {
      await exec(`reg import "${manifest.environmentBackup}"`, { windowsHide: true, timeout: 15000 })
    }
    if (manifest.hklmConnectionsBackup) {
      await execElevated(`reg import "${manifest.hklmConnectionsBackup}"`, { timeout: 15000 })
    }
    await notifyWinInetSettingsChanged()
    await clearManifest()
    return {
      success: true,
      message: 'Сетевые настройки восстановлены из backup',
      details: `Backup created at: ${new Date(manifest.createdAt).toLocaleString()}`
    }
  } catch (err: any) {
    return {
      success: false,
      message: err.message || String(err),
      details: err.stderr || err.stdout
    }
  }
}

// Best-effort auto-rollback used on TUN stop, app exit, and crash recovery.
// Safe to call when baseline is not applied (returns success with skipped=true).
export async function rollbackTunNetworkBaselineIfApplied(
  reason: string
): Promise<SystemNetworkResult & { skipped?: boolean }> {
  if (process.platform !== 'win32') {
    return { success: true, skipped: true, message: 'Rollback недоступен (не Windows)' }
  }
  return withBaselineOpLock(async () => {
    if (!(await isBaselineApplied())) {
      return { success: true, skipped: true, message: 'Baseline не был применён - откатывать нечего' }
    }
    logEvent('info', 'system-network', `auto-rollback baseline: ${reason}`)
    const result = await rollbackTunNetworkBaselineUnlocked()
    if (!result.success) {
      logEvent('warn', 'system-network', 'auto-rollback failed', result)
    }
    return result
  })
}
