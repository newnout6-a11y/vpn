import { shell } from 'electron'
import { exec as execCb } from 'child_process'
import { mkdir, rename, stat } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { execElevated } from './admin'

const exec = promisify(execCb)

export type StoreRepairAction =
  | 'wsreset'
  | 'open-repair-settings'
  | 'reset-package'
  | 'reregister-package'
  | 'backup-cache'
  | 'open-region-settings'

export interface StoreRepairResult {
  success: boolean
  message: string
  details?: string
}

function ps(command: string) {
  return exec(`powershell -NoProfile -ExecutionPolicy Bypass -Command "${command}"`, {
    windowsHide: true,
    timeout: 60000,
    maxBuffer: 1024 * 1024
  })
}

function timestamp() {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
}

async function backupStoreCache(): Promise<StoreRepairResult> {
  const base = join(process.env.LOCALAPPDATA || '', 'Packages', 'Microsoft.WindowsStore_8wekyb3d8bbwe')
  if (!base || base.startsWith('\\Packages')) {
    return { success: false, message: 'LOCALAPPDATA не найден' }
  }

  const cache = join(base, 'LocalCache')
  try {
    await stat(cache)
  } catch {
    await mkdir(cache, { recursive: true })
    return { success: true, message: 'LocalCache отсутствовал, создан новый пустой каталог', details: cache }
  }

  const backup = join(base, `LocalCache.vpn-backup-${timestamp()}`)
  await rename(cache, backup)
  await mkdir(cache, { recursive: true })
  return {
    success: true,
    message: 'Кэш Microsoft Store переименован, создан новый LocalCache',
    details: backup
  }
}

export async function runStoreRepair(action: StoreRepairAction): Promise<StoreRepairResult> {
  try {
    switch (action) {
      case 'wsreset':
        await ps('Start-Process wsreset.exe')
        return { success: true, message: 'wsreset.exe запущен' }

      case 'open-repair-settings':
        await shell.openExternal('ms-settings:appsfeatures')
        return { success: true, message: 'Открыты параметры приложений Windows' }

      case 'reset-package': {
        // Reset-AppxPackage requires elevation — use execElevated
        const result = await execElevated(
          `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage Microsoft.WindowsStore | Reset-AppxPackage"`,
          { timeout: 60000 }
        )
        return {
          success: true,
          message: 'Reset-AppxPackage выполнен для Microsoft Store',
          details: (result.stdout || result.stderr || '').trim()
        }
      }

      case 'reregister-package': {
        const command =
          "Get-AppxPackage Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register ($_.InstallLocation + '\\AppXManifest.xml') }"
        const { stdout, stderr } = await ps(command)
        return {
          success: true,
          message: 'Пакет Microsoft Store пере-регистрирован',
          details: (stdout || stderr || '').trim()
        }
      }

      case 'backup-cache':
        return backupStoreCache()

      case 'open-region-settings':
        await shell.openExternal('ms-settings:regionlanguage')
        return { success: true, message: 'Открыты настройки региона Windows' }
    }
  } catch (err: any) {
    return {
      success: false,
      message: err.message || String(err),
      details: err.stderr || err.stdout
    }
  }
}
