import { app } from 'electron'
import { execFile as execFileCb } from 'child_process'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { execElevated } from './admin'

const execFile = promisify(execFileCb)

const HKCU_LOCATION = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location'
const HKLM_LOCATION = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors'

interface BackupManifest {
  hkcuBackup: string | null
  hklmBackup: string | null
  createdAt: number
}

export interface LocationPrivacyStatus {
  userDenied: boolean
  policyDisabled: boolean
  applied: boolean
  details: string[]
}

function backupDir() {
  // Store backups in ProgramData (survives app uninstall) instead of userData
  // (which is removed on uninstall, making rollback impossible).
  return join(app.getPath('programData') || 'C:\\ProgramData', 'VPN-Tunnel-Enforcer', 'privacy-backups')
}

function manifestPath() {
  return join(backupDir(), 'latest-location-backup.json')
}

function timestamp() {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
}

async function reg(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFile('reg.exe', args, {
    windowsHide: true,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
    encoding: 'utf8'
  }) as Promise<{ stdout: string; stderr: string }>
}

function runElevated(command: string): Promise<void> {
  return execElevated(command, { timeout: 30000 }).then(() => undefined)
}

async function exportKey(key: string, file: string): Promise<string | null> {
  try {
    await reg(['export', key, file, '/y'])
    return file
  } catch {
    return null
  }
}

async function createBackup(): Promise<BackupManifest> {
  await mkdir(backupDir(), { recursive: true })
  const stamp = timestamp()
  const hkcuBackup = await exportKey(HKCU_LOCATION, join(backupDir(), `hkcu-location-${stamp}.reg`))
  const hklmBackup = await exportKey(HKLM_LOCATION, join(backupDir(), `hklm-location-${stamp}.reg`))
  const manifest = { hkcuBackup, hklmBackup, createdAt: Date.now() }
  await writeFile(manifestPath(), JSON.stringify(manifest, null, 2), 'utf-8')
  return manifest
}

async function readManifest(): Promise<BackupManifest | null> {
  try {
    return JSON.parse(await readFile(manifestPath(), 'utf-8')) as BackupManifest
  } catch {
    return null
  }
}

async function queryValue(key: string, value: string): Promise<string | null> {
  try {
    const { stdout } = await reg(['query', key, '/v', value])
    const line = stdout.split(/\r?\n/).find(l => l.includes(value))
    if (!line) return null
    const parts = line.trim().split(/\s{2,}/)
    return parts[parts.length - 1] ?? null
  } catch {
    return null
  }
}

export async function getLocationPrivacyStatus(): Promise<LocationPrivacyStatus> {
  const consent = await queryValue(HKCU_LOCATION, 'Value')
  const disableLocation = await queryValue(HKLM_LOCATION, 'DisableLocation')
  const disableProvider = await queryValue(HKLM_LOCATION, 'DisableWindowsLocationProvider')

  const userDenied = consent?.toLowerCase() === 'deny'
  const policyDisabled = disableLocation === '0x1' || disableProvider === '0x1'
  const details = [
    `HKCU location consent: ${consent ?? 'not set'}`,
    `HKLM DisableLocation: ${disableLocation ?? 'not set'}`,
    `HKLM DisableWindowsLocationProvider: ${disableProvider ?? 'not set'}`
  ]

  return {
    userDenied,
    policyDisabled,
    applied: userDenied || policyDisabled,
    details
  }
}

export async function applyLocationPrivacy(): Promise<LocationPrivacyStatus> {
  const manifest = await createBackup()
  // Validate backup succeeded before modifying — if backup failed, abort.
  // Without a backup, rollback is impossible and Location stays disabled forever.
  if (!manifest.hkcuBackup) {
    throw new Error('Не удалось создать backup. Настройки местоположения не были изменены.')
  }
  await reg(['add', HKCU_LOCATION, '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'])
  await runElevated(
    `reg add "${HKLM_LOCATION}" /v DisableLocation /t REG_DWORD /d 1 /f && ` +
    `reg add "${HKLM_LOCATION}" /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f`
  )
  return getLocationPrivacyStatus()
}

export async function rollbackLocationPrivacy(): Promise<LocationPrivacyStatus> {
  const manifest = await readManifest()

  if (manifest?.hkcuBackup) {
    await reg(['import', manifest.hkcuBackup]).catch(() => undefined)
  } else {
    await reg(['delete', HKCU_LOCATION, '/v', 'Value', '/f']).catch(() => undefined)
  }

  if (manifest?.hklmBackup) {
    await runElevated(`reg import "${manifest.hklmBackup}"`)
  } else {
    await runElevated(
      `reg delete "${HKLM_LOCATION}" /v DisableLocation /f & ` +
      `reg delete "${HKLM_LOCATION}" /v DisableWindowsLocationProvider /f`
    ).catch(() => undefined)
  }

  return getLocationPrivacyStatus()
}
