import { app } from 'electron'
import { execFile as execFileCb } from 'child_process'
import { mkdir, readFile, writeFile, unlink } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { execElevated } from './admin'

const execFile = promisify(execFileCb)

const HKCU_LOCATION = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location'
const HKLM_LOCATION = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors'

export interface BackupManifest {
  hkcuBackup: string | null
  hkcuKeyExisted: boolean
  hklmBackup: string | null
  hklmKeyExisted: boolean
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
  return join(getProgramDataPath(), 'VPN-Tunnel-Enforcer', 'privacy-backups')
}

function getProgramDataPath(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (app as any).getPath('programData')
  } catch {
    return process.env.ProgramData || 'C:\\ProgramData'
  }
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

type KeyStatus = 'exists' | 'absent' | 'unknown'

async function checkKeyStatus(key: string): Promise<KeyStatus> {
  try {
    await reg(['query', key])
    return 'exists'
  } catch (err: any) {
    const text = String(err?.stderr || err?.stdout || err?.message || '')
    if (/unable to find|не удается найти|не удалось найти/i.test(text)) {
      return 'absent'
    }
    // If access was denied or unprivileged on HKLM, attempt elevated query
    if (key.startsWith('HKLM')) {
      try {
        await execElevated(`reg query "${key}"`, { timeout: 15000 })
        return 'exists'
      } catch (elevErr: any) {
        const elevText = String(elevErr?.stderr || elevErr?.stdout || elevErr?.message || '')
        if (/unable to find|не удается найти|не удалось найти/i.test(elevText)) {
          return 'absent'
        }
      }
    }
    return 'unknown'
  }
}

async function exportKey(key: string, file: string): Promise<string | null> {
  try {
    await reg(['export', key, file, '/y'])
    return file
  } catch {
    if (key.startsWith('HKLM')) {
      try {
        await execElevated(`reg export "${key}" "${file}" /y`, { timeout: 30000 })
        return file
      } catch {
        return null
      }
    }
    return null
  }
}

async function createBackup(): Promise<BackupManifest> {
  await mkdir(backupDir(), { recursive: true })

  // Preserve pre-existing manifest if an earlier apply is pending rollback
  const existing = await readManifest()
  if (existing) {
    return existing
  }

  const stamp = timestamp()
  const hkcuStatus = await checkKeyStatus(HKCU_LOCATION)
  const hklmStatus = await checkKeyStatus(HKLM_LOCATION)

  if (hkcuStatus === 'unknown') {
    throw new Error('Не удалось проверить состояние реестра HKCU перед созданием backup. Настройки местоположения не были изменены.')
  }
  if (hklmStatus === 'unknown') {
    throw new Error('Не удалось проверить состояние реестра HKLM перед созданием backup. Настройки местоположения не были изменены.')
  }

  const hkcuKeyExisted = hkcuStatus === 'exists'
  const hklmKeyExisted = hklmStatus === 'exists'

  const hkcuBackup = hkcuKeyExisted
    ? await exportKey(HKCU_LOCATION, join(backupDir(), `hkcu-location-${stamp}.reg`))
    : null
  const hklmBackup = hklmKeyExisted
    ? await exportKey(HKLM_LOCATION, join(backupDir(), `hklm-location-${stamp}.reg`))
    : null

  if (hkcuKeyExisted && !hkcuBackup) throw new Error('Не удалось создать backup HKCU')
  if (hklmKeyExisted && !hklmBackup) throw new Error('Не удалось создать backup HKLM')
  const manifest: BackupManifest = {
    hkcuBackup,
    hkcuKeyExisted,
    hklmBackup,
    hklmKeyExisted,
    createdAt: Date.now()
  }
  await writeFile(manifestPath(), JSON.stringify(manifest, null, 2), 'utf-8')
  return manifest
}

async function readManifest(): Promise<BackupManifest | null> {
  try {
    return JSON.parse(await readFile(manifestPath(), 'utf-8')) as BackupManifest
  } catch (err: any) {
    if (err?.code === 'ENOENT') return null
    throw err
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
  // Validate backup succeeded before modifying.
  // If either key existed prior to applying, its backup MUST have succeeded.
  if (manifest.hkcuKeyExisted && !manifest.hkcuBackup) {
    throw new Error('Не удалось создать backup HKCU. Настройки местоположения не были изменены.')
  }
  if (manifest.hklmKeyExisted && !manifest.hklmBackup) {
    throw new Error('Не удалось создать backup HKLM. Настройки местоположения не были изменены.')
  }

  await reg(['add', HKCU_LOCATION, '/v', 'Value', '/t', 'REG_SZ', '/d', 'Deny', '/f'])
  await runElevated(
    `reg add "${HKLM_LOCATION}" /v DisableLocation /t REG_DWORD /d 1 /f && ` +
    `reg add "${HKLM_LOCATION}" /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f`
  )
  return getLocationPrivacyStatus()
}

function isMissingRegistryError(err: any): boolean {
  return /unable to find|не удается найти|не удалось найти/i.test(String(err?.stderr || err?.message || ''))
}

async function deleteValue(key: string, name: string): Promise<void> {
  try { await reg(['delete', key, '/v', name, '/f']) }
  catch (err) {
    if (isMissingRegistryError(err)) return
    if (!key.startsWith('HKLM')) throw err
    try { await runElevated(`reg delete "${key}" /v "${name}" /f`) }
    catch (elevatedError) { if (!isMissingRegistryError(elevatedError)) throw elevatedError }
  }
}

export async function rollbackLocationPrivacy(): Promise<LocationPrivacyStatus> {
  const manifest = await readManifest()
  if (!manifest) return getLocationPrivacyStatus()
  let failed = false
  for (const item of [
    { key: HKCU_LOCATION, backup: manifest.hkcuBackup, existed: manifest.hkcuKeyExisted, values: ['Value'] },
    { key: HKLM_LOCATION, backup: manifest.hklmBackup, existed: manifest.hklmKeyExisted, values: ['DisableLocation', 'DisableWindowsLocationProvider'] }
  ]) {
    try {
      if (item.backup) {
        // reg import merges: explicitly remove only our values absent in the original key.
        const raw = await readFile(item.backup, 'utf16le')
        if (!raw.includes('Windows Registry Editor Version 5.00')) throw new Error('Invalid registry backup')
        const fullKey = item.key.replace(/^HKCU/, 'HKEY_CURRENT_USER').replace(/^HKLM/, 'HKEY_LOCAL_MACHINE').toLowerCase()
        let inKey = false
        const present = new Set<string>()
        for (const line of raw.split(/\r?\n/)) {
          const section = line.trim().match(/^\[(.+)\]$/)
          if (section) inKey = section[1].toLowerCase() === fullKey
          const value = inKey && line.match(/^"([^"]+)"=/)
          if (value) present.add(value[1].toLowerCase())
        }
        if (item.key.startsWith('HKLM')) await runElevated(`reg import "${item.backup}"`)
        else await reg(['import', item.backup])
        for (const value of item.values) if (!present.has(value.toLowerCase())) await deleteValue(item.key, value)
      } else if (item.existed === false) {
        for (const value of item.values) await deleteValue(item.key, value)
      } else { throw new Error('Missing registry backup') }
    } catch { failed = true }
  }
  if (failed) throw new Error('Не удалось полностью восстановить настройки реестра. Резервная копия сохранена.')
  await unlink(manifestPath())
  return getLocationPrivacyStatus()
}
