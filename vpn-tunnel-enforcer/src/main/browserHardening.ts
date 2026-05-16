import { exec as execCb } from 'child_process'
import { existsSync } from 'fs'
import { copyFile, mkdir, readFile, readdir, unlink, writeFile } from 'fs/promises'
import { app } from 'electron'
import { basename, dirname, join } from 'path'
import { promisify } from 'util'
import { logEvent } from './appLogger'

const exec = promisify(execCb)

export interface BrowserHardeningResult {
  success: boolean
  changed: boolean
  restartRequired: boolean
  message: string
  details: string[]
}

interface ChromiumTarget {
  name: string
  userDataDir: string
  policyKeys: string[]
  directProfile?: boolean
}

interface RegistryBackup {
  key: string
  backupPath: string | null
}

interface FileBackup {
  path: string
  backupPath: string | null
  existed: boolean
}

interface BackupManifest {
  createdAt: number
  registryBackups: RegistryBackup[]
  fileBackups: FileBackup[]
}

const WEBRTC_POLICY = {
  name: 'WebRtcIPHandlingPolicy',
  type: 'REG_SZ',
  data: 'disable_non_proxied_udp'
}

function backupDir(): string {
  return join(app.getPath('userData'), 'browser-hardening')
}

function manifestPath(): string {
  return join(backupDir(), 'latest-browser-hardening.json')
}

function timestamp(value = Date.now()): string {
  return new Date(value).toISOString().replace(/[:.]/g, '-')
}

function safeName(value: string): string {
  return value.replace(/[<>:"/\\|?*\x00-\x1F]+/g, '-')
}

function localAppData(): string {
  return process.env.LOCALAPPDATA || join(app.getPath('home'), 'AppData', 'Local')
}

function roamingAppData(): string {
  return process.env.APPDATA || join(app.getPath('home'), 'AppData', 'Roaming')
}

function chromiumTargets(): ChromiumTarget[] {
  const local = localAppData()
  const roaming = roamingAppData()
  return [
    {
      name: 'Yandex Browser',
      userDataDir: join(local, 'Yandex', 'YandexBrowser', 'User Data'),
      policyKeys: [
        'HKLM\\Software\\Policies\\YandexBrowser',
        'HKLM\\Software\\Policies\\Yandex\\YandexBrowser',
        'HKCU\\Software\\Policies\\YandexBrowser',
        'HKCU\\Software\\Policies\\Yandex\\YandexBrowser'
      ]
    },
    {
      name: 'Google Chrome',
      userDataDir: join(local, 'Google', 'Chrome', 'User Data'),
      policyKeys: ['HKLM\\Software\\Policies\\Google\\Chrome', 'HKCU\\Software\\Policies\\Google\\Chrome']
    },
    {
      name: 'Microsoft Edge',
      userDataDir: join(local, 'Microsoft', 'Edge', 'User Data'),
      policyKeys: ['HKLM\\Software\\Policies\\Microsoft\\Edge', 'HKCU\\Software\\Policies\\Microsoft\\Edge']
    },
    {
      name: 'Brave',
      userDataDir: join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
      policyKeys: ['HKLM\\Software\\Policies\\BraveSoftware\\Brave', 'HKCU\\Software\\Policies\\BraveSoftware\\Brave']
    },
    {
      name: 'Chromium',
      userDataDir: join(local, 'Chromium', 'User Data'),
      policyKeys: ['HKLM\\Software\\Policies\\Chromium', 'HKCU\\Software\\Policies\\Chromium']
    },
    {
      name: 'Vivaldi',
      userDataDir: join(local, 'Vivaldi', 'User Data'),
      policyKeys: ['HKLM\\Software\\Policies\\Vivaldi', 'HKCU\\Software\\Policies\\Vivaldi']
    },
    {
      name: 'Opera',
      userDataDir: join(roaming, 'Opera Software', 'Opera Stable'),
      policyKeys: ['HKLM\\Software\\Policies\\Opera Software\\Opera', 'HKCU\\Software\\Policies\\Opera Software\\Opera'],
      directProfile: true
    }
  ]
}

async function run(command: string): Promise<{ stdout: string; stderr: string }> {
  return exec(command, {
    windowsHide: true,
    timeout: 15000,
    maxBuffer: 1024 * 1024,
    encoding: 'utf8'
  }) as Promise<{ stdout: string; stderr: string }>
}

async function exportKey(key: string, file: string): Promise<string | null> {
  try {
    await run(`reg export "${key}" "${file}" /y`)
    return file
  } catch {
    return null
  }
}

async function queryValue(key: string, value: string): Promise<string | null> {
  try {
    const { stdout } = await run(`reg query "${key}" /v ${value}`)
    const line = stdout.split(/\r?\n/).find(l => l.includes(value))
    if (!line) return null
    const parts = line.trim().split(/\s{2,}/)
    return parts[parts.length - 1] ?? null
  } catch {
    return null
  }
}

async function readManifest(): Promise<BackupManifest | null> {
  try {
    return JSON.parse(await readFile(manifestPath(), 'utf8')) as BackupManifest
  } catch {
    return null
  }
}

async function writeManifest(manifest: BackupManifest): Promise<void> {
  await mkdir(backupDir(), { recursive: true })
  await writeFile(manifestPath(), JSON.stringify(manifest, null, 2), 'utf8')
}

async function ensureManifest(policyKeys: string[]): Promise<BackupManifest> {
  const manifest = await readManifest() ?? {
    createdAt: Date.now(),
    registryBackups: [],
    fileBackups: []
  }
  const dir = join(backupDir(), timestamp(manifest.createdAt))
  await mkdir(dir, { recursive: true })
  const knownKeys = new Set(manifest.registryBackups.map(x => x.key))
  for (const key of policyKeys) {
    if (knownKeys.has(key)) continue
    manifest.registryBackups.push({
      key,
      backupPath: await exportKey(key, join(dir, `${safeName(key)}.reg`))
    })
  }
  await writeManifest(manifest)
  return manifest
}

async function addFileBackup(manifest: BackupManifest, path: string): Promise<void> {
  if (manifest.fileBackups.some(x => x.path === path)) return
  const existed = existsSync(path)
  const dir = join(backupDir(), timestamp(manifest.createdAt))
  await mkdir(dir, { recursive: true })
  const backupPath = existed ? join(dir, `${safeName(path)}.bak`) : null
  if (backupPath) await copyFile(path, backupPath)
  manifest.fileBackups.push({ path, backupPath, existed })
  await writeManifest(manifest)
}

async function profilePreferencePaths(target: ChromiumTarget): Promise<string[]> {
  if (!existsSync(target.userDataDir)) return []
  if (target.directProfile) {
    const prefs = join(target.userDataDir, 'Preferences')
    return existsSync(prefs) ? [prefs] : []
  }
  const entries = await readdir(target.userDataDir, { withFileTypes: true }).catch(() => [])
  const dirs = entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .filter(name => name === 'Default' || /^Profile \d+$/i.test(name))
  return dirs
    .map(name => join(target.userDataDir, name, 'Preferences'))
    .filter(path => existsSync(path))
}

async function activeChromiumTargets(): Promise<ChromiumTarget[]> {
  const result: ChromiumTarget[] = []
  for (const target of chromiumTargets()) {
    if (existsSync(target.userDataDir)) result.push(target)
  }
  return result
}

async function applyChromiumPolicy(target: ChromiumTarget, details: string[]): Promise<boolean> {
  let changed = false
  for (const key of target.policyKeys) {
    try {
      const current = await queryValue(key, WEBRTC_POLICY.name)
      if (current === WEBRTC_POLICY.data) {
        details.push(`${target.name}: policy ${key}\\${WEBRTC_POLICY.name} уже применена`)
        continue
      }
      await run(`reg add "${key}" /v ${WEBRTC_POLICY.name} /t ${WEBRTC_POLICY.type} /d ${WEBRTC_POLICY.data} /f`)
      details.push(`${target.name}: policy ${key}\\${WEBRTC_POLICY.name}=${WEBRTC_POLICY.data}`)
      changed = true
    } catch (err: any) {
      details.push(`${target.name}: не удалось записать policy ${key}: ${err?.message || String(err)}`)
    }
  }
  return changed
}

async function applyChromiumPreferences(target: ChromiumTarget, manifest: BackupManifest, details: string[]): Promise<boolean> {
  const paths = await profilePreferencePaths(target)
  let changed = false
  for (const prefsPath of paths) {
    try {
      const raw = await readFile(prefsPath, 'utf8')
      const data = JSON.parse(raw)
      const before = JSON.stringify(data.webrtc ?? {})
      data.webrtc = {
        ...(data.webrtc ?? {}),
        ip_handling_policy: WEBRTC_POLICY.data,
        multiple_routes_enabled: false,
        nonproxied_udp_enabled: false
      }
      const after = JSON.stringify(data.webrtc)
      if (before === after) {
        details.push(`${target.name}: ${basename(dirname(prefsPath))} уже защищён`)
        continue
      }
      await addFileBackup(manifest, prefsPath)
      await writeFile(prefsPath, JSON.stringify(data), 'utf8')
      details.push(`${target.name}: обновлён ${prefsPath}`)
      changed = true
    } catch (err: any) {
      details.push(`${target.name}: не удалось обновить ${prefsPath}: ${err?.message || String(err)}`)
    }
  }
  return changed
}

function setFirefoxPref(raw: string, key: string, value: string): string {
  const line = `user_pref("${key}", ${value});`
  const rx = new RegExp(`user_pref\\("${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}",\\s*[^;]+\\);`, 'g')
  if (rx.test(raw)) return raw.replace(rx, line)
  return `${raw.trimEnd()}\n${line}\n`
}

async function firefoxUserJsPaths(): Promise<string[]> {
  const profilesDir = join(roamingAppData(), 'Mozilla', 'Firefox', 'Profiles')
  if (!existsSync(profilesDir)) return []
  const entries = await readdir(profilesDir, { withFileTypes: true }).catch(() => [])
  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => join(profilesDir, entry.name, 'user.js'))
}

async function applyFirefoxPreferences(manifest: BackupManifest, details: string[]): Promise<boolean> {
  const paths = await firefoxUserJsPaths()
  let changed = false
  for (const userJsPath of paths) {
    try {
      const raw = existsSync(userJsPath) ? await readFile(userJsPath, 'utf8') : ''
      let next = setFirefoxPref(raw, 'media.peerconnection.ice.no_host', 'true')
      next = setFirefoxPref(next, 'media.peerconnection.ice.default_address_only', 'true')
      next = setFirefoxPref(next, 'media.peerconnection.ice.proxy_only_if_behind_proxy', 'true')
      next = setFirefoxPref(next, 'media.peerconnection.enabled', 'false')
      if (next === raw) {
        details.push(`Firefox: ${basename(dirname(userJsPath))} уже защищён`)
        continue
      }
      await addFileBackup(manifest, userJsPath)
      await writeFile(userJsPath, next, 'utf8')
      details.push(`Firefox: обновлён ${userJsPath}`)
      changed = true
    } catch (err: any) {
      details.push(`Firefox: не удалось обновить ${userJsPath}: ${err?.message || String(err)}`)
    }
  }
  return changed
}

export async function applyBrowserLeakProtection(): Promise<BrowserHardeningResult> {
  if (process.platform !== 'win32') {
    return {
      success: false,
      changed: false,
      restartRequired: false,
      message: 'Защита браузеров доступна только на Windows',
      details: []
    }
  }

  const details: string[] = []
  const targets = await activeChromiumTargets()
  for (const target of chromiumTargets()) {
    if (!existsSync(target.userDataDir)) details.push(`${target.name}: профиль не найден, policy не менялась`)
  }
  const firefoxPaths = await firefoxUserJsPaths()
  if (targets.length === 0 && firefoxPaths.length === 0) {
    return {
      success: true,
      changed: false,
      restartRequired: false,
      message: 'Поддерживаемые профили браузеров не найдены.',
      details
    }
  }

  const manifest = await ensureManifest(targets.flatMap(target => target.policyKeys))
  let changed = false
  for (const target of targets) {
    const policyChanged = await applyChromiumPolicy(target, details)
    const prefsChanged = await applyChromiumPreferences(target, manifest, details)
    changed = changed || policyChanged || prefsChanged
  }
  changed = await applyFirefoxPreferences(manifest, details) || changed

  const result = {
    success: true,
    changed,
    restartRequired: true,
    message: changed
      ? 'Защита браузеров от WebRTC/IP leak применена. Полностью закройте браузеры, включая фоновые процессы, и откройте заново.'
      : 'Настройки защиты уже применены. Если браузер был открыт — полностью перезапустите его.',
    details
  }
  logEvent('info', 'browser-hardening', 'browser leak protection applied', result)
  return result
}

export async function rollbackBrowserLeakProtection(): Promise<BrowserHardeningResult> {
  if (process.platform !== 'win32') {
    return {
      success: false,
      changed: false,
      restartRequired: false,
      message: 'Откат защиты браузеров доступен только на Windows',
      details: []
    }
  }

  const manifest = await readManifest()
  if (!manifest) {
    return {
      success: false,
      changed: false,
      restartRequired: false,
      message: 'Backup защиты браузеров не найден',
      details: []
    }
  }

  const details: string[] = []
  for (const item of manifest.registryBackups) {
    try {
      await run(`reg delete "${item.key}" /v ${WEBRTC_POLICY.name} /f`).catch(() => ({ stdout: '', stderr: '' }))
      if (item.backupPath && existsSync(item.backupPath)) {
        await run(`reg import "${item.backupPath}"`)
        details.push(`Registry восстановлен: ${item.key}`)
      } else {
        details.push(`Registry policy удалена: ${item.key}\\${WEBRTC_POLICY.name}`)
      }
    } catch (err: any) {
      details.push(`Не удалось восстановить registry ${item.key}: ${err?.message || String(err)}`)
    }
  }
  for (const item of manifest.fileBackups) {
    try {
      if (item.existed && item.backupPath && existsSync(item.backupPath)) {
        await copyFile(item.backupPath, item.path)
        details.push(`Файл восстановлен: ${item.path}`)
      } else {
        await unlink(item.path).catch(() => undefined)
        details.push(`Файл удалён: ${item.path}`)
      }
    } catch (err: any) {
      details.push(`Не удалось восстановить ${item.path}: ${err?.message || String(err)}`)
    }
  }
  await unlink(manifestPath()).catch(() => undefined)

  const result = {
    success: true,
    changed: true,
    restartRequired: true,
    message: 'Защита браузеров откатана из backup. Полностью перезапустите браузеры.',
    details
  }
  logEvent('info', 'browser-hardening', 'browser leak protection rolled back', result)
  return result
}
