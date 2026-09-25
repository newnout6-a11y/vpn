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

import { execFile as execFileCb } from 'child_process'
import { ipcMain, dialog, app, type IpcMainInvokeEvent } from 'electron'
import { basename, dirname, extname, join } from 'path'
import { access, readdir } from 'fs/promises'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { compactForIpcLog } from './ipcLogging'
import { requireEnum, requireString } from './ipcValidation'
import { tunController } from './tunController'
import type { SplitTunnelApp, SplitTunnelConfig } from '../shared/ipc-types'

const execFile = promisify(execFileCb)

function encodedPowerShell(script: string): string {
  const prelude =
    '$ProgressPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf-16le').toString('base64')
}

// ─── Persistent Store ────────────────────────────────────────────────────────

interface SplitTunnelStore {
  splitTunnelApps: SplitTunnelApp[]
  splitTunnelEnabled: boolean
  // Exe paths the user explicitly deleted from the list. Refresh must not
  // re-add them — without this tombstone every refresh resurrects removed
  // apps with rule 'none'.
  splitTunnelRemovedPaths: string[]
}

const store = new Store<SplitTunnelStore>({
  name: 'split-tunnel',
  defaults: {
    splitTunnelApps: [],
    splitTunnelEnabled: true,
    splitTunnelRemovedPaths: []
  }
})

export function looksCorruptDisplayName(name: string): boolean {
  const value = String(name ?? '')
  const replacementCount = (value.match(/\uFFFD/g) ?? []).length
  if (replacementCount > 0) return true
  // Mojibake: Cyrillic/other text whose UTF-16LE bytes were read as UTF-8 (or
  // vice-versa) yields CJK Compatibility Ideographs (U+F900-FAFF), CJK Ext-A
  // (U+3400-9FFF), Hangul (U+AC00-D7AF) and scattered high-range letters
  // (U+0800-08FF). A legit app name never mixes Latin/Cyrillic with those.
  const mojibakeCount = (value.match(/[\u3400-\u9fff\uf900-\ufaff\uac00-\ud7af\u0800-\u08ff]/g) ?? []).length
  const hasKnownText = /[A-Za-zА-Яа-я0-9]/.test(value)
  const letterCount = (value.match(/[^\s\d\W_]/gu) ?? []).length
  // Legit Asian app names consist largely of CJK/Hangul glyphs — never
  // flag those. Only a name that ALSO carries Latin/Cyrillic text can be
  // mojibake, and real mojibake produces long runs, so require 3+
  // suspicious chars AND >= half of all letters.
  const latinCyrillicCount = (value.match(/[A-Za-z\u0410-\u044f]/g) ?? []).length
  const otherLetterCount = letterCount - mojibakeCount
  return (
    hasKnownText &&
    latinCyrillicCount > 0 &&
    mojibakeCount >= 3 &&
    mojibakeCount > otherLetterCount / 2
  )
}

function cleanDisplayName(name: string): string {
  const value = String(name ?? '')
  return value
    .replace(/\uFFFD+/g, ' ')
    .replace(looksCorruptDisplayName(value) ? /[\u3400-\u9fff\uf900-\ufaff\uac00-\ud7af\u0800-\u08ff]+/g : /(?!)/g, ' ')
    .replace(/\(\s*\d+\s*[-–][^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/\s+([,.)\]])/g, '$1')
    .replace(/([(])\s+/g, '$1')
    .replace(/,\s*(?=\d)/g, ' ')
    .replace(/,\s*$/g, '')
    .trim()
}

function mostlyNumeric(value: string): boolean {
  const compact = String(value ?? '').replace(/\s+/g, '')
  return compact.length > 0 && /^[\d.+\-()]+$/.test(compact)
}

function isGenericContainerName(value: string): boolean {
  return /^(application|app|bin|bin64|x64|x86|win64|win32|program files|program files \(x86\)|common files|current)$/i.test(
    value.trim()
  )
}

export function fallbackAppNameFromPath(path: string): string {
  const base = basename(path, extname(path)).trim()
  const parent = basename(dirname(path)).trim()
  const candidates = [parent, base].filter(Boolean)
  const picked = candidates.find(
    (candidate) =>
      !looksCorruptDisplayName(candidate) &&
      !mostlyNumeric(candidate) &&
      !isGenericContainerName(candidate)
  )
  return picked || base || path
}

export function sanitizeAppDisplayName(name: string, path: string): string {
  const trimmed = String(name ?? '').trim()
  const cleaned = cleanDisplayName(trimmed)
  if (!looksCorruptDisplayName(trimmed) && cleaned && !mostlyNumeric(cleaned)) return cleaned
  if (cleaned.length >= 3 && /[A-Za-zА-Яа-я]/.test(cleaned) && !mostlyNumeric(cleaned)) {
    return cleaned
  }
  return fallbackAppNameFromPath(path)
}

let appsWriteQueue: Promise<void> = Promise.resolve()

async function withAppsWriteLock<T>(operation: () => Promise<T> | T): Promise<T> {
  const previous = appsWriteQueue
  let release!: () => void
  appsWriteQueue = new Promise<void>((resolve) => {
    release = resolve
  })
  await previous.catch(() => undefined)
  try {
    return await operation()
  } finally {
    release()
  }
}


// ─── App Discovery ───────────────────────────────────────────────────────────

/**
 * Discovers installed Windows applications by scanning the registry Uninstall keys.
 * Returns apps with name, exe path, and icon (null for now — icon extraction is complex).
 */
let discoverAppsPromise: Promise<Array<{ name: string; path: string; icon: string | null }>> | null = null

export async function discoverInstalledApps(): Promise<
  Array<{ name: string; path: string; icon: string | null }>
> {
  if (process.platform !== 'win32') return []
  if (discoverAppsPromise) return discoverAppsPromise

  discoverAppsPromise = (async () => {
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

    // Many per-user apps (OpenAI Codex CLI, VS Code Insiders, portable tools)
    // install under %LOCALAPPDATA%\Programs WITHOUT writing an Uninstall key,
    // so the registry scan above never sees them. Scan that directory too.
    try {
      const localApps = await discoverLocalProgramsApps()
      for (const app of localApps) {
        const normalizedPath = app.path.toLowerCase()
        if (!seenPaths.has(normalizedPath)) {
          seenPaths.add(normalizedPath)
          apps.push(app)
        }
      }
    } catch (err) {
      logEvent('debug', 'split-tunnel', 'local Programs scan failed', err)
    }

    return apps
  })().finally(() => {
    discoverAppsPromise = null
  })

  return discoverAppsPromise
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
$hive=$root.Split('\\')[0]
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
      $results+=[pscustomobject]@{Name=[string]$props.DisplayName;Path=[string]$exe}
    }
  }
}
$results | ConvertTo-Json -Compress -Depth 3
`

  try {
    const { stdout } = await execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(psScript)],
      { windowsHide: true, timeout: 15000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }
    )

    const trimmed = stdout.trim()
    if (!trimmed || trimmed === 'null') return []

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
        name: sanitizeAppDisplayName(row.Name, row.Path.trim()),
        path: row.Path.trim(),
        icon: null // Icon extraction deferred — complex Win32 API needed
      }))
  } catch (err: any) {
    logEvent('debug', 'split-tunnel', `queryRegistryApps failed for ${registryPath}`, { error: err?.message })
    return []
  }
}

/**
 * Discovers per-user apps installed under %LOCALAPPDATA%\Programs that never
 * write a registry Uninstall key (OpenAI Codex CLI, portable Electron apps,
 * etc.). Walks each product directory a few levels deep looking for the
 * "main" executable and synthesises a friendly name from the folder path.
 *
 * Kept deliberately shallow + capped so a huge Programs tree can't stall the
 * scan: 2 levels of product dirs, then up to 2 levels inside each product.
 */
async function discoverLocalProgramsApps(): Promise<
  Array<{ name: string; path: string; icon: string | null }>
> {
  if (process.platform !== 'win32') return []
  const programsRoot = join(app.getPath('appData'), '..', 'Local', 'Programs')
  const results: Array<{ name: string; path: string; icon: string | null }> = []

  async function listDirs(dir: string): Promise<string[]> {
    try {
      const entries = await readdir(dir, { withFileTypes: true })
      // Include symlinks/junctions too: some installers (OpenAI Codex) lay out
      // `Codex\bin` as a junction, and Dirent.isDirectory() is false for those.
      return entries
        .filter(e => e.isDirectory() || e.isSymbolicLink())
        .map(e => join(dir, e.name))
    } catch {
      return []
    }
  }

  async function listExes(dir: string): Promise<string[]> {
    try {
      const entries = await readdir(dir, { withFileTypes: true })
      return entries
        .filter(e => e.isFile() && /\.exe$/i.test(e.name))
        .map(e => join(dir, e.name))
    } catch {
      return []
    }
  }

  // Pick the most "primary" exe for a product. Filter out installer/helper
  // executables (uninstallers, updaters, crash reporters, elevation helpers),
  // then prefer an exe whose leaf matches the product name, then the shortest
  // remaining leaf (heuristic for the launcher over `*-helper.exe` siblings).
  const HELPER_EXE_RX = /^(unins|uninstall|setup|update|inno|crash|crashpad|report|notifier|elevate|elevator|squirrel|service|helper|daemon|broker)/i
  function pickMainExe(exes: string[], productName: string): string | null {
    const candidates = exes.filter(p => !HELPER_EXE_RX.test(basename(p)))
    if (candidates.length === 0) return null
    // Compare against every meaningful word in the product name so "OpenAI
    // Codex" matches `codex.exe`, "Microsoft VS Code" matches `code.exe`, etc.
    const words = productName
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(w => w.length >= 3 && !/^(the|app|for|and|ide)$/.test(w))
    const matches = candidates.filter(p => {
      const leaf = basename(p, extname(p)).replace(/[\s_-]+/g, '').toLowerCase()
      return words.some(w => leaf === w || leaf === `${w}exe` || leaf.startsWith(w))
    })
    if (matches.length > 0) {
      // Among matches prefer the SHORTEST leaf — `codex.exe` over
      // `codex-code-mode-host.exe` (both start with the product word).
      matches.sort((a, b) => basename(a).length - basename(b).length)
      return matches[0]
    }
    candidates.sort((a, b) => basename(a).length - basename(b).length)
    return candidates[0]
  }

  // Build a display name from the product folder chain (e.g. "OpenAI\Codex").
  function nameFromPath(productDir: string): string {
    const rel = productDir.slice(programsRoot.length).replace(/^[\\/]+/, '')
    const parts = rel.split(/[\\/]+/).filter(Boolean)
    const meaningful = parts.filter(p => !isGenericContainerName(p) && !mostlyNumeric(p))
    return meaningful.join(' ') || basename(productDir)
  }

  // For nested products (OpenAI\Codex\bin\codex.exe) the vendor dir name
  // ("OpenAI") is too generic — derive the name from the exe's own folder
  // chain instead so we get "Codex" / "OpenAI Codex".
  function nameForExe(vendorDir: string, exePath: string): string {
    const vendorName = nameFromPath(vendorDir)
    const exeDirName = nameFromPath(dirname(exePath))
    // If the exe lives deeper than the vendor dir and its folder chain yields
    // a more specific name, prefer it; otherwise keep the vendor name.
    if (exeDirName && exeDirName.toLowerCase() !== vendorName.toLowerCase()) {
      // Combine vendor + product when both are meaningful ("OpenAI" + "Codex").
      if (vendorName && !exeDirName.toLowerCase().includes(vendorName.toLowerCase())) {
        return `${vendorName} ${exeDirName}`
      }
      return exeDirName
    }
    return vendorName
  }

  // Recursively collect candidate exes under `dir`, descending at most
  // `depth` levels into subdirectories. Stops descending a BRANCH as soon as
  // that branch yields exes (the launcher lives next to its helpers), but
  // keeps scanning SIBLING branches — `Vendor\ProductA` and `Vendor\ProductB`
  // must both be found. Returns entries of { dir, exes } so the caller can
  // name each product from the folder where its launcher actually lives.
  async function collectProducts(dir: string, depth: number): Promise<Array<{ dir: string; exes: string[] }>> {
    const here = await listExes(dir)
    if (here.length > 0 || depth <= 0) {
      return here.length > 0 ? [{ dir, exes: here }] : []
    }
    const subs = await listDirs(dir)
    const out: Array<{ dir: string; exes: string[] }> = []
    for (const sub of subs.slice(0, 8)) {
      out.push(...await collectProducts(sub, depth - 1))
    }
    return out
  }

  const vendorDirs = await listDirs(programsRoot)
  // Cap the number of product dirs we inspect to keep the scan fast.
  const MAX_PRODUCTS = 250
  let inspected = 0

  for (const vendorDir of vendorDirs) {
    if (inspected >= MAX_PRODUCTS) break
    inspected++
    // Search the vendor/product dir and up to 2 levels inside it for exes.
    // Sibling subdirectories are independent products — collect them all.
    const products = await collectProducts(vendorDir, 2)
    for (const product of products) {
      const exes = product.exes.filter(p => !HELPER_EXE_RX.test(basename(p)))
      if (exes.length === 0) continue
      const productName = nameFromPath(product.dir)
      const mainExe = pickMainExe(exes, productName)
      if (mainExe) {
        const displayName = nameForExe(vendorDir, mainExe)
        results.push({
          name: sanitizeAppDisplayName(displayName, mainExe),
          path: mainExe,
          icon: null
        })
      }
    }
  }

  return results
}

// ─── Rule Management ─────────────────────────────────────────────────────────

function normalizeStoredApps(apps: SplitTunnelApp[]): { apps: SplitTunnelApp[]; changed: boolean } {
  let changed = false
  const normalized = apps.map((app) => {
    if (app.kind === 'process') return app
    const name = sanitizeAppDisplayName(app.name, app.path)
    if (name === app.name) return app
    changed = true
    return { ...app, name }
  })
  return { apps: normalized, changed }
}

function getApps(): SplitTunnelApp[] {
  const apps = store.get('splitTunnelApps') ?? []
  const normalized = normalizeStoredApps(apps)
  if (normalized.changed) saveApps(normalized.apps)
  return normalized.apps
}

function saveApps(apps: SplitTunnelApp[]): void {
  store.set('splitTunnelApps', apps)
}

function getRemovedPaths(): Set<string> {
  const raw = store.get('splitTunnelRemovedPaths') ?? []
  return new Set(raw.filter((p): p is string => typeof p === 'string').map(p => p.toLowerCase()))
}

function rememberRemovedPath(path: string): void {
  const removed = getRemovedPaths()
  removed.add(path.toLowerCase())
  store.set('splitTunnelRemovedPaths', [...removed])
}

function forgetRemovedPath(path: string): void {
  const removed = getRemovedPaths()
  if (removed.delete(path.toLowerCase())) {
    store.set('splitTunnelRemovedPaths', [...removed])
  }
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

async function setRule(appId: string, rule: 'vpn' | 'direct' | 'none'): Promise<void> {
  await withAppsWriteLock(() => {
    const apps = getApps()
    const index = apps.findIndex((a) => a.id === appId)
    if (index === -1) {
      logEvent('warn', 'split-tunnel', `setRule: app not found`, { appId, rule })
      return
    }
    apps[index] = { ...apps[index], rule }
    saveApps(apps)
    logEvent('info', 'split-tunnel', `rule set`, { appId, name: apps[index].name, rule })
  })
}

async function addApp(exePath: string): Promise<SplitTunnelApp> {
  // Validate the path exists
  await access(exePath)

  return withAppsWriteLock(() => {
    const name = fallbackAppNameFromPath(exePath)
    const app: SplitTunnelApp = {
      id: randomUUID(),
      name,
      path: exePath,
      icon: null,
      rule: 'none',
      kind: 'app'
    }

    const apps = getApps()
    // Check for duplicate path
    const existing = apps.find((a) => a.path.toLowerCase() === exePath.toLowerCase())
    if (existing) {
      return existing
    }

    apps.push(app)
    saveApps(apps)
    // A manual add is an explicit user choice — clear any removal tombstone
    // so a later refresh keeps the app instead of dropping it again.
    forgetRemovedPath(exePath)
    logEvent('info', 'split-tunnel', `app added`, { id: app.id, name: app.name, path: app.path })
    return app
  })
}

/**
 * Normalize a user-typed process/command name into the form sing-box matches
 * against on Windows. sing-box compares the executable's base name including
 * the extension (e.g. `curl.exe`). We:
 *   - strip any directory part the user may have pasted (`C:\foo\curl.exe` →
 *     `curl.exe`) — process_name matches the leaf, process_path would need the
 *     full real path which a transient PATH command doesn't have;
 *   - trim quotes/whitespace;
 *   - append `.exe` when the user typed a bare command (`curl` → `curl.exe`),
 *     since Windows executables carry the extension and that's what sing-box
 *     sees. Names that already have an extension are left as-is.
 *   - lower-case for stable de-duplication (Windows process names are
 *     case-insensitive).
 * Returns null for input that can't be a valid Windows executable name
 * (empty, path separators left over, illegal filename characters).
 */
export function normalizeProcessName(input: string): string | null {
  let s = String(input ?? '').trim()
  if (!s) return null
  // Strip surrounding quotes a user might paste from a command line.
  s = s.replace(/^["']+|["']+$/g, '').trim()
  if (!s) return null
  // Reduce any path to its leaf component (handle both separators).
  const leaf = s.split(/[\\/]/).pop() ?? s
  if (!leaf) return null
  // Reject illegal Windows filename characters / whitespace inside the name.
  if (/[<>:"/\\|?*\s]/.test(leaf)) return null
  // Append .exe for a bare command name (no extension present).
  const withExt = /\.[a-z0-9]+$/i.test(leaf) ? leaf : `${leaf}.exe`
  return withExt.toLowerCase()
}

/**
 * Add a bare process/command name to bypass the VPN (route 'direct'). Unlike
 * addApp this does NOT touch the filesystem — the command may be anywhere on
 * PATH or invoked transiently from a terminal. The entry is created already
 * set to 'direct' because that's the only reason to add a command by name.
 */
export async function addProcessName(rawName: string): Promise<SplitTunnelApp> {
  const proc = normalizeProcessName(rawName)
  if (!proc) {
    throw new Error('Некорректное имя процесса. Пример: curl.exe или yt-dlp')
  }
  return withAppsWriteLock(() => {
    const apps = getApps()
    const existing = apps.find(
      (a) => a.kind === 'process' && a.path.toLowerCase() === proc
    )
    if (existing) {
      if (existing.rule !== 'direct') {
        const index = apps.findIndex((a) => a.id === existing.id)
        apps[index] = { ...existing, rule: 'direct' }
        saveApps(apps)
        return { ...existing, rule: 'direct' }
      }
      return existing
    }
    const entry: SplitTunnelApp = {
      id: randomUUID(),
      name: proc,
      path: proc,
      icon: null,
      rule: 'direct',
      kind: 'process'
    }
    apps.push(entry)
    saveApps(apps)
    logEvent('info', 'split-tunnel', 'process-name bypass added', { name: proc })
    return entry
  })
}

async function removeApp(appId: string): Promise<void> {
  await withAppsWriteLock(() => {
    const apps = getApps()
    const target = apps.find((a) => a.id === appId)
    const filtered = apps.filter((a) => a.id !== appId)
    if (filtered.length === apps.length) {
      logEvent('warn', 'split-tunnel', `removeApp: app not found`, { appId })
      return
    }
    saveApps(filtered)
    // Tombstone the path so the next refresh does not resurrect the app the
    // user just deleted. Process-name entries are user-created, never
    // discovered, so they need no tombstone.
    if (target && target.kind !== 'process') rememberRemovedPath(target.path)
    logEvent('info', 'split-tunnel', `app removed`, { appId })
  })
}

// ─── Sing-box Route Rule Generation ─────────────────────────────────────────

/**
 * Generates sing-box route rules for split tunnel configuration.
 *
 * - Apps with 'direct' rule → route through 'direct-out' (bypass VPN)
 * - Apps with 'vpn' / 'none' -> no special rule (follow default proxy-out)
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
    .map((a) => normalizeProcessName(a.path))
    .filter((name): name is string => Boolean(name))

  if (directProcessNames.length > 0) {
    rules.push({
      process_name: directProcessNames,
      outbound: 'direct-out'
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
  return apps
    .filter((a) => a.rule === 'direct')
    .map((a) => normalizeProcessName(a.path))
    .filter((name): name is string => Boolean(name))
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
  return apps
    .filter((a) => a.rule === 'vpn')
    .map((a) => normalizeProcessName(a.path))
    .filter((name): name is string => Boolean(name))
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
    const { BrowserWindow } = await import('electron')
    BrowserWindow.getAllWindows().forEach(win => {
      try { win.webContents.send('inapp-notification', { level: 'info', title: 'Применяем изменения', body: 'Перезапускаем защиту с обновлёнными правилами split tunneling', ts: Date.now() }) } catch {}
    })
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
    logEvent('debug', 'ipc', `${channel} started`, { args: compactForIpcLog(args) })
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
        const removedPaths = getRemovedPaths()
        const apps: SplitTunnelApp[] = discovered
          .filter((d) => !removedPaths.has(d.path.toLowerCase()))
          .map((d) => ({
            id: randomUUID(),
            name: sanitizeAppDisplayName(d.name, d.path),
            path: d.path,
            icon: d.icon,
            rule: 'none' as const,
            kind: 'app' as const
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

  // Re-scan installed apps and merge newly discovered ones into the stored
  // list. Existing entries keep their id AND their routing rule (matched by
  // path); only genuinely new apps are appended with rule 'none'. Returns the
  // full updated list plus how many were added, so the UI can report it.
  handleLogged('split-tunnel:refresh-apps', async () => {
    const discovered = await discoverInstalledApps()
    const added = await withAppsWriteLock(() => {
      const apps = getApps()
      const byPath = new Map(apps.map(a => [a.path.toLowerCase(), a]))
      const removedPaths = getRemovedPaths()
      let addedCount = 0
      for (const d of discovered) {
        const key = d.path.toLowerCase()
        if (byPath.has(key)) continue
        // The user previously deleted this path — respect that choice.
        if (removedPaths.has(key)) continue
        const entry: SplitTunnelApp = {
          id: randomUUID(),
          name: sanitizeAppDisplayName(d.name, d.path),
          path: d.path,
          icon: d.icon,
          rule: 'none',
          kind: 'app'
        }
        apps.push(entry)
        byPath.set(key, entry)
        addedCount++
      }
      if (addedCount > 0) saveApps(apps)
      return addedCount
    })
    logEvent('info', 'split-tunnel', 'app list refreshed', { added, total: getApps().length })
    return { apps: getApps(), added }
  })

  handleLogged('split-tunnel:set-rule', async (_event, appId: string, rule: 'vpn' | 'direct' | 'none') => {
    appId = requireString(appId, 'appId', { maxLength: 200 })
    rule = requireEnum(rule, 'rule', ['vpn', 'direct', 'none'])
    await setRule(appId, rule)
    // Hot-reload if TUN is active
    await hotReloadIfActive()
  })

  handleLogged('split-tunnel:add-app', async (_event, exePath: string) => {
    let targetPath = typeof exePath === 'string' ? exePath.trim() : ''
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
    targetPath = requireString(targetPath, 'exePath', { maxLength: 4096 })
    const app = await addApp(targetPath)
    return app
  })

  // Add a bare process/command name to bypass the VPN (route direct). This is
  // for terminal commands and CLI tools (curl, git, yt-dlp, …) that aren't
  // installed "apps" with a fixed path — the user just types the command name.
  // The entry is created already set to 'direct'. Hot-reloads if connected so
  // the bypass takes effect without a manual reconnect.
  handleLogged('split-tunnel:add-process', async (_event, rawName: string) => {
    rawName = requireString(rawName, 'rawName', { maxLength: 260 })
    const entry = await addProcessName(rawName)
    await hotReloadIfActive()
    return entry
  })

  handleLogged('split-tunnel:remove-app', async (_event, appId: string) => {
    appId = requireString(appId, 'appId', { maxLength: 200 })
    await removeApp(appId)
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
  addProcessName,
  normalizeProcessName,
  removeApp,
  getDirectProcessNames,
  getVpnProcessNames,
  generateSplitTunnelRouteRules,
  discoverInstalledApps,
  registerHandlers: registerSplitTunnelHandlers
}
