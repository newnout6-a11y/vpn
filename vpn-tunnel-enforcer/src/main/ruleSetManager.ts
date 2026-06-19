import { execFile as execFileCb } from 'child_process'
import { createHash } from 'crypto'
import { access, mkdir, readFile, rename, stat, unlink } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { app } from 'electron'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { buildBootstrapRouteAttempts } from './bootstrapRoute'
import { settingsStore, type AppSettings } from './settings'
import { smartRouteLocalRuleSetFiles, smartRouteRuleSetCatalog, type SmartRouteRuleSetDescriptor } from './smartRoute'

const execFile = promisify(execFileCb)
const RULE_SET_CACHE_DIR = 'smart-route-rule-sets'
const DOWNLOAD_TIMEOUT_MS = 60_000

interface RuleSetFileMetadata {
  tag: string
  fileName: string
  url: string
  lastCheckedAt: number | null
  lastUpdatedAt: number | null
  size: number | null
  sha256: string | null
  lastError: string | null
  lastRoute: string | null
}

interface RuleSetMetadataStore {
  files: Record<string, RuleSetFileMetadata>
  lastRefreshStartedAt: number | null
  lastRefreshFinishedAt: number | null
  lastRefreshOk: boolean | null
  lastRefreshError: string | null
}

export interface SmartRouteRuleSetFileState extends RuleSetFileMetadata {
  label: string
  exists: boolean
  path: string
}

export interface SmartRouteRuleSetState {
  mode: AppSettings['smartRuRuleSetMode']
  autoUpdate: boolean
  useProxy: boolean
  updateIntervalHours: number
  activeSource: 'bundled' | 'managed'
  managedComplete: boolean
  managedDir: string
  bundledDir: string
  lastRefreshStartedAt: number | null
  lastRefreshFinishedAt: number | null
  lastRefreshOk: boolean | null
  lastRefreshError: string | null
  files: SmartRouteRuleSetFileState[]
}

const metadataStore = new Store<RuleSetMetadataStore>({
  name: 'smart-route-rule-sets',
  defaults: {
    files: {},
    lastRefreshStartedAt: null,
    lastRefreshFinishedAt: null,
    lastRefreshOk: null,
    lastRefreshError: null
  }
})

let refreshInFlight: Promise<SmartRouteRuleSetState> | null = null

export function getBundledSmartRouteRuleSetDir(): string {
  if (app.isPackaged) return process.resourcesPath
  return join(app.getAppPath(), 'resources')
}

export function getManagedSmartRouteRuleSetDir(): string {
  return join(app.getPath('userData'), RULE_SET_CACHE_DIR)
}

export function chooseSmartRouteRuleSetSource(
  settings: Pick<AppSettings, 'smartRuRuleSetMode'>,
  managedComplete: boolean
): 'managed' | 'bundled' {
  return settings.smartRuRuleSetMode === 'managed' && managedComplete ? 'managed' : 'bundled'
}

function metadataFor(descriptor: SmartRouteRuleSetDescriptor): RuleSetFileMetadata {
  const existing = metadataStore.get('files')?.[descriptor.fileName]
  return {
    tag: descriptor.tag,
    fileName: descriptor.fileName,
    url: descriptor.url,
    lastCheckedAt: existing?.lastCheckedAt ?? null,
    lastUpdatedAt: existing?.lastUpdatedAt ?? null,
    size: existing?.size ?? null,
    sha256: existing?.sha256 ?? null,
    lastError: existing?.lastError ?? null,
    lastRoute: existing?.lastRoute ?? null
  }
}

function saveFileMetadata(fileName: string, metadata: RuleSetFileMetadata): void {
  metadataStore.set('files', {
    ...(metadataStore.get('files') ?? {}),
    [fileName]: metadata
  })
}

function shortError(err: any): string {
  const stderr = typeof err?.stderr === 'string' ? err.stderr.trim() : ''
  const stdout = typeof err?.stdout === 'string' ? err.stdout.trim() : ''
  return (stderr || stdout || err?.message || String(err)).replace(/\s+/g, ' ').slice(0, 500)
}

async function sha256File(path: string): Promise<string> {
  const data = await readFile(path)
  return createHash('sha256').update(data).digest('hex')
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

async function buildFileState(descriptor: SmartRouteRuleSetDescriptor): Promise<SmartRouteRuleSetFileState> {
  const managedDir = getManagedSmartRouteRuleSetDir()
  const path = join(managedDir, descriptor.fileName)
  const metadata = metadataFor(descriptor)
  const exists = await fileExists(path)
  return {
    ...metadata,
    label: descriptor.label,
    exists,
    path
  }
}

export async function isManagedSmartRouteRuleSetComplete(): Promise<boolean> {
  const files = smartRouteLocalRuleSetFiles()
  const managedDir = getManagedSmartRouteRuleSetDir()
  for (const file of files) {
    try {
      const info = await stat(join(managedDir, file))
      if (!info.isFile() || info.size <= 0) return false
    } catch {
      return false
    }
  }
  return true
}

export async function getPreferredSmartRouteRuleSetSourceDir(): Promise<{
  source: 'bundled' | 'managed'
  dir: string
  managedComplete: boolean
}> {
  const settings = settingsStore.get()
  const managedComplete = await isManagedSmartRouteRuleSetComplete()
  const source = chooseSmartRouteRuleSetSource(settings, managedComplete)
  return {
    source,
    dir: source === 'managed' ? getManagedSmartRouteRuleSetDir() : getBundledSmartRouteRuleSetDir(),
    managedComplete
  }
}

export async function getSmartRouteRuleSetState(): Promise<SmartRouteRuleSetState> {
  const settings = settingsStore.get()
  const files = await Promise.all(smartRouteRuleSetCatalog().map(buildFileState))
  const managedComplete = await isManagedSmartRouteRuleSetComplete()
  const activeSource = chooseSmartRouteRuleSetSource(settings, managedComplete)
  return {
    mode: settings.smartRuRuleSetMode,
    autoUpdate: settings.smartRuRuleSetAutoUpdate,
    useProxy: settings.smartRuRuleSetUseProxy,
    updateIntervalHours: settings.smartRuRuleSetUpdateIntervalHours,
    activeSource,
    managedComplete,
    managedDir: getManagedSmartRouteRuleSetDir(),
    bundledDir: getBundledSmartRouteRuleSetDir(),
    lastRefreshStartedAt: metadataStore.get('lastRefreshStartedAt') ?? null,
    lastRefreshFinishedAt: metadataStore.get('lastRefreshFinishedAt') ?? null,
    lastRefreshOk: metadataStore.get('lastRefreshOk') ?? null,
    lastRefreshError: metadataStore.get('lastRefreshError') ?? null,
    files
  }
}

async function downloadRuleSet(descriptor: SmartRouteRuleSetDescriptor, settings: AppSettings): Promise<void> {
  const dir = getManagedSmartRouteRuleSetDir()
  await mkdir(dir, { recursive: true })
  const tmp = join(dir, `${descriptor.fileName}.tmp-${process.pid}-${Date.now()}`)
  const dst = join(dir, descriptor.fileName)
  const now = Date.now()
  const metadata = metadataFor(descriptor)
  const routeAttempts = buildBootstrapRouteAttempts({
    mode: settings.smartRuRuleSetUseProxy ? settings.bootstrapRouteMode : 'direct',
    proxyAddr: settings.proxyOverride,
    proxyType: settings.proxyType
  })
  if (!routeAttempts.length) {
    const message = 'bootstrap route has no usable download attempts'
    saveFileMetadata(descriptor.fileName, {
      ...metadata,
      lastCheckedAt: now,
      lastRoute: null,
      lastError: message
    })
    throw new Error(message)
  }

  const commonArgs = [
    '-L',
    '--fail',
    '--silent',
    '--show-error',
    '--connect-timeout',
    '15',
    '--max-time',
    '45'
  ]
  const errors: string[] = []

  for (const route of routeAttempts) {
    const args = [
      ...commonArgs,
      ...route.curlArgs,
      '--output',
      tmp,
      descriptor.url
    ]

    try {
      await execFile(process.platform === 'win32' ? 'curl.exe' : 'curl', args, {
        windowsHide: true,
        timeout: DOWNLOAD_TIMEOUT_MS,
        encoding: 'utf8',
        maxBuffer: 1024 * 1024
      })
      const info = await stat(tmp)
      if (!info.isFile() || info.size <= 0) {
        throw new Error('downloaded rule-set is empty')
      }
      const sha256 = await sha256File(tmp)
      await rename(tmp, dst)
      saveFileMetadata(descriptor.fileName, {
        ...metadata,
        lastCheckedAt: now,
        lastUpdatedAt: now,
        size: info.size,
        sha256,
        lastRoute: route.label,
        lastError: null
      })
      return
    } catch (err) {
      await unlink(tmp).catch(() => undefined)
      errors.push(`${route.label}: ${shortError(err)}`)
    }
  }

  const error = errors.join(' | ')
  saveFileMetadata(descriptor.fileName, {
    ...metadata,
    lastCheckedAt: now,
    lastRoute: null,
    lastError: error
  })
  throw new Error(error)
}

export async function refreshSmartRouteRuleSets(force = false): Promise<SmartRouteRuleSetState> {
  if (refreshInFlight) return refreshInFlight
  refreshInFlight = (async () => {
    const settings = settingsStore.get()
    const startedAt = Date.now()
    metadataStore.set('lastRefreshStartedAt', startedAt)
    metadataStore.set('lastRefreshFinishedAt', null)
    metadataStore.set('lastRefreshOk', null)
    metadataStore.set('lastRefreshError', null)

    const errors: string[] = []
    for (const descriptor of smartRouteRuleSetCatalog()) {
      try {
        if (!force) {
          const file = metadataFor(descriptor)
          const intervalMs = settings.smartRuRuleSetUpdateIntervalHours * 60 * 60 * 1000
          const fresh = file.lastUpdatedAt && Date.now() - file.lastUpdatedAt < intervalMs
          const exists = await fileExists(join(getManagedSmartRouteRuleSetDir(), descriptor.fileName))
          if (fresh && exists) continue
        }
        await downloadRuleSet(descriptor, settings)
      } catch (err) {
        errors.push(`${descriptor.fileName}: ${shortError(err)}`)
      }
    }

    const complete = await isManagedSmartRouteRuleSetComplete()
    const ok = complete && errors.length === 0
    const finishedAt = Date.now()
    metadataStore.set('lastRefreshFinishedAt', finishedAt)
    metadataStore.set('lastRefreshOk', ok)
    metadataStore.set('lastRefreshError', errors.length > 0 ? errors.join(' | ') : null)
    logEvent(ok ? 'info' : complete ? 'warn' : 'warn', 'smart-route', 'managed rule-set refresh finished', {
      ok,
      complete,
      errors
    })
    return getSmartRouteRuleSetState()
  })().finally(() => {
    refreshInFlight = null
  })
  return refreshInFlight
}

export async function maybeAutoRefreshSmartRouteRuleSets(reason: string): Promise<void> {
  const settings = settingsStore.get()
  if (!settings.smartRuSplit) return
  if (settings.smartRuRuleSetMode !== 'managed') return
  if (!settings.smartRuRuleSetAutoUpdate) return
  const state = await getSmartRouteRuleSetState()
  const last = state.lastRefreshFinishedAt || Math.max(...state.files.map((file) => file.lastUpdatedAt || 0), 0)
  const intervalMs = settings.smartRuRuleSetUpdateIntervalHours * 60 * 60 * 1000
  if (state.managedComplete && last > 0 && Date.now() - last < intervalMs) return
  logEvent('info', 'smart-route', 'managed rule-set auto-refresh scheduled', { reason })
  refreshSmartRouteRuleSets(false).catch((err) => {
    logEvent('warn', 'smart-route', 'managed rule-set auto-refresh failed', err)
  })
}
