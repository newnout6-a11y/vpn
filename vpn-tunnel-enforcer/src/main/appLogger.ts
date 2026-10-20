import { classifyIpcError, ipcError, IpcFault } from '../shared/ipc-result'
import type { DiagnosticClearReport, DiagnosticArtifact } from '../shared/diagnostics'
import type { LogFileSnapshot } from '../shared/diagnostics'
export type { LogFileSnapshot } from '../shared/diagnostics'
import { app, shell } from 'electron'
import { mkdir, open, readFile, stat, writeFile, appendFile, unlink, truncate } from 'fs/promises'
import { join } from 'path'
import { getPrivilegedRuntimeDir } from './runtimePaths'
import { directoryExists, verifyDirectoryHardened } from './runtimeDirSecurity'
import { redactSensitiveConfig, redactSensitiveText } from './vpnProfiles'
import { watchEngineLogs } from './engineLogRetention'
import { currentActionMetadata, currentCorrelationId } from './actionCorrelation'
import { eventClockId, monotonicTimeMs } from './eventClock'
import { inspectAuditLog } from './auditLogIntegrity'
import type { AppEvent, AppLogLevel } from '../shared/app-event'
import { isAppEvent } from '../shared/app-event'

export type { AppLogLevel } from '../shared/app-event'

const MAX_DETAIL_CHARS = 4000
const MAX_READ_BYTES = 1024 * 1024
const TOPOLOGY_KEY_RE = /ip|ipv4|ipv6|address|addr|host|hostname|server|proxy|dns|adapter|alias|interface|ifindex|gateway|route|mac|endpoint|url|path/i
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
const IPV6_RE = /\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}(?:%\w+)?\b/gi
const MAC_RE = /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })
const WINDOWS_1251_DECODER = new TextDecoder('windows-1251')
const WINDOWS_1251_BYTES = new Map<string, number>()
for (let byte = 0; byte <= 255; byte += 1) {
  WINDOWS_1251_BYTES.set(WINDOWS_1251_DECODER.decode(Uint8Array.of(byte)), byte)
}

/** Repair UTF-8 bytes that were accidentally decoded as Windows-1251. */
export function repairMojibake(value: string): string {
  if (!/[РС][\u0400-\u04ff]|вЂ|в„|В[«»·]/.test(value)) return value
  const bytes: number[] = []
  for (const char of value) {
    const byte = WINDOWS_1251_BYTES.get(char)
    if (byte === undefined) return value
    bytes.push(byte)
  }
  try {
    const repaired = UTF8_DECODER.decode(Uint8Array.from(bytes))
    return repaired && !repaired.includes('\uFFFD') ? repaired : value
  } catch {
    return value
  }
}

// Size-based rotation for app.log. Without this the file grows forever —
// every IPC call logs at debug level, so over weeks of uptime the log can
// reach hundreds of MB, which (a) slows the append queue, (b) fills the user's
// disk, and (c) makes the diagnostics ZIP huge. When app.log crosses
// MAX_LOG_BYTES we rename it to app.prev.log (replacing any older generation)
// and start a fresh file. We keep exactly one previous generation — enough for
// support to see what happened before the roll, bounded at 2x the cap total.
const MAX_LOG_BYTES = 5 * 1024 * 1024
// Startup reports must not evict evidence earlier than ordinary events would.
// The allowance is bounded even if a partially failed scan/write is retried.
const MAX_INTEGRITY_MARKER_BYTES = 4096

// 2 x 5 MiB app generations + 2 x 10 MiB for each engine = 50 MiB.
let engineLogWatcher: ReturnType<typeof watchEngineLogs> | null = null
export function startEngineLogRetention(): () => Promise<void> {
  if (!engineLogWatcher) {
    const directory = getTunLogDir()
    engineLogWatcher = watchEngineLogs(directory, async () => {
      const acl = await verifyDirectoryHardened(directory)
      if (!acl.hardened) throw new Error('RuntimeSecurityAclError: engine log namespace is untrusted')
    }, error => logEvent('warn', 'logs', 'Engine log rotation failed; will retry', error))
  }
  return async () => {
    const watcher = engineLogWatcher
    engineLogWatcher = null
    await watcher?.stop()
  }
}

let queue = Promise.resolve()
// Cheap in-memory tally so we don't `stat()` the file on every single log
// line. We stat lazily (first write after startup) to seed it, then track
// growth from the byte length we append.
let currentLogBytes = -1
let integrityChecked = false
let integrityMarkerBytes = 0

export function getLogDir(): string {
  return join(app.getPath('userData'), 'logs')
}

let logDirEnsured = false

async function ensureLogDir(): Promise<void> {
  if (logDirEnsured) return
  await mkdir(getLogDir(), { recursive: true })
  logDirEnsured = true
}

export function getAppLogPath(): string {
  return join(getLogDir(), 'app.log')
}

function getAppLogPrevPath(): string {
  return join(getLogDir(), 'app.prev.log')
}

/**
 * Rotate app.log if it has grown past the cap. Called inside the serialized
 * write queue so it can't race with appends. Best-effort: any failure leaves
 * the current log in place (we'd rather keep logging to a big file than lose
 * logging entirely).
 */
async function rotateIfNeeded(incomingBytes: number): Promise<void> {
  try {
    if (currentLogBytes < 0) {
      // Seed from disk once.
      try {
        currentLogBytes = (await stat(getAppLogPath())).size
      } catch {
        currentLogBytes = 0
      }
    }
    if (currentLogBytes + incomingBytes <= MAX_LOG_BYTES + integrityMarkerBytes) return
    // Roll: app.log → app.prev.log (overwrite the older generation).
    const { rename, unlink, stat: fsStat } = await import('fs/promises')
    await unlink(getAppLogPrevPath()).catch(() => undefined)
    try {
      await rename(getAppLogPath(), getAppLogPrevPath())
      currentLogBytes = 0
      integrityMarkerBytes = 0
    } catch {
      // If rename failed (e.g. file locked), do NOT reset counter to 0. Re-stat from disk.
      try {
        currentLogBytes = (await fsStat(getAppLogPath())).size
      } catch {
        // Leave currentLogBytes as-is
      }
    }
  } catch {
    // Leave currentLogBytes as-is; we'll retry on the next write.
  }
}

function getTunLogDir(): string {
  return getPrivilegedRuntimeDir('tun-runtime')
}

function redactTopologyText(value: string): string {
  return value
    .replace(IPV4_RE, '<redacted-ip>')
    .replace(MAC_RE, '<redacted-mac>')
    .replace(IPV6_RE, '<redacted-ipv6>')
}

function redactTopologyValue(value: unknown, key?: string): unknown {
  const keyLooksSensitive = key ? TOPOLOGY_KEY_RE.test(key) : false
  if (typeof value === 'string') {
    const redacted = redactTopologyText(value)
    return keyLooksSensitive && redacted === value && value.trim() ? '<redacted-topology>' : redacted
  }
  if (typeof value === 'number') {
    return value
  }
  if (Array.isArray(value)) return value.map(item => redactTopologyValue(item, key))
  if (value && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [childKey, raw] of Object.entries(value as Record<string, unknown>)) {
      result[childKey] = redactTopologyValue(raw, childKey)
    }
    return result
  }
  return value
}

function normalizeDetail(value: unknown): unknown {
  if (value instanceof Error) {
    // Error fields need the same post-redaction size bound as other objects.
    value = { name: value.name, message: value.message, stack: value.stack }
  }

  if (typeof value === 'string') {
    const redacted = redactTopologyText(redactSensitiveText(repairMojibake(value)))
    return redacted.length > MAX_DETAIL_CHARS ? `${redacted.slice(0, MAX_DETAIL_CHARS)}...<truncated>` : redacted
  }

  try {
    const raw = JSON.stringify(value)
    if (!raw) return value
    const redacted = redactTopologyValue(redactSensitiveConfig(value))
    const redactedRaw = JSON.stringify(redacted)
    if (!redactedRaw) return redacted
    if (redactedRaw.length <= MAX_DETAIL_CHARS) return redacted
    return `${redactedRaw.slice(0, MAX_DETAIL_CHARS)}...<truncated>`
  } catch {
    return redactSensitiveText(String(value))
  }
}

type PendingEvent = Omit<AppEvent, 'version' | 'ts' | 'monotonicMs' | 'clockId'> & { ts?: string }

function formatLine(event: PendingEvent): string {
  return JSON.stringify({
    version: 1,
    ts: new Date().toISOString(),
    monotonicMs: monotonicTimeMs(),
    clockId: eventClockId,
    ...event
  } satisfies AppEvent) + '\n'
}

async function appendLine(line: string, integrityMarker = false): Promise<void> {
  const lineBytes = Buffer.byteLength(line, 'utf8')
  if (integrityMarker) integrityMarkerBytes = Math.min(MAX_INTEGRITY_MARKER_BYTES, integrityMarkerBytes + lineBytes)
  await rotateIfNeeded(lineBytes)
  try {
    await appendFile(getAppLogPath(), line, 'utf8')
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
    logDirEnsured = false
    await ensureLogDir()
    await appendFile(getAppLogPath(), line, 'utf8')
  }
  if (currentLogBytes >= 0) currentLogBytes += lineBytes
}

async function checkHistory(): Promise<void> {
  if (integrityChecked) return
  // No recursive logEvent calls: markers precede the admitted event in this queue.
  const generations = ['current', 'previous'] as const
  const snapshots = await Promise.all(generations.map(generation =>
    inspectAuditLog(generation === 'current' ? getAppLogPath() : getAppLogPrevPath()).catch(() => undefined)))
  for (const [index, generation] of generations.entries()) {
    const result = snapshots[index]
    if (generation === 'current' && result?.needsSeparator) {
      await appendFile(getAppLogPath(), '\n', 'utf8')
      if (currentLogBytes >= 0) currentLogBytes++
    }
    const messages: string[] = []
    if (result?.invalidRows) messages.push('history.corrupted')
    if (!result?.complete) messages.push('history.unavailable')
    for (const message of messages) {
      const details = { generation, ...(result ? { invalidRows: result.invalidRows, complete: result.complete } : { complete: false }) }
      console.error(`[logs] ${message}`, details)
      await appendLine(formatLine({ level: 'error', scope: 'logs', message, details,
        source: 'lifecycle', owner: 'unknown', route: 'unconfirmed', confidence: 'indeterminate' }), true)
    }
  }
  integrityChecked = true
}

/** Drain admitted writes; does not claim fsync or persistence after an I/O fault. */
export async function flushAppLog(): Promise<void> {
  await queue
}

export function logEvent(level: AppLogLevel, scope: string, message: string, details?: unknown): void {
  const normalizedDetails = details === undefined ? undefined : normalizeDetail(details)
  const normalizedMessage = redactTopologyText(redactSensitiveText(repairMojibake(message))).slice(0, MAX_DETAIL_CHARS)
  const correlationId = currentCorrelationId()
  const metadata = currentActionMetadata()
  const event: PendingEvent = { ts: new Date().toISOString(), level, scope: redactTopologyText(redactSensitiveText(scope)).slice(0, MAX_DETAIL_CHARS), message: normalizedMessage, details: normalizedDetails,
    source: metadata?.source ?? 'unknown', owner: metadata?.owner ?? 'unknown', route: 'unconfirmed', confidence: 'indeterminate',
    ...(correlationId ? { correlationId } : {}) }
  queue = queue
    .then(async () => {
      await ensureLogDir()
      await checkHistory()
      await appendLine(formatLine(event))
    })
    .catch(() => { console.error('[logs] history.write-failed') })

  const consoleLine = `[${event.scope}] ${normalizedMessage}`
  if (level === 'error') console.error(consoleLine, normalizedDetails ?? '')
  else if (level === 'warn') console.warn(consoleLine, normalizedDetails ?? '')
  else console.log(consoleLine, normalizedDetails ?? '')
}

async function readTail(path: string, maxBytes = MAX_READ_BYTES): Promise<LogFileSnapshot> {
  try {
    const info = await stat(path)
    if (info.size <= maxBytes) {
      return {
        name: path.split(/[\\/]/).pop() || path,
        path,
        exists: true,
        size: info.size,
        truncated: false,
        content: await readFile(path, 'utf8')
      }
    }

    const handle = await open(path, 'r')
    try {
      const buffer = Buffer.alloc(maxBytes)
      await handle.read(buffer, 0, maxBytes, Math.max(0, info.size - maxBytes))
      return {
        name: path.split(/[\\/]/).pop() || path,
        path,
        exists: true,
        size: info.size,
        truncated: true,
        content: buffer.toString('utf8')
      }
    } finally {
      await handle.close()
    }
  } catch {
    return {
      name: path.split(/[\\/]/).pop() || path,
      path,
      exists: false,
      size: 0,
      truncated: false,
      content: ''
    }
  }
}

function redactJsonLines(content: string): string {
  return content
    .split(/\r?\n/)
    .map((line) => {
      if (!line.trim()) return line
      try {
        return JSON.stringify(redactSensitiveConfig(JSON.parse(line)))
      } catch {
        return redactTopologyText(redactSensitiveText(line))
      }
    })
    .join('\n')
}

function redactSnapshot(snapshot: LogFileSnapshot): LogFileSnapshot {
  if (!snapshot.content.trim()) return snapshot
  if (/sing-box\.json$/i.test(snapshot.path)) {
    try {
      const redacted = redactSensitiveConfig(JSON.parse(snapshot.content))
      return {
        ...snapshot,
        content: JSON.stringify(redacted, null, 2)
      }
    } catch {
      return { ...snapshot, content: '<redacted: sing-box config>' }
    }
  }

  if (/app(?:\.prev)?\.log$/i.test(snapshot.path)) {
    const content = redactJsonLines(snapshot.content)
      .split(/\r?\n/)
      .map(line => {
        if (!line.trim()) return line
        try {
          const row = JSON.parse(line)
          const redacted = redactTopologyValue(row)
          // Only the validated root mechanism enum is safe; nested routes still redact.
          if (isAppEvent(row) && row.version === 1 && redacted && typeof redacted === 'object') {
            (redacted as Record<string, unknown>).route = row.route
          }
          return JSON.stringify(redacted)
        } catch {
          return redactTopologyText(line)
        }
      })
      .join('\n')
    return { ...snapshot, content }
  }

  return { ...snapshot, content: redactTopologyText(redactSensitiveText(snapshot.content)) }
}

export async function getFullLogs(): Promise<LogFileSnapshot[]> {
  const files = [
    getAppLogPath(),
    getAppLogPrevPath(),
    join(getTunLogDir(), 'sing-box.log'),
    join(getTunLogDir(), 'sing-box.prev.log'),
    join(getTunLogDir(), 'xray.log'),
    join(getTunLogDir(), 'xray.prev.log'),
    join(getTunLogDir(), 'sing-box.json')
  ]
  const snapshots = await Promise.all(files.map(file => readTail(file)))
  return snapshots.map(redactSnapshot)
}

export async function clearAppLog(): Promise<DiagnosticClearReport> {
  const report: DiagnosticClearReport = { success: true, cleared: [], absent: [], errors: [] }
  const cleanup = queue.catch(() => undefined).then(async () => {
    // Finish rollover before clearing so it cannot republish old generations.
    const watcher = engineLogWatcher
    engineLogWatcher = null
    try {
      await watcher?.stop()
      await ensureLogDir()
      const tunLogDir = getTunLogDir()
      const hasTunLogs = await directoryExists(tunLogDir)
      if (hasTunLogs) {
        const acl = await verifyDirectoryHardened(tunLogDir)
        if (!acl.hardened) throw new IpcFault('permission')
      }
      const targets: Array<{ artifact: DiagnosticArtifact; path: string; remove?: boolean }> = [
        { artifact: 'app-log', path: getAppLogPath() },
        { artifact: 'app-previous-log', path: getAppLogPrevPath(), remove: true },
        ...(hasTunLogs ? [
          { artifact: 'sing-box-log' as const, path: join(tunLogDir, 'sing-box.log') },
          { artifact: 'sing-box-previous-log' as const, path: join(tunLogDir, 'sing-box.prev.log'), remove: true },
          { artifact: 'xray-log' as const, path: join(tunLogDir, 'xray.log') },
          { artifact: 'xray-previous-log' as const, path: join(tunLogDir, 'xray.prev.log'), remove: true }
        ] : [])
      ]
      const results = await Promise.allSettled(targets.map(async target => {
        try {
          if (target.remove) await unlink(target.path)
          else await truncate(target.path, 0)
          return 'cleared' as const
        } catch (error) {
          if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return 'absent' as const
          throw error
        }
      }))
      results.forEach((result, index) => {
        const artifact = targets[index].artifact
        if (result.status === 'fulfilled') report[result.value].push(artifact)
        else {
          report.errors.push({ artifact, error: ipcError(classifyIpcError(result.reason)) })
          logEvent('error', 'diagnostics', `log cleanup failed: ${artifact}`, result.reason)
        }
      })
      report.success = report.errors.length === 0
      if (report.cleared.includes('app-log') || report.absent.includes('app-log')) {
        currentLogBytes = 0
        integrityMarkerBytes = 0
      }
    } finally {
      if (watcher) startEngineLogRetention()
    }
  })
  // Callers see rejection; later audit writes must still append to a healthy lane.
  queue = cleanup.catch(() => undefined)
  await cleanup
  return report
}

export async function openLogFolder(): Promise<string> {
  await ensureLogDir()
  const error = await shell.openPath(getLogDir())
  if (error) throw new Error(error)
  return getLogDir()
}
