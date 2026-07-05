import { app, shell } from 'electron'
import { mkdir, open, readFile, stat, writeFile, appendFile, unlink } from 'fs/promises'
import { join } from 'path'
import { redactSensitiveConfig, redactSensitiveText } from './vpnProfiles'

export type AppLogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LogFileSnapshot {
  name: string
  path: string
  exists: boolean
  size: number
  truncated: boolean
  content: string
}

const MAX_DETAIL_CHARS = 4000
const MAX_READ_BYTES = 1024 * 1024
const TOPOLOGY_KEY_RE = /ip|ipv4|ipv6|address|addr|host|hostname|server|proxy|dns|adapter|alias|interface|ifindex|gateway|route|mac|endpoint|url|path/i
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
const IPV6_RE = /\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}(?:%\w+)?\b/gi
const MAC_RE = /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi

// Size-based rotation for app.log. Without this the file grows forever —
// every IPC call logs at debug level, so over weeks of uptime the log can
// reach hundreds of MB, which (a) slows the append queue, (b) fills the user's
// disk, and (c) makes the diagnostics ZIP huge. When app.log crosses
// MAX_LOG_BYTES we rename it to app.prev.log (replacing any older generation)
// and start a fresh file. We keep exactly one previous generation — enough for
// support to see what happened before the roll, bounded at 2x the cap total.
const MAX_LOG_BYTES = 5 * 1024 * 1024

let queue = Promise.resolve()
// Cheap in-memory tally so we don't `stat()` the file on every single log
// line. We stat lazily (first write after startup) to seed it, then track
// growth from the byte length we append.
let currentLogBytes = -1

export function getLogDir(): string {
  return join(app.getPath('userData'), 'logs')
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
    if (currentLogBytes + incomingBytes <= MAX_LOG_BYTES) return
    // Roll: app.log → app.prev.log (overwrite the older generation).
    const { rename, unlink } = await import('fs/promises')
    await unlink(getAppLogPrevPath()).catch(() => undefined)
    await rename(getAppLogPath(), getAppLogPrevPath()).catch(() => undefined)
    currentLogBytes = 0
  } catch {
    // Leave currentLogBytes as-is; we'll retry on the next write.
  }
}

function getTunLogDir(): string {
  return join(app.getPath('userData'), 'tun-runtime')
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
    return keyLooksSensitive ? '<redacted-topology>' : value
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
    return redactTopologyValue(redactSensitiveConfig({
      name: value.name,
      message: value.message,
      stack: value.stack
    }))
  }

  if (typeof value === 'string') {
    const redacted = redactTopologyText(redactSensitiveText(value))
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

function formatLine(level: AppLogLevel, scope: string, message: string, details?: unknown): string {
  const normalizedMessage = redactTopologyText(redactSensitiveText(message))
  return JSON.stringify({
    ts: new Date().toISOString(),
    level,
    scope,
    message: normalizedMessage,
    details
  }) + '\n'
}

export function logEvent(level: AppLogLevel, scope: string, message: string, details?: unknown): void {
  const normalizedDetails = details === undefined ? undefined : normalizeDetail(details)
  const normalizedMessage = redactTopologyText(redactSensitiveText(message))
  const line = formatLine(level, scope, normalizedMessage, normalizedDetails)
  const lineBytes = Buffer.byteLength(line, 'utf8')
  queue = queue
    .then(async () => {
      await mkdir(getLogDir(), { recursive: true })
      await rotateIfNeeded(lineBytes)
      await appendFile(getAppLogPath(), line, 'utf8')
      // Track growth so we only stat() the file once per process.
      if (currentLogBytes >= 0) currentLogBytes += lineBytes
    })
    .catch(() => undefined)

  const consoleLine = `[${scope}] ${normalizedMessage}`
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
          return JSON.stringify(redactTopologyValue(JSON.parse(line)))
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
    join(getTunLogDir(), 'sing-box.json')
  ]
  const snapshots = await Promise.all(files.map(file => readTail(file)))
  return snapshots.map(redactSnapshot)
}

export async function clearAppLog(): Promise<void> {
  queue = queue.then(async () => {
    await mkdir(getLogDir(), { recursive: true })
    await mkdir(getTunLogDir(), { recursive: true }).catch(() => undefined)
    await Promise.all([
      writeFile(getAppLogPath(), '', 'utf8'),
      unlink(getAppLogPrevPath()).catch(() => undefined),
      writeFile(join(getTunLogDir(), 'sing-box.log'), '', 'utf8').catch(() => undefined),
      unlink(join(getTunLogDir(), 'sing-box.prev.log')).catch(() => undefined)
    ])
    currentLogBytes = 0
  })
  await queue
}

export async function openLogFolder(): Promise<string> {
  await mkdir(getLogDir(), { recursive: true })
  await shell.openPath(getLogDir())
  return getLogDir()
}
