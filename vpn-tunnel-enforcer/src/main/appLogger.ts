import { app, shell } from 'electron'
import { mkdir, open, readFile, stat, writeFile, appendFile } from 'fs/promises'
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

let queue = Promise.resolve()

export function getLogDir(): string {
  return join(app.getPath('userData'), 'logs')
}

export function getAppLogPath(): string {
  return join(getLogDir(), 'app.log')
}

function getTunLogDir(): string {
  return join(app.getPath('userData'), 'tun-runtime')
}

function normalizeDetail(value: unknown): unknown {
  if (value instanceof Error) {
    return redactSensitiveConfig({
      name: value.name,
      message: value.message,
      stack: value.stack
    })
  }

  if (typeof value === 'string') {
    const redacted = redactSensitiveText(value)
    return redacted.length > MAX_DETAIL_CHARS ? `${redacted.slice(0, MAX_DETAIL_CHARS)}...<truncated>` : redacted
  }

  try {
    const raw = JSON.stringify(value)
    if (!raw) return value
    const redacted = redactSensitiveConfig(value)
    const redactedRaw = JSON.stringify(redacted)
    if (!redactedRaw) return redacted
    if (redactedRaw.length <= MAX_DETAIL_CHARS) return redacted
    return `${redactedRaw.slice(0, MAX_DETAIL_CHARS)}...<truncated>`
  } catch {
    return redactSensitiveText(String(value))
  }
}

function formatLine(level: AppLogLevel, scope: string, message: string, details?: unknown): string {
  return JSON.stringify({
    ts: new Date().toISOString(),
    level,
    scope,
    message,
    details
  }) + '\n'
}

export function logEvent(level: AppLogLevel, scope: string, message: string, details?: unknown): void {
  const normalizedDetails = details === undefined ? undefined : normalizeDetail(details)
  const line = formatLine(level, scope, message, normalizedDetails)
  queue = queue
    .then(async () => {
      await mkdir(getLogDir(), { recursive: true })
      await appendFile(getAppLogPath(), line, 'utf8')
    })
    .catch(() => undefined)

  const consoleLine = `[${scope}] ${message}`
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
        return redactSensitiveText(line)
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

  if (/app\.log$/i.test(snapshot.path)) {
    return { ...snapshot, content: redactJsonLines(snapshot.content) }
  }

  return { ...snapshot, content: redactSensitiveText(snapshot.content) }
}

export async function getFullLogs(): Promise<LogFileSnapshot[]> {
  const files = [
    getAppLogPath(),
    join(getTunLogDir(), 'sing-box.log'),
    join(getTunLogDir(), 'sing-box.prev.log'),
    join(getTunLogDir(), 'sing-box.json')
  ]
  const snapshots = await Promise.all(files.map(file => readTail(file)))
  return snapshots.map(redactSnapshot)
}

export async function clearAppLog(): Promise<void> {
  await mkdir(getLogDir(), { recursive: true })
  await writeFile(getAppLogPath(), '', 'utf8')
}

export async function openLogFolder(): Promise<string> {
  await mkdir(getLogDir(), { recursive: true })
  await shell.openPath(getLogDir())
  return getLogDir()
}
