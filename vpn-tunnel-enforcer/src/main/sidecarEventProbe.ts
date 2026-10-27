// AT-08-007 / F-197: incremental, bounded preview; raw evidence stays on disk.
import { open, stat, type FileHandle } from 'fs/promises'

const CHUNK_BYTES = 64 * 1024
const MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_LINE_BYTES = 1024 * 1024
const MAX_KEYS = 4096

export interface SidecarEventProbe {
  events: number
  dataEvents: number
  engine: string | null
  categoryCounts: Record<string, number>
  wfpBlocks: number
  topDomains: Array<{ name: string; count: number }>
  topRemotes: Array<{ address: string; count: number }>
  lastDataEventAt: number | null
  warning?: string
}

export function emptySidecarEventProbe(warning?: string): SidecarEventProbe {
  return { events: 0, dataEvents: 0, engine: null, categoryCounts: {}, wfpBlocks: 0,
    topDomains: [], topRemotes: [], lastDataEventAt: null, ...(warning ? { warning } : {}) }
}

interface Cursor {
  key: string
  identity: string
  offset: number
  size: number
  mtime: number
  head: Buffer
  tail: Buffer
  partial: Buffer
  probe: SidecarEventProbe
  domains: Map<string, number>
  remotes: Map<string, number>
}

const identity = (info: { dev: number; ino: number; birthtimeMs: number }) => `${info.dev}:${info.ino}:${info.birthtimeMs}`

async function bytesAt(file: FileHandle, position: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length)
  const { bytesRead } = await file.read(buffer, 0, length, position)
  if (bytesRead !== length) throw new Error('sidecar file changed during read')
  return buffer
}

function count(map: Map<string, number>, key: string): void {
  if (key.length > 1024 || (!map.has(key) && map.size >= MAX_KEYS)) throw new Error('sidecar preview capacity exceeded')
  map.set(key, (map.get(key) ?? 0) + 1)
}

function addLine(cursor: Cursor, line: Buffer, sessionId: string): void {
  const text = line.toString('utf8').trim()
  if (!text) return
  const probe = cursor.probe
  probe.events++
  let row: Record<string, unknown>
  try {
    const parsed: unknown = JSON.parse(text)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid event')
    row = parsed as Record<string, unknown>
  } catch {
    probe.warning = 'sidecar event preview contains malformed records'
    return
  }
  if (row.session !== sessionId) {
    probe.warning = 'sidecar event preview contains invalid session identity'
    return
  }
  const category = typeof row.category === 'string' ? row.category : 'other'
  if (category === 'lifecycle') {
    if (typeof row.engine === 'string' && row.engine) probe.engine = row.engine
    return
  }
  if (category === 'health') return
  if (category.length > 256 || (!Object.hasOwn(probe.categoryCounts, category) && Object.keys(probe.categoryCounts).length >= MAX_KEYS)) {
    throw new Error('sidecar preview capacity exceeded')
  }
  probe.dataEvents++
  Object.defineProperty(probe.categoryCounts, category, { value: (Object.hasOwn(probe.categoryCounts, category) ? probe.categoryCounts[category] : 0) + 1, writable: true, enumerable: true, configurable: true })
  if (category === 'wfp' && (row.event === 'block' || row.action === 'block' || row.action === 'drop')) probe.wfpBlocks++
  if (typeof row.queryName === 'string' && row.queryName) count(cursor.domains, row.queryName)
  if (typeof row.remoteAddress === 'string' && row.remoteAddress) count(cursor.remotes, row.remotePort ? `${row.remoteAddress}:${row.remotePort}` : row.remoteAddress)
  if (typeof row.ts === 'string') {
    const time = Date.parse(row.ts)
    if (Number.isFinite(time)) probe.lastDataEventAt = time
  }
}

function consume(cursor: Cursor, chunk: Buffer, sessionId: string): void {
  const bytes = cursor.partial.length ? Buffer.concat([cursor.partial, chunk]) : chunk
  let start = 0
  let end: number
  while ((end = bytes.indexOf(10, start)) !== -1) {
    if (end - start > MAX_LINE_BYTES) throw new Error('sidecar event line exceeds preview limit')
    addLine(cursor, bytes.subarray(start, end), sessionId)
    start = end + 1
  }
  if (bytes.length - start > MAX_LINE_BYTES) throw new Error('sidecar event line exceeds preview limit')
  cursor.partial = Buffer.from(bytes.subarray(start))
}

function snapshot(cursor: Cursor): SidecarEventProbe {
  const top = (map: Map<string, number>) => [...map].sort((a, b) => b[1] - a[1]).slice(0, 5)
  return { ...cursor.probe, categoryCounts: { ...cursor.probe.categoryCounts },
    topDomains: top(cursor.domains).map(([name, count]) => ({ name, count })),
    topRemotes: top(cursor.remotes).map(([address, count]) => ({ address, count })) }
}

export function createSidecarEventProbeReader() {
  let cursor: Cursor | null = null
  let queue: Promise<unknown> = Promise.resolve()
  let blocked: { key: string; identity: string; size: number; mtime: number } | null = null
  async function read(path: string, sessionId: string): Promise<SidecarEventProbe> {
    let file: FileHandle | undefined
    const key = `${sessionId}\0${path}`
    try {
      file = await open(path, 'r')
      const info = await file.stat()
      if (!info.isFile()) throw new Error('sidecar events is not a file')
      const fileIdentity = identity(info)
      if (blocked?.key === key && blocked.identity === fileIdentity && info.size >= blocked.size
        && !(info.size === blocked.size && info.mtimeMs !== blocked.mtime)) {
        return emptySidecarEventProbe('sidecar event preview exceeds bounded capacity')
      }
      let reset = !cursor || cursor.key !== key || cursor.identity !== fileIdentity || info.size < cursor.offset
        || (info.size <= cursor.size && info.mtimeMs !== cursor.mtime)
      if (!reset && cursor) {
        reset = !(await bytesAt(file, 0, cursor.head.length)).equals(cursor.head)
          || !(await bytesAt(file, cursor.offset - cursor.tail.length, cursor.tail.length)).equals(cursor.tail)
      }
      if (reset) {
        blocked = null
        cursor = { key, identity: fileIdentity, offset: 0, size: info.size, mtime: info.mtimeMs, head: Buffer.alloc(0), tail: Buffer.alloc(0),
          partial: Buffer.alloc(0), probe: emptySidecarEventProbe(), domains: new Map(), remotes: new Map() }
      }
      const active = cursor!
      active.size = info.size
      active.mtime = info.mtimeMs
      const target = Math.min(info.size, active.offset + MAX_READ_BYTES)
      while (active.offset < target) {
        const bytes = await bytesAt(file, active.offset, Math.min(CHUNK_BYTES, target - active.offset))
        consume(active, bytes, sessionId)
        active.offset += bytes.length
      }
      active.head = await bytesAt(file, 0, Math.min(64, active.offset))
      active.tail = await bytesAt(file, Math.max(0, active.offset - 64), Math.min(64, active.offset))
      const after = await stat(path)
      if (identity(after) !== fileIdentity || after.size < active.offset) throw new Error('sidecar file replaced during read')
      active.size = info.size
      active.mtime = info.mtimeMs
      if (active.offset < info.size) return emptySidecarEventProbe('sidecar event preview is catching up')
      return snapshot(active)
    } catch (error) {
      if (cursor && /capacity|line exceeds/.test((error as Error).message)) blocked = { key, identity: cursor.identity, size: cursor.size, mtime: cursor.mtime }
      cursor = null
      return emptySidecarEventProbe('sidecar event preview is unavailable')
    } finally {
      await file?.close()
    }
  }
  return {
    read(path: string, sessionId: string): Promise<SidecarEventProbe> {
      const result = queue.then(() => read(path, sessionId))
      queue = result.catch(() => undefined)
      return result
    }
  }
}
