import { open } from 'node:fs/promises'
import { isAppEvent } from '../shared/app-event'

const MAX_ROW_BYTES = 256 * 1024
const MAX_SCAN_BYTES = 32 * 1024 * 1024

/** Scan a fixed file snapshot with bounded memory, never rewriting evidence. */
export async function inspectAuditLog(path: string): Promise<{ invalidRows: number; needsSeparator: boolean; complete: boolean }> {
  let handle
  try { handle = await open(path, 'r') } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { invalidRows: 0, needsSeparator: false, complete: true }
    throw error
  }
  try {
    const info = await handle.stat()
    if (!info.isFile()) throw new Error('Audit history is not a regular file')
    const { size } = info
    const last = Buffer.alloc(1)
    if (size) await handle.read(last, 0, 1, size - 1)
    const needsSeparator = size > 0 && last[0] !== 10
    const buffer = Buffer.alloc(64 * 1024)
    const row = Buffer.alloc(MAX_ROW_BYTES)
    const decoder = new TextDecoder('utf-8', { fatal: true })
    let length = 0, oversized = false, invalidRows = 0, position = 0
    const checkRow = () => {
      try {
        if (oversized || !isAppEvent(JSON.parse(decoder.decode(row.subarray(0, length))))) invalidRows++
      } catch { invalidRows++ }
      length = 0; oversized = false
    }
    const limit = Math.min(size, MAX_SCAN_BYTES)
    while (position < limit) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, limit - position), position)
      if (!bytesRead) break
      position += bytesRead
      for (let i = 0; i < bytesRead; i++) {
        if (buffer[i] === 10) checkRow()
        else if (length < MAX_ROW_BYTES) row[length++] = buffer[i]
        else oversized = true
      }
    }
    const complete = position === size
    if (complete && (length || oversized)) checkRow()
    return { invalidRows, needsSeparator, complete }
  } finally { await handle.close() }
}
