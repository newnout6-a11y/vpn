import { open, rm } from 'fs/promises'
import { renameSync } from 'fs'
import { randomUUID } from 'crypto'
import { dirname, join } from 'path'
import type { OperationLease } from './operationRegistry'

const MAX_CONFIG_IMPORT_BYTES = 16 * 1024 * 1024
type RejectRead = (code: 'file-too-large' | 'file-not-regular' | 'file-changed', reason?: 'validation' | 'conflict') => never

/** Capture bounded bytes from one handle; cancellation retains ownership until close. */
export async function readSelectedConfig(path: string, lease: OperationLease, reject: RejectRead): Promise<string> {
  const file = await open(path, 'r')
  try {
    lease.assertActive()
    const before = await file.stat()
    lease.assertActive()
    if (!before.isFile()) reject('file-not-regular')
    if (before.size > MAX_CONFIG_IMPORT_BYTES) reject('file-too-large')
    const buffer = Buffer.alloc(before.size + 1)
    let length = 0
    while (length < buffer.length) {
      lease.assertActive()
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, null)
      if (!bytesRead) break
      length += bytesRead
    }
    const after = await file.stat()
    lease.assertActive()
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) reject('file-changed', 'conflict')
    return buffer.subarray(0, length).toString('utf8')
  } finally { await file.close() }
}

/** The chosen destination changes only at a synchronous, terminal rename.
 * On cancellation, wait for raw staging/close before removing our own temp file. */
export async function writeConfigExport<T>(path: string, content: string, lease: OperationLease, result: T): Promise<T> {
  const temporary = join(dirname(path), `.vpnte-export-${randomUUID()}.tmp`)
  let created = false
  const staging = (async () => {
    const file = await open(temporary, 'wx', 0o600)
    created = true
    try {
      lease.assertActive()
      await file.writeFile(content, { encoding: 'utf8', signal: lease.signal })
      lease.assertActive()
      await file.sync()
    } finally { await file.close() }
  })()
  try {
    await lease.wait(staging)
    return lease.commit(() => {
      renameSync(temporary, path)
      created = false
      return result
    })
  } finally {
    await staging.catch(() => {})
    if (created) await rm(temporary, { force: true })
  }
}
