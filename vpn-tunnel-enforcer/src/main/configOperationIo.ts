import { open, rm } from 'fs/promises'
import { lstatSync, renameSync, type BigIntStats } from 'fs'
import { randomUUID } from 'crypto'
import { dirname, join } from 'path'
import type { OperationLease, SynchronousCommitResult } from './operationRegistry'
import { ConfigExportCreationFault, createPrivateConfigExport, prepareConfigExport } from './configExportSecurity'
import { logEvent } from './appLogger'
import { classifyIpcError, IpcFault } from '../shared/ipc-result'

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
export async function writeConfigExport<T>(path: string, content: string | AsyncIterable<Uint8Array>, lease: OperationLease, result: SynchronousCommitResult<T>, mode: 'redacted' | 'secrets'): Promise<T> {
  const temporary = join(dirname(path), `.vpnte-export-${randomUUID()}.tmp`)
  let created = false
  let identity: { dev: bigint; ino: bigint } | undefined
  let verifyDestination!: () => void
  const verifyIdentity = (current: BigIntStats) => {
    if (!identity || !current.isFile() || current.dev !== identity.dev || current.ino !== identity.ino) throw new IpcFault('conflict')
  }
  const staging = (async () => {
    if (process.platform === 'win32' && mode === 'secrets') {
      try { identity = await createPrivateConfigExport(temporary) }
      catch (error) {
        // A timeout after CreateNew can leave an empty private file. Without
        // confirmed identity, never delete an unrelated colliding/replaced path.
        if (!(error instanceof ConfigExportCreationFault) || error.indeterminate) try { logEvent('warn', 'config-manager', 'config export staging creation not confirmed', {
          operationKey: 'op_' + lease.operation.operationId.replaceAll('-', ''), cleanupFailed: true, reason: classifyIpcError(error)
        }) } catch { /* Preserve the original bounded failure. */ }
        throw error
      }
      created = true
    }
    const file = await open(temporary, created ? 'r+' : 'wx', 0o600)
    created = true
    try {
      const opened = await file.stat({ bigint: true })
      if (identity) verifyIdentity(opened)
      else identity = { dev: opened.dev, ino: opened.ino }
      lease.assertActive()
      verifyDestination = await prepareConfigExport(temporary, path, mode)
      lease.assertActive()
      await file.writeFile(content, { encoding: 'utf8', signal: lease.signal })
      lease.assertActive()
      await file.sync()
    } finally { await file.close() }
  })()
  try {
    await lease.wait(staging)
    return lease.commit(() => {
      const current = lstatSync(temporary, { bigint: true })
      verifyIdentity(current)
      verifyDestination()
      renameSync(temporary, path)
      created = false
      return result
    })
  } finally {
    await staging.catch(() => {})
    if (created) try {
      let current: BigIntStats | undefined
      try { current = lstatSync(temporary, { bigint: true }) }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
      if (current) { verifyIdentity(current); await rm(temporary, { force: true }) }
    } catch (error) {
      try { logEvent('error', 'config-manager', 'config export cleanup failed', {
        operationKey: 'op_' + lease.operation.operationId.replaceAll('-', ''),
        cleanupFailed: true, reason: classifyIpcError(error)
      }) } catch { /* Diagnostics must not replace the original failure/cancellation. */ }
    }
  }
}
