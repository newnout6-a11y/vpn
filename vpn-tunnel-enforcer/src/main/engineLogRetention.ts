// AT-08-001 / AT-01-009: bounded engine logs without restarting a live tunnel.
import { constants } from 'fs'
import { lstat, open, type FileHandle } from 'fs/promises'
import { join } from 'path'

export const ENGINE_LOG_BYTES = 10 * 1024 * 1024
export const ENGINE_LOG_CHECK_MS = 5000

async function checkedFile(path: string, create = false): Promise<FileHandle | null> {
  let before
  try { before = await lstat(path) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    if (!create) return null
  }
  if (before && (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1)) {
    throw new Error('Log file is not a regular owned file')
  }
  const file = await open(path, before ? constants.O_RDWR | (constants.O_NOFOLLOW ?? 0) : 'wx')
  const after = await file.stat()
  if (!after.isFile() || after.nlink !== 1 || (before && (before.dev !== after.dev || before.ino !== after.ino))) {
    await file.close()
    throw new Error('Log file changed during inspection')
  }
  return file
}

async function tail(file: FileHandle, size: number, limit: number): Promise<Buffer> {
  const bytes = Math.min(size, limit)
  const buffer = Buffer.alloc(bytes)
  const { bytesRead } = await file.read(buffer, 0, bytes, size - bytes)
  let result = buffer.subarray(0, bytesRead)
  // Discard the partial first line (also avoids a split UTF-8 character).
  if (size > limit) {
    const newline = result.indexOf(10)
    result = newline < 0 ? Buffer.alloc(0) : result.subarray(newline + 1)
  }
  return result
}

/** Caller must authorize the namespace before invoking this mutation. The live
 * file is truncated in place: Go's append handles keep writing to the same inode.
 * Renaming it would leave the engine writing to an abandoned generation. */
export async function maintainEngineLog(path: string, previous: string, limit = ENGINE_LOG_BYTES): Promise<void> {
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error('Invalid log size limit')
  const old = await checkedFile(previous)
  try {
    if (old && (await old.stat()).size > limit) {
      const content = await tail(old, (await old.stat()).size, limit)
      await old.truncate(0)
      await old.writeFile(content)
    }
  } finally { await old?.close() }
  const current = await checkedFile(path)
  if (!current) return
  try {
    const info = await current.stat()
    if (info.size <= limit) return
    const content = await tail(current, info.size, limit)
    const saved = await checkedFile(previous, true)
    try {
      await saved!.truncate(0)
      await saved!.writeFile(content)
    } finally { await saved?.close() }
    // Only truncate after the previous generation has been saved successfully.
    await current.truncate(0)
  } finally { await current.close() }
}

export function watchEngineLogs(directory: string, authorize: () => Promise<void>, onError: (error: unknown) => void) {
  let pending: Promise<void> | null = null
  let stopped = false
  let warned = false
  const check = (): Promise<void> => {
    if (stopped) return Promise.resolve()
    if (pending) return pending
    pending = (async () => {
      for (const name of ['sing-box', 'xray']) {
        const paths = [join(directory, `${name}.log`), join(directory, `${name}.prev.log`)]
        const infos = await Promise.all(paths.map(path => lstat(path).catch(error => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
          throw error
        })))
        if (!infos.some(info => info && info.size > ENGINE_LOG_BYTES)) continue
        // Native ACL checks are expensive; do them only when rotation is needed.
        await authorize()
        if (stopped) return
        await maintainEngineLog(paths[0], paths[1])
      }
      warned = false
    })().catch(error => {
      if (!warned) { warned = true; onError(error) }
    }).finally(() => { pending = null })
    return pending
  }
  const timer = setInterval(() => { void check() }, ENGINE_LOG_CHECK_MS)
  timer.unref()
  void check()
  return {
    check,
    async stop() { stopped = true; clearInterval(timer); await pending }
  }
}
