import { createHash, randomUUID } from 'crypto'
import { constants, type Stats } from 'fs'
import { lstat, open, rename, unlink, type FileHandle } from 'fs/promises'
import { basename, dirname, join, resolve } from 'path'

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | null)?.code === 'ENOENT'
}

function assertRegularFile(info: Stats): void {
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) {
    throw new Error('Runtime artifact is not a regular file or is hard-linked')
  }
}

function sameIdentity(before: Stats, after: Stats): boolean {
  return before.dev === after.dev && before.ino === after.ino
}

function assertUnchanged(before: Stats, after: Stats): void {
  assertRegularFile(after)
  if (!sameIdentity(before, after) || before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
    throw new Error('Runtime artifact changed during verification')
  }
}

// lstat the whole path: a regular leaf can still sit behind a directory junction.
// This supplements, not replaces, the caller's native ACL/owner/reparse checks.
async function inspectDirectories(path: string): Promise<Map<string, Stats>> {
  const directories = new Map<string, Stats>()
  let directory = dirname(path)
  while (true) {
    const info = await lstat(directory)
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Runtime directory is a reparse point or is not a directory')
    directories.set(directory, info)
    const parent = dirname(directory)
    if (parent === directory) return directories
    directory = parent
  }
}

async function verifyDirectories(directories: Map<string, Stats>): Promise<void> {
  for (const [path, before] of directories) {
    const after = await lstat(path)
    if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after)) {
      throw new Error('Runtime directory changed or is a reparse point')
    }
  }
}

async function readVerifiedFile(path: string, allowMissing = false, expectedIdentity?: Stats): Promise<Buffer | null> {
  const directories = await inspectDirectories(path)
  let before: Stats
  try { before = await lstat(path) }
  catch (error) {
    if (allowMissing && isMissing(error)) return null
    throw error
  }
  assertRegularFile(before)
  if (expectedIdentity && !sameIdentity(expectedIdentity, before)) throw new Error('Runtime artifact changed during staging')
  // O_NOFOLLOW is unavailable on Windows. Compare handle and pathname identities
  // there as well; the verified directory ACL remains the race-prevention boundary.
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
  try {
    assertUnchanged(before, await file.stat())
    const bytes = await file.readFile()
    assertUnchanged(before, await file.stat())
    assertUnchanged(before, await lstat(path))
    await verifyDirectories(directories)
    return bytes
  } finally { await file.close() }
}

const hash = (data: Buffer) => createHash('sha256').update(data).digest('hex')

/** AT-01-009, F-005/F-006: only the app-bundled resource is a trust source.
 * Run after native directory ACL/owner/reparse verification, before execution.
 * Do not overwrite an existing inode or learn an expected hash from staging. */
export async function stageVerifiedRuntimeArtifact(source: string, destination: string): Promise<boolean> {
  source = resolve(source)
  destination = resolve(destination)
  const bytes = (await readVerifiedFile(source))!
  const expected = hash(bytes)
  const directories = await inspectDirectories(destination)
  const existing = await readVerifiedFile(destination, true)
  if (existing && hash(existing) === expected) return false

  await verifyDirectories(directories)
  const temporary = join(dirname(destination), `.${basename(destination)}.${randomUUID()}.tmp`)
  let file: FileHandle | null = await open(temporary, 'wx', 0o600)
  try {
    assertRegularFile(await file.stat())
    // Write exactly the authenticated snapshot, never reopen the source to copy.
    await file.writeFile(bytes)
    await file.sync()
    const stagedIdentity = await file.stat()
    assertRegularFile(stagedIdentity)
    await file.close()
    file = null
    const staged = (await readVerifiedFile(temporary, false, stagedIdentity))!
    if (hash(staged) !== expected) throw new Error('Runtime artifact hash verification failed')
    await verifyDirectories(directories)
    // A missing leaf is the only recoverable inspection error. Never follow a
    // newly planted symlink/hard link, even if its target has the expected bytes.
    await readVerifiedFile(destination, true)
    await rename(temporary, destination)
    const published = (await readVerifiedFile(destination, false, stagedIdentity))!
    if (hash(published) !== expected) throw new Error('Runtime artifact hash verification failed')
    await verifyDirectories(directories)
    return true
  } finally {
    try { await file?.close() }
    finally {
      // A rejected parent path must not be followed even for cleanup. Leave the
      // temporary behind rather than deleting through an untrusted junction.
      await verifyDirectories(directories)
      await unlink(temporary).catch(error => { if (!isMissing(error)) throw error })
    }
  }
}
