// AT-01-009; WP-1/WP-2; F-005/F-006: real filesystem abuse regressions.
import { mkdtemp, writeFile, readFile, readdir, stat, lstat, open, rename, utimes, symlink, link, mkdir, copyFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { basename, join, resolve } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('fs/promises', async importOriginal => {
  const fs = await importOriginal<typeof import('fs/promises')>()
  const mocked = { ...fs, lstat: vi.fn(fs.lstat), open: vi.fn(fs.open), rename: vi.fn(fs.rename), copyFile: vi.fn(fs.copyFile) }
  return { ...mocked, default: mocked }
})
import { stageVerifiedRuntimeArtifact } from './runtimeArtifact'
let directory: string, source: string, destination: string
beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), 'vpnte-runtime-hash-')); source = join(directory, 'bundled.exe'); destination = join(directory, 'runtime.exe'); await writeFile(source, 'trusted executable') })
afterEach(async () => {
  const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
  vi.restoreAllMocks()
  vi.mocked(lstat).mockReset().mockImplementation(fs.lstat)
  vi.mocked(open).mockReset().mockImplementation(fs.open)
  vi.mocked(rename).mockReset().mockImplementation(fs.rename)
  vi.clearAllMocks()
  await rm(directory, { recursive: true, force: true })
})
describe('runtime artifact authentication', () => {
  it('reuses only byte-identical copies', async () => {
    expect(await stageVerifiedRuntimeArtifact(source, destination)).toBe(true)
    expect(await stageVerifiedRuntimeArtifact(source, destination)).toBe(false)
  })
  it('overwrites planted same-size/same-time bytes before they can run', async () => {
    await writeFile(destination, 'planted executable')
    const timestamp = (await stat(source)).mtime
    await utimes(destination, timestamp, timestamp)
    expect((await stat(destination)).size).toBe((await stat(source)).size)
    expect(await stageVerifiedRuntimeArtifact(source, destination)).toBe(true)
    expect(await readFile(destination, 'utf8')).toBe('trusted executable')
  })
  it.each(['EACCES', 'EPERM', 'EIO'])('fails closed on destination inspection error %s without copying (AT-01-009)', async code => {
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    const denied = Object.assign(new Error('inspection denied'), { code })
    vi.mocked(lstat).mockImplementation(async path => {
      if (resolve(String(path)) === resolve(destination)) throw denied
      return fs.lstat(path)
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toMatchObject({ code })
    expect(copyFile).not.toHaveBeenCalled()
    expect(await readdir(directory)).toEqual(['bundled.exe'])
  })
  it('does not treat an unreadable existing destination as missing (AT-01-009)', async () => {
    await writeFile(destination, 'planted executable')
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    vi.mocked(open).mockImplementation(async (path, flags, mode) => {
      if (resolve(String(path)) === resolve(destination)) throw Object.assign(new Error('read denied'), { code: 'EACCES' })
      return fs.open(path, flags, mode)
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toMatchObject({ code: 'EACCES' })
    expect(await readFile(destination, 'utf8')).toBe('planted executable')
    expect((await readdir(directory)).filter(name => name.endsWith('.tmp'))).toEqual([])
  })
  it.each(['write', 'hash', 'rename'])('preserves the old artifact and cleans staging on %s failure (AT-01-009)', async failure => {
    await writeFile(destination, 'previous executable')
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    if (failure === 'rename') vi.mocked(rename).mockRejectedValueOnce(Object.assign(new Error('publish failed'), { code: 'EBUSY' }))
    else vi.mocked(open).mockImplementation(async (path, flags, mode) => {
      const file = await fs.open(path, flags, mode)
      if (flags === 'wx') {
        const write = file.writeFile.bind(file)
        vi.spyOn(file, 'writeFile').mockImplementationOnce(async () => {
          await write('partial or corrupt executable')
          if (failure === 'write') throw new Error('write failed')
        })
      }
      return file
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow(failure === 'hash' ? 'hash verification failed' : 'failed')
    expect(await readFile(destination, 'utf8')).toBe('previous executable')
    expect((await readdir(directory)).filter(name => name.endsWith('.tmp'))).toEqual([])
    if (failure !== 'rename') expect(rename).not.toHaveBeenCalled()
  })
  it('never follows a changed directory junction during staging cleanup (AT-01-009)', async () => {
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    const runtime = join(directory, 'runtime'); await mkdir(runtime)
    const target = join(directory, 'victim-directory'); await mkdir(target)
    destination = join(runtime, 'runtime.exe')
    let victim = ''
    vi.mocked(open).mockImplementation(async (path, flags, mode) => {
      const file = await fs.open(path, flags, mode)
      if (flags === 'wx') {
        const close = file.close.bind(file)
        vi.spyOn(file, 'close').mockImplementationOnce(async () => {
          await close()
          await fs.rename(runtime, join(directory, 'moved-runtime'))
          await symlink(target, runtime, 'junction')
          victim = join(target, basename(String(path)))
          await writeFile(victim, 'untouched victim')
        })
      }
      return file
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow(/directory|reparse/)
    expect(await readFile(victim, 'utf8')).toBe('untouched victim')
  })
  it('detects source mutation during its descriptor read (AT-01-009)', async () => {
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    vi.mocked(open).mockImplementation(async (path, flags, mode) => {
      const file = await fs.open(path, flags, mode)
      if (resolve(String(path)) === resolve(source)) {
        const read = file.readFile.bind(file)
        vi.spyOn(file, 'readFile').mockImplementationOnce(async () => {
          const bytes = await read()
          await writeFile(source, 'changed source executable')
          return bytes
        })
      }
      return file
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow('changed')
    expect(await readdir(directory)).toEqual(['bundled.exe'])
  })
  it('rejects a source symlink planted between inspection and open (AT-01-009)', async () => {
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    const target = join(directory, 'moved-source.exe')
    let replaced = false
    vi.mocked(open).mockImplementation(async (path, flags, mode) => {
      if (!replaced && resolve(String(path)) === resolve(source)) {
        replaced = true; await fs.rename(source, target); await symlink(target, source)
      }
      return fs.open(path, flags, mode)
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow()
    expect(await readFile(target, 'utf8')).toBe('trusted executable')
    expect(rename).not.toHaveBeenCalled()
  })
  it.each(['symlink', 'bytes', 'identity'])('rejects a post-publish %s substitution (AT-01-009)', async substitution => {
    const fs = await vi.importActual<typeof import('fs/promises')>('fs/promises')
    vi.mocked(rename).mockImplementation(async (from, to) => {
      await fs.rename(from, to)
      if (substitution === 'symlink') { await rm(String(to)); await symlink(source, to) }
      else if (substitution === 'identity') {
        // Keep the published inode alive so its file ID cannot be reused.
        await fs.rename(to, join(directory, 'replaced.exe'))
        await writeFile(to, 'trusted executable')
      } else await writeFile(to, 'corrupt published executable')
    })
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow(/regular file|changed|hash verification/)
    expect(await readFile(source, 'utf8')).toBe('trusted executable')
    expect((await readdir(directory)).filter(name => name.endsWith('.tmp'))).toEqual([])
  })
  it('rejects hard-linked destinations without altering another file (AT-01-009)', async () => {
    const target = join(directory, 'victim'); await writeFile(target, 'planted executable')
    await link(target, destination)
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow(/regular file|linked/)
    expect(await readFile(target, 'utf8')).toBe('planted executable')
  })
  it.each(['source', 'destination'])('rejects a %s directory junction (AT-01-009)', async kind => {
    const target = join(directory, 'target'); await mkdir(target)
    const alias = join(directory, 'alias'); await symlink(target, alias, 'junction')
    if (kind === 'source') { await writeFile(join(target, 'bundled.exe'), 'trusted executable'); source = join(alias, 'bundled.exe') }
    else destination = join(alias, 'runtime.exe')
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow(/reparse|symbolic|directory/i)
    expect(copyFile).not.toHaveBeenCalled()
  })
  it('rejects symlinks without following or overwriting their targets', async () => {
    const target = join(directory, 'victim'); await writeFile(target, 'victim')
    await symlink(target, destination)
    await expect(stageVerifiedRuntimeArtifact(source, destination)).rejects.toThrow('regular file')
    expect(await readFile(target, 'utf8')).toBe('victim')
  })
})
