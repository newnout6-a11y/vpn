// AT-08-001 / AT-01-009: size boundaries, live append handles and refused paths.
import { mkdtemp, mkdir, writeFile, readFile, stat, open, link, rm, appendFile } from 'fs/promises'
import { join } from 'path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ENGINE_LOG_BYTES, ENGINE_LOG_CHECK_MS, maintainEngineLog, watchEngineLogs } from './engineLogRetention'

const dirs: string[] = []
async function fixture() {
  const root = join(process.cwd(), '.tmp')
  await mkdir(root, { recursive: true })
  const dir = await mkdtemp(join(root, 'log-retention-'))
  dirs.push(dir)
  return { dir, current: join(dir, 'xray.log'), previous: join(dir, 'xray.prev.log') }
}
afterEach(async () => {
  vi.useRealTimers()
  await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })))
})
describe('bounded engine logs', () => {
  it('keeps an append handle usable, retains complete UTF-8 lines, and replaces only one generation', async () => {
    const { current, previous } = await fixture()
    await writeFile(current, 'discarded\n' + 'новая строка\n'.repeat(20))
    const writer = await open(current, 'a')
    try {
      await maintainEngineLog(current, previous, 100)
      expect((await stat(current)).size).toBe(0)
      const retained = await readFile(previous, 'utf8')
      expect(Buffer.byteLength(retained)).toBeLessThanOrEqual(100)
      expect(retained).toMatch(/^(новая строка\n)+$/)
      await writer.writeFile('after rotation\n')
      expect(await readFile(current, 'utf8')).toBe('after rotation\n')
      await writer.writeFile('new generation\n'.repeat(20))
      await maintainEngineLog(current, previous, 100)
      expect(await readFile(previous, 'utf8')).toMatch(/^(new generation\n)+$/)
    } finally { await writer.close() }
  })
  it('does not rotate at the exact limit and repairs oversized previous logs with an absent current file', async () => {
    const { current, previous } = await fixture()
    await writeFile(current, 'x'.repeat(100))
    await maintainEngineLog(current, previous, 100)
    expect((await stat(current)).size).toBe(100)
    await rm(current)
    await writeFile(previous, 'old\n'.repeat(50))
    await maintainEngineLog(current, previous, 100)
    expect((await stat(previous)).size).toBeLessThanOrEqual(100)
  })
  it('does not truncate the current log if the previous generation cannot be written', async () => {
    const { current, previous } = await fixture()
    const text = 'current\n'.repeat(30)
    await writeFile(current, text)
    await mkdir(previous)
    await expect(maintainEngineLog(current, previous, 100)).rejects.toThrow()
    expect(await readFile(current, 'utf8')).toBe(text)
  })
  it('refuses hard-linked files without modifying the linked target', async () => {
    const { dir, current, previous } = await fixture()
    const target = join(dir, 'foreign.log')
    await writeFile(target, 'foreign\n'.repeat(30))
    await link(target, current)
    await expect(maintainEngineLog(current, previous, 100)).rejects.toThrow('regular owned file')
    expect((await stat(target)).size).toBe(240)
  })
  it('rejects invalid limits and missing logs require no creation', async () => {
    const { current, previous, dir } = await fixture()
    await expect(maintainEngineLog(current, previous, 0)).rejects.toThrow('Invalid')
    await maintainEngineLog(current, previous)
    expect(await import('fs/promises').then(fs => fs.readdir(dir))).toEqual([])
  })
  it('checks both engines periodically, serializes checks, and stops without further mutations', async () => {
    const { dir } = await fixture()
    for (const name of ['xray', 'sing-box']) await writeFile(join(dir, `${name}.log`), Buffer.alloc(ENGINE_LOG_BYTES + 1, 10))
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    const authorize = vi.fn(async () => { await gate })
    const error = vi.fn()
    vi.useFakeTimers()
    const watcher = watchEngineLogs(dir, authorize, error)
    const first = watcher.check()
    expect(watcher.check()).toBe(first)
    release()
    try {
      await first
      expect(authorize).toHaveBeenCalledTimes(2)
      expect(error).not.toHaveBeenCalled()
      await appendFile(join(dir, 'xray.log'), Buffer.alloc(ENGINE_LOG_BYTES + 1, 10))
      await vi.advanceTimersByTimeAsync(ENGINE_LOG_CHECK_MS)
      await watcher.check()
      expect((await stat(join(dir, 'xray.log'))).size).toBe(0)
    } finally { await watcher.stop() }
    await appendFile(join(dir, 'xray.log'), 'stopped')
    await watcher.check()
    expect(await readFile(join(dir, 'xray.log'), 'utf8')).toBe('stopped')
    expect(ENGINE_LOG_CHECK_MS).toBe(5000)
  })
  it('does not bless an untrusted namespace, warns once, and retries after authorization recovers', async () => {
    const { dir, current } = await fixture()
    await writeFile(current, Buffer.alloc(ENGINE_LOG_BYTES + 1, 10))
    const authorize = vi.fn().mockRejectedValue(new Error('ACL refused'))
    const error = vi.fn()
    const watcher = watchEngineLogs(dir, authorize, error)
    try {
      await watcher.check()
      await watcher.check()
      expect(error).toHaveBeenCalledOnce()
      expect((await stat(current)).size).toBe(ENGINE_LOG_BYTES + 1)
      authorize.mockResolvedValue(undefined)
      await watcher.check()
      expect((await stat(current)).size).toBe(0)
    } finally { await watcher.stop() }
  })
})
