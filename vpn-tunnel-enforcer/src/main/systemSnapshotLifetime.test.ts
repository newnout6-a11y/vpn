// AT-00-003: actual snapshot queue/persistence with held native collection and writes.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readdir, rm, readFile } from 'node:fs/promises'
import { join } from 'node:path'
const state = vi.hoisted(() => ({ dir: '', collect: vi.fn(), log: vi.fn(), writing: false, writeGate: null as Promise<void> | null }))
vi.mock('electron', () => ({ app: { getPath: () => state.dir, getVersion: () => 'fixture' } }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('./systemNetwork', () => ({ getTunNetworkBaselineManifestPath: () => join(state.dir, 'missing') }))
vi.mock('child_process', () => ({
  execFile: Object.assign(() => {}, { [Symbol.for('nodejs.util.promisify.custom')]: state.collect }),
  exec: Object.assign(() => {}, { [Symbol.for('nodejs.util.promisify.custom')]: async () => ({ stdout: '' }) })
}))
vi.mock('fs/promises', async importOriginal => {
  const real = await importOriginal<typeof import('node:fs/promises')>()
  return { ...real, open: async (...args: Parameters<typeof real.open>) => {
    const file = await real.open(...args), write = file.writeFile.bind(file)
    file.writeFile = async (...values: Parameters<typeof file.writeFile>) => {
      state.writing = true
      if (state.writeGate) await state.writeGate
      return write(...values)
    }
    return file
  } }
})
import { captureSnapshot } from './systemSnapshot'
let releases: Array<() => void> = [], tasks: Promise<unknown>[] = []
function gate<T>(value: T) {
  let release!: () => void
  const promise = new Promise<T>(done => { release = () => done(value) })
  releases.push(release)
  return { promise, release }
}
function capture(controller: AbortController) {
  const task = captureSnapshot('manual', { signal: controller.signal })
  void task.catch(() => {}); tasks.push(task); return task
}
beforeEach(async () => {
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'snapshot-owned-'))
  state.collect.mockReset().mockResolvedValue({ stdout: '' }); state.log.mockClear()
  state.writing = false; state.writeGate = null
})
afterEach(async () => {
  releases.splice(0).forEach(release => release()); await Promise.allSettled(tasks.splice(0))
  await rm(state.dir, { recursive: true, force: true })
})
describe('owned snapshots', () => {
  it('does not start an aborted queued capture or persist a late collection', async () => {
    const first = new AbortController(), second = new AbortController(), native = gate({ stdout: '' })
    state.collect.mockReturnValueOnce(native.promise)
    const one = capture(first), two = capture(second)
    await vi.waitFor(() => expect(state.collect).toHaveBeenCalledOnce())
    first.abort(); second.abort(); native.release()
    await expect(one).rejects.toMatchObject({ category: 'cancelled' })
    await expect(two).rejects.toMatchObject({ category: 'cancelled' })
    expect(state.collect).toHaveBeenCalledOnce()
    expect(await readdir(state.dir)).toEqual([])
    expect(state.log).not.toHaveBeenCalled()
  })
  it('removes a cancelled temporary write without publishing a snapshot', async () => {
    const controller = new AbortController(), write = gate<void>(undefined)
    state.writeGate = write.promise
    const result = capture(controller)
    await vi.waitFor(() => expect(state.writing).toBe(true))
    controller.abort(); write.release()
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    expect(await readdir(join(state.dir, 'snapshots'))).toEqual([])
    expect(state.log).not.toHaveBeenCalled()
  })
  it('writes an active snapshot atomically and preserves unowned callers', async () => {
    const path = await capture(new AbortController())
    expect(path).toBeTruthy()
    expect(JSON.parse(await readFile(path!, 'utf8'))).toMatchObject({ reason: 'manual', appVersion: 'fixture' })
    expect((await readdir(join(state.dir, 'snapshots'))).every(name => name.endsWith('.json'))).toBe(true)
    const legacy = captureSnapshot('tun-post-stop'); tasks.push(legacy)
    expect(JSON.parse(await readFile((await legacy)!, 'utf8')).reason).toBe('tun-post-stop')
  })
})
