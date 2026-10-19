// AT-00-003: actual summary generation must not publish after a late read.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { IpcFault } from '../shared/ipc-result'
const state = vi.hoisted(() => ({ dir: '', reading: false, writing: false, holdWrite: '', gate: null as Promise<void> | null }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => join(state.dir, 'missing-runtime') }))
vi.mock('fs/promises', async importOriginal => {
  const real = await importOriginal<typeof import('node:fs/promises')>()
  return { ...real, writeFile: async (...args: Parameters<typeof real.writeFile>) => {
    const value = await real.writeFile(...args)
    if (state.holdWrite && String(args[0]).endsWith(state.holdWrite)) { state.writing = true; await state.gate }
    return value
  }, readFile: async (...args: Parameters<typeof real.readFile>) => {
    if (String(args[0]).endsWith('events.ndjson')) { state.reading = true; if (state.gate && !state.holdWrite) await state.gate }
    return real.readFile(...args)
  } }
})
import { generateTrafficForensicsSummary, type TrafficForensicsSummaryManifest } from './trafficForensicsSummary'
let release: (() => void) | undefined, pending: Promise<unknown> | undefined
const manifest = () => ({ sessionDir: state.dir, sessionId: 'fixture', mode: 'directVpn', target: 'fixture', engine: null,
  startedAt: 1, parserErrors: [], normalizedArtifacts: [] }) as unknown as TrafficForensicsSummaryManifest
beforeEach(async () => {
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'summary-owned-'))
  state.reading = false; state.writing = false; state.holdWrite = ''; state.gate = null; release = undefined; pending = undefined
  await writeFile(join(state.dir, 'events.ndjson'), '{"timestamp":1,"event":"fixture"}\n')
})
afterEach(async () => {
  release?.(); await pending?.catch(() => {})
  await rm(state.dir, { recursive: true, force: true })
})
describe('forensic summary lifetime', () => {
  it('does not write normalized artifacts or summary after a cancelled read', async () => {
    state.gate = new Promise<void>(done => { release = done })
    const controller = new AbortController()
    pending = generateTrafficForensicsSummary(manifest(), () => { if (controller.signal.aborted) throw new IpcFault('cancelled') })
    void pending.catch(() => {})
    await vi.waitFor(() => expect(state.reading).toBe(true))
    controller.abort(); release!()
    await expect(pending).rejects.toMatchObject({ category: 'cancelled' })
    expect(await readdir(state.dir)).toEqual(['events.ndjson'])
  })
  it.each(['timeline.ndjson', 'flows.ndjson', 'summary.json'])('keeps live generations unchanged when cancelled during staged %s', async name => {
    await writeFile(join(state.dir, 'summary.json'), 'retained summary')
    await writeFile(join(state.dir, 'flows.ndjson'), 'retained flows')
    const output = join(state.dir, 'export'); await mkdir(output)
    state.holdWrite = name; state.gate = new Promise<void>(done => { release = done })
    const controller = new AbortController()
    pending = generateTrafficForensicsSummary(manifest(), () => { if (controller.signal.aborted) throw new IpcFault('cancelled') }, output)
    void pending.catch(() => {})
    await vi.waitFor(() => expect(state.writing).toBe(true))
    controller.abort(); release!()
    await expect(pending).rejects.toMatchObject({ category: 'cancelled' })
    expect(await readFile(join(state.dir, 'summary.json'), 'utf8')).toBe('retained summary')
    expect(await readFile(join(state.dir, 'flows.ndjson'), 'utf8')).toBe('retained flows')
  })
  it('preserves normal summary/normalized artifact generation', async () => {
    pending = generateTrafficForensicsSummary(manifest())
    await expect(pending).resolves.toMatchObject({ summaryPath: join(state.dir, 'summary.json') })
    expect(await readdir(state.dir)).toEqual(expect.arrayContaining(['summary.json', 'timeline.ndjson', 'flows.ndjson', 'app-events.ndjson']))
  })
})
