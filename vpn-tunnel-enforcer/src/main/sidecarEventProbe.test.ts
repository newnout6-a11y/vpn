// AT-08-007 / F-197: actual local files, bounded incremental preview, no sidecar/network.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as fs from 'fs/promises'
import { join, resolve } from 'path'
import { createSidecarEventProbeReader } from './sidecarEventProbe'

const io = vi.hoisted(() => ({ reads: [] as number[], failRead: false }))
vi.mock('fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  return { ...actual, open: async (...args: Parameters<typeof actual.open>) => {
    const file = await actual.open(...args)
    const read = file.read.bind(file)
    file.read = ((buffer: Buffer, offset: number, length: number, position: number) => {
      io.reads.push(length)
      if (io.failRead) return Promise.reject(new Error('fixture read failed'))
      return read(buffer, offset, length, position)
    }) as typeof file.read
    return file
  } }
})

let root: string
let path: string
beforeEach(async () => {
  io.reads.length = 0
  io.failRead = false
  await fs.mkdir('.tmp', { recursive: true })
  root = await fs.mkdtemp(join(resolve('.tmp'), 'sidecar-probe-test-'))
  path = join(root, 'events.ndjson')
})
afterEach(async () => {
  vi.restoreAllMocks()
  if (!resolve(root).startsWith(resolve('.tmp') + require('path').sep)) throw new Error('fixture escaped .tmp')
  await fs.rm(root, { recursive: true, force: true })
})
const event = (extra: Record<string, unknown> = {}) => JSON.stringify({ session: 's', category: 'tcp', remoteAddress: '198.51.100.2', ts: '2026-06-19T00:00:00.000Z', ...extra }) + '\n'

describe('incremental sidecar preview', () => {
  it('counts each appended row once; unchanged reads only validate bounded anchors', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, event({ category: 'lifecycle', engine: 'ferrisetw' }) + event())
    expect(await reader.read(path, 's')).toMatchObject({ events: 2, dataEvents: 1, engine: 'ferrisetw', categoryCounts: { tcp: 1 } })
    io.reads.length = 0
    expect(await reader.read(path, 's')).toMatchObject({ events: 2, dataEvents: 1 })
    expect(io.reads.reduce((sum, bytes) => sum + bytes, 0)).toBeLessThanOrEqual(256)
    await fs.appendFile(path, event({ category: 'wfp', action: 'drop' }))
    expect(await reader.read(path, 's')).toMatchObject({ events: 3, dataEvents: 2, wfpBlocks: 1, categoryCounts: { tcp: 1, wfp: 1 } })
  })
  it('retains partial lines and multibyte UTF-8 across appends without loss or duplicates', async () => {
    const reader = createSidecarEventProbeReader()
    const bytes = Buffer.from(event({ queryName: 'пример.рф', category: 'dns' }))
    const split = bytes.indexOf(Buffer.from('пример')) + 1
    await fs.writeFile(path, bytes.subarray(0, split))
    expect(await reader.read(path, 's')).toMatchObject({ events: 0, dataEvents: 0 })
    await fs.appendFile(path, bytes.subarray(split))
    expect(await reader.read(path, 's')).toMatchObject({ events: 1, dataEvents: 1, topDomains: [{ name: 'пример.рф', count: 1 }] })
    expect(await reader.read(path, 's')).toMatchObject({ events: 1, dataEvents: 1 })
  })
  it('resets on rotation, truncation and truncate/regrow between polls', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, event() + event())
    expect((await reader.read(path, 's')).dataEvents).toBe(2)
    await fs.rename(path, path + '.old')
    await fs.writeFile(path, event({ category: 'dns' }))
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 1, categoryCounts: { dns: 1 } })
    await fs.writeFile(path, '')
    expect((await reader.read(path, 's')).dataEvents).toBe(0)
    await fs.appendFile(path, event({ category: 'wfp', event: 'block' }))
    expect((await reader.read(path, 's')).wfpBlocks).toBe(1)
    await fs.writeFile(path, event({ category: 'udp' }).repeat(3))
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 3, wfpBlocks: 0, categoryCounts: { udp: 3 } })
  })
  it('does not return stale health after missing/read failures and rejects another session', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, event())
    expect((await reader.read(path, 's')).dataEvents).toBe(1)
    await fs.rm(path)
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview is unavailable' })
    await fs.writeFile(path, event({ session: 'old' }))
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview contains invalid session identity' })
    expect(await reader.read(path, 'old')).toMatchObject({ dataEvents: 1 })
  })
  it.each([undefined, null, 7, false, 'old'])('rejects missing or invalid session identity %j as health evidence', async session => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, event({ session, category: 'lifecycle', engine: 'untrusted' }) + event({ session }))
    expect(await reader.read(path, 's')).toMatchObject({ events: 2, dataEvents: 0, engine: null, categoryCounts: {},
      lastDataEventAt: null, warning: 'sidecar event preview contains invalid session identity' })
  })
  it('serializes concurrent status reads and does not treat malformed records as data evidence', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, 'invalid-json\n' + event({ category: 'health' }) + event())
    const result = await Promise.all([reader.read(path, 's'), reader.read(path, 's')])
    for (const probe of result) expect(probe).toMatchObject({ events: 3, dataEvents: 1, warning: 'sidecar event preview contains malformed records' })
  })
  it('invalidates cached evidence after a failed read and rebuilds it after recovery', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, event())
    expect((await reader.read(path, 's')).dataEvents).toBe(1)
    io.failRead = true
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview is unavailable' })
    io.failRead = false
    await fs.appendFile(path, event())
    expect((await reader.read(path, 's')).dataEvents).toBe(2)
  })
  it('bounds work per status call and resumes all unconsumed events on the next call', async () => {
    const reader = createSidecarEventProbeReader()
    const row = event()
    const count = Math.ceil(4 * 1024 * 1024 / Buffer.byteLength(row)) + 20
    await fs.writeFile(path, row.repeat(count))
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview is catching up' })
    expect(await reader.read(path, 's')).toMatchObject({ events: count, dataEvents: count, categoryCounts: { tcp: count } })
  })
  it('bounds oversized records/aggregate cardinality and recovers after truncation', async () => {
    const reader = createSidecarEventProbeReader()
    await fs.writeFile(path, 'x'.repeat(1024 * 1024 + 1))
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview is unavailable' })
    expect(await reader.read(path, 's')).toMatchObject({ dataEvents: 0, warning: 'sidecar event preview exceeds bounded capacity' })
    await fs.writeFile(path, event())
    expect((await reader.read(path, 's')).dataEvents).toBe(1)
    await fs.writeFile(path, Array.from({ length: 4097 }, (_, index) => event({ queryName: `${index}.example` })).join(''))
    expect((await reader.read(path, 's')).dataEvents).toBe(0)
  })
})
