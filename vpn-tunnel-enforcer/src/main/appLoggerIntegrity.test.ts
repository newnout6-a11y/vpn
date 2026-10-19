// AT-00-005/010, F-143: production logger, actual JSONL files and reloads.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ directory: '' }))
vi.mock('electron', () => ({ app: { getPath: () => state.directory }, shell: { openPath: vi.fn() } }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => join(state.directory, 'missing-runtime') }))
vi.mock('./vpnProfiles', () => ({ redactSensitiveConfig: (value: unknown) => value, redactSensitiveText: (value: string) => value }))
let logger: typeof import('./appLogger'), path: string, previous: string
const oldRows = () => Array.from({ length: 100 }, (_, i) => JSON.stringify({
  ts: '2026-10-19T12:00:00.000Z', level: 'info', scope: 'history', message: `old-${i}`
})).join('\n') + '\n'
const rows = (raw: string): Array<Record<string, any>> => raw.split('\n').flatMap(line => {
  try { const row = JSON.parse(line); return row && typeof row === 'object' && !Array.isArray(row) ? [row] : [] } catch { return [] }
})
async function appended(message = 'new-event') {
  let raw = ''
  await vi.waitFor(async () => {
    raw = await readFile(path, 'utf8')
    expect(rows(raw).some(row => row.message === message)).toBe(true)
  }, { timeout: 5_000 })
  return raw
}
beforeEach(async () => {
  await mkdir(join(process.cwd(), '.tmp'), { recursive: true })
  state.directory = await mkdtemp(join(process.cwd(), '.tmp', 'audit-integrity-'))
  await mkdir(join(state.directory, 'logs'))
  path = join(state.directory, 'logs', 'app.log'); previous = join(state.directory, 'logs', 'app.prev.log')
  vi.resetModules()
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  logger = await import('./appLogger')
})
afterEach(async () => {
  await logger.flushAppLog()
  vi.restoreAllMocks()
  await rm(state.directory, { recursive: true, force: true })
})

describe('durable application event history integrity', () => {
  it('keeps 100 legacy entries and appends the versioned event without a false corruption marker', async () => {
    const original = oldRows(); await writeFile(path, original)
    logger.logEvent('info', 'fixture', 'new-event')
    const raw = await appended(), parsed = rows(raw)
    expect(raw.startsWith(original)).toBe(true)
    expect(parsed).toHaveLength(101)
    expect(parsed.at(-1)).toMatchObject({ version: 1, source: 'unknown', owner: 'unknown', route: 'unconfirmed', confidence: 'indeterminate' })
    expect(parsed.some(row => row.message === 'history.corrupted')).toBe(false)
  })

  it.each(['truncated', 'garbage', 'schema', 'utf8', 'oversized'] as const)('marks a %s tail, preserves its bytes and continues writing', async damage => {
    const tail = damage === 'truncated' ? Buffer.from('{"message":"FAKE-private-tail')
      : damage === 'garbage' ? Buffer.from('FAKE-private-tail!')
        : damage === 'schema' ? Buffer.from('{"private":"FAKE-private-tail"}')
          : damage === 'utf8' ? Buffer.from([0xff, 0xfe, 10]) : Buffer.alloc(300_000, 120)
    const original = Buffer.concat([Buffer.from(oldRows()), tail]); await writeFile(path, original)
    logger.logEvent('info', 'fixture', 'new-event')
    logger.logEvent('info', 'fixture', 'second-event')
    const raw = await appended('second-event'), parsed = rows(raw)
    expect((await readFile(path)).subarray(0, original.length).equals(original)).toBe(true)
    expect(parsed.filter(row => row.message?.startsWith('old-'))).toHaveLength(100)
    const markers = parsed.filter(row => row.message === 'history.corrupted')
    expect(markers).toHaveLength(1)
    expect(markers[0]).toMatchObject({ level: 'error', details: { generation: 'current', invalidRows: 1 } })
    expect(JSON.stringify(markers)).not.toContain('FAKE-private-tail')
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain('FAKE-private-tail')
    expect(parsed.some(row => row.message === 'new-event')).toBe(true)
  })

  it('detects corruption in the retained generation without rewriting either generation', async () => {
    const older = oldRows() + 'broken'; await writeFile(previous, older)
    const current = oldRows(); await writeFile(path, current)
    logger.logEvent('info', 'fixture', 'new-event')
    const raw = await appended()
    expect(await readFile(previous, 'utf8')).toBe(older)
    expect(raw.startsWith(current)).toBe(true)
    expect(rows(raw).find(row => row.message === 'history.corrupted')).toMatchObject({ details: { generation: 'previous', invalidRows: 1 } })
  })

  it('separates a valid unterminated JSON record without calling it corruption', async () => {
    const original = oldRows().trimEnd(); await writeFile(path, original)
    logger.logEvent('info', 'fixture', 'new-event')
    const parsed = rows(await appended())
    expect(parsed).toHaveLength(101)
    expect(parsed.some(row => row.message === 'history.corrupted')).toBe(false)
  })

  it('captures action identity before its scope ends and serializes marker/event clocks monotonically', async () => {
    await writeFile(path, oldRows() + 'broken')
    const { withCorrelation } = await import('./actionCorrelation')
    const id = 'ipc_11111111111141118111111111111111'
    withCorrelation(id, () => logger.logEvent('info', 'automation', 'owned-event'), { source: 'ipc', owner: 'rotation' })
    logger.logEvent('info', 'fixture', 'new-event')
    const parsed = rows(await appended()).filter(row => row.version === 1)
    expect(parsed.find(row => row.message === 'owned-event')).toMatchObject({ correlationId: id, source: 'ipc', owner: 'rotation' })
    expect(parsed.map(row => row.monotonicMs)).toEqual(parsed.map(row => row.monotonicMs).sort((a, b) => a - b))
    expect(new Set(parsed.map(row => row.clockId)).size).toBe(1)
  })

  it('rechecks retained damage after a restart, without marking its own versioned records corrupt', async () => {
    await writeFile(path, oldRows() + 'broken')
    logger.logEvent('info', 'fixture', 'first-run')
    await logger.flushAppLog()
    vi.resetModules(); logger = await import('./appLogger')
    logger.logEvent('info', 'fixture', 'new-event')
    const parsed = rows(await appended())
    expect(parsed.filter(row => row.message === 'history.corrupted')).toHaveLength(2)
    expect(parsed.filter(row => row.message === 'history.corrupted').map(row => row.details.invalidRows)).toEqual([1, 1])
  })

  it('counts separate invalid records in both generations before appending markers', async () => {
    await writeFile(path, oldRows() + '{}\nnull\n')
    await writeFile(previous, oldRows() + '[]\n')
    logger.logEvent('info', 'fixture', 'new-event')
    const markers = rows(await appended()).filter(row => row.message === 'history.corrupted')
    expect(markers.map(row => row.details)).toEqual([
      { generation: 'current', invalidRows: 2, complete: true },
      { generation: 'previous', invalidRows: 1, complete: true }
    ])
  })

  it('handles valid multi-chunk UTF8 and CRLF without a false corruption marker', async () => {
    const original = JSON.stringify({ ts: '2026-10-19T12:00:00.000Z', level: 'info', scope: 'fixture', message: 'Я'.repeat(65_535) }) + '\r\n'
    await writeFile(path, original)
    logger.logEvent('info', 'fixture', 'new-event')
    expect(rows(await appended()).map(row => row.message)).toEqual(['Я'.repeat(65_535), 'new-event'])
  })

  it('reports unreadable previous history without suppressing new writes or exposing paths', async () => {
    await mkdir(previous)
    logger.logEvent('info', 'fixture', 'new-event')
    const marker = rows(await appended()).find(row => row.message === 'history.unavailable')
    expect(marker).toMatchObject({ details: { generation: 'previous', complete: false } })
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(state.directory)
  })

  it('bounds newly written text so restart validation accepts the logger own output', async () => {
    logger.logEvent('info', 's'.repeat(300_000), 'm'.repeat(300_000))
    await logger.flushAppLog()
    vi.resetModules(); logger = await import('./appLogger')
    logger.logEvent('info', 'fixture', 'new-event')
    expect(rows(await appended())).toHaveLength(2)
  })

  it('reports a write failure without raw exception data and retries after the obstruction is removed', async () => {
    await mkdir(path)
    logger.logEvent('info', 'fixture', 'failed-event')
    await logger.flushAppLog()
    expect(console.error).toHaveBeenCalledWith('[logs] history.write-failed')
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(state.directory)
    await rm(path, { recursive: true })
    logger.logEvent('info', 'fixture', 'new-event')
    expect(rows(await appended()).some(row => row.message === 'failed-event')).toBe(false)
  })

  it('reports both known corruption and an incomplete scan of the retained generation', async () => {
    const handle = await open(previous, 'w')
    try {
      await handle.truncate(34 * 1024 * 1024)
      await handle.write(Buffer.from('{}\n'), 0, 3, 0)
    } finally { await handle.close() }
    logger.logEvent('info', 'fixture', 'new-event')
    const parsed = rows(await appended())
    expect(parsed.find(row => row.message === 'history.corrupted')).toMatchObject({ details: { generation: 'previous', invalidRows: 1, complete: false } })
    expect(parsed.find(row => row.message === 'history.unavailable')).toMatchObject({ details: { generation: 'previous', complete: false } })
  })

  it('does not let startup markers rotate away retained damage before an ordinary event would', async () => {
    const older = oldRows() + 'broken'; await writeFile(previous, older)
    const line = JSON.stringify({ ts: '2026-10-19T12:00:00.000Z', level: 'info', scope: 'fixture', message: 'padding' }) + '\n'
    const original = line.repeat(Math.floor((5 * 1024 * 1024 - 450) / Buffer.byteLength(line)))
    await writeFile(path, original)
    logger.logEvent('info', 'fixture', 'new-event')
    const raw = await appended()
    expect(raw.startsWith(original)).toBe(true)
    expect(await readFile(previous, 'utf8')).toBe(older)
    // Ordinary events must still eventually rotate: the exemption is bounded.
    for (let i = 0; i < 12; i++) logger.logEvent('info', 'fixture', 'next-event')
    await logger.flushAppLog()
    expect(await readFile(previous, 'utf8')).toContain('history.corrupted')
    expect(await readFile(previous, 'utf8')).not.toBe(older)
  })
})
