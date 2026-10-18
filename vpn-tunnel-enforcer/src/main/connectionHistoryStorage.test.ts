import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { ConnectionLogEntry } from '../shared/ipc-types'

const state = vi.hoisted(() => ({ dir: '', logEvent: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: state.logEvent }))
// electron-store delegates persistence/deserialization to Conf. Keep its real
// disk backend, replacing only Electron's userData/version discovery.
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) {
      super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' })
    }
  } }
})

const entry: Omit<ConnectionLogEntry, 'id'> = {
  startedAt: 1700000000000, endedAt: 1700000001000,
  profileId: 'profile-1', profileName: 'Test', mode: 'hard',
  bytesDown: 10, bytesUp: 20, disconnectReason: 'user'
}
const file = () => join(state.dir, 'connection-history.json')
const reload = async () => {
  vi.resetModules()
  return (await import('./connectionHistory')).connectionHistoryService
}
const corruptionEvents = () => state.logEvent.mock.calls.filter(call => call[2] === 'history.corrupted')

beforeEach(async () => {
  await mkdir(join(process.cwd(), '.tmp'), { recursive: true })
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'history-storage-'))
  state.logEvent.mockClear()
})
afterEach(async () => {
  expect(dirname(state.dir)).toBe(join(process.cwd(), '.tmp'))
  await rm(state.dir, { recursive: true, force: true })
})

describe('connection history persistence (AT-00-010; F-143)', () => {
  it('preserves 100 events and legacy optional fields across reload', async () => {
    const service = await reload()
    const written = Array.from({ length: 100 }, () => service.addEntry(entry))
    // Existing records predate outcome/errorMessage; they remain valid.
    const legacy = { ...written[0] }
    delete legacy.outcome
    delete legacy.errorMessage
    written[0] = legacy
    await writeFile(file(), JSON.stringify({ connectionHistory: written }))
    const restarted = await reload()
    expect(restarted.getEntries()).toEqual(written)
    expect(JSON.parse(restarted.exportJson())).toEqual(written)
    expect(restarted.exportCsv().split('\n')).toHaveLength(101)
    expect(corruptionEvents()).toEqual([])
  })

  it.each(['truncated', 'garbage-tail'])('reports %s JSON after 100 events and accepts new writes', async damage => {
    const service = await reload()
    for (let i = 0; i < 100; i++) service.addEntry(entry)
    const original = await readFile(file(), 'utf8')
    await writeFile(file(), damage === 'truncated' ? original.slice(0, original.length / 2) : original + 'garbage')
    const restarted = await reload()
    expect(restarted.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(1)
    expect(corruptionEvents()[0]).toEqual(['error', 'connection-history', 'history.corrupted', { reason: 'invalid-json' }])
    const next = restarted.addEntry(entry)
    expect((await reload()).getEntries()).toEqual([next])
  })

  it('retains valid records and reports malformed array members without leaking contents', async () => {
    const service = await reload()
    const good = service.addEntry(entry)
    const bad = [null, { ...good, profileName: { token: 'must-not-log' } }, { ...good, bytesDown: -1 },
      { ...good, outcome: { kind: 'singbox-crash', headline: {} } }]
    await writeFile(file(), JSON.stringify({ connectionHistory: [good, ...bad] }))
    const restarted = await reload()
    expect(restarted.getEntries()).toEqual([good])
    expect(restarted.getEntries()).toEqual([good])
    expect(corruptionEvents()).toHaveLength(1)
    expect(corruptionEvents()[0][3]).toEqual({ reason: 'invalid-schema', rejectedEntries: 4 })
    expect(JSON.stringify(state.logEvent.mock.calls)).not.toContain('must-not-log')
    const next = restarted.addEntry(entry)
    expect((await reload()).getEntries()).toEqual([good, next])
  })

  it.each([null, [], 'secret-value', { connectionHistory: {} }])('reports an invalid root instead of silently dropping history: %j', async value => {
    await writeFile(file(), JSON.stringify(value))
    const service = await reload()
    expect(service.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(1)
    service.addEntry(entry)
    expect((await reload()).getEntries()).toHaveLength(1)
  })

  it('detects corruption during a session and reports changed damage separately', async () => {
    const service = await reload()
    service.addEntry(entry)
    await writeFile(file(), '{broken')
    expect(service.getEntries()).toEqual([])
    expect(service.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(1)
    await writeFile(file(), '{different')
    expect(service.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(2)
    service.addEntry(entry)
    await writeFile(file(), '{different')
    expect(service.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(3)
  })

  it.each([
    { mode: ['hard'] }, { disconnectReason: ['user'] }, { bytesUp: '20' }, { endedAt: {} },
    { errorMessage: [] }, { outcome: { kind: 'future-kind', headline: 'test' } },
    { outcome: { kind: 'unknown', headline: 'test', evidence: { egressIp: {} } } },
    { outcome: { kind: 'unknown', headline: 'test', evidence: { adaptiveAttempts: -1 } } },
    { outcome: { kind: 'unknown', headline: 'test', evidence: { killSwitchEngaged: 'true' } } },
    { outcome: { kind: 'unknown', headline: 'test', evidence: { outboundFault: ['upstream-unreachable'] } } }
  ])('rejects malformed field values on read and before write: %j', async fields => {
    const service = await reload()
    const good = service.addEntry(entry)
    await writeFile(file(), JSON.stringify({ connectionHistory: [{ ...good, ...fields }] }))
    expect(service.getEntries()).toEqual([])
    expect(corruptionEvents()).toHaveLength(1)
    const damaged = await readFile(file(), 'utf8')
    expect(() => service.addEntry({ ...entry, ...fields } as typeof entry)).toThrow('Invalid connection history entry')
    expect(await readFile(file(), 'utf8')).toBe(damaged)
  })

  it('keeps all structured evidence fields and resets corruption suppression after clear', async () => {
    const service = await reload()
    const complete = service.addEntry({ ...entry, outcome: { kind: 'singbox-crash', headline: 'crash', evidence: {
      singboxExitCode: 1, singboxStderrTail: 'stderr', outboundFault: 'upstream-unreachable',
      adaptiveMode: 'external-managed', adaptiveAttempts: 2, autoRestartAttempts: 1,
      killSwitchEngaged: true, leakDetectedDuringSession: false, networkTransition: 'changed',
      egressCountry: 'US', egressIp: '198.51.100.7', proxyEngine: 'xray', hint: 'retry'
    } } })
    expect((await reload()).getEntries()).toEqual([complete])
    await writeFile(file(), '{bad')
    service.getEntries()
    expect(corruptionEvents()).toHaveLength(1)
    service.clearHistory()
    await writeFile(file(), '{bad')
    service.getEntries()
    expect(corruptionEvents()).toHaveLength(2)
  })

  it('does not treat a filesystem read failure as recoverable JSON damage', async () => {
    await mkdir(file())
    await expect(reload()).rejects.toThrow()
    expect(corruptionEvents()).toEqual([])
  })
})
