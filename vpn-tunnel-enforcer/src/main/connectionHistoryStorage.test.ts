import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { ConnectionLogEntry, ConnectionHistoryEntryInput } from '../shared/ipc-types'
import { SESSION_OUTCOME_KINDS } from '../shared/ipc-types'
import { OPERATION_PRIORITY } from '../shared/operation'
import { randomUUID } from 'node:crypto'
import ts from 'typescript'

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

const entry: ConnectionHistoryEntryInput = {
  startedAt: 1700000000000, endedAt: 1700000001000, durationMs: 1000,
  profileId: 'profile-1', profileName: 'Test', mode: 'hard',
  bytesDown: 10, bytesUp: 20, disconnectReason: 'user',
  provenance: { source: 'unknown', owner: 'unknown', route: 'unconfirmed', confidence: 'indeterminate' }
}
const file = () => join(state.dir, 'connection-history.json')
const reload = async () => {
  vi.resetModules()
  return (await import('./connectionHistory')).connectionHistoryService
}
const corruptionEvents = () => state.logEvent.mock.calls.filter(call => call[2] === 'history.corrupted')

async function sessionTracking(service: Awaited<ReturnType<typeof reload>>) {
  // Execute the actual main session functions, replacing only their boundaries.
  const source = ts.createSourceFile('index.ts', await readFile(join(process.cwd(), 'src/main/index.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
  const names = ['openSession', 'writeSessionEntry', 'closeSession', 'recordStartFailure', 'startProtectionFromTray']
  const functions = source.statements.filter(node => ts.isFunctionDeclaration(node) && [...names, 'startProtectionFromTrayEffects', 'captureSessionOrigin'].includes(node.name?.text ?? ''))
  expect(names.every(name => functions.some(node => ts.isFunctionDeclaration(node) && node.name?.text === name))).toBe(true)
  const { currentCorrelationId, currentActionMetadata, withCorrelation } = await import('./actionCorrelation')
  const { randomUUID } = await import('node:crypto')
  const { monotonicTimeMs } = await import('./eventClock')
  const { makeOutcome, outcomeKindToDisconnectReason, sessionOutcomeConfidence } = await import('./sessionOutcome')
  const notificationIds: Array<string | undefined> = []
  const dependencies = { currentCorrelationId, currentActionMetadata, withCorrelation, randomUUID, monotonicTimeMs, connectionHistoryService: service, makeOutcome, outcomeKindToDisconnectReason, sessionOutcomeConfidence,
    settingsStore: { get: () => ({ connectionMode: 'localProxy', routingMode: 'hard' }) },
    resolveProxyForTrayStart: async () => null, notify: () => notificationIds.push(currentCorrelationId()),
    restoreAndFocusMainWindow: () => {},
    trafficMonitor: { getCurrentStats: () => ({ sessionDownloadBytes: 10, sessionUploadBytes: 20 }) }, logEvent: state.logEvent }
  const code = ts.transpileModule(`let currentSession = null;
${functions.map(node => node.getText(source)).join('\n')}
return { open: (mode = 'hard') => openSession({ id: 'profile', name: 'Test', mode }),
close: (kind = 'user-stop') => closeSession(makeOutcome(kind)),
failure: () => recordStartFailure({ id: 'profile', name: 'Test', mode: 'hard' }, 'Start failed'),
tray: startProtectionFromTray };`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  return { ...new Function(...Object.keys(dependencies), code)(...Object.values(dependencies)), notificationIds } as {
    open(mode?: ConnectionLogEntry['mode']): void; close(kind?: NonNullable<ConnectionLogEntry['outcome']>['kind']): void; failure(): void; tray(): Promise<void>; notificationIds: Array<string | undefined>
  }
}

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
  it.each([-3_600_000, 40 * 86_400_000])('keeps calendar filters and monotonic duration after a %i ms correction (AT-00-005)', async correction => {
    const service = await reload(), tracking = await sessionTracking(service)
    const epoch = 1792368000000, corrected = epoch + correction
    const wallClock = vi.spyOn(Date, 'now').mockReturnValue(epoch)
    try {
      tracking.open()
      await new Promise(resolve => setTimeout(resolve, 15))
      wallClock.mockReturnValue(corrected)
      tracking.close()
      tracking.open(); tracking.close()
      tracking.failure()
      const reloaded = await reload(), [saved, fresh, failed] = reloaded.getEntries()
      expect(saved).toMatchObject({ startedAt: epoch, endedAt: corrected })
      expect(saved.durationMs).toBeGreaterThanOrEqual(10)
      expect(saved.durationMs).toBeLessThan(10_000)
      expect(fresh).toMatchObject({ startedAt: corrected, endedAt: corrected })
      expect(failed).toMatchObject({ startedAt: corrected, endedAt: corrected, durationMs: 0 })
      expect(reloaded.filter({ dateFrom: corrected, dateTo: corrected }).map(entry => entry.id)).toEqual([fresh.id, failed.id])
      if (correction > 0) for (const period of ['day', 'week', 'month'] as const) expect(reloaded.stats(period).entryCount).toBe(1)
    } finally { wallClock.mockRestore() }
  })
  it.each(['ipc', 'tray', 'lifecycle'] as const)('retains %s provenance and every admitted owner after a different stop action (AT-00-005)', async source => {
    const service = await reload(), tracking = await sessionTracking(service)
    const { withCorrelation } = await import('./actionCorrelation')
    const { ConnectionLifecycle } = await import('./connectionLifecycle')
    for (const owner of Object.keys(OPERATION_PRIORITY) as Array<keyof typeof OPERATION_PRIORITY>) {
      const lane = new ConnectionLifecycle(() => {})
      const start = () => lane.start(async () => { tracking.open(); return { success: true } }, { owner })
      if (source === 'lifecycle') await start()
      else await withCorrelation((source === 'ipc' ? 'ipc_' : 'op_') + randomUUID().replaceAll('-', ''), start, { source })
      await withCorrelation('ipc_' + randomUUID().replaceAll('-', ''), () => lane.stop(async () => { tracking.close(); return { success: true } }))
    }
    const entries = (await reload()).getEntries()
    const expected = Object.keys(OPERATION_PRIORITY).map(owner => ({ source, owner, route: 'tun', confidence: 'observed' }))
    expect(entries.map(entry => entry.provenance)).toEqual(expected)
    expect(JSON.parse(service.exportJson()).map((entry: ConnectionLogEntry) => entry.provenance)).toEqual(expected)
    const csv = service.exportCsv().split('\n').map(row => row.split(','))
    expect(csv.slice(1).map(row => ['source', 'owner', 'route', 'confidence'].map(key => row[csv[0].indexOf(key)])))
      .toEqual(expected.map(p => [p.source, p.owner, p.route, p.confidence]))
  })

  it.each(['hard', 'direct', 'soft'] as const)('records the %s mechanism without attesting packet-level protection (AT-00-005)', async mode => {
    const service = await reload(), tracking = await sessionTracking(service)
    tracking.open(mode); tracking.close()
    expect((await reload()).getEntries()[0]).toMatchObject({ mode, provenance: { source: 'runtime', owner: 'unknown',
      route: mode === 'soft' ? 'soft-env' : 'tun', confidence: 'observed' } })
  })

  it.each(SESSION_OUTCOME_KINDS)('reports conservative confidence for %s (AT-00-005)', async kind => {
    const service = await reload(), tracking = await sessionTracking(service)
    tracking.open(); tracking.close(kind)
    const confidence = kind === 'unknown' ? 'indeterminate'
      : ['user-stop', 'app-quit', 'server-switch', 'rotation', 'schedule', 'start-failed'].includes(kind) ? 'observed' : 'inferred'
    expect((await reload()).getEntries()[0]).toMatchObject({ provenance: { source: 'runtime', owner: 'unknown', route: 'tun', confidence } })
  })

  it('requires provenance on every new write while retaining legacy reads (AT-00-005)', async () => {
    const service = await reload()
    const { provenance: _provenance, ...legacy } = entry as ConnectionHistoryEntryInput
    expect(() => service.addEntry(legacy as ConnectionHistoryEntryInput)).toThrow('Invalid connection history entry')
    await writeFile(file(), JSON.stringify({ connectionHistory: [{ ...legacy, id: 'legacy' }] }))
    expect((await reload()).getEntries()).toEqual([{ ...legacy, id: 'legacy' }])
  })

  it('requires elapsed duration on new writes and exports it unchanged (AT-00-005)', async () => {
    const service = await reload()
    const { durationMs: _duration, ...legacy } = entry
    expect(() => service.addEntry(legacy as ConnectionHistoryEntryInput)).toThrow('Invalid connection history entry')
    service.addEntry(entry)
    expect(JSON.parse(service.exportJson())[0].durationMs).toBe(entry.durationMs)
    const csv = service.exportCsv().split('\n').map(row => row.split(','))
    expect(Number(csv[1][csv[0].indexOf('durationMs')])).toBe(entry.durationMs)
  })

  it('correlates repeated missing-proxy tray attempts before lifecycle admission (AT-00-005)', async () => {
    const service = await reload(), tracking = await sessionTracking(service)
    await tracking.tray(); await tracking.tray()
    const entries = (await reload()).getEntries()
    expect(entries).toHaveLength(2)
    const ids = entries.map(entry => entry.correlationId)
    expect(ids.every(id => typeof id === 'string' && /^op_[0-9a-f]{32}$/.test(id))).toBe(true)
    expect(new Set(ids).size).toBe(2)
    expect(tracking.notificationIds).toEqual(ids)
    expect(entries.every(entry => entry.outcome?.kind === 'start-failed')).toBe(true)
    expect(entries.every(entry => JSON.stringify(entry.provenance) === JSON.stringify({ source: 'tray', owner: 'manual', route: 'unconfirmed', confidence: 'observed' }))).toBe(true)
  })

  it('links guarded IPC and production session tracking to reloaded disk history (AT-00-005)', async () => {
    const service = await reload(), tracking = await sessionTracking(service)
    const { ipcMain } = await import('electron')
    const originalHandle = ipcMain.handle
    const handlers = new Map<string, (...args: any[]) => Promise<any>>()
    ipcMain.handle = vi.fn((channel, listener) => { handlers.set(channel, listener as never) })
    try {
      const { installTrustedIpcBoundary, registerTrustedRenderer } = await import('./ipcSecurity')
      const { ConnectionLifecycle } = await import('./connectionLifecycle')
      installTrustedIpcBoundary()
      const lane = new ConnectionLifecycle(() => {})
      ipcMain.handle('start-direct-vpn', () => lane.start(async () => { tracking.open(); return { success: true } }))
      ipcMain.handle('stop-tun', () => lane.stop(async () => { tracking.close(); return { success: true } }))
      const frame = { url: 'file:///C:/app/index.html' }, sender = { id: 7, mainFrame: frame }
      registerTrustedRenderer(sender as never, frame.url)
      const event = { sender, senderFrame: frame }
      const start = await handlers.get('start-direct-vpn')!(event)
      const stop = await handlers.get('stop-tun')!(event)
      expect(start).toMatchObject({ ok: true, result: { success: true } })
      expect(stop).toMatchObject({ ok: true, result: { success: true } })
      expect(stop.correlationId).not.toBe(start.correlationId)
      expect((await reload()).getEntries()).toMatchObject([{ correlationId: start.correlationId }])
    } finally { ipcMain.handle = originalHandle }
  })

  it.each(['manual-stop', 'no-context'])('persists the original connect ID after %s (AT-00-005)', async ending => {
    const service = await reload(), tracking = await sessionTracking(service)
    const { withCorrelation } = await import('./actionCorrelation')
    const connectId = 'ipc_00000000000040008000000000000001', stopId = 'ipc_00000000000040008000000000000002'
    await withCorrelation(connectId, async () => tracking.open())
    if (ending === 'manual-stop') await withCorrelation(stopId, async () => tracking.close())
    else tracking.close()
    expect(service.getEntries()).toMatchObject([{ correlationId: connectId }])
    const restarted = await reload()
    expect(restarted.getEntries()).toMatchObject([{ correlationId: connectId }])
    expect(JSON.parse(restarted.exportJson())).toMatchObject([{ correlationId: connectId }])
    const csv = restarted.exportCsv().split('\n').map(row => row.split(','))
    expect(csv[1][csv[0].indexOf('correlationId')]).toBe(connectId)
  })

  it('persists a failed start action without inventing an ID for untracked sessions (AT-00-005)', async () => {
    const service = await reload(), tracking = await sessionTracking(service)
    const { withCorrelation } = await import('./actionCorrelation')
    const failedId = 'op_00000000000040008000000000000001'
    withCorrelation(failedId, () => tracking.failure())
    tracking.open(); tracking.close()
    const entries = (await reload()).getEntries()
    expect(entries[0]).toMatchObject({ correlationId: failedId, outcome: { kind: 'start-failed' } })
    expect(entries[1]).not.toHaveProperty('correlationId')
  })
  it.each(SESSION_OUTCOME_KINDS)('roundtrips shared outcome kind %s', async kind => {
    const service = await reload()
    const written = service.addEntry({ ...entry, outcome: { kind, headline: kind } })
    expect((await reload()).getEntries()).toEqual([written])
    expect(corruptionEvents()).toEqual([])
  })

  it('preserves 100 events and legacy optional fields across reload', async () => {
    const service = await reload()
    const written = Array.from({ length: 100 }, () => service.addEntry(entry))
    // Existing records predate outcome/errorMessage; they remain valid.
    const legacy = { ...written[0] }
    delete legacy.outcome
    delete legacy.errorMessage
    delete legacy.provenance
    delete legacy.durationMs
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
    expect(JSON.parse(await readFile(file(), 'utf8')).rejectedConnectionHistory).toEqual(bad)
    restarted.addEntry(entry)
    expect(JSON.parse(await readFile(file(), 'utf8')).rejectedConnectionHistory).toEqual(bad)
    restarted.clearHistory()
    expect(JSON.parse(await readFile(file(), 'utf8')).rejectedConnectionHistory).toEqual([])
  })

  it('preserves an outcome from a newer build when appending valid history', async () => {
    const service = await reload()
    const good = service.addEntry(entry)
    const future = { ...good, outcome: { kind: 'future-outcome', headline: 'Newer version', futureEvidence: { version: 2 } } }
    await writeFile(file(), JSON.stringify({ connectionHistory: [good, future] }))
    expect((await reload()).getEntries()).toEqual([good])
    service.addEntry(entry)
    expect(JSON.parse(await readFile(file(), 'utf8')).rejectedConnectionHistory).toEqual([future])
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
    ...[-1, 'raw-secret', null, Number.POSITIVE_INFINITY].map(durationMs => ({ durationMs })),
    ...[null, {}, { source: 'ipc', owner: 'manual', route: 'tun' },
      ...['source', 'owner', 'route', 'confidence'].map(key => ({ source: 'ipc', owner: 'manual', route: 'tun', confidence: 'observed', [key]: 'raw-secret' })),
      { source: 'ipc', owner: 'manual', route: 'soft-env', confidence: 'observed' },
      { source: 'ipc', owner: 'manual', route: 'tun', confidence: 'observed', secret: 'raw-secret' }]
      .map(provenance => ({ provenance })),
    ...['raw-secret', '00000000-0000-4000-8000-000000000001', 'ipc_' + '0'.repeat(32),
      'ipc_00000000000040008000000000000001\n', null, {}].map(correlationId => ({ correlationId })),
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
