// AT-00-005: real IPC boundary, lifecycle, logger, redactor and on-disk JSONL.
import { expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import type { IpcMainInvokeEvent } from 'electron'

const state = vi.hoisted(() => ({ directory: '', handlers: new Map<string, (event: IpcMainInvokeEvent) => Promise<unknown>>() }))
vi.mock('electron', () => ({ app: { isPackaged: true, getPath: () => state.directory }, shell: {}, ipcMain: {
  handle: (channel: string, listener: (event: IpcMainInvokeEvent) => Promise<unknown>) => state.handlers.set(channel, listener)
} }))

it('keeps concurrent IPC actions correlated through native waits, operation events and redacted disk logs', async () => {
  const root = resolve('.tmp')
  mkdirSync(root, { recursive: true })
  state.directory = mkdtempSync(join(root, 'action-correlation-'))
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  vi.setSystemTime(new Date('2026-10-19T00:00:00Z'))
  try {
    const { ipcMain } = await import('electron')
    const { installTrustedIpcBoundary, registerTrustedRenderer } = await import('./ipcSecurity')
    const { ConnectionLifecycle } = await import('./connectionLifecycle')
    const { logEvent, getAppLogPath, getFullLogs } = await import('./appLogger')
    const { unwrapIpcResult, serializeIpcError } = await import('../shared/ipc-result')
    installTrustedIpcBoundary()
    const operations: { action: string; correlationId: string }[] = []
    const release: Array<() => void> = []
    const secret = '8093a2ec-f028-4e3c-96a7-b301efaf23dd'
    let requests = 0
    ipcMain.handle('start-direct-vpn', () => {
      const action = requests++ === 0 ? 'a' : 'b'
      // Independent fake resource owners exercise concurrent async scopes.
      const lane = new ConnectionLifecycle(() => {}, undefined, operation => {
        operations.push({ action, correlationId: operation.correlationId })
        logEvent('info', `lifecycle-${action}`, 'operation', operation)
      })
      return lane.start(async owner => {
        logEvent('info', `effect-${action}`, 'before native wait', { credential: secret })
        await owner.wait(new Promise<void>(done => { release.push(done) }))
        logEvent('info', `effect-${action}`, 'after native wait', { password: 'private-test-password' })
        return { success: true }
      })
    })
    const frame = { url: 'file:///C:/app/index.html' }, sender = { mainFrame: frame, id: 7 }
    registerTrustedRenderer(sender as never, frame.url)
    const event = { sender, senderFrame: frame } as unknown as IpcMainInvokeEvent
    const invoke = state.handlers.get('start-direct-vpn')!
    const first = invoke(event), second = invoke(event)
    expect(release).toHaveLength(2)
    // A Windows/NTP clock correction must not reorder this action's events.
    vi.setSystemTime(new Date('2026-10-18T23:00:00Z'))
    release[1]()
    const b = await second as { correlationId: string }
    release[0]()
    const a = await first as { correlationId: string }
    await expect.poll(() => { try { return readFileSync(getAppLogPath(), 'utf8').trim().split('\n').length } catch { return 0 } }).toBe(8)
    expect(a.correlationId).not.toBe(b.correlationId)
    expect(unwrapIpcResult(a)).toEqual({ success: true })
    expect(unwrapIpcResult(b)).toEqual({ success: true })
    expect(operations.filter(op => op.action === 'a').map(op => op.correlationId)).toEqual([a.correlationId, a.correlationId])
    expect(operations.filter(op => op.action === 'b').map(op => op.correlationId)).toEqual([b.correlationId, b.correlationId])

    ipcMain.handle('get-settings', () => { throw new Error('must-not-log C:\\private\\settings.json') })
    const failure = await state.handlers.get('get-settings')!(event) as { correlationId: string }
    let remote: unknown
    try { unwrapIpcResult(failure) } catch (error) { remote = serializeIpcError(error, 'en') }
    expect(remote).toMatchObject({ correlationId: failure.correlationId, category: 'internal' })
    await expect.poll(() => { try { return readFileSync(getAppLogPath(), 'utf8').trim().split('\n').length } catch { return 0 } }).toBe(9)
    const raw = readFileSync(getAppLogPath(), 'utf8')
    const rows = raw.trim().split('\n').map(line => JSON.parse(line))
    const timestamps = rows.map(row => row.monotonicMs)
    expect(timestamps.every(Number.isFinite)).toBe(true)
    expect(timestamps).toEqual([...timestamps].sort((left, right) => left - right))
    expect(new Set(rows.map(row => row.clockId)).size).toBe(1)
    expect(rows[0].clockId).toMatch(/^clock_[0-9a-f]{24}$/)
    expect(rows[0].ts).toBe('2026-10-19T00:00:00.000Z')
    expect(rows.at(-1).ts).toBe('2026-10-18T23:00:00.000Z')
    for (const [action, response] of [['a', a], ['b', b]] as const) {
      const actionRows = rows.filter(row => row.scope.endsWith(`-${action}`))
      expect(actionRows).toHaveLength(4)
      expect(actionRows.map(row => row.correlationId)).toEqual(Array(4).fill(response.correlationId))
    }
    expect(rows.at(-1).correlationId).toBe(failure.correlationId)
    expect(raw).not.toMatch(/must-not-log|private-test-password|8093a2ec|settings\.json/)
    expect(raw).toContain('<redacted-uuid>')
    // Diagnostics applies redaction again when reading the on-disk log.
    const exported = (await getFullLogs()).find(file => file.path === getAppLogPath())!
    expect(exported.exists).toBe(true)
    const exportedRows = exported.content.trim().split('\n').map(line => JSON.parse(line))
    expect(exportedRows.map(row => row.monotonicMs)).toEqual(timestamps)
    expect(exportedRows.map(row => row.clockId)).toEqual(rows.map(row => row.clockId))
    expect(exportedRows.map(row => row.correlationId)).toEqual(rows.map(row => row.correlationId))
    expect(exported.content).not.toMatch(/must-not-log|private-test-password|8093a2ec|settings\.json/)
  } finally {
    vi.useRealTimers()
    vi.restoreAllMocks()
    if (dirname(state.directory) !== root) throw new Error('Unsafe owned correlation fixture cleanup')
    rmSync(state.directory, { recursive: true, force: true })
  }
})

it('distinguishes concurrent operation keys within one action through disk and diagnostic redaction (AT-00-005)', async () => {
  vi.resetModules()
  const root = resolve('.tmp')
  mkdirSync(root, { recursive: true })
  state.directory = mkdtempSync(join(root, 'operation-correlation-'))
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  const { operations } = await import('./operations')
  const releases: Array<() => void> = []
  const gates = Array.from({ length: 2 }, () => new Promise<void>(resolve => { releases.push(resolve) }))
  try {
    const { getAppLogPath, getFullLogs, logEvent } = await import('./appLogger')
    const { withCorrelation } = await import('./actionCorrelation')
    const correlationId = 'ipc_3d49f22af56f4eb795812df333b9aa55'
    const [cancelled, successful] = withCorrelation(correlationId, () => [
      operations.run('speed-test', async lease => lease.wait(gates[0])).catch(error => error),
      operations.run('export', async lease => { await lease.wait(gates[1]); return 'saved' })
    ])
    const records = operations.list()
    expect(records).toHaveLength(2)
    expect(new Set(records.map(record => record.operationId)).size).toBe(2)
    expect(operations.cancel(records[0].operationId)).toBe(true)
    expect(await cancelled).toMatchObject({ category: 'cancelled' })
    releases[1]()
    expect(await successful).toBe('saved')
    releases[0]()
    await operations.close()
    logEvent('info', 'fixture', 'secret masking remains active', { credential: '8093a2ec-f028-4e3c-96a7-b301efaf23dd' })
    await expect.poll(() => { try { return readFileSync(getAppLogPath(), 'utf8').trim().split('\n').length } catch { return 0 } }).toBe(5)
    const raw = readFileSync(getAppLogPath(), 'utf8')
    const events = raw.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')
    const keys = records.map(record => 'op_' + record.operationId.replaceAll('-', ''))
    expect(new Set(events.map(row => row.details.operationKey))).toEqual(new Set(keys))
    for (const [index, key] of keys.entries()) {
      const group = events.filter(row => row.details.operationKey === key)
      expect(group.map(row => row.details.status)).toEqual(['running', index === 0 ? 'cancelled' : 'success'])
      expect(group.every(row => row.correlationId === correlationId && row.details.correlationId === correlationId)).toBe(true)
      expect(raw).not.toContain(records[index].operationId)
    }
    expect(raw).not.toContain('8093a2ec')
    const exported = (await getFullLogs()).find(file => file.path === getAppLogPath())!
    const readBack = exported.content.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')
    expect(readBack).toEqual(events)
    expect(exported.content).not.toContain('8093a2ec')
  } finally {
    for (const release of releases) release()
    await operations.close()
    vi.restoreAllMocks()
    if (dirname(state.directory) !== root) throw new Error('Unsafe owned operation fixture cleanup')
    rmSync(state.directory, { recursive: true, force: true })
  }
})
