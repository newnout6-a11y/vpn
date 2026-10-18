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
    const timestamps = rows.map(row => Date.parse(row.ts))
    expect(timestamps.every(Number.isFinite)).toBe(true)
    expect(timestamps).toEqual([...timestamps].sort((left, right) => left - right))
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
    expect(exportedRows.map(row => row.correlationId)).toEqual(rows.map(row => row.correlationId))
    expect(exported.content).not.toMatch(/must-not-log|private-test-password|8093a2ec|settings\.json/)
  } finally {
    vi.useRealTimers()
    vi.restoreAllMocks()
    if (dirname(state.directory) !== root) throw new Error('Unsafe owned correlation fixture cleanup')
    rmSync(state.directory, { recursive: true, force: true })
  }
})
