// AT-00-001/004/005, AT-08-005; F-074/F-138/F-143: real handlers + trusted guard.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IpcFault, ipcError } from '../shared/ipc-result'
const s = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => Promise<any>>(),
  rm: vi.fn(), mkdir: vi.fn(), open: vi.fn(), clear: vi.fn(), stop: vi.fn(), exists: vi.fn(), acl: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: (ch: string, fn: any) => s.handlers.set(ch, fn) }, shell: { openPath: s.open } }))
vi.mock('fs/promises', () => ({ rm: s.rm, mkdir: s.mkdir }))
vi.mock('./appLogger', () => ({ clearAppLog: s.clear, logEvent: vi.fn() }))
vi.mock('./trafficForensics', () => ({ stopTrafficForensicsSession: s.stop }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => '/private/traffic' }))
vi.mock('./systemSnapshot', () => ({ getSnapshotsDir: () => '/private/snapshots' }))
vi.mock('./tunController', () => ({ getTunRuntimeDir: () => '/private/runtime' }))
vi.mock('./runtimeDirSecurity', () => ({ directoryExists: s.exists, verifyDirectoryHardened: s.acl }))
import { registerDiagnosticMaintenanceHandlers } from './diagnosticMaintenance'
import { installTrustedIpcBoundary } from './ipcSecurity'
import { logEvent } from './appLogger'
const invoke = (ch: string) => s.handlers.get(ch)!({ sender: {} })
const raw = 'FAKE-SECRET at /private/credentials.json'
const failures = [
  ['permission', () => Object.assign(new Error(raw), { code: 'EACCES' })],
  ['network', () => Object.assign(new Error(raw), { code: 'ECONNREFUSED' })],
  ['timeout', () => Object.assign(new Error(raw), { code: 'ETIMEDOUT' })],
  ['validation', () => new IpcFault('validation')], ['conflict', () => new IpcFault('conflict')],
  ['cancelled', () => Object.assign(new Error(raw), { name: 'AbortError' })],
  ['internal', () => new Error(raw)]
] as const
beforeEach(() => {
  vi.resetAllMocks(); s.handlers.clear()
  s.stop.mockResolvedValue({ running: false, cleanupPending: false })
  s.exists.mockResolvedValue(true); s.acl.mockResolvedValue({ hardened: true })
  s.clear.mockResolvedValue({ success: true, cleared: ['app-log'], absent: [], errors: [] })
  s.open.mockResolvedValue('')
  installTrustedIpcBoundary(); registerDiagnosticMaintenanceHandlers()
})
describe('diagnostic maintenance results', () => {
  it.each(failures)('preserves successful clears and canonical %s failure', async (category, create) => {
    const error = create(); s.rm.mockRejectedValueOnce(error)
    const response = await invoke('clear-diagnostic-artifacts')
    expect(response).toMatchObject({ ok: true, result: { success: false,
      cleared: ['traffic-forensics', 'app-log'], absent: [], errors: [{ artifact: 'snapshots', error: ipcError(category) }] } })
    expect(JSON.stringify(response)).not.toMatch(/FAKE-SECRET|\/private\//)
    expect(s.clear).toHaveBeenCalledOnce()
    expect(logEvent).toHaveBeenCalledWith('error', 'diagnostics', 'artifact cleanup failed: snapshots', error)
  })
  it.each([{ running: true }, { cleanupPending: true }])('retains all evidence while capture is unconfirmed: %j', async status => {
    s.stop.mockResolvedValue(status)
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: false, error: ipcError('conflict') })
    expect(s.rm).not.toHaveBeenCalled(); expect(s.clear).not.toHaveBeenCalled()
  })
  it('retains all evidence if the forensic namespace is untrusted', async () => {
    s.acl.mockResolvedValue({ hardened: false })
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: false, error: ipcError('permission') })
    expect(s.rm).not.toHaveBeenCalled(); expect(s.clear).not.toHaveBeenCalled()
  })
  it('skips a missing forensic namespace and returns only confirmed clears', async () => {
    s.exists.mockResolvedValue(false)
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: true, result: { success: true, cleared: ['snapshots', 'app-log'], absent: ['traffic-forensics'], errors: [] } })
    expect(s.acl).not.toHaveBeenCalled(); expect(s.rm).toHaveBeenCalledOnce()
  })
  it('records an already absent snapshots directory separately', async () => {
    s.rm.mockRejectedValueOnce(Object.assign(new Error('missing'), { code: 'ENOENT' }))
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: true, result: { success: true,
      cleared: ['traffic-forensics', 'app-log'], absent: ['snapshots'], errors: [] } })
  })
  it('keeps the log partial report in both cleanup channels', async () => {
    const report = { success: false, cleared: ['app-log'], absent: [], errors: [{ artifact: 'xray-log', error: ipcError('permission') }] }
    s.clear.mockResolvedValue(report)
    expect(await invoke('clear-app-log')).toMatchObject({ ok: true, result: report })
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: true, result: { ...report, cleared: ['snapshots', 'traffic-forensics', 'app-log'] } })
  })
  it('retains directory successes if log preflight fails', async () => {
    s.clear.mockRejectedValue(Object.assign(new Error(raw), { code: 'EACCES' }))
    expect(await invoke('clear-diagnostic-artifacts')).toMatchObject({ ok: true, result: { success: false,
      cleared: ['snapshots', 'traffic-forensics'], absent: [], errors: [{ artifact: 'logs', error: ipcError('permission') }] } })
  })
  for (const ch of ['open-snapshots-folder', 'open-tun-log-folder']) {
    it.each(failures)(`${ch} rejects canonical %s failures`, async (category, create) => {
      s.open.mockRejectedValue(create())
      const response = await invoke(ch)
      expect(response).toMatchObject({ ok: false, error: ipcError(category) })
      expect(JSON.stringify(response)).not.toMatch(/FAKE-SECRET|\/private\//)
    })
    it(`${ch} rejects a nonempty shell receipt`, async () => {
      s.open.mockResolvedValue(raw)
      expect(await invoke(ch)).toMatchObject({ ok: false, error: ipcError('internal') })
    })
  }
  it('preserves the folder success contracts', async () => {
    expect(await invoke('open-snapshots-folder')).toMatchObject({ ok: true, result: { success: true, path: '/private/snapshots' } })
    expect(await invoke('open-tun-log-folder')).toMatchObject({ ok: true, result: '/private/runtime' })
  })
  it.each(failures)('snapshot directory creation preserves canonical %s', async (category, create) => {
    s.mkdir.mockRejectedValue(create())
    expect(await invoke('open-snapshots-folder')).toMatchObject({ ok: false, error: ipcError(category) })
    expect(s.open).not.toHaveBeenCalled()
  })
  it('writes artifact failure diagnostics after log clear, retaining evidence', async () => {
    s.rm.mockRejectedValueOnce(new Error(raw))
    await invoke('clear-diagnostic-artifacts')
    const diagnostic = vi.mocked(logEvent).mock.calls.findIndex(call => call[2] === 'artifact cleanup failed: snapshots')
    expect(vi.mocked(logEvent).mock.invocationCallOrder[diagnostic]).toBeGreaterThan(s.clear.mock.invocationCallOrder[0])
  })
})
