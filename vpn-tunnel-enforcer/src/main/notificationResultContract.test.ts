// AT-00-001/004/005; F-138/F-074/F-143: production handlers and IPC guard.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IPC_VERSION, IpcFault, ipcError } from '../shared/ipc-result'

const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => Promise<any>>(), reset: vi.fn(), open: vi.fn(), check: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: (channel: string, fn: (...args: any[]) => Promise<any>) => state.handlers.set(channel, fn) }, shell: { openExternal: state.open } }))
vi.mock('electron-store', () => ({ default: class { get() { return {} }; set() {} } }))
vi.mock('./notifications', () => ({ resetWindowsNotificationBlock: state.reset, getWindowsNotificationState: state.check, setNotificationPrefsProvider: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { installTrustedIpcBoundary } from './ipcSecurity'
import { registerNotificationPrefsIpcHandlers } from './notificationPrefs'
import { logEvent } from './appLogger'

const invoke = (channel: string, ...args: unknown[]) => state.handlers.get(channel)!({ sender: {} }, ...args)
const raw = 'FAKE-SECRET at /private/credentials.json'
const failures = [
  ['permission', () => Object.assign(new Error(raw), { code: 'EACCES' })],
  ['timeout', () => Object.assign(new Error(raw), { code: 'ETIMEDOUT' })],
  ['network', () => Object.assign(new Error(raw), { code: 'ECONNREFUSED' })],
  ['validation', () => new IpcFault('validation')],
  ['conflict', () => new IpcFault('conflict')],
  ['cancelled', () => Object.assign(new Error(raw), { name: 'AbortError' })],
  ['internal', () => new Error(raw)],
  ['internal', () => ({ message: { malformed: true } })],
  ['internal', () => raw]
] as const

describe('notification result taxonomy', () => {
  beforeEach(() => { vi.resetAllMocks(); installTrustedIpcBoundary(); registerNotificationPrefsIpcHandlers() })
  for (const channel of ['notifications:check-os-state', 'notifications:reset-os-block', 'notifications:open-windows-settings']) {
    it.each(failures)(`${channel} propagates %s through the canonical outer envelope`, async (category, create) => {
      state.reset.mockRejectedValue(create()); state.open.mockRejectedValue(create()); state.check.mockRejectedValue(create())
      const response = await invoke(channel)
      expect(response).toEqual({ version: IPC_VERSION, correlationId: expect.stringMatching(/^ipc_[0-9a-f]{32}$/), ok: false, error: ipcError(category) })
      expect(JSON.stringify(response)).not.toContain('FAKE-SECRET')
      expect(vi.mocked(logEvent)).toHaveBeenCalledWith(category === 'cancelled' ? 'debug' : 'error', 'ipc-security', 'IPC request failed', expect.objectContaining({ channel, correlationId: response.correlationId, reason: category }))
    })
  }
  it('preserves cleared entries and typed failures in a partial reset report', async () => {
    const report = { cleared: ['legacy'], errors: [{ appUserModelId: 'current', error: ipcError('permission') }] }
    state.reset.mockResolvedValue(report)
    expect(await invoke('notifications:reset-os-block')).toMatchObject({ ok: true, result: report })
  })
  it('rejects invalid patches before updating preferences', async () => {
    for (const patch of [{ sound: 'true' }, { method: 'unknown' }, { unknown: true }]) {
      expect(await invoke('notifications:set-prefs', patch)).toMatchObject({ ok: false, error: ipcError('validation') })
    }
  })
  it('keeps proven OS state and successful settings launch', async () => {
    state.check.mockResolvedValue({ enabled: false, appUserModelId: 'current' })
    expect(await invoke('notifications:check-os-state')).toMatchObject({ ok: true, result: { osNotificationsEnabled: false, appUserModelId: 'current' } })
    state.open.mockResolvedValue(undefined)
    expect(await invoke('notifications:open-windows-settings')).toMatchObject({ ok: true, result: { ok: true } })
    expect(state.open).toHaveBeenCalledWith('ms-settings:notifications')
  })
})
