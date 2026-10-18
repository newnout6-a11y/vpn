import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: unknown[]) => Promise<unknown>>(), reset: vi.fn(), open: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: (channel: string, fn: (...args: unknown[]) => Promise<unknown>) => state.handlers.set(channel, fn) }, shell: { openExternal: state.open } }))
vi.mock('electron-store', () => ({ default: class { get() { return {} }; set() {} } }))
vi.mock('./notifications', () => ({ resetWindowsNotificationBlock: state.reset, getWindowsNotificationState: vi.fn(), setNotificationPrefsProvider: vi.fn() }))
import { registerNotificationPrefsIpcHandlers } from './notificationPrefs'

describe('notification result types (AT-00-001/004; F-138/F-074)', () => {
  beforeEach(() => { vi.resetAllMocks(); registerNotificationPrefsIpcHandlers() })
  for (const channel of ['notifications:reset-os-block', 'notifications:open-windows-settings']) {
    it.each([[new Error('expected message'), 'expected message'], [{ message: { malformed: true } }, '[object Object]'], ['failure', 'failure']])(
      `${channel} preserves string failures and converts non-string messages`, async (error, message) => {
        state.reset.mockRejectedValue(error); state.open.mockRejectedValue(error)
        expect(await state.handlers.get(channel)!()).toEqual({ ok: false, error: message })
      })
  }
})
