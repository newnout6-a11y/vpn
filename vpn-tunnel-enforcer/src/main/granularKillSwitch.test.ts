import { beforeEach, describe, expect, it, vi } from 'vitest'

const storeData = vi.hoisted(() => new Map<string, any>())
const enableKillSwitchMock = vi.hoisted(() => vi.fn())
const disableKillSwitchIfActiveMock = vi.hoisted(() => vi.fn(async () => ({ success: true, message: 'disabled' })))
const isKillSwitchActiveMock = vi.hoisted(() => vi.fn(async () => false))
const settingsGetMock = vi.hoisted(() => vi.fn(() => ({ firewallKillSwitch: false })))
const settingsSaveMock = vi.hoisted(() => vi.fn())
const logEventMock = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  BrowserWindow: { getAllWindows: () => [] },
  dialog: { showOpenDialog: vi.fn() }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    defaults: Record<string, any>

    constructor(options: { defaults?: Record<string, any> } = {}) {
      this.defaults = options.defaults ?? {}
    }

    get(key: string, fallback?: any) {
      if (storeData.has(key)) return storeData.get(key)
      if (Object.prototype.hasOwnProperty.call(this.defaults, key)) return this.defaults[key]
      return fallback
    }

    set(key: string, value: any) {
      storeData.set(key, value)
    }
  }
}))

vi.mock('./firewallKillSwitch', () => ({
  enableKillSwitch: enableKillSwitchMock,
  disableKillSwitchIfActive: disableKillSwitchIfActiveMock,
  isKillSwitchActive: isKillSwitchActiveMock
}))

vi.mock('./appLogger', () => ({ logEvent: logEventMock }))
vi.mock('./notifications', () => ({ notify: vi.fn() }))
vi.mock('./settings', () => ({
  settingsStore: {
    get: settingsGetMock,
    save: settingsSaveMock
  }
}))

describe('granularKillSwitch level application', () => {
  beforeEach(() => {
    vi.resetModules()
    storeData.clear()
    enableKillSwitchMock.mockReset()
    disableKillSwitchIfActiveMock.mockClear()
    isKillSwitchActiveMock.mockClear()
    settingsGetMock.mockClear()
    settingsSaveMock.mockClear()
    logEventMock.mockClear()
  })

  it('rejects and rolls back when enabling before init would otherwise mask a boot race', async () => {
    const { granularKillSwitch } = await import('./granularKillSwitch')

    await expect(granularKillSwitch.setLevel('standard')).rejects.toThrow(/sing-box path is initialized/)

    expect(granularKillSwitch.getLevel()).toBe('off')
    expect(storeData.get('killSwitchLevel')).toBeUndefined()
    expect(settingsSaveMock).not.toHaveBeenCalled()
    expect(enableKillSwitchMock).not.toHaveBeenCalled()
  })

  it('rolls back the stored level when firewall rule installation fails', async () => {
    enableKillSwitchMock.mockResolvedValue({ success: false, message: 'access denied' })
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')

    await expect(granularKillSwitch.setLevel('strict')).rejects.toThrow(/Failed to engage kill-switch/)

    expect(granularKillSwitch.getLevel()).toBe('off')
    expect(storeData.get('killSwitchLevel')).toBe('off')
    expect(enableKillSwitchMock).toHaveBeenCalledWith(expect.objectContaining({
      singboxExePath: 'C:\\Tools\\sing-box.exe'
    }))
    expect(settingsSaveMock).toHaveBeenLastCalledWith({ firewallKillSwitch: false })
  })
})
