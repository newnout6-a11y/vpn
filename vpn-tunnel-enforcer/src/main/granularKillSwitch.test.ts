import { beforeEach, describe, expect, it, vi } from 'vitest'

const storeData = vi.hoisted(() => new Map<string, any>())
const enableKillSwitchMock = vi.hoisted(() => vi.fn())
const disableKillSwitchIfActiveMock = vi.hoisted(() => vi.fn(async () => ({ success: true, message: 'disabled' })))
const updateExceptionsMock = vi.hoisted(() => vi.fn(async (_apps: string[], _cidrs: string[], _strict?: boolean) => ({ success: true, message: 'updated' })))
const writeFault = vi.hoisted(() => ({ exceptions: false }))
const isKillSwitchActiveMock = vi.hoisted(() => vi.fn(async () => false))
const settingsGetMock = vi.hoisted(() => vi.fn(() => ({ firewallKillSwitch: false })))
const settingsSaveMock = vi.hoisted(() => vi.fn())
const logEventMock = vi.hoisted(() => vi.fn())
const tunRunningMock = vi.hoisted(() => vi.fn(() => false))

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
      if (key === 'killSwitchExceptions' && writeFault.exceptions) { writeFault.exceptions = false; throw new Error('disk full') }
      storeData.set(key, value)
    }
  }
}))

vi.mock('./firewallKillSwitch', async importOriginal => {
  const actual = await importOriginal<typeof import('./firewallKillSwitch')>()
  return { ...actual, enableKillSwitch: enableKillSwitchMock,
    disableKillSwitchIfActive: disableKillSwitchIfActiveMock,
    isKillSwitchActive: isKillSwitchActiveMock, updateKillSwitchExceptions: updateExceptionsMock }
})

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: vi.fn(() => ({ running: tunRunningMock() }))
  }
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
    updateExceptionsMock.mockReset().mockResolvedValue({ success: true, message: 'updated' })
    writeFault.exceptions = false
    disableKillSwitchIfActiveMock.mockReset().mockResolvedValue({ success: true, message: 'disabled' })
    isKillSwitchActiveMock.mockReset().mockResolvedValue(false)
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

  it('keeps standard protection installed while connected so a drop cannot race activation', async () => {
    enableKillSwitchMock.mockResolvedValue({ success: true, message: 'enabled' })
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    granularKillSwitch.setVpnConnected(true)

    await granularKillSwitch.setLevel('standard')

    expect(granularKillSwitch.getLevel()).toBe('standard')
    expect(granularKillSwitch.isVpnConnected()).toBe(true)
    expect(enableKillSwitchMock).toHaveBeenCalled()
    expect(disableKillSwitchIfActiveMock).not.toHaveBeenCalled()
  })

  it('engages kill-switch in standard mode when VPN is not connected', async () => {
    enableKillSwitchMock.mockResolvedValue({ success: true, message: 'enabled' })
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    granularKillSwitch.setVpnConnected(false)

    await granularKillSwitch.setLevel('standard')

    expect(granularKillSwitch.getLevel()).toBe('standard')
    expect(enableKillSwitchMock).toHaveBeenCalledWith(expect.objectContaining({
      singboxExePath: 'C:\\Tools\\sing-box.exe'
    }))
  })

  it('dynamically queries tunController running status when vpnConnected was not mutated directly', async () => {
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')

    tunRunningMock.mockReturnValue(true)
    expect(granularKillSwitch.isVpnConnected()).toBe(true)

    tunRunningMock.mockReturnValue(false)
    expect(granularKillSwitch.isVpnConnected()).toBe(false)
  })
  it('uses differential updates rather than rebuilding an active firewall', async () => {
    isKillSwitchActiveMock.mockResolvedValue(true)
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    await granularKillSwitch.setLevel('standard')
    expect(updateExceptionsMock).toHaveBeenCalledWith([], [], false)
    expect(enableKillSwitchMock).not.toHaveBeenCalled()
    expect(disableKillSwitchIfActiveMock).not.toHaveBeenCalled()
  })
  it('does not report a successful level change if firewall disable fails', async () => {
    isKillSwitchActiveMock.mockResolvedValue(true)
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    await granularKillSwitch.setLevel('strict')
    disableKillSwitchIfActiveMock.mockResolvedValue({ success: false, message: 'access denied' })
    await expect(granularKillSwitch.setLevel('off')).rejects.toThrow('disengage')
    expect(granularKillSwitch.getLevel()).toBe('strict')
  })
  it('serializes 50 concurrent changes and commits the complete exception set (AT-03-008)', async () => {
    isKillSwitchActiveMock.mockResolvedValue(true)
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    const operations = Array.from({ length: 50 }, (_, i) => granularKillSwitch.addException({ type: 'ip', value: `192.0.2.${i+1}`, label: `test-${i}` }))
    await Promise.all(operations)
    expect(granularKillSwitch.getExceptions()).toHaveLength(50)
    expect(updateExceptionsMock.mock.calls.map(c => c[1].length)).toEqual(Array.from({ length: 50 }, (_, i) => i+1))
    expect(storeData.get('killSwitchExceptions')).toHaveLength(50)
  })
  it('does not persist proposed exceptions after system failure', async () => {
    isKillSwitchActiveMock.mockResolvedValue(true)
    updateExceptionsMock.mockResolvedValueOnce({ success: false, message: 'read-back failed' })
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    await expect(granularKillSwitch.addException({ type: 'ip', value: '192.0.2.1', label: 'test' })).rejects.toThrow('read-back')
    expect(granularKillSwitch.getExceptions()).toEqual([])
    expect(storeData.get('killSwitchExceptions')).toBeUndefined()
  })
  it('compensates the real exception set if store persistence fails', async () => {
    isKillSwitchActiveMock.mockResolvedValue(true)
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    writeFault.exceptions = true
    await expect(granularKillSwitch.addException({ type: 'ip', value: '192.0.2.1', label: 'test' })).rejects.toThrow('disk full')
    expect(updateExceptionsMock.mock.calls.map(c => c[1])).toEqual([['192.0.2.1'], []])
    expect(granularKillSwitch.getExceptions()).toEqual([])
  })

})
