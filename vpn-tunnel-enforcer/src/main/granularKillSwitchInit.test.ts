import { beforeEach, describe, expect, it, vi } from 'vitest'

const storeState = vi.hoisted(() => ({ data: {} as Record<string, any> }))
const settingsSaveMock = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  BrowserWindow: { getAllWindows: () => [] },
  dialog: { showOpenDialog: vi.fn() }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private defaults: Record<string, any>
    constructor(opts: { defaults?: Record<string, any> }) {
      this.defaults = opts.defaults ?? {}
    }
    get(key: string, fallback?: any) {
      return storeState.data[key] ?? this.defaults[key] ?? fallback
    }
    set(key: string, value: any) {
      storeState.data[key] = value
    }
  }
}))

vi.mock('./firewallKillSwitch', () => ({
  enableKillSwitch: vi.fn(),
  disableKillSwitchIfActive: vi.fn(async () => ({ success: true })),
  isKillSwitchActive: vi.fn(async () => false)
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./notifications', () => ({ notify: vi.fn() }))
vi.mock('./settings', () => ({
  settingsStore: {
    get: () => ({ firewallKillSwitch: false }),
    save: settingsSaveMock
  }
}))

describe('granularKillSwitch initialization guard', () => {
  beforeEach(() => {
    storeState.data = {}
    settingsSaveMock.mockClear()
    vi.resetModules()
  })

  it('rejects enabling levels before init without mutating settings', async () => {
    const { granularKillSwitch } = await import('./granularKillSwitch')

    await expect(granularKillSwitch.setLevel('standard')).rejects.toThrow(/initialized/)

    expect(granularKillSwitch.getLevel()).toBe('off')
    expect(storeState.data.killSwitchLevel).toBeUndefined()
    expect(settingsSaveMock).not.toHaveBeenCalled()
  })

  it('allows setting off before init', async () => {
    const { granularKillSwitch } = await import('./granularKillSwitch')

    await expect(granularKillSwitch.setLevel('off')).resolves.toBeUndefined()

    expect(granularKillSwitch.getLevel()).toBe('off')
  })
})
