import { beforeEach, describe, expect, it, vi } from 'vitest'

const storeState = vi.hoisted(() => ({ data: {} as Record<string, any> }))
const execElevatedMock = vi.hoisted(() => vi.fn(async (_command: string) => ({ stdout: '', stderr: '' })))

vi.mock('electron', () => ({
  app: {
    isPackaged: true,
    setLoginItemSettings: vi.fn(),
    getPath: () => '/tmp/vpnte-test'
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private defaults: Record<string, any>
    constructor(opts: { defaults?: Record<string, any> }) {
      this.defaults = opts.defaults ?? {}
    }
    get(key: string) {
      return storeState.data[key] ?? this.defaults[key]
    }
    set(key: string, value: any) {
      storeState.data[key] = value
    }
  }
}))

vi.mock('./admin', () => ({
  execElevated: execElevatedMock
}))

describe('settings login item side effects', () => {
  beforeEach(() => {
    storeState.data = {}
    execElevatedMock.mockClear()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    Object.defineProperty(process, 'execPath', { value: 'C:\\Program Files\\VPNTE\\VPNTE.exe', configurable: true })
    Object.defineProperty(process, 'resourcesPath', { value: 'C:\\Program Files\\VPNTE\\resources', configurable: true })
    vi.resetModules()
  })

  it('does not recreate scheduled tasks on unrelated settings saves', async () => {
    const { settingsStore } = await import('./settings')

    settingsStore.save({ checkInterval: 1234 })

    expect(execElevatedMock).not.toHaveBeenCalled()
  })

  it('creates boot recovery at most once per process', async () => {
    const { settingsStore } = await import('./settings')

    settingsStore.setLoginItem(true)
    settingsStore.setLoginItem(false)

    const commands = execElevatedMock.mock.calls.map((call) => String(call[0]))
    expect(commands.filter((cmd) => cmd.includes('VPNTE Boot Recovery'))).toHaveLength(1)
    expect(commands.filter((cmd) => cmd.includes('VPN Tunnel Enforcer'))).toHaveLength(2)
  })
})
