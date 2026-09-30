import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const storeState = vi.hoisted(() => ({ data: {} as Record<string, any> }))
const execElevatedMock = vi.hoisted(() => vi.fn(async (_command: string) => ({ stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' })))
const dialogMock = vi.hoisted(() => vi.fn(async () => ({ response: 0 })))
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: vi.fn(async () => null) }))
const descriptors = Object.fromEntries(['platform', 'execPath', 'resourcesPath'].map(key => [key, Object.getOwnPropertyDescriptor(process, key)]))

vi.mock('electron', () => ({
  dialog: { showMessageBox: dialogMock },
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
    execElevatedMock.mockReset()
    execElevatedMock.mockResolvedValue({ stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' })
    dialogMock.mockClear()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    Object.defineProperty(process, 'execPath', { value: 'C:\\Program Files\\VPNTE\\VPNTE.exe', configurable: true })
    Object.defineProperty(process, 'resourcesPath', { value: 'C:\\Program Files\\VPNTE\\resources', configurable: true })
    vi.resetModules()
  })

  afterEach(() => {
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (descriptor) Object.defineProperty(process, key, descriptor)
      else Reflect.deleteProperty(process, key)
    }
  })

  it('does not recreate scheduled tasks on unrelated settings saves', async () => {
    const { settingsStore } = await import('./settings')

    settingsStore.save({ checkInterval: 1234 })

    expect(execElevatedMock).not.toHaveBeenCalled()
  })

  it('creates boot recovery at most once per process', async () => {
    const { settingsStore, getBootRecoveryRegistrationStatus } = await import('./settings')

    settingsStore.setLoginItem(true)
    settingsStore.setLoginItem(false)

    const commands = execElevatedMock.mock.calls.map((call) => String(call[0]))
    const recoveryCommands = commands.filter(cmd => cmd.includes('-EncodedCommand'))
    expect(recoveryCommands).toHaveLength(1)
    expect(Buffer.from(recoveryCommands[0].split(' ').at(-1)!, 'base64').toString('utf16le')).toContain('-RegisterTask')
    expect(commands.filter((cmd) => cmd.includes('VPN Tunnel Enforcer'))).toHaveLength(2)
    await vi.waitFor(() => expect(getBootRecoveryRegistrationStatus().status).toBe('verified'))
    expect(dialogMock).not.toHaveBeenCalled()
  })
})
