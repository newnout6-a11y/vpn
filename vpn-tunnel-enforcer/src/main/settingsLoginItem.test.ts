import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const storeState = vi.hoisted(() => ({ data: {} as Record<string, any> }))
const execElevatedMock = vi.hoisted(() => vi.fn(async (_command: string) => ({ stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' })))
const dialogMock = vi.hoisted(() => vi.fn(async () => ({ response: 0 })))
const reportMock = vi.hoisted(() => vi.fn<() => Promise<any>>(async () => null))
const logMock = vi.hoisted(() => vi.fn())
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: reportMock }))
vi.mock('./appLogger', () => ({ logEvent: logMock }))
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
    dialogMock.mockReset()
    dialogMock.mockResolvedValue({ response: 0 })
    reportMock.mockReset()
    reportMock.mockResolvedValue(null)
    logMock.mockClear()
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

  // AT-03-002/003, F-043/F-150: diagnostics subset, not reboot/L3 proof.
  it.each(['register', 'read-back', 'report'] as const)('records the actual %s failure and permits a retry', async stage => {
    const failure = Object.assign(new Error('native failure'), { stderr: 'native stderr', code: 5 })
    if (stage === 'register') execElevatedMock.mockImplementation(async command => {
      if (command.includes('-EncodedCommand')) throw failure
      return { stdout: '', stderr: '' }
    })
    if (stage === 'read-back') execElevatedMock.mockResolvedValue({ stdout: 'not verified', stderr: 'marker stderr' })
    if (stage === 'report') reportMock.mockRejectedValue(failure)
    const { settingsStore, getBootRecoveryRegistrationStatus } = await import('./settings')
    settingsStore.setLoginItem(false)
    await vi.waitFor(() => expect(getBootRecoveryRegistrationStatus().status).toBe('failed'))
    expect(getBootRecoveryRegistrationStatus().message).toContain(stage)
    expect(logMock).toHaveBeenCalledWith('error', 'boot-recovery', expect.any(String), expect.objectContaining({ stage }))
    const diagnostic = logMock.mock.calls.find(call => call[3]?.stage === stage)![3]
    expect(diagnostic.stderr).toBe(stage === 'read-back' ? 'marker stderr' : 'native stderr')
    expect(diagnostic.error).toBe(stage === 'read-back' ? 'Boot Recovery read-back marker missing' : 'native failure')
    expect(dialogMock).toHaveBeenCalledWith(expect.objectContaining({
      message: stage === 'report' ? expect.stringContaining('отчёт') : expect.stringContaining('не подтверждена')
    }))
    if (stage !== 'report') expect(reportMock).not.toHaveBeenCalled()
    execElevatedMock.mockResolvedValue({ stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' })
    reportMock.mockResolvedValue(null)
    settingsStore.setLoginItem(false)
    await vi.waitFor(() => expect(getBootRecoveryRegistrationStatus().status).toBe('verified'))
    expect(execElevatedMock.mock.calls.filter(call => call[0].includes('-EncodedCommand'))).toHaveLength(2)
  })

  it('bounds native error fields before passing them to the redacting logger', async () => {
    execElevatedMock.mockImplementation(async command => {
      if (command.includes('-EncodedCommand')) throw Object.assign(new Error('E'.repeat(5000)), { stderr: 'S'.repeat(8000), code: 'C'.repeat(100) })
      return { stdout: '', stderr: '' }
    })
    const { settingsStore, getBootRecoveryRegistrationStatus } = await import('./settings')
    settingsStore.setLoginItem(false)
    await vi.waitFor(() => expect(getBootRecoveryRegistrationStatus().status).toBe('failed'))
    expect(logMock.mock.calls.find(call => call[3]?.stage === 'register')![3]).toEqual({
      stage: 'register', error: 'E'.repeat(1024), stderr: 'S'.repeat(2048), code: 'C'.repeat(64)
    })
  })

  it('does not call a verified task unregistered when displaying a recovery warning fails', async () => {
    reportMock.mockResolvedValue({ status: 'strict-retained' })
    dialogMock.mockRejectedValue(new Error('dialog unavailable'))
    const { settingsStore, getBootRecoveryRegistrationStatus } = await import('./settings')
    settingsStore.setLoginItem(false)
    await vi.waitFor(() => expect(logMock).toHaveBeenCalledWith('error', 'boot-recovery', 'recovery warning could not be displayed', expect.any(Object)))
    expect(getBootRecoveryRegistrationStatus().status).toBe('verified')
    expect(dialogMock).toHaveBeenCalledTimes(1)
    expect(dialogMock).toHaveBeenCalledWith(expect.objectContaining({ type: 'warning' }))
    settingsStore.setLoginItem(false)
    expect(execElevatedMock.mock.calls.filter(call => call[0].includes('-EncodedCommand'))).toHaveLength(1)
  })
})
