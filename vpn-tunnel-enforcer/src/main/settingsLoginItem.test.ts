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
    get(key: string, fallback?: unknown) {
      return storeState.data[key] ?? this.defaults[key] ?? fallback
    }
    get store() { return storeState.data }
    set store(value: Record<string, any>) { storeState.data = value }
    get path() { return '/missing-vpnte-settings-test/settings.json' }
    set(key: string, value: any) {
      storeState.data[key] = value
    }
  }
}))

vi.mock('./admin', () => ({
  execElevated: execElevatedMock
}))

// Mimics the OS: Create/Delete flip the task, the encoded query script reports it, everything else is a verified registration.
let taskPresent = false
function queryScript(command: string): boolean {
  const match = /-EncodedCommand ([A-Za-z0-9+/]+={0,2})$/.exec(command)
  return !!match && Buffer.from(match[1], 'base64').toString('utf16le').includes('LOGIN_TASK_QUERY')
}
function statefulElevated(overrides: (command: string) => Promise<{ stdout: string; stderr: string }> | undefined = () => undefined) {
  return async (command: string) => {
    const custom = overrides(command)
    if (custom) return custom
    if (command.includes('/Create')) taskPresent = true
    if (command.includes('/Delete')) taskPresent = false
    if (queryScript(command)) return { stdout: taskPresent ? 'PRESENT' : 'ABSENT', stderr: '' }
    return { stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' }
  }
}

describe('settings login item side effects', () => {
  beforeEach(() => {
    storeState.data = {}
    execElevatedMock.mockReset()
    taskPresent = false
    execElevatedMock.mockImplementation(statefulElevated())
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

  it('setLoginItemChecked reports a failed scheduled-task command and keeps the saved setting', async () => {
    const { settingsStore } = await import('./settings')
    await settingsStore.setLoginItemChecked(true)
    expect(settingsStore.get().autoStart).toBe(true)
    execElevatedMock.mockImplementation(statefulElevated((command) => (command.includes('/Delete') ? Promise.reject(new Error('schtasks delete refused')) : undefined)))
    await expect(settingsStore.setLoginItemChecked(false)).rejects.toThrow('schtasks delete refused')
    // The OS still has the task, so the stored value must not claim otherwise.
    expect(settingsStore.get().autoStart).toBe(true)
  })

  it('setLoginItemChecked persists the setting once the command succeeded and the task reads back', async () => {
    const { settingsStore } = await import('./settings')
    await expect(settingsStore.setLoginItemChecked(true)).resolves.toMatchObject({ autoStart: true })
    expect(execElevatedMock.mock.calls.some(([command]) => String(command).includes('/Create'))).toBe(true)
    expect(execElevatedMock.mock.calls.some(([command]) => queryScript(String(command)))).toBe(true)
    expect(settingsStore.get().autoStart).toBe(true)
  })

  it('setLoginItemChecked refuses a task state that does not read back, and puts the previous state back', async () => {
    const { settingsStore } = await import('./settings')
    // Create "succeeds" but the query keeps saying the task is absent.
    execElevatedMock.mockImplementation(statefulElevated((command) => (queryScript(command) ? Promise.resolve({ stdout: 'ABSENT', stderr: '' }) : undefined)))
    await expect(settingsStore.setLoginItemChecked(true)).rejects.toThrow(/readback/)
    expect(settingsStore.get().autoStart).toBe(false)
    expect(execElevatedMock.mock.calls.some(([command]) => String(command).includes('/Delete'))).toBe(true)
  })

  it('a query failure that is not "task not found" is an unknown state, never absence', async () => {
    const { settingsStore } = await import('./settings')
    await settingsStore.setLoginItemChecked(true)
    // schtasks-style failure: exit code 1 for access denied. It must not be read as "the task is gone".
    execElevatedMock.mockImplementation(statefulElevated((command) => (queryScript(command) ? Promise.reject(Object.assign(new Error('Access is denied'), { code: 1 })) : undefined)))
    await expect(settingsStore.setLoginItemChecked(false)).rejects.toThrow()
    expect(settingsStore.get().autoStart).toBe(true)
  })

  it('an unrecognised query answer is an unknown state', async () => {
    const { settingsStore } = await import('./settings')
    execElevatedMock.mockImplementation(statefulElevated((command) => (queryScript(command) ? Promise.resolve({ stdout: 'something else', stderr: '' }) : undefined)))
    await expect(settingsStore.setLoginItemChecked(true)).rejects.toThrow()
    expect(settingsStore.get().autoStart).toBe(false)
  })

  it('setLoginItemChecked keeps a settings save that completed while the task command was running', async () => {
    const { settingsStore } = await import('./settings')
    execElevatedMock.mockImplementation(statefulElevated((command) => {
      if (command.includes('/Create')) { taskPresent = true; settingsStore.save({ stealthMode: true }); return Promise.resolve({ stdout: 'RECOVERY_TASK_VERIFIED', stderr: '' }) }
      return undefined
    }))
    const saved = await settingsStore.setLoginItemChecked(true)
    expect(saved.stealthMode).toBe(true)
    expect(settingsStore.get().stealthMode).toBe(true)
    expect(settingsStore.get().autoStart).toBe(true)
  })

  /** Makes the first write of the settings object fail, once. */
  function failFirstSettingsWrite() {
    let failNextWrite = true
    storeState.data = new Proxy(storeState.data as any, {
      set(target: any, key: string, value: any) {
        if (failNextWrite && key === 'settings') { failNextWrite = false; throw new Error('Disk full') }
        target[key] = value
        return true
      }
    })
  }

  it('setLoginItemChecked puts the task back when saving fails afterwards', async () => {
    const { settingsStore } = await import('./settings')
    settingsStore.get() // Complete startup migration before injecting the later settings save failure.
    failFirstSettingsWrite()
    await expect(settingsStore.setLoginItemChecked(true)).rejects.toThrow('Disk full')
    const commands = execElevatedMock.mock.calls.map(([command]) => String(command))
    expect(commands.some((command) => command.includes('/Create'))).toBe(true)
    expect(commands.some((command) => command.includes('/Delete'))).toBe(true)
    expect(taskPresent).toBe(false)
    expect(settingsStore.get().autoStart).toBe(false)
  })

  it('reports an unknown state, with both causes reachable, when the restore after a failed save is not confirmed', async () => {
    const { settingsStore } = await import('./settings')
    settingsStore.get()
    failFirstSettingsWrite()
    execElevatedMock.mockImplementation(statefulElevated((command) => (command.includes('/Delete') ? Promise.reject(new Error('delete refused')) : undefined)))
    const error: any = await settingsStore.setLoginItemChecked(true).catch((e) => e)
    expect(error.message).toMatch(/Autostart state is unknown/)
    expect(error.message).toContain('Disk full')
    expect(error.message).toContain('delete refused')
    expect(error.cause).toBeInstanceOf(Error)
    expect(error.cause.message).toBe('delete refused')
    expect(error.originalCause).toBeInstanceOf(Error)
    expect(error.originalCause.message).toBe('Disk full')
    expect(settingsStore.get().autoStart).toBe(false)
  })

  it('the plain setLoginItem stays fire-and-forget and never rejects on a failed command', async () => {
    const { settingsStore } = await import('./settings')
    execElevatedMock.mockRejectedValue(new Error('schtasks refused'))
    expect(() => settingsStore.setLoginItem(true)).not.toThrow()
    await Promise.resolve()
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
