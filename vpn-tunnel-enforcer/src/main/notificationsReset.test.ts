// AT-00-004/005; F-074/F-143: registry faults must not become enabled/success.
import { ipcError } from '../shared/ipc-result'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const execMock = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  app: { getName: () => 'vpnte-legacy', getPath: () => '/tmp/vpnte-test' },
  Notification: Object.assign(
    class {
      constructor(_opts: any) {}
      show() {}
    },
    { isSupported: () => true }
  )
}))

vi.mock('child_process', () => {
  const execWithCustom: any = execMock
  execWithCustom[Symbol.for('nodejs.util.promisify.custom')] = (file: string, args: string[], opts: any) =>
    new Promise((resolve, reject) => {
      execMock(`${file.replace('.exe', '')} ${args.join(' ')}`, opts, (err: Error | null, stdout: string, stderr: string) => {
        if (err) reject(Object.assign(err, { stdout, stderr }))
        else resolve({ stdout, stderr })
      })
    })
  return {
    execFile: execWithCustom,
    default: { execFile: execWithCustom }
  }
})

vi.mock('./settings', () => ({
  settingsStore: { get: () => ({ desktopNotifications: true }) }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

const realPlatform = process.platform

function setPlatform(p: string) {
  Object.defineProperty(process, 'platform', { value: p, configurable: true })
}

describe('resetWindowsNotificationBlock', () => {
  beforeEach(() => {
    vi.resetModules()
    execMock.mockReset()
    setPlatform('win32')
  })

  afterEach(() => {
    setPlatform(realPlatform)
  })

  it('deletes only blocked Enabled=0 values and preserves explicit allow state', async () => {
    execMock.mockImplementation((cmd: string, _opts: any, cb: Function) => {
      if (cmd.includes('reg query') && cmd.includes('com.vpntunnelenforcer.app')) {
        cb(null, 'Enabled    REG_DWORD    0x1', '')
        return
      }
      if (cmd.includes('reg query') && cmd.includes('vpnte-legacy')) {
        cb(null, 'Enabled    REG_DWORD    0x0', '')
        return
      }
      if (cmd.includes('reg delete') && cmd.includes('vpnte-legacy') && cmd.includes('/v Enabled')) {
        cb(null, '', '')
        return
      }
      cb(new Error(`unexpected command: ${cmd}`), '', `unexpected command: ${cmd}`)
    })

    const { resetWindowsNotificationBlock } = await import('./notifications')
    const result = await resetWindowsNotificationBlock()

    const commands = execMock.mock.calls.map((call) => String(call[0]))
    expect(commands).not.toHaveLength(0)
    expect(result.cleared).toEqual(['vpnte-legacy'])
    expect(commands.some((cmd) => cmd.includes('com.vpntunnelenforcer.app') && cmd.includes('reg delete'))).toBe(false)
    expect(commands.some((cmd) => cmd.includes('/va'))).toBe(false)
    expect(commands.some((cmd) => cmd.includes('reg delete') && cmd.includes('/v Enabled'))).toBe(true)
  })
})


describe('Windows notification evidence', () => {
  beforeEach(() => { vi.resetModules(); execMock.mockReset(); setPlatform('win32') })
  afterEach(() => setPlatform(realPlatform))

  it.each([
    ['permission', Object.assign(new Error('private registry failure'), { code: 'EACCES' })],
    ['timeout', Object.assign(new Error('private registry failure'), { code: 'ETIMEDOUT' })],
    ['internal', Object.assign(new Error('private registry failure'), { code: 1 })],
    ['timeout', Object.assign(new Error('private registry failure'), { killed: true, signal: 'SIGTERM' })]
  ])('rejects %s reads and does not cache a false enabled result', async (_category, fault) => {
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(fault, '', 'private registry failure'))
    const notifications = await import('./notifications')
    await expect(notifications.getWindowsNotificationState()).rejects.toBeDefined()
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(null, 'Enabled    REG_DWORD    0x0', ''))
    expect(await notifications.getWindowsNotificationState()).toMatchObject({ enabled: false })
  })

  it.each([
    'ERROR: The system was unable to find the specified registry key or value.',
    'Ошибка: Не удается найти указанный раздел или параметр в реестре.',
    Buffer.from('8ee8a8a1aaa03a208da520e3a4a0a5e2e1ef20ada0a9e2a820e3aaa0a7a0adadeba920e0a0a7a4a5ab20a8aba820afa0e0a0aca5e2e020a220e0a5a5e1e2e0a52e0d0a', 'hex')
  ])('accepts only proven missing values as the Windows default: %s', async message => {
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(Object.assign(new Error(String(message)), { code: 1 }), '', message))
    const notifications = await import('./notifications')
    expect(await notifications.getWindowsNotificationState()).toEqual({ enabled: true, appUserModelId: null })
    expect(await notifications.resetWindowsNotificationBlock()).toEqual({ cleared: [], errors: [] })
  })

  it('rejects successful but unparseable registry output', async () => {
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(null, 'Enabled REG_SZ bad-data', ''))
    const notifications = await import('./notifications')
    await expect(notifications.getWindowsNotificationState()).rejects.toBeDefined()
    const result = await notifications.resetWindowsNotificationBlock()
    expect(result.cleared).toEqual([])
    expect(result.errors).toHaveLength(2)
    expect(result.errors[0]).toMatchObject({ error: ipcError('internal') })
  })

  it('retains successful clears and canonical per-AUMID failures', async () => {
    execMock.mockImplementation((cmd: string, _opts: unknown, cb: Function) => {
      if (cmd.includes('vpnte-legacy')) return cb(Object.assign(new Error('FAKE-SECRET at /private/test'), { code: 'EACCES' }), '', 'Access is denied.')
      cb(null, cmd.includes('query') ? 'Enabled REG_DWORD 0x0' : '', '')
    })
    const { resetWindowsNotificationBlock } = await import('./notifications')
    const report = await resetWindowsNotificationBlock()
    expect(report).toEqual({ cleared: ['com.vpntunnelenforcer.app'], errors: [{ appUserModelId: 'vpnte-legacy', error: ipcError('permission') }] })
    expect(JSON.stringify(report)).not.toContain('FAKE-SECRET')
  })

  it('recognizes reg access-denied exit 1 separately from missing values', async () => {
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(Object.assign(new Error('command failed'), { code: 1 }), '', 'ERROR: Access is denied.'))
    const { resetWindowsNotificationBlock } = await import('./notifications')
    const result = await resetWindowsNotificationBlock()
    expect(result.errors).toHaveLength(2)
    expect(result.errors[0]).toMatchObject({ error: ipcError('permission') })
  })

  it('uses the in-app fallback when OS status cannot be established', async () => {
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(new Error('read failed'), '', ''))
    const { notify, setInAppFallbackCallback } = await import('./notifications')
    const fallback = vi.fn()
    setInAppFallbackCallback(fallback)
    await notify('error', 'Fault', 'Body')
    expect(fallback).toHaveBeenCalledOnce()
  })
  it('does not repopulate invalidated cache from a stale in-flight registry read', async () => {
    let release!: () => void
    execMock.mockImplementationOnce((_cmd: string, _opts: unknown, cb: Function) => { release = () => cb(null, 'Enabled REG_DWORD 0x0', '') })
    const notifications = await import('./notifications')
    const oldRead = notifications.getWindowsNotificationState()
    notifications.invalidateOsNotificationStateCache()
    release()
    await oldRead
    execMock.mockImplementation((_cmd: string, _opts: unknown, cb: Function) => cb(null, 'Enabled REG_DWORD 0x1', ''))
    expect(await notifications.getWindowsNotificationState()).toMatchObject({ enabled: true })
  })

  it('reports delete timeout without losing earlier clears or exposing command text', async () => {
    execMock.mockImplementation((cmd: string, _opts: unknown, cb: Function) => {
      if (cmd.includes('delete') && cmd.includes('vpnte-legacy')) return cb(Object.assign(new Error('FAKE-SECRET'), { killed: true, signal: 'SIGTERM' }), '', '')
      cb(null, cmd.includes('query') ? 'Enabled REG_DWORD 0x0' : '', '')
    })
    const { resetWindowsNotificationBlock } = await import('./notifications')
    expect(await resetWindowsNotificationBlock()).toEqual({ cleared: ['com.vpntunnelenforcer.app'], errors: [{ appUserModelId: 'vpnte-legacy', error: ipcError('timeout') }] })
  })

})
