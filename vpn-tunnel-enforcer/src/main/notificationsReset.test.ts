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
  execWithCustom[Symbol.for('nodejs.util.promisify.custom')] = (cmd: string, opts: any) =>
    new Promise((resolve, reject) => {
      execMock(cmd, opts, (err: Error | null, stdout: string, stderr: string) => {
        if (err) reject(Object.assign(err, { stdout, stderr }))
        else resolve({ stdout, stderr })
      })
    })
  return {
    exec: execWithCustom,
    default: { exec: execWithCustom }
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
