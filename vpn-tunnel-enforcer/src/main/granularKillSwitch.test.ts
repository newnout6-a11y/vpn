import { beforeEach, describe, expect, it, vi } from 'vitest'
import fc from 'fast-check'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

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
vi.mock('./recoveryManifest', () => ({
  persistRecoveryPolicy: vi.fn(async () => {})
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
  it('keeps native policy, store and audit aligned for 50 seeded mixed mutations (AT-03-008)', async () => {
    const { granularKillSwitch } = await import('./granularKillSwitch')
    granularKillSwitch.init('C:\\Tools\\sing-box.exe')
    const initial = await Promise.all(Array.from({ length: 25 }, (_, i) =>
      granularKillSwitch.addException({ type: 'ip', value: `192.0.2.${i+1}`, label: `initial-${i}` })))
    const changes = [
      ...initial.map(entry => ({ kind: 'remove' as const, value: entry.value, id: entry.id })),
      ...Array.from({ length: 25 }, (_, i) => ({ kind: 'add' as const, value: `198.51.100.${i+1}`, id: '' }))
    ]
    const order = fc.sample(fc.shuffledSubarray(changes, { minLength: 50, maxLength: 50 }), { seed: 30008, numRuns: 1 })[0]
    isKillSwitchActiveMock.mockResolvedValue(true)
    updateExceptionsMock.mockClear(); logEventMock.mockClear()
    await Promise.all(order.map(change => change.kind === 'remove'
      ? granularKillSwitch.removeException(change.id)
      : granularKillSwitch.addException({ type: 'ip', value: change.value, label: 'UI fixture' })))
    let expected = initial.map(entry => entry.value)
    expect(updateExceptionsMock).toHaveBeenCalledTimes(50)
    for (const [index, change] of order.entries()) {
      expected = change.kind === 'remove' ? expected.filter(value => value !== change.value) : [...expected, change.value]
      expect(updateExceptionsMock.mock.calls[index][1]).toEqual(expected)
    }
    expect(granularKillSwitch.getExceptions().map(entry => entry.value)).toEqual(expected)
    expect(storeData.get('killSwitchExceptions')).toEqual(granularKillSwitch.getExceptions())
    const audit = logEventMock.mock.calls.filter(call => call[2].startsWith('exception '))
    expect(audit.map(call => call[3].value)).toEqual(order.map(change => change.value))
    expect(audit.map(call => call[2])).toEqual(order.map(change => `exception ${change.kind === 'add' ? 'added' : 'removed'} and synchronized`))
  })
  it.skipIf(process.platform !== 'win32')('rejects a real 8.3 alias as a duplicate of the long executable path (AT-03-009)', async context => {
    const root = join(process.cwd(), '.tmp')
    await mkdir(root, { recursive: true })
    const directory = await mkdtemp(join(root, 'kill-switch-path-'))
    try {
      const executable = join(directory, 'Long application name.exe')
      await writeFile(executable, 'fixture')
      const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
Add-Type -TypeDefinition 'using System; using System.Text; using System.Runtime.InteropServices; public static class ShortPathFixture { [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetShortPathName(string path, StringBuilder result, uint size); }'
$buffer=New-Object Text.StringBuilder 32768
if([ShortPathFixture]::GetShortPathName('${executable.replace(/'/g, "''")}', $buffer, $buffer.Capacity) -eq 0){throw 'Short path lookup failed'}
$buffer.ToString()`
      const shortPath = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 15000, windowsHide: true }).trim()
      if (shortPath.toLowerCase() === executable.toLowerCase()) context.skip('This NTFS volume does not create 8.3 aliases')
      const { granularKillSwitch } = await import('./granularKillSwitch')
      granularKillSwitch.init('C:\\Tools\\sing-box.exe')
      const added = await granularKillSwitch.addException({ type: 'app', value: executable, label: 'Long path' })
      expect(added.value).toBe(await realpath(executable))
      await expect(granularKillSwitch.addException({ type: 'app', value: shortPath, label: 'Short path' }))
        .rejects.toThrow('equivalent')
      expect(storeData.get('killSwitchExceptions')).toEqual([added])
      expect(updateExceptionsMock).not.toHaveBeenCalled()
    } finally { await rm(directory, { recursive: true, force: true }) }
  }, 20000)
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
