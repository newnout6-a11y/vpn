// AT-03-001/012: an isolated fixed read cannot execute caller source or mutate policy.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { FIREWALL_STATUS_PS } from './firewallStatus'
const boundary = vi.hoisted(() => ({ execFile: vi.fn() }))
vi.mock('child_process', () => ({ execFile: boundary.execFile }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { readFirewallStatusSnapshot } from './firewallStatusRead'

beforeEach(() => { boundary.execFile.mockReset() })
describe('isolated passive firewall reader', () => {
  it('uses one fixed source and bounded hidden process without encoded commands or a shell', async () => {
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, '{"rules":[]}', ''))
    expect(await readFirewallStatusSnapshot()).toBe('{"rules":[]}')
    const [file, args, options] = boundary.execFile.mock.calls[0]
    expect(file).toBe('powershell.exe')
    expect(args.slice(0, -1)).toEqual(['-NoProfile', '-NoLogo', '-NonInteractive', '-Command'])
    expect(args.at(-1)).toContain(FIREWALL_STATUS_PS)
    // Win32 CreateProcessW permits32767 UTF-16 units. Even doubling every
    // script character for argument escaping leaves room for fixed argv/path.
    expect(args.at(-1).length * 2 + 1024).toBeLessThan(32767)
    expect(args.at(-1)).toContain("Join-Path $PSHOME 'Modules\\NetSecurity\\NetSecurity.psd1'")
    expect(args.at(-1)).toContain("Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Management\\Microsoft.PowerShell.Management.psd1'")
    expect(args.at(-1)).not.toMatch(/(?:Set|New|Remove|Enable|Disable)-NetFirewall|Start-Process|Invoke-Expression|EncodedCommand/)
    expect(options).toEqual({ encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 4 * 1024 * 1024 })
  })
  it.each(['timeout', 'permission', 'maxBuffer'])('propagates %s failure without a retry or fallback', async reason => {
    const error = new Error(reason)
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(error, 'partial', 'private diagnostic'))
    await expect(readFirewallStatusSnapshot()).rejects.toBe(error)
    expect(boundary.execFile).toHaveBeenCalledTimes(1)
  })
  it('does not settle a read until its process callback and preserves the full snapshot', async () => {
    let complete!: (error: Error | null, stdout: string, stderr: string) => void
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => { complete = callback })
    const settled = vi.fn()
    const result = readFirewallStatusSnapshot().then(value => { settled(); return value })
    await Promise.resolve()
    expect(settled).not.toHaveBeenCalled()
    complete(null, '{"rules":[{"name":"VPNTE-fixture"}]}', '')
    expect(await result).toBe('{"rules":[{"name":"VPNTE-fixture"}]}')
    expect(settled).toHaveBeenCalledOnce()
  })
})
