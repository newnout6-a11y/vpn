import { beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
const state = vi.hoisted(() => ({ exec: vi.fn() }))
vi.mock('child_process', async original => {
  const actual = await original<typeof import('child_process')>()
  return { ...actual, default: { ...actual, execFile: state.exec }, execFile: state.exec }
})
import { readAdaptiveNetworkIdentity, ADAPTIVE_NETWORK_IDENTITY_SCRIPT } from './adaptiveNetworkIdentity'

function result(value: any) {
  state.exec.mockImplementation((_exe, _args, _options, cb) => { cb(null, JSON.stringify(value)); return {} })
}
const row = { alias: 'Wi-Fi', guid: 'fixture-guid', profiles: ['Домашняя сеть'], gateways: ['192.168.1.1', 'fe80::1'] }
beforeEach(() => { state.exec.mockReset(); result([row]) })
describe('private network identity read (AT-10-007)', () => {
  it('uses a bounded hidden read-only native call and keeps a stable IPv4 identity across IPv6 lockdown', async () => {
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    result({ ...row, gateways: ['192.168.1.1'] })
    expect(await readAdaptiveNetworkIdentity()).toEqual([{ ...row, gateways: ['192.168.1.1'] }])
    const [_exe, args, options] = state.exec.mock.calls[0]
    expect(options).toMatchObject({ windowsHide: true, timeout: 4000, maxBuffer: 256 * 1024 })
    const script = Buffer.from(args[args.length - 1], 'base64').toString('utf16le')
    expect(script).toContain('Get-NetConnectionProfile')
    expect(script).not.toMatch(/Set-Net|Remove-Net|Disable-Net/)
  })
  it.each([{ value: [] }, { value: null }, { value: {} }, { value: [{ alias: 'Wi-Fi', guid: 'guid', profiles: [], gateways: [] }] }, { value: [{ ...row, profiles: [42] }] }])('fails closed for missing / malformed identity: %j', async ({ value }) => {
    result(value)
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
  })
  it('returns unknown when the command fails or emits truncated JSON', async () => {
    state.exec.mockImplementation((_exe, _args, _options, cb) => cb(new Error('timeout')))
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
    state.exec.mockImplementation((_exe, _args, _options, cb) => cb(null, '{broken'))
    expect(await readAdaptiveNetworkIdentity()).toBeNull()
  })
  it.runIf(process.platform === 'win32')('executes the production script with fake native cmdlets, retaining arrays and Unicode', () => {
    const harness = `
function Get-NetAdapter { [pscustomobject]@{Status='Up';MacAddress='00-11-22-33-44-55';InterfaceDescription='Physical Wi-Fi';Name='Wi-Fi';InterfaceGuid='fixture-guid';ifIndex=7}; [pscustomobject]@{Status='Up';MacAddress='00-11-22-33-44-66';InterfaceDescription='Wintun Userspace Tunnel';Name='sing-tun';ifIndex=8} }
function Get-NetConnectionProfile { param($InterfaceIndex,$ErrorAction) [pscustomobject]@{Name='Домашняя сеть'} }
function Get-NetRoute { param($InterfaceIndex,$ErrorAction) [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1'} }
${ADAPTIVE_NETWORK_IDENTITY_SCRIPT}`
    const stdout = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(harness, 'utf16le').toString('base64')], { windowsHide: true, timeout: 10000, encoding: 'utf8' })
    expect(JSON.parse(stdout.trim())).toEqual([{ alias: 'Wi-Fi', guid: 'fixture-guid', profiles: ['Домашняя сеть'], gateways: ['192.168.1.1'] }])
  })
})
