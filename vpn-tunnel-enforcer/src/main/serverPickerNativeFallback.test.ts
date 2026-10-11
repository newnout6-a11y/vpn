// AT-07-007 / AT-08-007: physical IPv4 sources — native iphlpapi read is preferred over a cold
// PowerShell spawn, and a failed native read still yields the PowerShell result (behaviour, not call order).
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  native: vi.fn<() => Array<{ alias: string; ipv4: string }>>(),
  powershell: vi.fn<() => string>(),
  interfaces: vi.fn(() => ({}))
}))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' }, dialog: {}, ipcMain: { handle: vi.fn() } }))
vi.mock('electron-store', () => ({ default: class { get() { return undefined } set() {} } }))
vi.mock('os', async importOriginal => {
  const actual = await importOriginal<typeof import('os')>()
  return { ...actual, networkInterfaces: state.interfaces, default: { ...actual, networkInterfaces: state.interfaces } }
})
vi.mock('child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('child_process')>()
  const { promisify } = await import('util')
  const execFile = Object.assign(vi.fn(), {
    [promisify.custom]: async () => ({ stdout: Buffer.from(state.powershell(), 'utf8'), stderr: Buffer.alloc(0) })
  })
  return { ...actual, default: { ...actual, execFile }, execFile }
})
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  applyClientDeviceToOutbound: vi.fn(), clientFingerprintForDevice: vi.fn(), normalizeClientDevice: vi.fn(),
  resolveVpnProfiles: vi.fn(), exportOutboundToUri: vi.fn()
}))
vi.mock('./tunController', () => ({ getDirectProxyPort: () => null, tunController: { getStatus: () => ({ running: false }) } }))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(), findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (value: string) => value, refreshGroup: vi.fn()
}))
vi.mock('./native/nativeNetworkReads', () => ({ nativePhysicalIpv4Sources: state.native, nativeActiveTunnels: vi.fn() }))

async function sources() {
  vi.resetModules()
  const picker = await import('./serverPicker')
  return picker.getPhysicalIpv4Sources()
}

describe.skipIf(process.platform !== 'win32')('physical IPv4 sources: native first, PowerShell fallback', () => {
  beforeEach(() => {
    state.native.mockReset()
    state.powershell.mockReset().mockReturnValue(JSON.stringify([{ Alias: 'Wi-Fi', Ipv4: '192.168.1.10' }]))
    state.interfaces.mockReset().mockReturnValue({})
  })

  it('uses the native read and spawns no PowerShell', async () => {
    state.native.mockReturnValue([{ alias: 'Ethernet', ipv4: '10.0.0.5' }])

    expect(await sources()).toEqual([{ alias: 'Ethernet', ipv4: '10.0.0.5' }])
    expect(state.powershell).not.toHaveBeenCalled()
  })

  it('returns the PowerShell result when the native read fails', async () => {
    state.native.mockImplementation(() => { throw new Error('GetAdaptersAddresses rc=87') })

    expect(await sources()).toEqual([{ alias: 'Wi-Fi', ipv4: '192.168.1.10' }])
    expect(state.powershell).toHaveBeenCalledTimes(1)
  })

  it('does not cache or return an empty native answer: PowerShell is asked', async () => {
    state.native.mockReturnValue([])

    expect(await sources()).toEqual([{ alias: 'Wi-Fi', ipv4: '192.168.1.10' }])
    expect(state.powershell).toHaveBeenCalledTimes(1)
  })

  it('skips both when os.networkInterfaces already answers', async () => {
    state.interfaces.mockReturnValue({ 'Wi-Fi': [{ family: 'IPv4', internal: false, mac: '5c:c3:36:f5:a6:0a', address: '192.168.1.10' }] })

    expect(await sources()).toEqual([{ alias: 'Wi-Fi', ipv4: '192.168.1.10' }])
    expect(state.native).not.toHaveBeenCalled()
    expect(state.powershell).not.toHaveBeenCalled()
  })
})
