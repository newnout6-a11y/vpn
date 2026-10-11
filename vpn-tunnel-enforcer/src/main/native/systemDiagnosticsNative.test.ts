// AT-08-007 / AT-07-002: systemDiagnostics reads native first and falls back to PowerShell, never to empty data.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ exec: vi.fn(), native: vi.fn() }))
vi.mock('child_process', () => {
  const exec = vi.fn()
  ;(exec as any)[Symbol.for('nodejs.util.promisify.custom')] = mocks.exec
  const api = { exec, execFile: vi.fn() }
  return { ...api, default: api }
})
vi.mock('electron', () => ({ app: { getVersion: () => 't', getAppPath: () => '/', getPath: () => '/tmp', isPackaged: false } }))
vi.mock('../admin', () => ({ isProcessElevated: vi.fn(async () => false) }))
vi.mock('../appLogger', () => ({ getAppLogPath: () => '/tmp/app.log', getLogDir: () => '/tmp', logEvent: vi.fn() }))
vi.mock('../connectionPlanner', () => ({ getRoutingPlan: vi.fn() }))
vi.mock('../leakDiagnostics', () => ({ runLeakCheck: vi.fn() }))
vi.mock('../settings', () => ({ getBootRecoveryRegistrationStatus: () => ({}), settingsStore: { get: () => ({}) } }))
vi.mock('../ruleSetManager', () => ({ getSmartRouteRuleSetState: vi.fn() }))
vi.mock('../recoveryManifest', () => ({ readBootRecoveryReport: vi.fn() }))
vi.mock('../trafficForensics', () => ({ getTrafficForensicsStatus: vi.fn() }))
vi.mock('../tunController', () => ({ getTunRuntimeDir: () => '/tmp', parseProxyAddress: vi.fn(), probeTcp: vi.fn(), tunController: { getStatus: () => ({}) } }))
vi.mock('../runtimeDirSecurity', () => ({ verifyDirectoryHardened: vi.fn() }))
vi.mock('../serverPicker', () => ({ getActiveProfile: vi.fn(() => null) }))
vi.mock('./nativeNetworkReads', () => ({
  nativeAdapterRows: mocks.native, nativeIpConfigRows: mocks.native, nativeRouteRows: mocks.native
}))

import { nativeOrPs } from '../systemDiagnostics'

beforeEach(() => {
  mocks.exec.mockReset()
  mocks.native.mockReset()
})

describe('nativeOrPs', () => {
  it('returns the native rows and does not spawn PowerShell', async () => {
    mocks.native.mockReturnValue([{ Name: 'Wi-Fi', Status: 'Up' }])

    await expect(nativeOrPs(() => mocks.native(), 'Get-NetAdapter')).resolves.toEqual([{ Name: 'Wi-Fi', Status: 'Up' }])
    expect(mocks.exec).not.toHaveBeenCalled()
  })

  it('runs the PowerShell script and parses its JSON when the native read throws', async () => {
    mocks.native.mockImplementation(() => { throw new Error('GetAdaptersAddresses failed: 5') })
    mocks.exec.mockResolvedValue({ stdout: '[{"Name":"Ethernet","Status":"Up"}]', stderr: '' })

    await expect(nativeOrPs(() => mocks.native(), 'Get-NetAdapter')).resolves.toEqual([{ Name: 'Ethernet', Status: 'Up' }])
    expect(mocks.exec).toHaveBeenCalledTimes(1)
  })

  it('propagates a PowerShell failure after a native failure instead of inventing empty data', async () => {
    mocks.native.mockImplementation(() => { throw new Error('native broke') })
    mocks.exec.mockRejectedValue(new Error('powershell timed out'))

    await expect(nativeOrPs(() => mocks.native(), 'Get-NetAdapter')).rejects.toThrow('powershell timed out')
  })
})
