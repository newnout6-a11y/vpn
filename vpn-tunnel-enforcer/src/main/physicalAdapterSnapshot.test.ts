// AT-03-005/006/007/012: production snapshot routing with controlled native boundaries.
import { beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ worker: vi.fn(), helper: vi.fn(), elevated: vi.fn() }))
vi.mock('electron', () => ({ app: { getPath: () => 'C:\\fixture' } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./admin', () => ({ execElevated: mocks.elevated }))
vi.mock('./runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: vi.fn() }))
vi.mock('./recoveryManifest', () => ({ recoveryManifestPath: () => 'C:\\fixture\\manifest.json', readRecoveryManifest: vi.fn(async () => null), writeRecoveryManifest: vi.fn(), removeRecoveryManifest: vi.fn() }))
vi.mock('./elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => true, execElevatedPs: mocks.helper }))
vi.mock('./recoveryPsWorker', () => ({ executeRecoveryOperation: mocks.worker, RecoveryWorkerError: class extends Error {
  constructor(public code: string, message: string) { super(message) }
} }))
import { RecoveryWorkerError } from './recoveryPsWorker'
const row = { ifIndex: 17, interfaceGuid: '11111111-1111-1111-1111-111111111111', alias: 'Беспроводная сеть',
  description: 'MediaTek Wi-Fi', ipv6Enabled: true, ipv4Dns: ['1.1.1.1'], ipv4DnsSource: 'dhcp',
  gateways: ['10.0.0.1'], networkProfiles: ['Office'], isCellularOrTethering: false }
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  mocks.worker.mockResolvedValue(JSON.stringify(row))
  mocks.helper.mockResolvedValue({ stdout: JSON.stringify(row), stderr: '', exitCode: 0 })
})
describe.skipIf(process.platform !== 'win32')('physical snapshot uses the read-only worker', () => {
  it('leaves the privileged helper free while DNS discovery is still running', async () => {
    let finish!: (value: string) => void
    mocks.worker.mockReturnValue(new Promise(resolve => { finish = resolve }))
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    let settled = false
    const pending = getPhysicalAdapterDnsSources().then(value => { settled = true; return value })
    await vi.waitFor(() => expect(mocks.worker).toHaveBeenCalledWith({ op: 'inspect-physical-adapters' }, 20000))
    expect(mocks.helper).not.toHaveBeenCalled()
    expect(settled).toBe(false)
    finish(JSON.stringify(row))
    expect(await pending).toEqual([{ ifIndex: 17, alias: row.alias, ipv4DnsServers: ['1.1.1.1'] }])
  })
  it('preserves a fresh read after the caller invalidates adapter/DNS snapshots', async () => {
    const api = await import('./physicalAdapterLockdown')
    expect((await api.getPhysicalAdapterDnsSources())[0].ipv4DnsServers).toEqual(['1.1.1.1'])
    api.clearPhysicalAdaptersSnapshotCache()
    mocks.worker.mockResolvedValue(JSON.stringify({ ...row, ipv4Dns: ['9.9.9.9'] }))
    // The routing-only DNS cache has its own 60-second TTL.
    const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 61000)
    try { expect((await api.getPhysicalAdapterDnsSources())[0].ipv4DnsServers).toEqual(['9.9.9.9']) }
    finally { clock.mockRestore() }
    expect(mocks.worker).toHaveBeenCalledTimes(2)
  })
  it('uses the same fixed inspection script only for unavailable before dispatch', async () => {
    mocks.worker.mockRejectedValue(new RecoveryWorkerError('unavailable', 'Worker unavailable'))
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    expect(await getPhysicalAdapterDnsSources()).toHaveLength(1)
    expect(mocks.helper).toHaveBeenCalledWith(expect.stringContaining('Get-NetConnectionProfile'), 20000, 'physical-adapter-lockdown')
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it.each(['closed', 'busy', 'timeout', 'exited', 'protocol', 'rejected'] as const)('does not retry after worker %s', async code => {
    const error = new RecoveryWorkerError(code, 'Native observation uncertain')
    mocks.worker.mockRejectedValue(error)
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    await expect(getPhysicalAdapterDnsSources()).rejects.toBe(error)
    expect(mocks.helper).not.toHaveBeenCalled()
    expect(mocks.elevated).not.toHaveBeenCalled()
  })
  it.each(['', '[]', 'null'])('does not fabricate adapters from an empty snapshot: %j', async value => {
    mocks.worker.mockResolvedValue(value)
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    expect(await getPhysicalAdapterDnsSources()).toEqual([])
    expect(mocks.helper).not.toHaveBeenCalled()
  })
})
