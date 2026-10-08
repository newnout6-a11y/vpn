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
import { executeRecoveryOperation, RecoveryWorkerError } from './recoveryPsWorker'
const row = { ifIndex: 17, interfaceGuid: '11111111-1111-1111-1111-111111111111', alias: 'Беспроводная сеть',
  description: 'MediaTek Wi-Fi', ipv6Enabled: true, ipv4Dns: ['1.1.1.1'], ipv4DnsSource: 'dhcp',
  gateways: ['10.0.0.1'], networkProfiles: ['Office'], isCellularOrTethering: false }
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  mocks.worker.mockResolvedValue(JSON.stringify(row))
  mocks.helper.mockResolvedValue({ stdout: JSON.stringify(row), stderr: '', exitCode: 0 })
})
describe.skipIf(process.platform !== 'win32')('routing DNS and full lockdown inspection use separate transports', () => {
  it('leaves the privileged helper free while DNS discovery is still running', async () => {
    let finish!: (value: string) => void
    mocks.worker.mockReturnValue(new Promise(resolve => { finish = resolve }))
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    let settled = false
    const pending = getPhysicalAdapterDnsSources().then(value => { settled = true; return value })
    const concurrent = getPhysicalAdapterDnsSources()
    await vi.waitFor(() => expect(mocks.worker).toHaveBeenCalledWith({ op: 'inspect-physical-dns' }, 20000))
    expect(mocks.helper).not.toHaveBeenCalled()
    expect(settled).toBe(false)
    expect(mocks.worker).toHaveBeenCalledOnce()
    finish(JSON.stringify(row))
    expect(await pending).toEqual([{ ifIndex: 17, alias: row.alias, ipv4DnsServers: ['1.1.1.1'] }])
    expect(await concurrent).toEqual(await pending)
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
    expect(mocks.helper).toHaveBeenCalledWith(expect.stringContaining('Get-DnsClientServerAddress'), 20000, 'physical-adapter-lockdown')
    expect(mocks.helper.mock.calls[0][0]).not.toMatch(/Get-NetRoute|Get-NetAdapterBinding|Get-NetConnectionProfile|Get-ItemProperty/)
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
  it('keeps a blocked full baseline out of the runtime ACL queue and never uses DNS as a proof (AT-01-009/AT-03-006)', async () => {
    let finish!: (value: { stdout: string }) => void
    mocks.helper.mockImplementation((script: string) => script.includes('Get-NetConnectionProfile')
      ? new Promise(resolve => { finish = resolve }) : Promise.resolve({ stdout: '{}' }))
    mocks.worker.mockImplementation(async ({op}: {op: string}) => op === 'inspect-dns-policy'
      ? JSON.stringify(['smartNameResolution', 'parallelAandAAAA'].map(tag => ({tag,exists:false,type:null,data:null})))
      : op === 'inspect-runtime-acl' ? 'FRESH_ACL' : JSON.stringify(row))
    const api = await import('./physicalAdapterLockdown'), controller = new AbortController()
    await api.getPhysicalAdapterDnsSources()
    const pending = api.applyPhysicalAdapterLockdown('192.168.250.254', {signal: controller.signal})
    await vi.waitFor(() => expect(mocks.helper).toHaveBeenCalledWith(expect.stringContaining('Get-NetConnectionProfile'), 20000, 'physical-adapter-lockdown'))
    await expect(executeRecoveryOperation({op:'inspect-runtime-acl',runtimeDir:'C:\\fixture'})).resolves.toBe('FRESH_ACL')
    expect(mocks.worker.mock.calls.some(([request]) => request.op === 'inspect-physical-adapters')).toBe(false)
    controller.abort(); finish({stdout:JSON.stringify(row)})
    await expect(pending).resolves.toMatchObject({applied:false,cancelled:true})
  })
  it.each([
    '{bad', JSON.stringify({...row,ifIndex:0}), JSON.stringify({...row,alias:'bad\nname'}),
    JSON.stringify({...row,ipv4Dns:['not-an-ip']}), JSON.stringify({...row,ipv4Dns:['::1']})
  ])('rejects invalid routing-only DNS data: %j (AT-03-012)', async value => {
    mocks.worker.mockResolvedValue(value)
    const { getPhysicalAdapterDnsSources } = await import('./physicalAdapterLockdown')
    await expect(getPhysicalAdapterDnsSources()).rejects.toThrow()
    expect(mocks.helper).not.toHaveBeenCalled()
  })
})
