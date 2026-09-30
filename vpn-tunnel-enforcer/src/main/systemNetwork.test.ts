// AT-03-003 / AT-03-007 / AT-03-012: baseline fault injection, not Windows L3.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({
  manifest: null as any, failRead: false, failWrite: false, failApply: false,
  failNetsh: false, failNotify: false, failedSteps: [] as number[], scripts: [] as string[],
  writes: [] as any[], operations: [] as string[]
}))
const fixture = () => ({
  schemaVersion: 1, owner: 'VPNTE', createdAt: 1780000000000, userSid: 'S-1-5-21-1-2-3-1001',
  values: [
    ...['ProxyEnable', 'ProxyServer', 'AutoConfigURL', 'AutoDetect'].map(name => ({ target: 'internet', name, exists: false, kind: null, data: null })),
    ...['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'].map(name => ({ target: 'environment', name, exists: true, kind: 'ExpandString', data: '%CORPORATE_PROXY%' })),
    { target: 'winhttp', name: 'WinHttpSettings', exists: true, kind: 'Binary', data: [0, 1, 255] }
  ]
})
function response(command: string) {
  state.operations.push(command.startsWith('netsh') ? 'netsh' : 'ps')
  if (command.startsWith('netsh')) {
    if (state.failNetsh) throw new Error('WinHTTP reset failed')
    return { stdout: '', stderr: '' }
  }
  const script = Buffer.from(command.split(' ').at(-1)!, 'base64').toString('utf16le')
  state.scripts.push(script)
  if (script.includes('ToUnixTimeMilliseconds')) return { stdout: JSON.stringify(fixture()), stderr: '' }
  if (script.includes("Write-Output 'BASELINE_APPLIED'")) {
    if (!state.manifest) throw new Error('Mutated before durable snapshot')
    if (state.failApply) throw new Error('apply failed')
    return { stdout: 'BASELINE_APPLIED', stderr: '' }
  }
  if (script.includes('ConvertTo-Json -InputObject @($results)')) return {
    stdout: JSON.stringify(state.manifest.values.map((s: any, i: number) => ({ name: `${s.target}/${s.name}`, success: !state.failedSteps.includes(i), error: state.failedSteps.includes(i) ? 'injected failure' : null }))), stderr: ''
  }
  if (script.includes('InternetSetOption') && state.failNotify) throw new Error('notification failed')
  return { stdout: '', stderr: '' }
}
vi.mock('./admin', () => ({ execElevated: vi.fn(async (command: string) => response(command)) }))
vi.mock('child_process', () => {
  const exec = (command: string, _options: unknown, callback: Function) => {
    try { const result = response(command); callback(null, { stdout: result.stdout, stderr: result.stderr }) }
    catch (error) { callback(error) }
  }
  return { exec, default: { exec } }
})
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./recoveryManifest', () => ({
  recoveryManifestPath: (name: string) => `C:\\ProgramData\\VPNTE\\manifests\\${name}`,
  readRecoveryManifest: async (_name: string, validate: Function) => {
    if (state.failRead) throw new Error('Untrusted storage')
    return state.manifest ? validate(state.manifest) : null
  },
  writeRecoveryManifest: async (_name: string, value: unknown, validate: Function) => {
    if (state.failWrite) throw new Error('disk full')
    state.manifest = validate(value); state.writes.push(structuredClone(value)); state.operations.push('persist')
  },
  removeRecoveryManifest: async () => { state.manifest = null; state.operations.push('clear') }
}))
import { applyTunNetworkBaseline, getTunNetworkBaselineManifestPath, rollbackTunNetworkBaseline, validateNetworkBackupManifest } from './systemNetwork'
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
beforeEach(() => {
  state.manifest = null; state.failRead = false; state.failWrite = false; state.failApply = false
  state.failNetsh = false; state.failNotify = false; state.failedSteps = []; state.scripts = []; state.writes = []; state.operations = []
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
})
afterEach(() => Object.defineProperty(process, 'platform', platform))
describe('trusted typed network baseline', () => {
  it('uses canonical trusted storage rather than AppData or arbitrary reg files', () => {
    expect(getTunNetworkBaselineManifestPath()).toBe('C:\\ProgramData\\VPNTE\\manifests\\latest-tun-network-baseline.json')
    expect(validateNetworkBackupManifest(fixture()).values).toHaveLength(9)
  })
  it.each([
    { schemaVersion: 2 }, { userSid: "'; malicious" }, { owner: 'foreign' },
    { values: [] }, { values: fixture().values.map((s, i) => i === 0 ? { ...s, target: 'arbitrary-registry' } : s) },
    { values: fixture().values.map((s, i) => i === 0 ? { ...s, name: 'malicious-value' } : s) },
    { values: fixture().values.map((s, i) => i === 0 ? { ...s, exists: true, kind: 'Binary', data: [256] } : s) }
  ])('rejects invalid registry data %j', patch => {
    expect(() => validateNetworkBackupManifest({ ...fixture(), ...patch })).toThrow()
  })
  it('persists baseline before effects and retains first snapshot on repeat apply', async () => {
    expect((await applyTunNetworkBaseline()).success).toBe(true)
    expect(state.operations.indexOf('persist')).toBeLessThan(state.operations.indexOf('netsh'))
    expect((await applyTunNetworkBaseline()).skipped).toBe(true)
    expect(state.writes).toHaveLength(1)
    expect(state.scripts.every(script => !script.includes('reg import'))).toBe(true)
  })
  it('does not mutate when storage is untrusted or persistence fails', async () => {
    state.failRead = true
    expect((await applyTunNetworkBaseline()).success).toBe(false)
    expect(state.operations).toHaveLength(0)
    state.failRead = false; state.failWrite = true
    expect((await applyTunNetworkBaseline()).success).toBe(false)
    expect(state.operations).not.toContain('netsh')
  })
  it('reports failure and compensates if application fails after persistence', async () => {
    state.failApply = true
    expect((await applyTunNetworkBaseline()).success).toBe(false)
    expect(state.scripts.some(script => script.includes('foreach ($s in $values)'))).toBe(true)
    expect(state.manifest).toBeNull()
  })
  it('does not claim successful apply on WinHTTP reset failure', async () => {
    state.failNetsh = true
    expect((await applyTunNetworkBaseline()).success).toBe(false)
    expect(state.manifest).toBeNull()
  })
  it.each(Array.from({ length: 9 }, (_, i) => i))('retains snapshot and independent steps after failed rollback step %i', async step => {
    state.manifest = fixture(); state.failedSteps = [step]
    const result = await rollbackTunNetworkBaseline()
    expect(result.success).toBe(false)
    expect(result.warnings).toHaveLength(1)
    expect(state.manifest).not.toBeNull()
    expect(state.scripts[0]).toContain('foreach ($s in $values)')
    expect(state.scripts[0]).toContain('catch { $results +=')
    expect(state.scripts[0]).toContain('Registry read-back mismatch')
  })
  it('retains snapshot on notification failure, clears only after verified recovery', async () => {
    state.manifest = fixture(); state.failNotify = true
    expect((await rollbackTunNetworkBaseline()).success).toBe(false)
    expect(state.manifest).not.toBeNull()
    state.failNotify = false
    expect((await rollbackTunNetworkBaseline()).success).toBe(true)
    expect(state.manifest).toBeNull()
  })
  it('treats trusted absence as a no-op, untrusted data as failure', async () => {
    expect((await rollbackTunNetworkBaseline()).skipped).toBe(true)
    state.failRead = true
    expect((await rollbackTunNetworkBaseline()).success).toBe(false)
  })
  it('serializes concurrent applications without replacing the first baseline', async () => {
    const results = await Promise.all(Array.from({ length: 50 }, () => applyTunNetworkBaseline()))
    expect(results.every(result => result.success)).toBe(true)
    expect(state.writes).toHaveLength(1)
  })
})
