// AT-03-003 / AT-03-007 / AT-03-012: baseline fault injection, not Windows L3.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
const state = vi.hoisted(() => ({
  manifest: null as any, failRead: false, failWrite: false, failApply: false,
  failNetsh: false, failNotify: false, failedSteps: [] as number[], scripts: [] as string[],
  writes: [] as any[], operations: [] as string[], nativeFailure: false, reportPatch: null as any
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
  if (state.nativeFailure) throw Object.assign(new Error(`Command failed: ${command}`), {
    code: 1, stderr: 'Baseline user identity mismatch'
  })
  state.scripts.push(script)
  if (script.includes('ToUnixTimeMilliseconds')) return { stdout: JSON.stringify(fixture()), stderr: '' }
  if (script.includes("Write-Output 'BASELINE_APPLIED'")) {
    if (!state.manifest) throw new Error('Mutated before durable snapshot')
    if (state.failApply) throw new Error('apply failed')
    return { stdout: 'BASELINE_APPLIED', stderr: '' }
  }
  if (script.includes('steps=@($results)')) return {
    stdout: JSON.stringify({ steps: state.manifest.values.map((s: any, i: number) => ({ name: `${s.target}/${s.name}`, success: !state.failedSteps.includes(i), error: state.failedSteps.includes(i) ? 'injected failure' : null })),
      notification: { success: !state.failNotify, error: state.failNotify ? 'notification failed' : null }, timings: { registryMs: 1, notifyMs: 2 }, ...state.reportPatch }), stderr: ''
  }
  if (script.includes('InternetSetOption') && state.failNotify) throw new Error('notification failed')
  return { stdout: '', stderr: '' }
}
vi.mock('./admin', () => ({ execElevated: vi.fn(async (command: string) => response(command)) }))
vi.mock('child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('child_process')>()
  const execFile = (file: string, args: string[], _options: unknown, callback: Function) => {
    const command = `${file} ${args.join(' ')}`
    try { const result = response(command); callback(null, { stdout: result.stdout, stderr: result.stderr }) }
    catch (error) { callback(error) }
  }
  return { ...actual, execFile, default: { ...actual, execFile } }
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
  state.nativeFailure = false; state.reportPatch = null
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
})
afterEach(() => Object.defineProperty(process, 'platform', platform))
describe('trusted typed network baseline', () => {
  it('restores all values and notifies WinINet in one native process', async () => {
    state.manifest = fixture()
    expect((await rollbackTunNetworkBaseline()).success).toBe(true)
    expect(state.scripts).toHaveLength(1)
    expect(state.scripts[0]).toContain('try { Send-WinInetSettingsChanged }')
    expect(state.operations).toEqual(['ps', 'clear'])
  })
  it.each([
    { notification: undefined }, { notification: { success: true, error: 'unverified' } },
    { notification: { success: false, error: null } }, { timings: undefined },
    { timings: { registryMs: -1, notifyMs: 0 } }, { timings: { registryMs: 1, notifyMs: '0' } },
    { steps: [] }, { steps: fixture().values.map(s => ({ name: `${s.target}/${s.name}`, success: 'true', error: null })) }
  ])('retains journal on malformed combined recovery report: %j', patch => {
    state.manifest = fixture(); state.reportPatch = patch
    return rollbackTunNetworkBaseline().then(result => {
      expect(result.success).toBe(false)
      expect(state.manifest).not.toBeNull()
    })
  })
  it.skipIf(process.platform !== 'win32')('native restore/read-back handles all registry types in an isolated test subtree', async () => {
    const manifest = fixture()
    manifest.values = [
      { target: 'internet', name: 'ProxyEnable', exists: true, kind: 'DWord', data: 1 },
      { target: 'internet', name: 'ProxyServer', exists: true, kind: 'String', data: 'fixture' },
      { target: 'internet', name: 'AutoConfigURL', exists: true, kind: 'QWord', data: '9223372036854775807' },
      { target: 'internet', name: 'AutoDetect', exists: false, kind: null, data: null },
      { target: 'environment', name: 'HTTP_PROXY', exists: true, kind: 'ExpandString', data: '%FIXTURE_PROXY%' },
      { target: 'environment', name: 'HTTPS_PROXY', exists: true, kind: 'MultiString', data: ['first', 'second'] },
      { target: 'environment', name: 'ALL_PROXY', exists: true, kind: 'String', data: '' },
      { target: 'environment', name: 'NO_PROXY', exists: false, kind: null, data: null },
      { target: 'winhttp', name: 'WinHttpSettings', exists: true, kind: 'Binary', data: [0, 1, 255] }
    ] as any
    state.manifest = manifest
    await rollbackTunNetworkBaseline()
    const captured = state.scripts[0]
    const helpers = captured.slice(0, captured.indexOf('\nif ([Security.Principal.WindowsIdentity]'))
    const report = captured.slice(captured.indexOf('$values ='))
    // All registry targets resolve below this process-owned GUID subtree.
    // The actual network keys, ProgramData manifests and HKLM are untouched.
    const script = `$ProgressPreference='SilentlyContinue';${helpers}
$testRoot='Software\\VPNTE-Recovery-Test-'+[Guid]::NewGuid().ToString('N')
function Get-BaseKey($target) { return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testRoot) }
function Send-WinInetSettingsChanged {}
try { ${report} }
finally { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRoot,$false) }`
    const stdout = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000 })
    const steps = JSON.parse(stdout.trim()).steps
    expect(steps).toHaveLength(9)
    expect(steps.every((step: any) => step.success && step.error === null)).toBe(true)
  })
  // AT-03-007 / F-033: execute actual JSON decoding and report construction,
  // substituting only registry effects. Never run the real Restore-Snapshot.
  it.skipIf(process.platform !== 'win32').each([null, ...Array.from({ length: 9 }, (_, i) => i)])(
    'native PowerShell reports nine independent rollback steps (failed step %s)', async failedStep => {
      state.manifest = fixture()
      await rollbackTunNetworkBaseline()
      const productionReport = state.scripts[0].slice(state.scripts[0].indexOf('$values ='))
      const failedName = failedStep === null ? '' : fixture().values[failedStep].name
      const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';function Send-WinInetSettingsChanged {};function Restore-Snapshot($s) { if ($s.name -eq '${failedName}') { throw 'injected native failure' } }\n${productionReport}`
      const stdout = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000 })
      const steps = JSON.parse(stdout.trim()).steps
      expect(steps).toHaveLength(9)
      expect(steps.map((step: any) => step.name)).toEqual(fixture().values.map(s => `${s.target}/${s.name}`))
      expect(steps.map((step: any) => step.success)).toEqual(fixture().values.map((_s, i) => i !== failedStep))
    }
  )
  it('retains the snapshot and reports native stderr without a huge encoded command', async () => {
    state.manifest = fixture(); state.nativeFailure = true
    const result = await rollbackTunNetworkBaseline()
    expect(result.success).toBe(false)
    expect(result.warnings?.[0]).toContain('Baseline user identity mismatch')
    expect(result.warnings?.[0]).not.toContain('-EncodedCommand')
    expect(result.warnings?.[0].length).toBeLessThan(200)
    expect(state.manifest).not.toBeNull()
  })
  it.skipIf(process.platform !== 'win32')('native notification failure preserves the nine independent step results', async () => {
    state.manifest = fixture(); await rollbackTunNetworkBaseline()
    const report = state.scripts[0].slice(state.scripts[0].indexOf('$values ='))
    const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';function Restore-Snapshot($s) {};function Send-WinInetSettingsChanged {throw 'injected notification failure'};${report}`
    const stdout = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000 })
    const result = JSON.parse(stdout.trim())
    expect(result.steps).toHaveLength(9)
    expect(result.steps.every((s: any) => s.success)).toBe(true)
    expect(result.notification).toEqual({ success: false, error: 'injected notification failure' })
    expect(result.timings.registryMs).toBeGreaterThanOrEqual(0)
    expect(result.timings.notifyMs).toBeGreaterThanOrEqual(0)
  })
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
  it.skipIf(!process.env.VPNTE_PWSH)('parses all generated baseline scripts with real PowerShell', async () => {
    await applyTunNetworkBaseline()
    await rollbackTunNetworkBaseline()
    for (const script of state.scripts) {
      const encoded = Buffer.from(script).toString('base64')
      const command = `$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'));$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|Out-String|Write-Output;exit 1}`
      expect(() => execFileSync(process.env.VPNTE_PWSH!, ['-NoProfile', '-NonInteractive', '-Command', command], { encoding: 'utf8' })).not.toThrow()
    }
  })
  it('serializes concurrent applications without replacing the first baseline', async () => {
    const results = await Promise.all(Array.from({ length: 50 }, () => applyTunNetworkBaseline()))
    expect(results.every(result => result.success)).toBe(true)
    expect(state.writes).toHaveLength(1)
  })
})
