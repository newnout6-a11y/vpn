// AT-03-003 / AT-03-007 / AT-03-012: baseline fault injection, not Windows L3.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import { join } from 'path'
const state = vi.hoisted(() => ({
  manifest: null as any, failRead: false, failWrite: false, failApply: false,
  failNetsh: false, failNotify: false, failedSteps: [] as number[], scripts: [] as string[],
  writes: [] as any[], operations: [] as string[], nativeFailure: false, reportPatch: null as any, logDirectory: ''
}))
vi.mock('electron', () => ({ app: { getPath: () => state.logDirectory }, shell: { openPath: vi.fn() } }))
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
  if (script.includes('steps=@($results)')) {
    const valuesPayload = /\$values = .*FromBase64String\('([^']+)'\)/.exec(script)?.[1]
    if (!valuesPayload) throw new Error('Baseline rollback fixture: missing encoded values payload')
    return {
      stdout: JSON.stringify({ steps: JSON.parse(Buffer.from(valuesPayload, 'base64').toString('utf8')).map((s: any, i: number) => ({ name: `${s.target}/${s.name}`, success: !state.failedSteps.includes(i), error: state.failedSteps.includes(i) ? 'injected failure' : null })),
        notification: { success: !state.failNotify, error: state.failNotify ? 'notification failed' : null }, timings: { registryMs: 1, notifyMs: 2 }, ...state.reportPatch }), stderr: ''
    }
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
// AT-03-003 / AT-03-007: native WinINet notification is mocked; default is "koffi unavailable" so the PS fallback stays covered.
const native = vi.hoisted(() => ({ mode: 'unavailable' as 'unavailable' | 'ok' | 'false', calls: 0 }))
vi.mock('./native/winInet', () => {
  class WinInetCallError extends Error {}
  return {
    WinInetCallError,
    notifyWinInetSettingsChangedNative: async () => {
      native.calls++
      if (native.mode === 'unavailable') throw new Error('koffi load failed')
      if (native.mode === 'false') throw new WinInetCallError('WinINet refresh failed')
    }
  }
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
import { applyTunNetworkBaseline, getTunNetworkBaselineManifestPath, rollbackTunNetworkBaseline, rollbackTunNetworkBaselineIfApplied, rollbackTunNetworkBaselineOrThrow, validateNetworkBackupManifest } from './systemNetwork'
import { logEvent } from './appLogger'
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
beforeEach(() => {
  vi.mocked(logEvent).mockClear()
  state.manifest = null; state.failRead = false; state.failWrite = false; state.failApply = false
  state.failNetsh = false; state.failNotify = false; state.failedSteps = []; state.scripts = []; state.writes = []; state.operations = []
  state.nativeFailure = false; state.reportPatch = null
  native.mode = 'unavailable'; native.calls = 0
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
})
afterEach(() => Object.defineProperty(process, 'platform', platform))
describe('trusted typed network baseline', () => {
  it.each(['missing', 'invalid', 'duplicate'] as const)('restores valid baseline records after %s records, retaining the journal (AT-03-003c)', async kind => {
    const original = fixture()
    state.manifest = structuredClone(original)
    if (kind === 'missing') state.manifest.values.splice(0, 4)
    if (kind === 'invalid') for (let i = 0; i < 4; i++) state.manifest.values[i].exists = 'false'
    if (kind === 'duplicate') state.manifest.values[0] = { ...state.manifest.values[1] }
    const result = await rollbackTunNetworkBaseline()
    expect(result.success).toBe(false)
    expect(result.warnings?.length).toBeGreaterThan(0)
    expect(state.manifest).not.toBeNull()
    expect(state.operations).not.toContain('clear')
    const steps = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'baseline rollback step')
    expect(steps.map(call => (call[3] as any).name)).toEqual(original.values.slice(kind === 'duplicate' ? 2 : 4).map(s => `${s.target}/${s.name}`))
    expect(steps.every(call => (call[3] as any).success)).toBe(true)
    expect(vi.mocked(logEvent).mock.calls.some(call => call[2] === 'baseline rollback step rejected')).toBe(true)
    expect(() => validateNetworkBackupManifest(state.manifest)).toThrow()
  })
  it('performs no native effects when no baseline records are valid (AT-03-003c)', async () => {
    state.manifest = { ...fixture(), values: [] }
    const result = await rollbackTunNetworkBaseline()
    expect(result).toMatchObject({ success: false, warnings: expect.any(Array) })
    expect(result.warnings).toHaveLength(9)
    expect(state.operations).toEqual([])
    expect(logEvent).toHaveBeenCalledWith('error', 'system-network', 'baseline rollback completed', expect.objectContaining({ operationId: result.operationId, success: false, warnings: result.warnings }))
  })
  it.each([{ owner: 'foreign' }, { schemaVersion: 2 }, { userSid: 'invalid' }])('does not salvage records across an invalid envelope %j (AT-03-003/012)', async patch => {
    state.manifest = { ...fixture(), ...patch }
    expect((await rollbackTunNetworkBaseline()).success).toBe(false)
    expect(state.operations).toEqual([])
  })
  it('keeps receipt IDs distinct through real logger/redaction/file writes across a failed rollback and retry (AT-03-007)', async () => {
    const temporary = join(process.cwd(), '.tmp'); mkdirSync(temporary, { recursive: true })
    state.logDirectory = mkdtempSync(join(temporary, 'baseline-log-correlation-'))
    const logger = await vi.importActual<typeof import('./appLogger')>('./appLogger')
    vi.mocked(logEvent).mockImplementation(logger.logEvent)
    const consoleSpies = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')]
    for (const spy of consoleSpies) spy.mockImplementation(() => undefined)
    const credentialUuid = '12345678-1234-4123-8123-123456789abc'
    try {
      state.manifest = fixture(); state.failedSteps = [3]
      const failed = await rollbackTunNetworkBaselineIfApplied('failed attempt')
      state.failedSteps = []
      const retried = await rollbackTunNetworkBaselineIfApplied('retry')
      logger.logEvent('info', 'test', 'credential masking remains active', { note: credentialUuid })
      logger.logEvent('debug', 'test', 'correlation write barrier')
      let raw = ''
      let records: Array<{ scope: string; message: string; details?: any }> = []
      await vi.waitFor(() => {
        raw = readFileSync(logger.getAppLogPath(), 'utf8')
        records = raw.trim().split(/\r?\n/).map(line => JSON.parse(line))
        expect(records.at(-1)?.message).toBe('correlation write barrier')
      })
      expect(failed.success).toBe(false)
      expect(retried.success).toBe(true)
      expect(failed.operationId).not.toBe(retried.operationId)
      const events = records.filter(record => record.scope === 'system-network')
      expect(new Set(events.map(record => record.details?.operationId))).toEqual(new Set([failed.operationId, retried.operationId]))
      for (const receipt of [failed, retried]) {
        const operation = events.filter(record => record.details?.operationId === receipt.operationId)
        expect(operation.filter(record => record.message === 'baseline rollback step')).toHaveLength(9)
        expect(operation.find(record => record.message === 'baseline rollback completed')?.details.success).toBe(receipt.success)
      }
      expect(raw).not.toContain(credentialUuid)
      expect(raw).toContain('<redacted-uuid>')
    } finally {
      vi.mocked(logEvent).mockReset()
      for (const spy of consoleSpies) spy.mockRestore()
      rmSync(state.logDirectory, { recursive: true, force: true })
    }
  })
  it.each(['step', 'notification', 'untrusted'])('rejects incomplete %s recovery for callers using exceptions (AT-03-007)', async failure => {
    state.manifest = fixture()
    if (failure === 'step') state.failedSteps = [3]
    if (failure === 'notification') state.failNotify = true
    if (failure === 'untrusted') state.failRead = true
    const failed = await rollbackTunNetworkBaselineOrThrow('failed start').catch(error => error as Error)
    expect(failed).toBeInstanceOf(Error)
    expect((failed as Error).message).toContain('Повторите восстановление сети')
    expect((failed as Error).message).toContain(failure === 'step' ? 'injected' : failure === 'notification' ? 'notification failed' : 'Untrusted storage')
    expect(state.manifest).not.toBeNull()
  })
  it('accepts trusted absence and successful retry without changing the result contract (AT-03-007)', async () => {
    expect(await rollbackTunNetworkBaselineOrThrow('no baseline')).toMatchObject({ success: true, skipped: true })
    state.manifest = fixture()
    state.failedSteps = [3]
    await expect(rollbackTunNetworkBaselineOrThrow('failed recovery')).rejects.toThrow('injected failure')
    state.failedSteps = []
    expect(await rollbackTunNetworkBaselineOrThrow('retry')).toMatchObject({ success: true })
    expect(state.manifest).toBeNull()
  })
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
  it('apply notifies WinINet in-process without spawning PowerShell when native is available', async () => {
    native.mode = 'ok'
    expect((await applyTunNetworkBaseline()).success).toBe(true)
    expect(native.calls).toBe(1)
    expect(state.scripts.some(script => script.includes('InternetSetOption'))).toBe(false)
  })
  it('apply falls back to PowerShell when native is unavailable, and still fails closed on notify failure', async () => {
    expect((await applyTunNetworkBaseline()).success).toBe(true)
    expect(state.scripts.some(script => script.includes('InternetSetOption'))).toBe(true)
    state.manifest = null; state.failNotify = true
    expect((await applyTunNetworkBaseline()).success).toBe(false)
  })
  it('apply treats a native WinINet false as authoritative: no PowerShell retry, baseline rolled back', async () => {
    native.mode = 'false'
    const result = await applyTunNetworkBaseline()
    expect(result.success).toBe(false)
    expect(result.details).toContain('WinINet refresh failed')
    // Only the (separate) combined rollback script embeds InternetSetOption; no standalone notify script ran.
    expect(state.scripts.filter(script => script.includes('InternetSetOption') && !script.includes('steps=@($results)'))).toHaveLength(0)
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
    expect(result).toHaveProperty('operationId', expect.any(String))
    const events = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'baseline rollback step')
    expect(events).toHaveLength(9)
    for (const [index, event] of events.entries()) {
      expect(event[3]).toMatchObject({ operationId: result.operationId, success: index !== step })
    }
  })
  it('inherits the Stop ID in all baseline rollback events (AT-03-007)', async () => {
    state.manifest = fixture()
    const operationId = '00000000-0000-4000-8000-000000000007'
    const result = await rollbackTunNetworkBaselineIfApplied('TUN stopped', operationId)
    expect(result).toMatchObject({ success: true, operationId })
    const events = vi.mocked(logEvent).mock.calls.filter(call => call[1] === 'system-network')
    expect(events.filter(call => call[2] === 'baseline rollback step')).toHaveLength(9)
    for (const event of events) expect(event[3]).toMatchObject({ operationId })
  })
  it('correlates the failed rollback and successful retry separately (AT-03-007)', async () => {
    state.manifest = fixture(); state.failedSteps = [3]
    const failed = await rollbackTunNetworkBaseline()
    state.failedSteps = []
    const retried = await rollbackTunNetworkBaseline()
    expect(failed.success).toBe(false)
    expect(retried.success).toBe(true)
    expect(state.manifest).toBeNull()
    expect(failed).toHaveProperty('operationId', expect.stringMatching(/^baseline_[a-f0-9]{32}$/))
    expect(retried).toHaveProperty('operationId', expect.stringMatching(/^baseline_[a-f0-9]{32}$/))
    expect(failed.operationId).not.toBe(retried.operationId)
    const events = vi.mocked(logEvent).mock.calls.filter(call => call[1] === 'system-network')
    expect(events.every(call => [failed.operationId, retried.operationId].includes((call[3] as any)?.operationId))).toBe(true)
    const completions = events.filter(call => call[2] === 'baseline rollback completed')
    expect(completions.map(call => call[3])).toEqual([
      expect.objectContaining({ operationId: failed.operationId, success: false }),
      expect.objectContaining({ operationId: retried.operationId, success: true })
    ])
  })
  it('correlates untrusted reads without inventing completed rollback steps (AT-03-007/012)', async () => {
    state.failRead = true
    const result = await rollbackTunNetworkBaseline()
    expect(result.success).toBe(false)
    expect(result).toHaveProperty('operationId', expect.any(String))
    const events = vi.mocked(logEvent).mock.calls
    expect(events.find(call => call[2] === 'CRITICAL_SECURITY_EVENT: baseline recovery unknown')?.[3])
      .toMatchObject({ operationId: result.operationId })
    expect(events.some(call => call[2] === 'baseline rollback step')).toBe(false)
    expect(state.scripts).toEqual([])
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
