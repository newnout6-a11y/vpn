// AT-00-003 / AT-03-006/007/010/012: production code with controlled OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src/main/physicalAdapterLockdown.ts'), 'utf8')
const ast = ts.createSourceFile('physicalAdapterLockdown.ts', source, ts.ScriptTarget.Latest, true)
function compile<T>(name: string, deps: Record<string, unknown>): T {
  const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)
  if (!declaration) throw new Error(`Missing production function ${name}`)
  const js = ts.transpileModule(declaration.getText(ast).replace(/^export /, '') + `\nreturn ${name};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  }).outputText
  return new Function(...Object.keys(deps), js)(...Object.values(deps))
}
const adapter = () => ({ ifIndex: 17, interfaceGuid: '11111111-1111-1111-1111-111111111111', alias: 'Wi-Fi',
  ipv6Enabled: false, ipv4DnsServers: [], isCellularOrTethering: false, forcedIpv6Off: false, forcedDnsTo: null })
const quote = (value: string) => `'${value.replace(/'/g, "''")}'`
const registryApplyLine = compile<(tag: string, key: string, name: string) => string>('registryApplyLine', { psSingleQuote: quote })
const policyProof = '\nDNS_SMNR:off\nDNS_PARALLEL:off'
function harness() {
  const deps = {
    process: { platform: 'win32' }, logEvent: vi.fn(),
    readManifest: vi.fn(async (): Promise<any> => null), writeManifest: vi.fn(async (_manifest: any) => {}),
    snapshotPhysicalAdapters: vi.fn(async () => [adapter()]),
    snapshotTransitionAdapters: vi.fn(async () => ({ teredoType: null, sixToFourState: null, isatapState: null })),
    snapshotDnsRegistryPolicy: vi.fn(async () => ({ smartNameResolution: { exists: false }, parallelAandAAAA: { exists: false } })),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async () => ({ rolledBack: true })),
    runPS: vi.fn(async (_script: string, _timeout: number, _signal?: AbortSignal) => 'A0_ipv6:off\nA0_dns:skip' + policyProof),
    registryApplyLine, psSingleQuote: quote, clearPhysicalAdaptersSnapshotCache: vi.fn()
  }
  const apply = compile<(dns: string, options?: { forceDns?: boolean; signal?: AbortSignal }) => Promise<any>>('applyPhysicalAdapterLockdown', deps)
  return { ...deps, apply }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

describe('physical adapter apply cancellation', () => {
  it('admits no reads or writes after an initial abort', async () => {
    const h = harness(), controller = new AbortController(); controller.abort()
    expect(await h.apply('192.168.250.254', { signal: controller.signal })).toMatchObject({ applied: false, cancelled: true, warnings: [] })
    expect(h.readManifest).not.toHaveBeenCalled()
    expect(h.writeManifest).not.toHaveBeenCalled()
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('waits for shared reads but does not journal or mutate after cancellation', async () => {
    const h = harness(), controller = new AbortController(), read = deferred<ReturnType<typeof adapter>[]>()
    h.snapshotPhysicalAdapters.mockReturnValue(read.promise)
    const result = h.apply('192.168.250.254', { signal: controller.signal })
    await vi.waitFor(() => expect(h.snapshotPhysicalAdapters).toHaveBeenCalledOnce())
    controller.abort(); read.resolve([adapter()])
    expect(await result).toMatchObject({ applied: false, cancelled: true, warnings: [] })
    expect(h.writeManifest).not.toHaveBeenCalled()
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('keeps a pre-existing journal for its recovery owner instead of reapplying on abort', async () => {
    const h = harness(), controller = new AbortController()
    h.readManifest.mockImplementation(async () => { controller.abort(); return { adapters: [adapter()] } })
    expect(await h.apply('192.168.250.254', { signal: controller.signal })).toMatchObject({ applied: true, cancelled: true, adapters: 1 })
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).not.toHaveBeenCalled()
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('retains the pending journal for compensation if cancellation occurs during persistence', async () => {
    const h = harness(), controller = new AbortController()
    h.writeManifest.mockImplementation(async () => { controller.abort() })
    expect(await h.apply('192.168.250.254', { signal: controller.signal })).toMatchObject({ applied: true, cancelled: true })
    expect(h.writeManifest).toHaveBeenCalledOnce()
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('does not interrupt an admitted native batch or settle before its final journal', async () => {
    const h = harness(), controller = new AbortController(), native = deferred<string>()
    h.runPS.mockReturnValue(native.promise)
    let settled = false
    const result = h.apply('192.168.250.254', { forceDns: false, signal: controller.signal }).then(value => { settled = true; return value })
    await vi.waitFor(() => expect(h.runPS).toHaveBeenCalledOnce())
    expect(h.runPS.mock.calls[0][2]).toBe(controller.signal)
    controller.abort(); await Promise.resolve()
    expect(settled).toBe(false)
    native.resolve('A0_ipv6:already-off\nA0_ipv6:off\nA0_dns:skip' + policyProof)
    expect(await result).toMatchObject({ applied: true, warnings: [] })
    expect(h.writeManifest).toHaveBeenCalledTimes(2)
  })
  it.each(['physical-lockdown-cancelled-before-dispatch', 'elevated-helper-timeout'])('preserves pending recovery for %s', async code => {
    const h = harness()
    h.runPS.mockRejectedValue(Object.assign(new Error('native result unknown'), { code }))
    const result = await h.apply('192.168.250.254')
    expect(result.applied).toBe(true)
    expect(result.cancelled === true).toBe(code.startsWith('physical-lockdown-cancelled'))
    expect(h.writeManifest).toHaveBeenCalledOnce()
  })
  it('keeps conservative recovery after a failed native read-back', async () => {
    const h = harness(); h.snapshotPhysicalAdapters.mockResolvedValue([{ ...adapter(), ipv6Enabled: true }])
    h.runPS.mockResolvedValue('A0_ipv6_err: IPv6 read-back mismatch\nA0_dns:skip' + policyProof)
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: [expect.stringContaining('read-back mismatch')] })
    expect(h.writeManifest).toHaveBeenCalledOnce()
    expect(h.writeManifest.mock.calls[0][0].adapters[0].forcedIpv6Off).toBe(true)
  })
  it('does not report DNS policy success without fresh native proof', async () => {
    const h = harness(); h.runPS.mockResolvedValue('A0_ipv6:off\nA0_dns:skip')
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: ['DNS_SMNR_err: policy not verified', 'DNS_PARALLEL_err: policy not verified'] })
    expect(h.writeManifest).toHaveBeenCalledOnce()
  })
  it.each([false, true])('passes startup cancellation and retains compensation ownership (native failure=%s)', nativeFailure => {
    const tun = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
    const begin = tun.indexOf('const adapterLockdownPromise:')
    const end = tun.indexOf('adapterLockdownPromise?.catch', begin)
    const js = ts.transpileModule(`let adapterLockdownEngaged=false,adapterLockdownWarning=null;const wantAdapterLockdown=true,adapterLockdownForceDns=false,TUN_IPV4_RESOLVER='192.168.250.254';${tun.slice(begin, end)}\nreturn {promise:adapterLockdownPromise,state:()=>({adapterLockdownEngaged,adapterLockdownWarning})};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const controller = new AbortController(), rollback = vi.fn()
    if (nativeFailure) controller.abort()
    const apply = vi.fn(async (_dns: string, _options: { signal: AbortSignal }) => ({ applied: true, cancelled: !nativeFailure, adapters: 1, warnings: nativeFailure ? ['native read-back failed'] : [] }))
    const result = new Function('startAbortController', 'applyPhysicalAdapterLockdown', 'timeAsync', 'logEvent', 'rollbackPhysicalAdapterLockdownIfApplied', js)(controller, apply, (_: string, f: () => unknown) => f(), vi.fn(), rollback)
    return result.promise.then(() => {
      expect(apply.mock.calls[0][1]).toMatchObject({ signal: controller.signal })
      expect(result.state()).toEqual({ adapterLockdownEngaged: true, adapterLockdownWarning: null })
      expect(rollback).not.toHaveBeenCalled()
    })
  })
})

describe('adapter native transport', () => {
  it('admits the complete native apply through the physical helper policy', async () => {
    const h = harness(); await h.apply('192.168.250.254', { forceDns: false })
    const helperSource = readFileSync(join(process.cwd(), 'src/main/elevatedPsHelper.ts'), 'utf8')
    const helperAst = ts.createSourceFile('helper.ts', helperSource, ts.ScriptTarget.Latest, true)
    const nodes = helperAst.statements.filter(node =>
      ts.isFunctionDeclaration(node) && node.name?.text === 'validateScriptPolicy' ||
      ts.isVariableStatement(node) && node.declarationList.declarations.some(d => ['BLOCKED_SCRIPT_TOKENS', 'POLICY_REQUIRED_TOKENS', 'POLICY_FORBIDDEN_TOKENS'].includes(d.name.getText(helperAst))))
    const js = ts.transpileModule(nodes.map(node => node.getText(helperAst).replace(/^export /, '')).join('\n') + '\nreturn validateScriptPolicy;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const validate = new Function('ElevatedPsHelperError', js)(Error)
    expect(() => validate(h.runPS.mock.calls[0][0], 'physical-adapter-lockdown')).not.toThrow()
    expect(() => validate(h.runPS.mock.calls[0][0] + '\nNew-NetFirewallRule', 'physical-adapter-lockdown')).toThrow()
  })
  function transport() {
    const deps = { Buffer, logEvent: vi.fn(), isElevatedPsHelperRunning: () => true,
      execElevatedPs: vi.fn(async () => ({ stdout: 'verified', stderr: '', exitCode: 0 })),
      execElevated: vi.fn(async () => ({ stdout: 'fallback' })) }
    return { ...deps, run: compile<(s: string, timeout?: number, signal?: AbortSignal) => Promise<string>>('runPS', deps) }
  }
  it.each(['elevated-helper-timeout', 'elevated-helper-exited', 'elevated-helper-stopped', 'unclassified'])('never replays an unknown native outcome: %s', async code => {
    const h = transport(), error = Object.assign(new Error('unknown effects'), { code })
    h.execElevatedPs.mockRejectedValue(error)
    await expect(h.run('Disable-NetAdapterBinding')).rejects.toBe(error)
    expect(h.execElevated).not.toHaveBeenCalled()
  })
  it.each(['elevated-helper-script-rejected', 'elevated-helper-script-too-large', 'elevated-helper-unavailable'])('allows a known pre-dispatch fallback: %s', async code => {
    const h = transport(); h.execElevatedPs.mockRejectedValue(Object.assign(new Error('not dispatched'), { code }))
    expect(await h.run('Get-NetAdapter')).toBe('fallback')
    expect(h.execElevated).toHaveBeenCalledOnce()
  })
  it('stops fallback dispatch if abort arrives with the pre-dispatch rejection', async () => {
    const h = transport(), controller = new AbortController()
    h.execElevatedPs.mockImplementation(async () => { controller.abort(); throw Object.assign(new Error('not dispatched'), { code: 'elevated-helper-unavailable' }) })
    await expect(h.run('Disable-NetAdapterBinding', 30000, controller.signal)).rejects.toMatchObject({ code: 'physical-lockdown-cancelled-before-dispatch' })
    expect(h.execElevated).not.toHaveBeenCalled()
  })
  it('does not mistake a failed helper reply for a successful command or replay it', async () => {
    const h = transport(); h.execElevatedPs.mockResolvedValue({ stdout: '', stderr: 'native failure', exitCode: 1 })
    await expect(h.run('Disable-NetAdapterBinding')).rejects.toThrow('native failure')
    expect(h.execElevated).not.toHaveBeenCalled()
  })
})

describe.skipIf(process.platform !== 'win32')('fresh IPv6 proof in production native batch', () => {
  it.each([
    ['disabled', '$false', '$false', 1, 0, true],
    ['enabled', '$true', '$false', 1, 1, true],
    ['empty', '$false', '$false', 0, 0, false],
    ['ambiguous', '$false', '$false', 2, 0, false],
    ['missing state', '$null', '$false', 1, 0, false],
    ['string state', "'False'", '$false', 1, 0, false],
    ['failed readback', '$true', '$true', 1, 1, false]
  ])('%s binding', async (_name, first, after, count, disables, verified) => {
    const h = harness(); await h.apply('192.168.250.254', { forceDns: false })
    const batch = h.runPS.mock.calls[0][0]
    const begin = batch.indexOf('try {\n  $binding ='), end = batch.indexOf('\nWrite-Output "A0_dns:skip"', begin)
    if (begin < 0 || end < 0) throw new Error('Production IPv6 native block missing')
    // Both cmdlets are shadowed: this test cannot modify any real adapter.
    const ps = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$ownedAdapter=@{Name='fixture'};$script:reads=0;$script:disables=0
function Get-NetAdapterBinding { param($InterfaceAlias,$ComponentID,$ErrorAction) $script:reads++; if ($script:reads -eq 1) { for($i=0;$i -lt ${count};$i++){[pscustomobject]@{Enabled=${first}}} } else {[pscustomobject]@{Enabled=${after}}} }
function Disable-NetAdapterBinding { param($InterfaceAlias,$ComponentID,$ErrorAction) $script:disables++ }
$output=@(& {${batch.slice(begin, end)}})
@{disables=$script:disables;verified=($output -contains 'A0_ipv6:off');alreadyOff=($output -contains 'A0_ipv6:already-off')} | ConvertTo-Json -Compress`
    const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(ps, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15000, encoding: 'utf8' }).trim())
    expect(result).toMatchObject({ disables, verified, alreadyOff: _name === 'disabled' })
  })
})

describe.skipIf(process.platform !== 'win32')('DNS policy apply native proof', () => {
  it.each([
    ['already set', true, 1, 'DWord', false, 0, true],
    ['absent', false, 0, 'DWord', false, 1, true],
    ['existing zero', true, 0, 'DWord', false, 1, true],
    ['wrong kind', true, 1, 'String', false, 1, true],
    ['write readback mismatch', true, 0, 'DWord', true, 1, false]
  ])('%s', (_name, exists, value, kind, fail, writes, verified) => {
    const block = registryApplyLine('DNS_TEST', 'HKLM\\fixture', 'FixtureValue').replace('[Microsoft.Win32.Registry]::LocalMachine', '$fixtureRegistry')
    expect(block).not.toContain('[Microsoft.Win32.Registry]::LocalMachine')
    const ps = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$script:exists=$${exists};$script:value=${value};$script:kind=[Microsoft.Win32.RegistryValueKind]::${kind};$script:writes=0;$script:closes=0
$fixtureKey=[pscustomobject]@{}
$fixtureKey | Add-Member ScriptMethod GetValueNames {if($script:exists){'FixtureValue'}}
$fixtureKey | Add-Member ScriptMethod GetValueKind {param($name) if(-not $script:exists){throw 'missing value'};$script:kind}
$fixtureKey | Add-Member ScriptMethod GetValue {param($name) $script:value}
$fixtureKey | Add-Member ScriptMethod SetValue {param($name,$value,$kind) $script:writes++; if(-not $${fail}){$script:exists=$true;$script:value=$value;$script:kind=$kind}}
$fixtureKey | Add-Member ScriptMethod Close {$script:closes++}
$fixtureRegistry=[pscustomobject]@{};$fixtureRegistry | Add-Member ScriptMethod CreateSubKey {param($path) $fixtureKey}
$output=@(& {${block}})
@{writes=$script:writes;closes=$script:closes;verified=($output -contains 'DNS_TEST:off');alreadyOff=($output -contains 'DNS_TEST:already-off')} | ConvertTo-Json -Compress`
    const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(ps, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15000, encoding: 'utf8' }).trim())
    expect(result).toEqual({ writes, closes: 1, verified, alreadyOff: _name === 'already set' })
  })
})
