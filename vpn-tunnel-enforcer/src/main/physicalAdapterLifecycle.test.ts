// AT-00-003 / AT-03-006/007/010/012: production code with controlled OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { isIP } from 'node:net'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { ipcError } from '../shared/ipc-result'
import { classifyRecoveryError } from './recoveryErrors'

const source = readFileSync(join(process.cwd(), 'src/main/physicalAdapterLockdown.ts'), 'utf8')
const ast = ts.createSourceFile('physicalAdapterLockdown.ts', source, ts.ScriptTarget.Latest, true)
function compile<T>(name: string, deps: Record<string, unknown>): T {
  deps = { ipcError, classifyRecoveryError, applyNativeAdapterLockdown: async () => null, restoreNativeAdapterLockdown: async () => null, ...deps }
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
    registryApplyLine, psSingleQuote: quote, clearPhysicalAdaptersSnapshotCache: vi.fn(),
    applyNativeAdapterLockdown: vi.fn(async (): Promise<string | null> => null)
  }
  const apply = compile<(dns: string, options?: { forceDns?: boolean; signal?: AbortSignal }) => Promise<any>>('applyPhysicalAdapterLockdown', deps)
  return { ...deps, apply }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

describe('adapter rollback correlation (AT-03-007)', () => {
  it('continues independent policy recovery after native staging refusal without replaying interface writes', async () => {
    const deps = { process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: async () => ({ adapters: [adapter()], dnsRegistryPolicy: {} }), registryRestoreLine: () => 'restore-independent-policy',
      restoreNativeAdapterLockdown: vi.fn(async () => { throw new Error('untrusted native runtime') }),
      runPS: vi.fn(async (_script: string) => 'DNS_SMNR:delete\nDNS_PARALLEL:delete'),
      deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn() }
    const rollback = compile<(reason: string) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    expect(await rollback('test')).toMatchObject({ success: false, rolledBack: false, restoredAdapters: [] })
    expect(deps.runPS).toHaveBeenCalledOnce()
    expect(deps.runPS.mock.calls[0][0]).toContain('restore-independent-policy')
    expect(deps.runPS.mock.calls[0][0]).not.toMatch(/Enable-NetAdapterBinding|Set-DnsClientServerAddress|Get-NetAdapter/)
    expect(deps.deleteManifest).not.toHaveBeenCalled()
  })
  it.each([
    ['ifIndex', 0], ['alias', 'FAKE-PRIVATE\nPAYLOAD'], ['ipv6Enabled', null], ['forcedIpv6Off', 'private'],
    ['interfaceGuid', 'FAKE-PRIVATE-PAYLOAD'], ['ipv4DnsSource', 'private'], ['ipv4DnsServers', ['FAKE-PRIVATE-PAYLOAD']],
    ['forcedDnsTo', ['FAKE-PRIVATE-PAYLOAD']]
  ])('identifies invalid %s without echoing the snapshot (AT-03-012)', (field, value) => {
    const validate = compile<(value: unknown) => any>('validateLockdownManifest', { isIP })
    const manifest = { schemaVersion: 1, owner: 'VPNTE', appliedAt: Date.now(), tunDnsIpv4: '192.168.250.254',
      adapters: [{ ...adapter(), ipv4DnsSource: 'static', ipv6Enabled: true, forcedIpv6Off: true, [field as string]: value }],
      dnsRegistryPolicy: { smartNameResolution: { exists: false }, parallelAandAAAA: { exists: false } } }
    expect(() => validate(manifest)).toThrow(`Invalid adapter snapshot: ${field}`)
  })
  it.each(['A0_ipv6:noop-unverified', 'A0_ipv6_err: diagnostic mentions A0_ipv6:noop', 'A0_ipv6:noop\nA0_ipv6_err: denied', 'A0_ipv6:noop\nA0_ipv6:noop'])(
    'does not promote an ambiguous native marker into a restored receipt: %s (AT-00-004/AT-03-007)', async ipv6 => {
      const deps = { process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
        readManifest: async () => ({ adapters: [adapter()], dnsRegistryPolicy: {} }), registryRestoreLine: () => '',
        runPS: async () => `${ipv6}\nA0_dns:noop\nDNS_SMNR:delete\nDNS_PARALLEL:delete`,
        deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn() }
      const rollback = compile<(reason: string) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
      expect(await rollback('test')).toMatchObject({ success: false, rolledBack: false, restoredAdapters: [] })
      expect(deps.deleteManifest).not.toHaveBeenCalled()
    }
  )
  it.each([
    ['A0_dns:noop', 'A0_dns_err: diagnostic mentions A0_dns:noop'],
    ['DNS_SMNR:delete', 'DNS_SMNR:delete\nDNS_SMNR_err: denied'],
    ['TRANS_teredo:restore', 'TRANS_teredo:restore\nTRANS_teredo:unknown']
  ])('retains recovery after ambiguous DNS/policy/transition marker %s (AT-03-007)', async (original, replacement) => {
    const deps = { process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: async () => ({ adapters: [adapter()], transitionAdapters: {}, dnsRegistryPolicy: {} }),
      netshRestoreLine: () => '', registryRestoreLine: () => '',
      runPS: async () => 'A0_ipv6:noop\nA0_dns:noop\nDNS_SMNR:delete\nDNS_PARALLEL:delete\nTRANS_teredo:restore\nTRANS_6to4:unknown\nTRANS_isatap:unknown'.replace(original, replacement),
      deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn() }
    const rollback = compile<(reason: string) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    expect(await rollback('test')).toMatchObject({ success: false, rolledBack: false, error: ipcError('internal') })
    expect(deps.deleteManifest).not.toHaveBeenCalled()
  })
  // AT-00-004/008 + AT-03-003c: execute rollback and its DNS retry wrapper together.
  it.each(['partial', 'native', 'cleanup', 'absent', 'success'] as const)('reports %s recovery without losing independently restored adapters', async outcome => {
    const raw = 'FAKE-SECRET at C:\\private\\credentials.json\n at unsafe (C:\\private\\app.js:1:2)'
    const deps = {
      process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: vi.fn(async () => outcome === 'absent' ? null : { adapters: [adapter(), { ...adapter(), alias: 'Ethernet' }], dnsRegistryPolicy: {} }),
      registryRestoreLine: vi.fn(() => ''), clearPhysicalAdaptersSnapshotCache: vi.fn(),
      deleteManifest: vi.fn(async () => { if (outcome === 'cleanup') throw Object.assign(new Error(raw), { code: 'EACCES' }) }),
      runPS: vi.fn(async () => {
        if (outcome === 'native') throw Object.assign(new Error(raw), { code: 'elevated-helper-timeout' })
        return `A0_ipv6:${outcome === 'partial' ? 'error' : 'noop'}\nA0_dns:noop\nA1_ipv6:noop\nA1_dns:noop\nDNS_SMNR:delete\nDNS_PARALLEL:delete`
      })
    }
    const rollback = compile<(reason: string, options?: unknown) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    const repair = compile<(reason: string) => Promise<any>>('repairOrphanedPhysicalAdapterDns', { ...deps, rollbackPhysicalAdapterLockdownIfApplied: rollback })
    const result = await rollback('test')
    const dns = await repair('retry')
    expect(result.success).toBe(outcome === 'absent' || outcome === 'success')
    expect(dns.success).toBe(result.success)
    expect(dns.repaired).toBe(outcome === 'success')
    expect(dns.adapters).toEqual(outcome === 'partial' ? ['Ethernet'] : ['success', 'cleanup'].includes(outcome) ? ['Wi-Fi', 'Ethernet'] : [])
    expect(JSON.stringify([result, dns])).not.toMatch(/FAKE-SECRET|private| at /)
    if (outcome === 'native') {
      expect(result.error).toEqual(ipcError('timeout'))
      expect(result).not.toHaveProperty('restoredAdapters')
      expect(result.message).not.toContain('из 2')
    } else if (outcome === 'partial' || outcome === 'cleanup') {
      expect(result.error).toEqual(ipcError(outcome === 'partial' ? 'internal' : 'permission'))
      expect(result.warnings.length).toBeGreaterThan(0)
      expect(dns.error).toEqual(result.error)
      expect(result.message).toContain(outcome === 'partial' ? '1 из 2' : '2 из 2')
      expect(dns.message).toBe(result.message)
    } else if (outcome === 'absent') {
      expect(result).toMatchObject({ rolledBack: false, skipped: true })
      expect(dns).toMatchObject({ repaired: false, skipped: true })
      expect(deps.runPS).not.toHaveBeenCalled()
    }
    expect(deps.deleteManifest).toHaveBeenCalledTimes(outcome === 'cleanup' || outcome === 'success' ? 2 : 0)
  })
  it.each([
    ['permission', { code: 'EPERM' }], ['timeout', { code: null, killed: true, signal: 'SIGTERM' }],
    ['internal', { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true, signal: 'SIGTERM' }], ['internal', { code: 'elevated-helper-exited' }]
  ] as const)('keeps manifest and classifies native %s receipt %j', async (category, receipt) => {
    const deps = { process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: async () => ({ adapters: [adapter()], dnsRegistryPolicy: {} }), registryRestoreLine: () => '',
      runPS: vi.fn(async () => { throw Object.assign(new Error('C:\\private\\secret'), receipt) }),
      deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn() }
    const rollback = compile<(reason: string) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    const result = await rollback('test')
    expect(result).toMatchObject({ success: false, rolledBack: false, error: ipcError(category) })
    expect(result).not.toHaveProperty('skipped')
    expect(result).not.toHaveProperty('restoredAdapters')
    expect(deps.deleteManifest).not.toHaveBeenCalled()
    expect(deps.runPS).toHaveBeenCalledOnce()
    expect(JSON.stringify(result)).not.toContain('private')
  })
  it.each(['adapter', 'duplicate', 'transition', 'policy', 'empty'] as const)('recovers valid neighbors of a bad %s record (AT-03-003c)', async failure => {
    const valid = { ...adapter(), ipv4DnsSource: 'static', forcedIpv6Off: true, ipv6Enabled: true }
    const disk: any = { schemaVersion: 1, owner: 'VPNTE', appliedAt: Date.now(), tunDnsIpv4: '192.168.250.254',
      adapters: [valid, { ...valid, interfaceGuid: '22222222-2222-2222-2222-222222222222', alias: 'Ethernet' }],
      transitionAdapters: { teredoType: 'client', sixToFourState: null, isatapState: null },
      dnsRegistryPolicy: { smartNameResolution: { exists: false }, parallelAandAAAA: { exists: false } } }
    if (failure === 'adapter') disk.adapters[0].interfaceGuid = "';invalid"
    if (failure === 'duplicate') disk.adapters.push({ ...valid, interfaceGuid: `{${valid.interfaceGuid!.toUpperCase()}}` })
    if (failure === 'transition') disk.transitionAdapters.teredoType = 'invalid'
    if (failure === 'policy') disk.dnsRegistryPolicy.smartNameResolution = { exists: true, type: 'REG_DWORD', data: 'overflow' }
    if (failure === 'empty') disk.adapters = []
    const validate = compile<(value: unknown, rejected?: string[]) => any>('validateLockdownManifest', { isIP })
    const deps = {
      process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: vi.fn(async (rejected?: string[]) => validate(disk, rejected)),
      netshRestoreLine: compile('netshRestoreLine', { netshState: compile('netshState', {}) }),
      registryRestoreLine: compile('registryRestoreLine', { psSingleQuote: quote }),
      deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn(),
      runPS: vi.fn(async (_script: string) => 'A0_ipv6:on\nA0_dns:noop\nA1_ipv6:on\nA1_dns:noop\nTRANS_teredo:restore\nTRANS_6to4:unknown\nTRANS_isatap:unknown\nDNS_SMNR:delete\nDNS_PARALLEL:delete')
    }
    const rollback = compile<(reason: string, options: { operationId: string }) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    const result = await rollback('partial recovery', { operationId: 'stop_fixture' })
    expect(result).toMatchObject({ rolledBack: false, warnings: expect.any(Array) })
    expect(result.warnings.length).toBeGreaterThan(0)
    expect(result.message).toContain('Часть записей отката пропущена')
    expect(result.message).not.toMatch(/\d+ из \d+/)
    expect(deps.deleteManifest).not.toHaveBeenCalled()
    expect(() => validate(disk)).toThrow()
    expect(deps.runPS).toHaveBeenCalledOnce()
    const script = deps.runPS.mock.calls[0][0] as string
    expect(script).not.toContain('invalid')
    expect(script).not.toContain('overflow')
    if (failure === 'empty') {
      expect(script).not.toMatch(/Get-NetAdapter|Set-DnsClientServerAddress|Enable-NetAdapterBinding/)
      expect(script).toContain('netsh interface teredo set state type=')
      expect(script).toContain('DisableSmartNameResolution')
      expect(script).toContain('DisableParallelAandAAAA')
    } else expect(script).toContain('22222222-2222-2222-2222-222222222222')
    if (failure === 'duplicate') expect(script).not.toContain(valid.interfaceGuid)
    if (failure === 'policy') {
      expect(script).not.toMatch(/(?:SetValue|DeleteValue)\('DisableSmartNameResolution'/)
      expect(script).toContain('DisableParallelAandAAAA')
    }
    expect(deps.logEvent).toHaveBeenCalledWith('error', 'phys-lockdown', 'adapter rollback step rejected', expect.objectContaining({ operationId: 'stop_fixture', success: false }))
  })
  it.each(['success', 'adapter', 'policy', 'native'])('retains Stop ID and independent outcomes: %s', async failing => {
    const operationId = '00000000-0000-4000-8000-000000000007'
    const deps = {
      process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: vi.fn(async () => ({ adapters: [adapter(), { ...adapter(), alias: 'Ethernet' }], dnsRegistryPolicy: {} })),
      registryRestoreLine: vi.fn(() => ''), deleteManifest: vi.fn(), clearPhysicalAdaptersSnapshotCache: vi.fn(),
      runPS: vi.fn(async () => {
        if (failing === 'native') throw new Error('helper failed')
        return `A0_ipv6:${failing === 'adapter' ? 'error' : 'noop'}\nA0_dns:noop\nA1_ipv6:noop\nA1_dns:noop\nDNS_SMNR:${failing === 'policy' ? 'error' : 'delete'}\nDNS_PARALLEL:delete`
      })
    }
    const rollback = compile<(reason: string, options: { operationId: string }) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    expect((await rollback('TUN stopped', { operationId })).rolledBack).toBe(failing === 'success')
    expect(deps.logEvent.mock.calls.length).toBeGreaterThan(0)
    for (const event of deps.logEvent.mock.calls) expect(event[3]).toMatchObject({ operationId })
    expect(deps.deleteManifest).toHaveBeenCalledTimes(failing === 'success' ? 1 : 0)
    if (failing !== 'native') {
      expect(deps.logEvent).toHaveBeenCalledWith('info', 'phys-lockdown', 'rolled back Ethernet', expect.objectContaining({ operationId, ipv6Ok: true, dnsOk: true }))
      expect(deps.logEvent).toHaveBeenCalledWith(failing === 'policy' ? 'warn' : 'info', 'phys-lockdown', failing === 'policy' ? 'partial DNS registry policy rollback' : 'DNS registry policy restored', expect.objectContaining({ operationId, dnsSmnrOk: failing !== 'policy', dnsParallelOk: true }))
    }
  })
  it('preserves Stop ID when DNS safety repair retries the trusted adapter rollback', async () => {
    const operationId = '00000000-0000-4000-8000-000000000007'
    const deps = { process: { platform: 'win32' }, readManifest: async () => ({ adapters: [adapter()] }),
      rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async () => ({ success: true, rolledBack: true, restoredAdapters: ['Wi-Fi'] })) }
    const repair = compile<(reason: string, id: string) => Promise<any>>('repairOrphanedPhysicalAdapterDns', deps)
    expect(await repair('safety repair', operationId)).toEqual({ success: true, repaired: true, adapters: ['Wi-Fi'] })
    expect(deps.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledWith('safety repair', { operationId })
  })
  it('retains the trusted manifest until its diagnostic copy is deleted, so cleanup can be retried (AT-00-004/AT-03-007)', async () => {
    let trusted = true, failDiagnostic = true
    const effects: string[] = []
    const deleteManifest = compile<() => Promise<void>>('deleteManifest', {
      MANIFEST_BASENAME: 'fixture', manifestPath: () => 'diagnostic-only',
      unlink: async () => { effects.push('diagnostic'); if (failDiagnostic) throw Object.assign(new Error('diagnostic locked'), { code: 'EACCES' }) },
      removeRecoveryManifest: async () => { effects.push('trusted'); trusted = false }
    })
    const deps = { process: { platform: 'win32' }, logEvent: vi.fn(), psSingleQuote: quote,
      readManifest: async () => trusted ? { adapters: [adapter()], dnsRegistryPolicy: {} } : null,
      registryRestoreLine: () => '', runPS: async () => 'A0_ipv6:noop\nA0_dns:noop\nDNS_SMNR:delete\nDNS_PARALLEL:delete',
      deleteManifest, clearPhysicalAdaptersSnapshotCache: vi.fn() }
    const rollback = compile<(reason: string) => Promise<any>>('rollbackPhysicalAdapterLockdownIfApplied', deps)
    expect(await rollback('test')).toMatchObject({ success: false, error: ipcError('permission'), restoredAdapters: ['Wi-Fi'] })
    expect(trusted).toBe(true)
    expect(effects).toEqual(['diagnostic'])
    failDiagnostic = false
    expect(await rollback('retry')).toMatchObject({ success: true, rolledBack: true })
    expect(trusted).toBe(false)
    expect(effects).toEqual(['diagnostic', 'diagnostic', 'trusted'])
    expect(await rollback('empty')).toMatchObject({ success: true, skipped: true })
  })
})

// AT-03-006/007: the snapshot that feeds the rollback manifest must not come from the warm-up cache.
describe('physical adapter apply snapshot freshness', () => {
  it('does not pre-warm an adapter snapshot at startup that connect would ignore anyway', () => {
    const indexSource = readFileSync(join(process.cwd(), 'src/main/index.ts'), 'utf8')
    expect(indexSource).not.toMatch(/warmPhysicalAdaptersSnapshot|snapshotPhysicalAdapters\(/)
    expect(source).not.toMatch(/function warmPhysicalAdaptersSnapshot/)
  })

  it('requests a fresh adapter snapshot by default', async () => {
    const h = harness()
    await h.apply('192.168.250.254')
    expect(h.snapshotPhysicalAdapters).toHaveBeenCalledWith({ forceFresh: true })
  })

  it('uses the cache only when the caller explicitly opts out', async () => {
    const h = harness()
    await h.apply('192.168.250.254', { forceFresh: false } as any)
    expect(h.snapshotPhysicalAdapters).toHaveBeenCalledWith({ forceFresh: false })
  })
})

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
  it.each(['added', 'removed', 'replaced', 'unknown'])('rolls back instead of claiming coverage when adapter set is %s during apply (AT-03-006)', async change => {
    const h = harness()
    h.snapshotPhysicalAdapters.mockResolvedValueOnce([adapter()])
    if (change === 'unknown') h.snapshotPhysicalAdapters.mockRejectedValueOnce(new Error('adapter query failed'))
    else h.snapshotPhysicalAdapters.mockResolvedValueOnce(change === 'removed' ? [] : change === 'added'
      ? [adapter(), { ...adapter(), interfaceGuid: '22222222-2222-2222-2222-222222222222' }]
      : [{ ...adapter(), interfaceGuid: '22222222-2222-2222-2222-222222222222' }])
    const result = await h.apply('192.168.250.254', { forceDns: false })
    expect(result).toMatchObject({ applied: false, warnings: [expect.stringContaining('adapter')] })
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledOnce()
    expect(h.writeManifest).toHaveBeenCalledOnce()
    expect(h.snapshotPhysicalAdapters).toHaveBeenCalledTimes(2)
  })
  it('retains recovery ownership when hot-plug compensation fails (AT-03-006/007)', async () => {
    const h = harness()
    h.snapshotPhysicalAdapters.mockResolvedValueOnce([adapter()]).mockResolvedValueOnce([])
    h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValue({ rolledBack: false })
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: expect.arrayContaining([expect.stringContaining('rollback')]) })
    expect(h.writeManifest).toHaveBeenCalledOnce()
  })
  it('accepts a rename only for the same GUID set (AT-03-006)', async () => {
    const h = harness()
    h.snapshotPhysicalAdapters.mockResolvedValueOnce([adapter()]).mockResolvedValueOnce([{ ...adapter(), alias: 'Renamed Wi-Fi' }])
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: [] })
    expect(h.snapshotPhysicalAdapters).toHaveBeenCalledTimes(2)
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).not.toHaveBeenCalled()
    expect(h.snapshotPhysicalAdapters).toHaveBeenLastCalledWith({ forceFresh: true, retainedGuids: [adapter().interfaceGuid] })
  })
  it('verifies an existing journal against fresh adapters before idempotent success (AT-03-006)', async () => {
    const h = harness()
    h.readManifest.mockResolvedValue({ tunDnsIpv4: '192.168.250.254', forceDns: false, adapters: [adapter()] })
    h.snapshotPhysicalAdapters.mockResolvedValue([])
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: false, warnings: [expect.stringContaining('adapter')] })
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledOnce()
    expect(h.runPS).not.toHaveBeenCalled()
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
  it('calls native only after the durable journal and never replays its adapter mutations', async () => {
    const h = harness()
    h.runPS.mockResolvedValue(policyProof)
    h.applyNativeAdapterLockdown.mockImplementation(async () => {
      expect(h.writeManifest).toHaveBeenCalledOnce()
      expect(h.runPS).not.toHaveBeenCalled()
      return 'A0_ipv6:off\nA0_dns:skip\n'
    })
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: [] })
    const script = h.runPS.mock.calls[0][0]
    expect(script).toContain('VPNTE_AUXILIARY_LOCKDOWN')
    expect(script).not.toMatch(/Disable-NetAdapterBinding|Set-DnsClientServerAddress|\$ownedAdapter/)
    expect(h.writeManifest).toHaveBeenCalledTimes(2)
  })
  it('retains pending recovery after native failure while still running independent global policy', async () => {
    const h = harness()
    h.runPS.mockResolvedValue(policyProof)
    h.applyNativeAdapterLockdown.mockResolvedValue('A0_ipv6_err: native code=1\nA0_dns_err: native code=1\n')
    expect(await h.apply('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: [expect.stringContaining('native code=1')] })
    expect(h.runPS.mock.calls[0][0]).not.toContain('Disable-NetAdapterBinding')
    expect(h.writeManifest).toHaveBeenCalledOnce()
  })
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
