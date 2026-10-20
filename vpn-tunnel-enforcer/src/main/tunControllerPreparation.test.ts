// AT-02-002/004/005, AT-03-006: execute production preparation with fake OS boundaries.
// These L2 races verify ordering; they do not prove native Windows latency or egress.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { connectionFailure } from '../shared/operation'
import { classifyIpcError } from '../shared/ipc-result'
import { RecoveryWorkerError } from './recoveryPsWorker'

const source = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
const begin = source.indexOf('let runtimePromise: Promise<')
const end = source.indexOf('// Kill only VPNTE-owned runtime binaries.', begin)
if (begin < 0 || end < 0) throw new Error('Production preparation boundary not found')
const preparation = source.slice(begin, end)
const ast = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
const classifier = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'classifyTunError')!

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

function harness(dns: Promise<unknown[]>, mode = 'directVpn', engine = 'xray', adapterLockdownPromise = Promise.resolve()) {
  const os = {
    dns, mode, engine, connectionFailure, classifyIpcError, RecoveryWorkerError,
    adapterLockdownPromise,
    startXray: vi.fn(async () => ({ socksPort: 1234, resolvedIp: '198.51.100.1', exePath: 'fixture-xray.exe' })),
    stopXray: vi.fn(async () => {}),
    rollbackEarlyAdapterLockdown: vi.fn(async () => {}),
    prepareRuntime: vi.fn(async (...args: any[]) => {
      args[3].signal?.throwIfAborted()
      await args[3].xrayStartup
      return { singbox: 'fixture.exe', config: 'fixture.json' }
    }),
    logEvent: vi.fn(), mark: vi.fn(),
    phaseStart: () => 0, endPhase: vi.fn(),
    resolveProxyEngine: () => engine,
    uniqueProcessNames: (items: string[]) => [...new Set(items)],
    timeAsync: async (_name: string, effect: () => Promise<unknown>) => effect(),
    timePromise: (_name: string, promise: Promise<unknown>) => promise,
    finishStart: (result: unknown) => result,
    parseProxyAddress: vi.fn(() => ({ host: '127.0.0.1', port: 10808 })),
    getProxyOwnerProcesses: vi.fn(async () => []),
    probeTcp: vi.fn(async () => true),
    validateProxyFullTunnel: vi.fn(async (): Promise<any> => ({ ok: true }))
  }
  const compiled = ts.transpileModule(`
    ${classifier.getText(ast)}
    const dnsSourcesPromise=dns, smartRuSplit=true, smartRuMapsDirect=false;
    let proxyOwnerProcessNames=[], proxyOwnerProgramPaths=[], stopRequested=false;
    const startAbortController=new AbortController();
    const proxyAddr='127.0.0.1:10808', proxyType='socks5', wantKillSwitch=true;
    const startOptions={}, publicWifiCompatibility=true, splitTunnelDirectNames=[], splitTunnelDirectPaths=[];
    const vpnProfile={outbound:{type:'vless'},clientDevice:'pc',name:'fixture'};
    const startupCleanupTasks=[];
    async function run(){ try { ${preparation}
      return runtimePromise ? await runtimePromise : null;
      } finally {await Promise.allSettled(startupCleanupTasks)}
    }
    return {run,cancel:()=>{stopRequested=true;startAbortController.abort()}};
  `, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const control = new Function(...Object.keys(os), compiled)(...Object.values(os)) as {
    run: () => Promise<any>; cancel: () => void
  }
  return { ...os, ...control }
}

function runtimeHarness() {
  const runtimeBegin = source.indexOf('async function prepareRuntime(')
  const runtimeEnd = source.indexOf('\n}', runtimeBegin) + 2
  const os = {
    getTunRuntimeDir: () => 'fixture-runtime', join,
    ensureElevatedRuntimeDirHardened: vi.fn(async () => ({ hardened: true, message: '' })),
    getBundledResource: (name: string) => name,
    RUNTIME_EXE_NAME: 'vpnte-sing-box.exe', CRONET_DLL_NAME: 'libcronet.dll',
    pickFreeLocalPort: vi.fn(async () => 12345),
    stat: vi.fn(async () => ({})), rename: vi.fn(async () => {}), access: vi.fn(async () => {}),
    copyResourceIfStale: vi.fn(async () => false),
    updateTunAdapterAlias: vi.fn(), logEvent: vi.fn(),
    generateSingboxConfig: vi.fn((..._args: any[]) => ({ fixture: true })),
    writeFile: vi.fn(async () => {})
  }
  const compiled = ts.transpileModule(source.slice(runtimeBegin, runtimeEnd) + '\nreturn prepareRuntime;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const run = new Function(...Object.keys(os), compiled)(...Object.values(os)) as (...args: any[]) => Promise<unknown>
  return { ...os, run }
}

afterEach(() => vi.useRealTimers())

describe('parallel runtime staging safety (AT-01-009 / AT-02-002/005)', () => {
  it('preserves explicit runtime options without an Xray startup join', async () => {
    const h = runtimeHarness()
    await h.run('127.0.0.1:10808', 'socks5', [], { xraySocksPort: 54321, resolvedVpnEndpointIp: '198.51.100.12' })
    expect(h.generateSingboxConfig.mock.calls[0][3]).toMatchObject({ xraySocksPort: 54321, resolvedVpnEndpointIp: '198.51.100.12' })
    expect(h.writeFile).toHaveBeenCalledOnce()
  })
  it('stages verified artifacts before Xray readiness but writes config with its actual result only', async () => {
    const xray = deferred<{ socksPort: number; resolvedIp: string | null }>()
    const h = runtimeHarness()
    const pending = h.run({ outbound: { type: 'vless' } }, 'socks5', ['vpnte-xray.exe'], { xrayStartup: xray.promise })
    await vi.waitFor(() => expect(h.copyResourceIfStale).toHaveBeenCalledTimes(3))
    expect(h.generateSingboxConfig).not.toHaveBeenCalled()
    expect(h.writeFile).not.toHaveBeenCalled()
    xray.resolve({ socksPort: 54321, resolvedIp: '198.51.100.10' })
    await pending
    expect(h.generateSingboxConfig.mock.calls[0][3]).toMatchObject({ xraySocksPort: 54321, resolvedVpnEndpointIp: '198.51.100.10' })
    expect(h.generateSingboxConfig.mock.calls[0][3]).not.toHaveProperty('xrayStartup')
    expect(h.writeFile).toHaveBeenCalledOnce()
  })
  it('refuses staging when the fresh ACL proof fails', async () => {
    const h = runtimeHarness()
    h.ensureElevatedRuntimeDirHardened.mockResolvedValue({ hardened: false, message: 'unsafe namespace' })
    await expect(h.run({ outbound: {} }, 'socks5', [], {})).rejects.toThrow('unsafe namespace')
    expect(h.copyResourceIfStale).not.toHaveBeenCalled()
    expect(h.writeFile).not.toHaveBeenCalled()
  })
  it.each(['cancelled', 'failed'])('does not write a config when Xray startup is %s', async outcome => {
    const xray = deferred<{ socksPort: number; resolvedIp: string | null }>()
    const controller = new AbortController()
    const h = runtimeHarness()
    const pending = h.run({ outbound: {} }, 'socks5', [], { xrayStartup: xray.promise, signal: controller.signal })
    const rejected = expect(pending).rejects.toThrow()
    await vi.waitFor(() => expect(h.copyResourceIfStale).toHaveBeenCalledTimes(3))
    if (outcome === 'cancelled') {
      controller.abort()
      xray.resolve({ socksPort: 54321, resolvedIp: null })
    } else {
      // The production join consumes an Xray rejection before any config write.
      xray.reject(new Error('Xray startup failed'))
    }
    await rejected
    expect(h.generateSingboxConfig).not.toHaveBeenCalled()
    expect(h.writeFile).not.toHaveBeenCalled()
  })
  it('does not copy artifacts after cancellation during the ACL inspection', async () => {
    const proof = deferred<{ hardened: boolean; message: string }>()
    const controller = new AbortController()
    const h = runtimeHarness()
    h.ensureElevatedRuntimeDirHardened.mockImplementation(async () => proof.promise)
    const pending = h.run({ outbound: {} }, 'socks5', [], { signal: controller.signal })
    const rejected = expect(pending).rejects.toThrow()
    controller.abort(); proof.resolve({ hardened: true, message: '' })
    await rejected
    expect(h.copyResourceIfStale).not.toHaveBeenCalled()
    expect(h.writeFile).not.toHaveBeenCalled()
  })
})

describe('Direct VPN preparation overlap', () => {
  it('stages sing-box while Xray is starting and joins their simulated costs (AT-02-002)', async () => {
    vi.useFakeTimers()
    const h = harness(Promise.resolve([]))
    h.startXray.mockImplementation(async () => {
      await new Promise(done => setTimeout(done, 1500))
      return { socksPort: 4321, resolvedIp: '198.51.100.2', exePath: 'fixture-xray.exe' }
    })
    h.prepareRuntime.mockImplementation(async (...args: any[]) => {
      await new Promise(done => setTimeout(done, 700))
      await args[3].xrayStartup
      return { singbox: 'fixture.exe', config: 'fixture.json' }
    })
    const completed = vi.fn()
    const pending = h.run().then(completed)
    await vi.advanceTimersByTimeAsync(0)
    expect(h.prepareRuntime).toHaveBeenCalledOnce()
    expect(h.prepareRuntime.mock.calls[0][2]).toContain('vpnte-xray.exe')
    await vi.advanceTimersByTimeAsync(1499)
    expect(completed).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    await pending
    expect(completed).toHaveBeenCalledOnce() // 1500 ms, rather than 1500 + 700.
  })

  it('retains the start owner until staging settles after cancellation (AT-02-005)', async () => {
    const xray = deferred<{ socksPort: number; resolvedIp: string; exePath: string }>()
    const staging = deferred<void>()
    const h = harness(Promise.resolve([]))
    h.startXray.mockImplementation(async () => xray.promise)
    h.prepareRuntime.mockImplementation(async () => {
      await staging.promise
      throw new Error('staging refused')
    })
    const completed = vi.fn()
    const pending = h.run().then(result => { completed(); return result })
    await vi.waitFor(() => expect(h.prepareRuntime).toHaveBeenCalledOnce())
    h.cancel()
    xray.resolve({ socksPort: 1234, resolvedIp: '198.51.100.1', exePath: 'fixture-xray.exe' })
    await vi.waitFor(() => expect(h.stopXray).toHaveBeenCalledOnce())
    expect(completed).not.toHaveBeenCalled()
    staging.resolve()
    expect(await pending).toMatchObject({ success: false })
    expect(completed).toHaveBeenCalledOnce()
  })

  it('joins an early staging failure and cleans Xray without an unhandled rejection (AT-02-005)', async () => {
    const xray = deferred<{ socksPort: number; resolvedIp: string; exePath: string }>()
    const h = harness(Promise.resolve([]))
    h.startXray.mockImplementation(async () => xray.promise)
    h.prepareRuntime.mockRejectedValue(new Error('unsafe runtime'))
    const pending = h.run()
    await vi.waitFor(() => expect(h.prepareRuntime).toHaveBeenCalledOnce())
    xray.reject(new Error('Xray refused shared ACL proof'))
    expect(await pending).toMatchObject({ success: false, category: 'internal', error: expect.stringContaining('xray-core') })
    expect(h.logEvent).toHaveBeenCalledWith('error', 'tun', 'xray startup failed', expect.objectContaining({ message: 'Xray refused shared ACL proof' }))
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
  })
  it('starts Xray before DNS sources finish, but passes the complete snapshot to runtime', async () => {
    const dns = deferred<unknown[]>()
    const h = harness(dns.promise)
    const pending = h.run()
    await vi.waitFor(() => expect(h.startXray).toHaveBeenCalledOnce())
    expect(h.prepareRuntime).not.toHaveBeenCalled()
    const sources = [{ interfaceGuid: 'fixture-guid', servers: ['192.0.2.53'] }]
    dns.resolve(sources)
    await pending
    expect(h.prepareRuntime).toHaveBeenCalledOnce()
    expect(h.prepareRuntime.mock.calls[0][3]).toMatchObject({
      smartRuSplit: true, smartRuDirectDnsSources: sources
    })
    expect(await h.prepareRuntime.mock.calls[0][3].xrayStartup).toMatchObject({ socksPort: 1234, resolvedIp: '198.51.100.1' })
    expect(h.stopXray).not.toHaveBeenCalled()
  })

  it('overlaps independent simulated costs instead of summing them', async () => {
    vi.useFakeTimers()
    const dns = new Promise<unknown[]>(done => setTimeout(() => done([]), 2893))
    const h = harness(dns)
    h.startXray.mockImplementation(async () => {
      await new Promise(done => setTimeout(done, 1820))
      return { socksPort: 1234, resolvedIp: '198.51.100.1', exePath: 'fixture-xray.exe' }
    })
    const completed = vi.fn()
    const pending = h.run().then(completed)
    await vi.advanceTimersByTimeAsync(2892)
    expect(completed).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    await pending
    expect(completed).toHaveBeenCalledOnce()
  })

  it('confirms Xray exit before releasing lockdown on cancellation during DNS wait', async () => {
    const dns = deferred<unknown[]>()
    const exit = deferred<void>()
    const h = harness(dns.promise)
    h.stopXray.mockImplementation(async () => exit.promise)
    const pending = h.run()
    await vi.waitFor(() => expect(h.startXray).toHaveBeenCalledOnce())
    h.cancel()
    dns.resolve([])
    await vi.waitFor(() => expect(h.stopXray).toHaveBeenCalledOnce())
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
    expect(h.prepareRuntime).not.toHaveBeenCalled()
    exit.resolve()
    expect(await pending).toMatchObject({ success: false, error: 'Запуск отменён' })
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
  })

  it('retains adapter restrictions when cancelled Xray exit is unconfirmed', async () => {
    const dns = deferred<unknown[]>()
    const h = harness(dns.promise)
    h.stopXray.mockRejectedValue(new Error('exit timeout'))
    const pending = h.run()
    await vi.waitFor(() => expect(h.startXray).toHaveBeenCalledOnce())
    h.cancel()
    dns.resolve([])
    expect(await pending).toMatchObject({ success: false, warning: expect.stringContaining('protection retained') })
    expect(h.prepareRuntime).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
  })

  it('waits for compensating lockdown cleanup when Xray fails before DNS finishes', async () => {
    const dns = deferred<unknown[]>()
    const h = harness(dns.promise)
    h.startXray.mockRejectedValue(new Error('config rejected'))
    h.rollbackEarlyAdapterLockdown.mockImplementation(async () => { await dns.promise })
    const pending = h.run()
    const completed = vi.fn()
    void pending.then(completed)
    await vi.waitFor(() => expect(h.stopXray).toHaveBeenCalledOnce())
    expect(completed).not.toHaveBeenCalled()
    dns.resolve([])
    expect(await pending).toMatchObject({ success: false, category: 'internal', error: expect.stringContaining('xray-core') })
    expect(h.logEvent).toHaveBeenCalledWith('error', 'tun', 'xray startup failed', expect.objectContaining({ message: expect.stringContaining('config rejected') }))
    expect(h.prepareRuntime).toHaveBeenCalledOnce()
  })

  it('retains the start owner and restrictions until native lockdown settles if Xray exit fails', async () => {
    const dns = deferred<unknown[]>()
    const lockdown = deferred<void>()
    const held = harness(dns.promise, 'directVpn', 'xray', lockdown.promise)
    held.startXray.mockRejectedValue(new Error('readiness failed'))
    held.stopXray.mockRejectedValue(new Error('exit timeout'))
    const completed = vi.fn()
    const pending = held.run().then(result => { completed(); return result })
    await vi.waitFor(() => expect(held.stopXray).toHaveBeenCalledOnce())
    expect(completed).not.toHaveBeenCalled()
    expect(held.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
    dns.resolve([])
    lockdown.resolve()
    expect(await pending).toMatchObject({ success: false, warning: expect.stringContaining('protection retained') })
    expect(held.prepareRuntime).toHaveBeenCalledOnce()
  })

  it('keeps the local proxy preflight behind its DNS-source wait', async () => {
    const dns = deferred<unknown[]>()
    const h = harness(dns.promise, 'localProxy')
    const pending = h.run()
    await Promise.resolve()
    expect(h.probeTcp).not.toHaveBeenCalled()
    dns.resolve([])
    await pending
    expect(h.probeTcp).toHaveBeenCalledOnce()
    expect(h.startXray).not.toHaveBeenCalled()
  })
  it.each([
    ['split', 'Global/Proxy'], ['direct', 'напрямую'], ['offline', 'VPN-сервер']
  ] as const)('keeps safe %s proxy remediation in startup failure (AT-00-004)', async (reason, hint) => {
    const h = harness(Promise.resolve([]), 'localProxy')
    const validator = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'validateProxyFullTunnel')!
    let probes = 0
    const deps = { process: { platform: 'win32' }, curlProxyUrl: () => 'socks5://127.0.0.1:10808',
      fetchPublicIpDirect: async () => '203.0.113.1',
      curlText: async () => {
        if (reason === 'offline') throw new Error('FAKE-native-secret at C:\\private\\proxy.txt')
        return reason === 'split' && probes++ > 0 ? '203.0.113.2' : '203.0.113.1'
      }, extractPublicIpv4: (text: string) => text,
      PROXY_PUBLIC_IP_CHECKS: [{ label: 'a', url: 'https://a.invalid' }, { label: 'b', url: 'https://b.invalid' }],
      waitForDirectIpGrace: async (task: Promise<string>) => ({ ready: true, ip: await task }) }
    const js = ts.transpileModule(validator.getText(ast) + ';return validateProxyFullTunnel;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const validate = new Function(...Object.keys(deps), js)(...Object.values(deps))
    h.validateProxyFullTunnel.mockImplementation(validate)
    const result = await h.run()
    expect(result).toMatchObject({ success: false, category: 'network', error: expect.stringContaining(hint) })
    expect(result.error).not.toContain('FAKE-native-secret')
    expect(h.prepareRuntime).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
  })
  it('explains upstream address syntax without returning parse exceptions (AT-00-004)', async () => {
    const h = harness(Promise.resolve([]), 'localProxy')
    h.parseProxyAddress.mockImplementation(() => { throw new Error('FAKE-native-secret at C:\\private\\proxy.txt') })
    const result = await h.run()
    expect(result).toMatchObject({ success: false, category: 'validation', error: expect.stringContaining('host:port') })
    expect(result.error).not.toContain('FAKE-native-secret')
    expect(h.prepareRuntime).not.toHaveBeenCalled()
  })
  it('names runtime preparation failure and keeps diagnostics private (AT-00-004)', async () => {
    let block: ts.CatchClause | undefined
    const visit = (node: ts.Node) => {
      if (ts.isCatchClause(node) && node.block.getText(ast).includes("logEvent('error', 'tun', 'failed to prepare TUN runtime'")) block = node
      ts.forEachChild(node, visit)
    }
    visit(ast)
    if (!block) throw new Error('Runtime preparation catch missing')
    const error = Object.assign(new Error('FAKE-private-path C:\\private\\engine.exe'), { code: 'EACCES' })
    const deps = { error, connectionFailure, classifyIpcError, RecoveryWorkerError, cleanupPromise: Promise.resolve(),
      rollbackEarlyAdapterLockdown: vi.fn(async () => {}), stopXray: vi.fn(async () => {}), logEvent: vi.fn(), finishStart: (result: unknown) => result }
    const js = ts.transpileModule(`${classifier.getText(ast)}; return async () => {try {throw error} ${block.getText(ast)}}`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const result = await new Function(...Object.keys(deps), js)(...Object.values(deps))()
    expect(result).toMatchObject({ success: false, category: 'permission', error: expect.stringContaining('TUN runtime') })
    expect(result.error).toContain('журнал')
    expect(result.error).not.toContain('FAKE-private-path')
    expect(deps.logEvent).toHaveBeenCalledWith('error', 'tun', 'failed to prepare TUN runtime', error)
    expect(deps.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
    expect(deps.stopXray).toHaveBeenCalledOnce()
  })
})
