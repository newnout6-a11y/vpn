// AT-02-002/004/005, AT-03-006: execute production preparation with fake OS boundaries.
// These L2 races verify ordering; they do not prove native Windows latency or egress.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
const begin = source.indexOf('let runtimePromise: Promise<')
const end = source.indexOf('// Kill only VPNTE-owned runtime binaries.', begin)
if (begin < 0 || end < 0) throw new Error('Production preparation boundary not found')
const preparation = source.slice(begin, end)

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

function harness(dns: Promise<unknown[]>, mode = 'directVpn', engine = 'xray', adapterLockdownPromise = Promise.resolve()) {
  const os = {
    dns, mode, engine,
    adapterLockdownPromise,
    startXray: vi.fn(async () => ({ socksPort: 1234, resolvedIp: '198.51.100.1', exePath: 'fixture-xray.exe' })),
    stopXray: vi.fn(async () => {}),
    rollbackEarlyAdapterLockdown: vi.fn(async () => {}),
    prepareRuntime: vi.fn(async (..._args: unknown[]) => ({ singbox: 'fixture.exe', config: 'fixture.json' })),
    logEvent: vi.fn(), mark: vi.fn(),
    phaseStart: () => 0, endPhase: vi.fn(),
    resolveProxyEngine: () => engine,
    uniqueProcessNames: (items: string[]) => [...new Set(items)],
    timeAsync: async (_name: string, effect: () => Promise<unknown>) => effect(),
    timePromise: (_name: string, promise: Promise<unknown>) => promise,
    finishStart: (result: unknown) => result,
    parseProxyAddress: () => ({ host: '127.0.0.1', port: 10808 }),
    getProxyOwnerProcesses: vi.fn(async () => []),
    probeTcp: vi.fn(async () => true),
    validateProxyFullTunnel: vi.fn(async () => ({ ok: true }))
  }
  const compiled = ts.transpileModule(`
    const dnsSourcesPromise=dns, smartRuSplit=true, smartRuMapsDirect=false;
    let proxyOwnerProcessNames=[], proxyOwnerProgramPaths=[], stopRequested=false;
    const startAbortController=new AbortController();
    const proxyAddr='127.0.0.1:10808', proxyType='socks5', wantKillSwitch=true;
    const startOptions={}, publicWifiCompatibility=true, splitTunnelDirectNames=[];
    const vpnProfile={outbound:{type:'vless'},clientDevice:'pc',name:'fixture'};
    async function run(){ ${preparation}
      return runtimePromise ? await runtimePromise : null;
    }
    return {run,cancel:()=>{stopRequested=true;startAbortController.abort()}};
  `, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const control = new Function(...Object.keys(os), compiled)(...Object.values(os)) as {
    run: () => Promise<any>; cancel: () => void
  }
  return { ...os, ...control }
}

afterEach(() => vi.useRealTimers())

describe('Direct VPN preparation overlap', () => {
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
      xraySocksPort: 1234, smartRuSplit: true, smartRuDirectDnsSources: sources
    })
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
    expect(await pending).toMatchObject({ success: false, error: expect.stringContaining('config rejected') })
    expect(h.prepareRuntime).not.toHaveBeenCalled()
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
    expect(held.prepareRuntime).not.toHaveBeenCalled()
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
})
