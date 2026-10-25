// AT-02-002 / AT-02-004 / AT-02-005: execute cold-start preparation with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { EventEmitter } from 'node:events'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const source = readFileSync('src/main/tunController.ts', 'utf8')
const ast = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
let validation = ''
function visit(node: ts.Node) {
  if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'validateRuntime') validation = node.getText(ast)
  ts.forEachChild(node, visit)
}
visit(ast)
const begin = source.indexOf('const slots = await allocateXraySwitchSlots()')
const end = source.indexOf('startAbortController.signal.throwIfAborted()', begin) + 'startAbortController.signal.throwIfAborted()'.length
const joinBegin = source.indexOf('runtime = await runtimePromise', end)
const joinEnd = source.indexOf('} catch (err: any)', joinBegin)
if (!validation || begin < 0 || joinBegin < 0 || joinEnd < 0) throw new Error('Production cold-start validation not found')
function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function harness() {
  const preparation = held<{ singbox: string; config: string }>(), check = held<unknown>(), probe = held<string>()
  const owner = new AbortController(), ready = vi.fn(), child = new EventEmitter()
  const deps = {
    preparation, check, probe, owner, ready, child,
    allocateXraySwitchSlots: async () => ({ a: { port: 51001, username: 'test', password: 'test' } }),
    startXray: async () => ({ socksPort: 51001, resolvedIp: '192.0.2.1', exePath: 'fixture-xray.exe' }),
    prepareRuntime: vi.fn(() => preparation.promise), execFile: vi.fn(() => Object.assign(check.promise, { child })),
    probeSocksUpstream: vi.fn(() => probe.promise), outboundConfigurationKey: () => 'fixture',
    uniqueProcessNames: (names: string[]) => names
  }
  const body = `
    const startAbortController=owner, startupCleanupTasks=[];
    const vpnProfile={outbound:{},clientDevice:'pc'}, startOptions={}, mode='directVpn', proxyType='socks5';
    const splitTunnelDirectPaths=[], publicWifiCompatibility=true, smartRuSplit=false,smartRuMapsDirect=false,dnsSourcesPromise=Promise.resolve([]);
    let runtimePromise=null,runtimeCheckPromise=null,preparedXraySwitch=null,xraySocksPort,resolvedVpnEndpointIp;
    let proxyOwnerProgramPaths=[],proxyOwnerProcessNames=[];
    const timeAsync=(_phase,work)=>work(),timePromise=(_phase,pending)=>pending;
    const ${validation};
    return {run:async()=>{try{${source.slice(begin, end)}
      const cleanupPromise=Promise.resolve();let runtime;
      ${source.slice(joinBegin, joinEnd)}
      ready();
    }finally{await Promise.all(startupCleanupTasks)}},tasks:startupCleanupTasks};`
  const js = ts.transpileModule(body, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  return { ...deps, ...new Function(...Object.keys(deps), js)(...Object.values(deps)) }
}
describe('owned cold-start config validation', () => {
  it('checks the prepared config during HTTPS readiness and joins both before TUN admission', async () => {
    const h = harness(), running = h.run()
    await vi.waitFor(() => expect(h.probeSocksUpstream).toHaveBeenCalledOnce())
    expect(h.execFile).not.toHaveBeenCalled()
    h.preparation.resolve({ singbox: 'fixture.exe', config: 'fixture.json' })
    await vi.waitFor(() => expect(h.execFile).toHaveBeenCalledOnce())
    expect(h.execFile).toHaveBeenCalledWith('fixture.exe', ['check', '-c', 'fixture.json'], expect.objectContaining({ windowsHide: true, timeout: 10000, signal: h.owner.signal }))
    h.check.resolve({ stdout: '' })
    h.child.emit('close')
    await Promise.all(h.tasks)
    expect(h.ready).not.toHaveBeenCalled()
    h.probe.resolve('192.0.2.2'); await running
    expect(h.ready).toHaveBeenCalledOnce()
    expect(h.execFile).toHaveBeenCalledOnce()
  })
  it('refuses TUN admission when parallel config validation fails despite a successful HTTPS probe', async () => {
    const h = harness(), rejected = expect(h.run()).rejects.toThrow('invalid configuration')
    h.preparation.resolve({ singbox: 'fixture.exe', config: 'fixture.json' })
    await vi.waitFor(() => expect(h.execFile).toHaveBeenCalledOnce())
    h.check.reject(new Error('invalid configuration'))
    h.child.emit('close')
    h.probe.resolve('192.0.2.2'); await rejected
    expect(h.ready).not.toHaveBeenCalled()
  })
  it('retains the cancelled owner until the config-check process has settled', async () => {
    const h = harness()
    let settled = false
    const rejected = expect(h.run().finally(() => { settled = true })).rejects.toThrow('cancelled')
    h.preparation.resolve({ singbox: 'fixture.exe', config: 'fixture.json' })
    await vi.waitFor(() => expect(h.execFile).toHaveBeenCalledOnce())
    h.owner.abort(); h.probe.reject(new Error('cancelled'))
    h.check.reject(new Error('config-check aborted'))
    await Promise.resolve(); await Promise.resolve()
    expect(settled).toBe(false)
    h.child.emit('close'); await rejected
    expect(h.ready).not.toHaveBeenCalled()
  })
})
