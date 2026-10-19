// AT-00-003: execute the actual endpoint probe with controlled OS/DNS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

function production<T>(name: string, dependencies: Record<string, unknown>): T {
  const source = ts.createSourceFile('serverPicker.ts', readFileSync(join(process.cwd(), 'src/main/serverPicker.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
  const fn = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)
  if (!fn) throw new Error(`Missing production probe ${name}`)
  const text = fn.getText(source).replace(/^export /, '')
  const js = ts.transpileModule(text + `\nreturn ${name};`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  return new Function(...Object.keys(dependencies), js)(...Object.values(dependencies))
}
function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}
function harness() {
  const deps = {
    physicalSourceTcpPing: vi.fn(async (): Promise<number | null> => null), physicalSourcePing: vi.fn(async (): Promise<number | null> => null),
    reliableTcpPing: vi.fn(async (): Promise<number | null> => null), reliableSocksTcpPing: vi.fn(async () => null),
    stealthTcpProbe: vi.fn(async (): Promise<number | null> => null), icmpPing: vi.fn(async () => 10),
    isPlausibleRemoteLatency: (n: number | null) => n !== null && n > 3,
    TCP_PROBE_TIMEOUT_MS: 100, TCP_PROBE_ATTEMPTS: 3, ICMP_PROBE_TIMEOUT_MS: 100
  }
  const probe = production<(host: string, port: number, running: boolean, proxy: number | null, signal: AbortSignal) => Promise<number | null>>('smartEndpointPing', deps)
  const abort = new AbortController()
  return { ...deps, run: () => probe('probe.example.test', 443, false, null, abort.signal), abort }
}

describe('rotation endpoint probe ownership', () => {
  it('does not release the physical ICMP sibling when TCP finishes first, including cancellation', async () => {
    const h = harness(), icmp = held<number | null>(), finished = vi.fn()
    h.physicalSourceTcpPing.mockResolvedValue(10); h.physicalSourcePing.mockReturnValue(icmp.promise)
    const pending = h.run().then(finished)
    await Promise.resolve(); await Promise.resolve()
    expect(finished).not.toHaveBeenCalled()
    h.abort.abort(); icmp.resolve(null); await pending
    expect(finished).toHaveBeenCalledWith(null)
    expect(h.reliableTcpPing).not.toHaveBeenCalled(); expect(h.stealthTcpProbe).not.toHaveBeenCalled()
  })
  it.each(['physicalSourceTcpPing', 'reliableTcpPing', 'stealthTcpProbe'] as const)('does not start another fallback after abort during %s', async phase => {
    const h = harness(), gate = held<number | null>()
    h[phase].mockReturnValue(gate.promise)
    const pending = h.run()
    await vi.waitFor(() => expect(h[phase]).toHaveBeenCalledOnce())
    h.abort.abort(); gate.resolve(null)
    expect(await pending).toBeNull()
    expect(h.icmpPing).not.toHaveBeenCalled()
    if (phase !== 'stealthTcpProbe') expect(h.stealthTcpProbe).not.toHaveBeenCalled()
    if (phase === 'physicalSourceTcpPing') expect(h.reliableTcpPing).not.toHaveBeenCalled()
  })
  it.each(['physicalSourcePing', 'physicalSourceTcpPing'] as const)('stops %s before iterating another physical interface', async name => {
    const abort = new AbortController(), gate = held<number | null>()
    const native = vi.fn(() => gate.promise)
    const probe = production<(...args: any[]) => Promise<number | null>>(name, {
      process: { platform: 'win32' }, isProbablyHostOrIp: () => true, ICMP_PROBE_TIMEOUT_MS: 100,
      getPhysicalIpv4Sources: async () => [{ ipv4: '192.0.2.1' }, { ipv4: '192.0.2.2' }],
      reliableTcpPing: native, pingFromSource: native, isPlausibleRemoteLatency: () => false
    })
    const pending = name === 'physicalSourcePing' ? probe('probe.example.test', abort.signal) : probe('probe.example.test', 443, abort.signal)
    await vi.waitFor(() => expect(native).toHaveBeenCalledOnce())
    abort.abort(); gate.resolve(null)
    expect(await pending).toBeNull(); expect(native).toHaveBeenCalledOnce()
  })
  it.each(['resolve', 'reject'] as const)('does not launch curl or secondary DNS after cancelled DNS %s', async outcome => {
    const abort = new AbortController(), dnsResult = held<string[]>(), lookup = vi.fn(), execFile = vi.fn()
    const probe = production<(host: string, port: number, signal: AbortSignal) => Promise<number | null>>('stealthTcpProbe', {
      process: { platform: 'win32' }, dns: { resolve4: () => dnsResult.promise, lookup }, execFile
    })
    const pending = probe('probe.example.test', 443, abort.signal)
    abort.abort()
    if (outcome === 'reject') dnsResult.reject(new Error('resolver failed'))
    else dnsResult.resolve(['192.0.2.10'])
    expect(await pending).toBeNull()
    expect(lookup).not.toHaveBeenCalled(); expect(execFile).not.toHaveBeenCalled()
  })
})
