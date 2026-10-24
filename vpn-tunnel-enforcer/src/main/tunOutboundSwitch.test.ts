// AT-00-003 / AT-00-007 / AT-02-002 / AT-02-011: execute the actual
// TUN-controller method and transition coordinator, with no native processes.
import { readFileSync } from 'node:fs'
import { isIP } from 'node:net'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { runProtectedOutboundSwitch, type OutboundSlot, type OutboundSwitchReceipt } from './protectedOutboundSwitch'

function gate<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

const source = ts.createSourceFile('tunController.ts', readFileSync('src/main/tunController.ts', 'utf8'), ts.ScriptTarget.Latest, true)
const declaration = source.statements.flatMap(node => ts.isVariableStatement(node) ? [...node.declarationList.declarations] : [])
  .find(node => ts.isIdentifier(node.name) && node.name.text === 'tunController')
if (!declaration?.initializer || !ts.isObjectLiteralExpression(declaration.initializer)) throw new Error('TUN controller not found')
const method = declaration.initializer.properties.find(node => ts.isMethodDeclaration(node) && node.name.getText(source) === 'switchOutbound')
if (!method) throw new Error('Production outbound-switch method not found')
const methodText = method.getText(source)

type Evidence = { ip: string | null; vpnIp: string | null; isLeak: boolean }
const fresh = (): Evidence => ({ ip: '198.51.100.42', vpnIp: '198.51.100.42', isLeak: false })

function harness() {
  const calls: string[] = []
  const controller = new AbortController()
  const running = new Set<OutboundSlot>(['a'])
  const state = { owner: true, active: 'a' as OutboundSlot, configurationKey: 'retained', engine: 'xray' }
  const outbound = { type: 'vless', server: 'server.example', blockQuic: false, tcpOnly: false }
  const previous = { mode: 'directVpn', vpnProfile: { name: 'Previous', protocol: 'vless', outbound: { ...outbound } } }
  const next = { mode: 'directVpn', vpnProfile: { name: 'Candidate', protocol: 'vless', outbound: { ...outbound } } }
  const initial = {
    runtime: { configurationKey: 'retained', slots: {
      a: { port: 51001, username: 'user-a', password: 'secret-a' },
      b: { port: 51002, username: 'user-b', password: 'secret-b' }
    } },
    api: { port: 51003, secret: '0123456789abcdef0123456789abcdef' },
    previous,
    status: { running: true, mode: 'directVpn', pid: 4100, startedAt: 1234, vpnProfileName: 'Previous', vpnProtocol: 'vless' }
  }
  const native = vi.fn(() => { throw new Error('Retained TUN must not restart or mutate native network protection') })
  const observations: Array<{ phase: string; generation: number; verified?: boolean }> = []
  const splitTunneling = {
    getDirectProcessNames: vi.fn(() => ['fixture.exe']),
    getDirectProcessPaths: vi.fn(() => ['C:\\Fixture\\fixture.exe'])
  }
  const splitImport = vi.fn(async () => ({ splitTunneling }))
  const deps = {
    initial,
    native,
    // CommonJS transpilation redirects only this lazy module boundary; the
    // production method and actual transition coordinator execute unchanged.
    require: (specifier: string) => {
      if (specifier !== './splitTunneling') throw new Error(`Unexpected native dependency: ${specifier}`)
      return splitImport()
    },
    runProtectedOutboundSwitch,
    isIP,
    resolveProxyEngine: vi.fn(() => state.engine),
    outboundConfigurationKey: vi.fn(() => state.configurationKey),
    shouldBlockQuicUdp443: vi.fn((value: typeof outbound) => value.blockQuic),
    isTcpOnlyNetworkOutbound: vi.fn((value: typeof outbound) => value.tcpOnly),
    getNativeXrayProfile: vi.fn(() => null),
    getActiveXraySlot: vi.fn(() => state.active),
    getXraySlotStatus: vi.fn((slot: OutboundSlot) => ({ running: running.has(slot) })),
    startXrayInSlot: vi.fn(async (slot: OutboundSlot, _outbound: unknown, _options: unknown) => {
      calls.push(`stage:${slot}`); running.add(slot); return { resolvedIp: '203.0.113.20' }
    }),
    probeSocksUpstream: vi.fn(async (endpoint: { port: number }, _signal: AbortSignal) => {
      calls.push(`probe:${endpoint.port}`); return '198.51.100.42'
    }),
    selectProtectedOutbound: vi.fn(async (_api: unknown, slot: OutboundSlot) => { calls.push(`select:${slot}`) }),
    areTunRoutesActive: vi.fn(async () => { calls.push('routes'); return true }),
    ipMonitor: {
      deferResume: vi.fn(() => { calls.push('defer') }),
      releaseDeferredResume: vi.fn(() => { calls.push('release') }),
      invalidateVpnIpBaseline: vi.fn(() => { calls.push('invalidate') }),
      recheck: vi.fn(async (_rebaseline: boolean, _owner: () => boolean): Promise<Evidence> => { calls.push('fresh-ip'); return fresh() })
    },
    activateXraySlot: vi.fn((slot: OutboundSlot) => { calls.push(`activate:${slot}`); state.active = slot }),
    stopXraySlot: vi.fn(async (slot: OutboundSlot, _reason: string) => { calls.push(`stop:${slot}`); running.delete(slot) }),
    protectedRestartCallback: vi.fn(() => { calls.push('history') }),
    observeOutboundSwitch: vi.fn((event: typeof observations[number]) => { observations.push(event) }),
    logEvent: vi.fn()
  }
  const compiled = ts.transpileModule(`
    let xraySwitchRuntime = initial.runtime, clashApiInfo = initial.api, lastStartOptions = initial.previous;
    let currentStatus = initial.status, startInProgress = false, stopInProgress = false, stopRequested = false;
    let appliedSplitTunnelRules = { names: ['fixture.exe'], paths: ['C:\\\\Fixture\\\\fixture.exe'] };
    let outboundSwitchCompletion = null, outboundSwitchAbort = null, outboundSwitchGeneration = 0;
    return {
      ${methodText},
      start: native, stop: native, restartProtected: native,
      disconnect: () => { stopRequested = true; outboundSwitchAbort?.abort(); },
      snapshot: () => ({ status: currentStatus, previous: lastStartOptions,
        busy: outboundSwitchCompletion !== null, abort: outboundSwitchAbort })
    };
  `, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
  const api = new Function(...Object.keys(deps), compiled)(...Object.values(deps)) as {
    switchOutbound: (next: unknown, options: { signal: AbortSignal; isOwner: () => boolean; onCommit: () => void }) => Promise<OutboundSwitchReceipt | null>
    disconnect: () => void
    snapshot: () => { status: typeof initial.status; previous: typeof previous; busy: boolean; abort: AbortController | null }
  }
  const onCommit = vi.fn(() => { calls.push('publish') })
  return { ...deps, api, state, next, previous, controller, running, calls, observations, onCommit, splitTunneling, splitImport,
    run: () => api.switchOutbound(next, { signal: controller.signal, isOwner: () => state.owner, onCommit }) }
}

describe('retained TUN controller integration (AT-00-003 / AT-00-007 / AT-02-002 / AT-02-011)', () => {
  it('keeps the same TUN/PID and old upstream until fresh route and egress proof complete', async () => {
    const h = harness(), proof = gate<Evidence>()
    h.ipMonitor.recheck.mockImplementationOnce(async () => { h.calls.push('fresh-ip'); return proof.promise })
    const pending = h.run()
    await vi.waitFor(() => expect(h.ipMonitor.recheck).toHaveBeenCalledOnce())
    expect([...h.running]).toEqual(['a', 'b'])
    expect(h.stopXraySlot).not.toHaveBeenCalled()
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.api.snapshot()).toMatchObject({ busy: true, status: { pid: 4100, startedAt: 1234, vpnProfileName: 'Previous' } })
    proof.resolve(fresh())
    expect(await pending).toMatchObject({ outcome: 'success', committed: true, previousStopped: true, activeSlot: 'b' })
    expect(h.calls.indexOf('fresh-ip')).toBeLessThan(h.calls.indexOf('activate:b'))
    expect(h.calls.lastIndexOf('routes')).toBeGreaterThan(h.calls.indexOf('fresh-ip'))
    expect(h.calls.indexOf('publish')).toBeLessThan(h.calls.indexOf('stop:a'))
    expect(h.api.snapshot()).toMatchObject({ busy: false, abort: null, status: { pid: 4100, startedAt: 1234, vpnProfileName: 'Candidate', proxyReachable: true } })
    expect(h.startXrayInSlot).toHaveBeenCalledWith('b', h.next.vpnProfile.outbound, expect.objectContaining({ portOverride: 51002, socksAuth: h.initial.runtime.slots.b }))
    expect(h.native).not.toHaveBeenCalled()
    expect(h.observations.at(-1)).toMatchObject({ phase: 'finished', verified: true })
  })

  it.each(['before-selector', 'after-selector'] as const)('cancellation %s preserves the old upstream without stopping TUN', async phase => {
    const h = harness(), held = gate<void>()
    if (phase === 'before-selector') h.probeSocksUpstream.mockImplementationOnce(async () => { await held.promise; return '198.51.100.42' })
    else h.selectProtectedOutbound.mockImplementationOnce(async (_api, slot) => { h.calls.push(`select:${slot}`); await held.promise })
    const pending = h.run()
    await vi.waitFor(() => expect(phase === 'before-selector' ? h.probeSocksUpstream : h.selectProtectedOutbound).toHaveBeenCalledOnce())
    h.controller.abort(); held.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: true, candidateStopped: true, activeSlot: 'a' })
    expect(h.running.has('a')).toBe(true)
    expect(h.stopXraySlot).toHaveBeenCalledExactlyOnceWith('b', 'protected upstream transition')
    expect(h.selectProtectedOutbound.mock.calls.map(call => call[1])).toEqual(phase === 'before-selector' ? [] : ['b', 'a'])
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.native).not.toHaveBeenCalled()
    expect(h.api.snapshot()).toMatchObject({ busy: false, abort: null, status: { pid: 4100, vpnProfileName: 'Previous' } })
    expect(h.observations.at(-1)).toMatchObject({ phase: 'finished', verified: true })
  })

  it.each([false, true])('native stop supersession prevents selector restoration and stale publication, external-owner-lost=%s', async ownerLost => {
    const h = harness(), selected = gate<void>()
    h.selectProtectedOutbound.mockImplementationOnce(async (_api, slot) => { h.calls.push(`select:${slot}`); await selected.promise })
    const pending = h.run()
    await vi.waitFor(() => expect(h.selectProtectedOutbound).toHaveBeenCalledOnce())
    if (ownerLost) h.state.owner = false
    h.api.disconnect(); selected.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: false, activeSlot: null, ownershipLost: true })
    expect(h.selectProtectedOutbound.mock.calls.map(call => call[1])).toEqual(['b'])
    expect(h.ipMonitor.recheck).not.toHaveBeenCalled()
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.observations.at(-1)).toMatchObject({ phase: 'finished', verified: false })
  })

  it.each(['settings', 'udp-block', 'tcp-only', 'engine'] as const)('incompatible %s returns to protected restart without starting effects', async incompatible => {
    const h = harness()
    if (incompatible === 'settings') h.state.configurationKey = 'changed'
    if (incompatible === 'udp-block') h.next.vpnProfile.outbound.blockQuic = true
    if (incompatible === 'tcp-only') h.next.vpnProfile.outbound.tcpOnly = true
    if (incompatible === 'engine') h.state.engine = 'sing-box'
    expect(await h.run()).toBeNull()
    expect(h.startXrayInSlot).not.toHaveBeenCalled()
    expect(h.selectProtectedOutbound).not.toHaveBeenCalled()
    expect(h.ipMonitor.deferResume).not.toHaveBeenCalled()
    expect(h.observations).toEqual([])
    expect(h.native).not.toHaveBeenCalled()
  })

  it.each(['names', 'paths'] as const)('changed split-tunnel %s rejects retaining stale TUN rules', async changed => {
    const h = harness()
    if (changed === 'names') h.splitTunneling.getDirectProcessNames.mockReturnValue(['other.exe'])
    else h.splitTunneling.getDirectProcessPaths.mockReturnValue(['C:\\Other\\other.exe'])
    expect(await h.run()).toBeNull()
    expect(h.startXrayInSlot).not.toHaveBeenCalled()
    expect(h.selectProtectedOutbound).not.toHaveBeenCalled()
    expect(h.observations).toEqual([])
    expect(h.native).not.toHaveBeenCalled()
  })

  it('disconnect during lazy admission prevents a stale candidate from starting', async () => {
    const h = harness(), loaded = gate<{ splitTunneling: typeof h.splitTunneling }>()
    h.splitImport.mockImplementationOnce(() => loaded.promise)
    const pending = h.run()
    await vi.waitFor(() => expect(h.splitImport).toHaveBeenCalledOnce())
    h.api.disconnect()
    loaded.resolve({ splitTunneling: h.splitTunneling })
    expect(await pending).toBeNull()
    expect(h.startXrayInSlot).not.toHaveBeenCalled()
    expect(h.ipMonitor.deferResume).not.toHaveBeenCalled()
    expect(h.observations).toEqual([])
  })

  it('rejects routes disappearing during HTTP even when providers return a fresh valid IP', async () => {
    const h = harness(), proof = gate<Evidence>()
    h.ipMonitor.recheck.mockImplementationOnce(async () => proof.promise)
    const pending = h.run()
    await vi.waitFor(() => expect(h.ipMonitor.recheck).toHaveBeenCalledOnce())
    h.areTunRoutesActive.mockResolvedValue(false)
    proof.resolve(fresh())
    expect(await pending).toMatchObject({ outcome: 'failed', committed: false, previousPreserved: false, candidateStopped: true, activeSlot: null })
    expect(h.selectProtectedOutbound.mock.calls.map(call => call[1])).toEqual(['b', 'a'])
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.observations.at(-1)).toMatchObject({ phase: 'finished', verified: false })
  })

  it('an initially aborted request never starts or selects a candidate', async () => {
    const h = harness()
    h.controller.abort()
    expect(await h.run()).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: true, activeSlot: 'a' })
    expect(h.startXrayInSlot).not.toHaveBeenCalled()
    expect(h.selectProtectedOutbound).not.toHaveBeenCalled()
    expect(h.stopXraySlot).not.toHaveBeenCalled()
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.api.snapshot()).toMatchObject({ busy: false, abort: null })
  })

  it.each(['stage', 'probe', 'selector'] as const)('candidate %s failure freshly proves the old upstream without false commit', async phase => {
    const h = harness()
    if (phase === 'stage') h.startXrayInSlot.mockRejectedValueOnce(new Error('stage failed'))
    if (phase === 'probe') h.probeSocksUpstream.mockRejectedValueOnce(new Error('probe failed'))
    if (phase === 'selector') h.selectProtectedOutbound.mockRejectedValueOnce(new Error('selector response lost'))
    expect(await h.run()).toMatchObject({ outcome: 'failed', committed: false, previousPreserved: true, candidateStopped: true, activeSlot: 'a' })
    expect(h.ipMonitor.recheck).toHaveBeenCalledOnce()
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.running.has('a')).toBe(true)
    expect(h.native).not.toHaveBeenCalled()
  })

  it.each(['unavailable-ip', 'mismatched-ip', 'leak', 'routes'] as const)('failed %s evidence never marks a transition verified', async failure => {
    const h = harness()
    if (failure === 'unavailable-ip') h.ipMonitor.recheck.mockResolvedValue({ ip: null, vpnIp: '198.51.100.42', isLeak: false })
    if (failure === 'mismatched-ip') h.ipMonitor.recheck.mockResolvedValue({ ip: '198.51.100.42', vpnIp: '203.0.113.99', isLeak: false })
    if (failure === 'leak') h.ipMonitor.recheck.mockResolvedValue({ ...fresh(), isLeak: true })
    if (failure === 'routes') h.areTunRoutesActive.mockResolvedValue(false)
    expect(await h.run()).toMatchObject({ outcome: 'failed', committed: false, previousPreserved: false, activeSlot: null })
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.observations.at(-1)).toMatchObject({ phase: 'finished', verified: false })
    expect(h.ipMonitor.releaseDeferredResume).toHaveBeenCalledOnce()
    expect(h.api.snapshot()).toMatchObject({ busy: false, abort: null })
  })

  it('aborts a held public-IP wave immediately and verifies restoration with a separate fresh wave', async () => {
    const h = harness(), provider = gate<Evidence>()
    let held = false, providerCancelled = false, candidateCanPublish: (() => boolean) | undefined
    h.ipMonitor.deferResume.mockImplementation(() => {
      h.calls.push('defer')
      if (held) { providerCancelled = true; provider.resolve({ ip: null, vpnIp: null, isLeak: false }) }
    })
    h.ipMonitor.recheck.mockImplementationOnce(async (_rebaseline, canPublish) => {
      held = true; candidateCanPublish = canPublish; return provider.promise
    })
    const pending = h.run()
    await vi.waitFor(() => expect(held).toBe(true))
    h.controller.abort()
    expect(providerCancelled).toBe(true)
    expect(candidateCanPublish?.()).toBe(false)
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: true, candidateStopped: true })
    expect(h.ipMonitor.recheck).toHaveBeenCalledTimes(2)
    expect(h.ipMonitor.recheck.mock.calls[1][1]()).toBe(true)
    expect(h.selectProtectedOutbound.mock.calls.map(call => call[1])).toEqual(['b', 'a'])
    expect(h.stopXraySlot).toHaveBeenCalledExactlyOnceWith('b', 'protected upstream transition')
    expect(h.onCommit).not.toHaveBeenCalled()
    expect(h.native).not.toHaveBeenCalled()
  })

  it('history-observer failure cannot roll back an already activated slot', async () => {
    const h = harness()
    h.protectedRestartCallback.mockImplementationOnce(() => { throw new Error('history unavailable') })
    expect(await h.run()).toMatchObject({ outcome: 'success', committed: true, previousStopped: true, activeSlot: 'b' })
    expect(h.onCommit).toHaveBeenCalledOnce()
    expect(h.state.active).toBe('b')
    expect(h.selectProtectedOutbound.mock.calls.map(call => call[1])).toEqual(['b'])
  })

  it('history observer sees the committed candidate name and start options', async () => {
    const h = harness()
    let observed: ReturnType<typeof h.api.snapshot> | undefined
    h.protectedRestartCallback.mockImplementationOnce(() => { observed = h.api.snapshot() })
    expect(await h.run()).toMatchObject({ outcome: 'success', committed: true })
    expect(observed).toMatchObject({
      status: { pid: 4100, startedAt: 1234, vpnProfileName: 'Candidate', vpnProtocol: 'vless', proxyReachable: true },
      previous: { vpnProfile: { name: 'Candidate' } }
    })
  })
})
