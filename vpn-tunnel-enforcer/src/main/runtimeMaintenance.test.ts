// AT-00-001/004/005/008, F-074/F-138/F-143: actual main handlers through the trusted boundary.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { classifyIpcError, ipcError, IpcFault } from '../shared/ipc-result'
import { currentCorrelationId } from './actionCorrelation'
const s = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => Promise<any>>() }))
vi.mock('electron', () => ({ ipcMain: { handle: (channel: string, handler: any) => s.handlers.set(channel, handler) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { ipcMain } from 'electron'
import { installTrustedIpcBoundary } from './ipcSecurity'

const channels = ['rollback-tun-network-baseline', 'firewall:repair-vpnte-rules', 'network:rollback-adapter-lockdown', 'tun:kill-stale-singbox'] as const
const source = ts.createSourceFile('index.ts', readFileSync(join(process.cwd(), 'src/main/index.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
const registrations: string[] = []
function visit(node: ts.Node) {
  if (ts.isCallExpression(node) && node.expression.getText(source) === 'handleLogged'
    && ts.isStringLiteral(node.arguments[0]) && channels.includes(node.arguments[0].text as typeof channels[number])) registrations.push(node.getText(source))
  ts.forEachChild(node, visit)
}
visit(source)
if (registrations.length !== channels.length) throw new Error('Production maintenance handlers missing')
const handle = source.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === 'handleLogged')!
const js = ts.transpileModule(`${handle.getText(source)}\n${registrations.join('\n')}`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
const raw = 'FAKE-SECRET at C:\\private\\credentials.json\n at unsafe (C:\\private\\app.js:1:2)'
function harness(active = false) {
  const health = { summary: 'ok', protectedTunnelActive: true, ourRuleCount: 3 }
  const deps = { ipcMain, ipcError, classifyIpcError, IpcFault, compactForLog: JSON.stringify,
    logEvent: vi.fn(), tunController: { getStatus: () => ({ running: active }) },
    rollbackTunNetworkBaseline: vi.fn(async () => ({ success: true, message: 'baseline restored' })),
    getFirewallRepairHealth: vi.fn(async () => health),
    repairVpnteFirewallRules: vi.fn(async () => ({ success: true, message: 'firewall restored', health })),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async () => ({ rolledBack: true, adapters: ['fixture'] })),
    killOwnedTunRuntimeProcesses: vi.fn(async (): Promise<any> => ({ success: true, candidates: 1, killed: 1, names: ['vpnte-xray.exe'] })) }
  new Function(...Object.keys(deps), js)(...Object.values(deps))
  return { ...deps, health, invoke: (channel: string) => s.handlers.get(channel)!({ sender: {} }) }
}
beforeEach(() => { s.handlers.clear(); installTrustedIpcBoundary() })
describe('runtime maintenance domain results', () => {
  it.each(channels)('%s returns a typed refusal during active TUN without mutations', async channel => {
    const h = harness(true), response = await h.invoke(channel)
    expect(response).toMatchObject({ ok: true, result: { success: false, blocked: true, skipped: true, error: ipcError('conflict') } })
    expect(h.rollbackTunNetworkBaseline).not.toHaveBeenCalled()
    expect(h.repairVpnteFirewallRules).not.toHaveBeenCalled()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).not.toHaveBeenCalled()
    expect(h.killOwnedTunRuntimeProcesses).not.toHaveBeenCalled()
    if (channel === 'firewall:repair-vpnte-rules') {
      expect(response.result.health).toEqual(h.health)
      expect(h.getFirewallRepairHealth).toHaveBeenCalledExactlyOnceWith({ protectedTunnelActive: true })
    }
    if (channel === 'tun:kill-stale-singbox') {
      expect(response.result).not.toHaveProperty('candidates')
      expect(response.result).not.toHaveProperty('killed')
    }
  })
  it.each(channels)('%s preserves inactive-TUN execution and its receipt', async channel => {
    const h = harness(), response = await h.invoke(channel)
    expect(response.ok).toBe(true)
    const target = { 'rollback-tun-network-baseline': h.rollbackTunNetworkBaseline,
      'firewall:repair-vpnte-rules': h.repairVpnteFirewallRules,
      'network:rollback-adapter-lockdown': h.rollbackPhysicalAdapterLockdownIfApplied,
      'tun:kill-stale-singbox': h.killOwnedTunRuntimeProcesses }[channel]
    expect(target).toHaveBeenCalledOnce()
    expect(response.result).toMatchObject(await target.mock.results[0].value)
  })
  it('preserves a partial termination receipt without claiming success', async () => {
    const h = harness()
    const receipt = { success: false, candidates: 2, killed: 1, names: ['vpnte-xray.exe'], error: ipcError('internal') }
    h.killOwnedTunRuntimeProcesses.mockResolvedValue(receipt)
    expect(await h.invoke('tun:kill-stale-singbox')).toMatchObject({ ok: true, result: { ...receipt, message: ipcError('internal').message } })
  })
  it('retains a confirmed empty runtime receipt', async () => {
    const h = harness()
    h.killOwnedTunRuntimeProcesses.mockResolvedValue({ success: true, candidates: 0, killed: 0, names: [] })
    expect(await h.invoke('tun:kill-stale-singbox')).toMatchObject({ ok: true, result: { success: true, candidates: 0, killed: 0, names: [] } })
  })
  it('does not mutate firewall rules if active-TUN health inspection fails', async () => {
    const h = harness(true)
    h.getFirewallRepairHealth.mockRejectedValue(Object.assign(new Error(raw), { code: 'EACCES' }))
    expect(await h.invoke('firewall:repair-vpnte-rules')).toMatchObject({ ok: false, error: ipcError('permission') })
    expect(h.repairVpnteFirewallRules).not.toHaveBeenCalled()
  })
  it.each(['permission', 'timeout', 'conflict', 'internal'] as const)('preserves canonical returned %s without fabricating counts', async category => {
    const h = harness()
    h.killOwnedTunRuntimeProcesses.mockResolvedValue({ success: false, error: ipcError(category) })
    const response = await h.invoke('tun:kill-stale-singbox')
    expect(response.result).toEqual({ success: false, error: ipcError(category), message: ipcError(category).message })
  })
  for (const channel of channels) it.each([
    ['permission', () => Object.assign(new Error(raw), { code: 'EACCES' })],
    ['timeout', () => Object.assign(new Error(raw), { code: 'ETIMEDOUT' })],
    ['network', () => Object.assign(new Error(raw), { code: 'ECONNRESET' })],
    ['validation', () => new IpcFault('validation')], ['cancelled', () => Object.assign(new Error(raw), { name: 'AbortError' })],
    ['conflict', () => new IpcFault('conflict')], ['internal', () => new Error(raw)]
  ] as const)(`${channel} sanitizes unexpected %s rejection and retains correlated diagnostics`, async (category, create) => {
    const h = harness(), error = create(), ids: Array<string | undefined> = []
    const target = { 'rollback-tun-network-baseline': h.rollbackTunNetworkBaseline,
      'firewall:repair-vpnte-rules': h.repairVpnteFirewallRules,
      'network:rollback-adapter-lockdown': h.rollbackPhysicalAdapterLockdownIfApplied,
      'tun:kill-stale-singbox': h.killOwnedTunRuntimeProcesses }[channel]
    target.mockRejectedValue(error)
    h.logEvent.mockImplementation(() => { ids.push(currentCorrelationId()) })
    const response = await h.invoke(channel)
    expect(response).toMatchObject({ ok: false, error: ipcError(category) })
    expect(JSON.stringify(response)).not.toMatch(/FAKE-SECRET|private|unsafe| at /)
    expect(h.logEvent).toHaveBeenCalledWith('error', 'ipc', `${channel} failed`, error)
    expect(ids.length).toBeGreaterThan(0)
    expect(ids.every(id => id === response.correlationId)).toBe(true)
  })
})
