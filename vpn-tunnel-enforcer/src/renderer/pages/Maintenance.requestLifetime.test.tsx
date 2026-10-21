// AT-00-003/008: real protection action and late routing/leak replies.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Maintenance } from './Maintenance'
import { useAppStore } from '../store'
import { ipcError } from '../../shared/ipc-result'

let api: Record<string, ReturnType<typeof vi.fn>>
let resolveRoute: (result: unknown) => void, rejectRoute: (error: unknown) => void
let resolveStatus: (status: unknown) => void
beforeEach(() => {
  useAppStore.setState({ logs: [], maintenanceRunningAction: null, maintenanceLastResult: '',
    maintenanceSystemDiagnostics: null, maintenanceFirewallHealth: null, maintenanceRepairSteps: null, globalToasts: [] })
  api = { getTunStatus: vi.fn(async () => ({ running: true })), operationsCancelRequest: vi.fn(async () => true),
    runLeakSelfTest: vi.fn(async () => ({ summary: 'FAKE-leak', physicalAdapterReached: false, publicIpMismatch: false })),
    runRoutingSelfTest: vi.fn(() => new Promise((resolve, reject) => { resolveRoute = resolve; rejectRoute = reject })) }
  Object.assign(window, { electronAPI: api })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

// AT-00-005: the stable event code survives the real Maintenance -> store path.
it.each(['warn', 'fail'] as const)('persists a %s health summary with its event code and original severity', async status => {
  Object.assign(api, {
    logRenderer: vi.fn(async () => ({ success: true })),
    runSystemDiagnostics: vi.fn(async () => ({ items: [{ id: 'network', category: 'Network', label: 'Network', status, value: 'fixture' }] })),
    firewallRepairHealth: vi.fn(async () => ({ summary: 'ok', services: [], profiles: [], recommendedActions: [], ourRuleCount: 0 }))
  })
  render(<Maintenance />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Проверить$/ })) })
  const level = status === 'fail' ? 'error' : 'warn'
  const message = useAppStore.getState().maintenanceLastResult
  expect(api.logRenderer).toHaveBeenLastCalledWith(level, message, 'health-check-summary')
  expect(useAppStore.getState().logs.at(-1)).toMatchObject({ level, message })
})

async function start() {
  const view = render(<Maintenance />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Проверить защиту' })) })
  return view
}
it.each(['success', 'error'])('cancels protection routing on unmount and fences late %s', async outcome => {
  const view = await start()
  const token = api.runRoutingSelfTest.mock.calls[0][0]
  expect(token).toMatch(/^[0-9a-f-]{36}$/)
  const beforeLogs = useAppStore.getState().logs.length
  view.unmount()
  expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(token)
  expect(useAppStore.getState().maintenanceRunningAction).toBeNull()
  await act(async () => {
    if (outcome === 'success') resolveRoute({ verdict: 'ok', message: 'FAKE-late' })
    else rejectRoute({ name: 'IpcRemoteError', ...ipcError('internal') })
  })
  expect(useAppStore.getState().maintenanceLastResult).toBe('')
  expect(useAppStore.getState().logs).toHaveLength(beforeLogs)
  expect(useAppStore.getState().globalToasts).toEqual([])
})
it('does not start routing after a late status reply on unmount', async () => {
  api.getTunStatus.mockImplementation(() => new Promise(resolve => { resolveStatus = resolve }))
  const view = await start(); view.unmount()
  await act(async () => { resolveStatus({ running: true }) })
  expect(api.runRoutingSelfTest).not.toHaveBeenCalled()
  expect(api.runLeakSelfTest).not.toHaveBeenCalled()
  expect(useAppStore.getState().maintenanceLastResult).toBe('')
})
it('keeps typed cancellation quiet and publishes current success normally', async () => {
  const view = await start()
  await act(async () => { rejectRoute({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
  expect(useAppStore.getState().maintenanceLastResult).toBe('')
  expect(useAppStore.getState().globalToasts).toEqual([])
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Проверить защиту' })) })
  await act(async () => { resolveRoute({ verdict: 'ok', message: 'FAKE-current' }) })
  expect(useAppStore.getState().maintenanceLastResult).toContain('FAKE-current')
  view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
})
it('cancels pending routing when the companion leak check fails', async () => {
  api.runLeakSelfTest.mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('network') })
  const view = await start()
  expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(api.runRoutingSelfTest.mock.calls[0][0])
  expect(useAppStore.getState().maintenanceLastResult).toBe(ipcError('network').message)
  await act(async () => { rejectRoute({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
  view.unmount(); expect(api.operationsCancelRequest).toHaveBeenCalledOnce()
})
it('does not let an old reply clear a new mounted action', async () => {
  const first = await start(), oldRelease = resolveRoute
  first.unmount()
  const second = await start()
  await act(async () => { oldRelease({ verdict: 'ok', message: 'FAKE-old' }) })
  expect(useAppStore.getState().maintenanceRunningAction).toBe('protection-test')
  expect(useAppStore.getState().maintenanceLastResult).toBe('')
  await act(async () => { resolveRoute({ verdict: 'ok', message: 'FAKE-new' }) })
  expect(useAppStore.getState().maintenanceLastResult).toContain('FAKE-new')
  second.unmount()
})
it.each(['success', 'error'])('cancels independent leak and routing tokens on unmount with late leak %s', async outcome => {
  let resolveLeak!: (value: unknown) => void, rejectLeak!: (error: unknown) => void
  api.runLeakSelfTest.mockImplementation(() => new Promise((yes, no) => { resolveLeak = yes; rejectLeak = no }))
  const view = await start(), leakToken = api.runLeakSelfTest.mock.calls[0][0], routeToken = api.runRoutingSelfTest.mock.calls[0][0]
  expect(leakToken).toMatch(/^[0-9a-f-]{36}$/)
  expect(leakToken).not.toBe(routeToken)
  await act(async () => { resolveRoute({ verdict: 'ok', message: 'FAKE-route' }) })
  const beforeLogs = useAppStore.getState().logs.length
  view.unmount()
  expect(api.operationsCancelRequest).toHaveBeenCalledWith(leakToken)
  expect(api.operationsCancelRequest).toHaveBeenCalledWith(routeToken)
  await act(async () => { if (outcome === 'success') resolveLeak({ summary: 'FAKE-late' }); else rejectLeak({ name: 'IpcRemoteError', ...ipcError('internal') }) })
  expect(useAppStore.getState().maintenanceLastResult).toBe('')
  expect(useAppStore.getState().logs).toHaveLength(beforeLogs)
  expect(useAppStore.getState().globalToasts).toEqual([])
})
it('cancels a pending leak check when routing fails', async () => {
  let release!: (value: unknown) => void
  api.runLeakSelfTest.mockImplementation(() => new Promise(yes => { release = yes }))
  const view = await start()
  await act(async () => { rejectRoute({ name: 'IpcRemoteError', ...ipcError('network') }) })
  expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(api.runLeakSelfTest.mock.calls[0][0])
  await act(async () => { release({ summary: 'FAKE-late' }) })
  expect(useAppStore.getState().maintenanceLastResult).toBe(ipcError('network').message)
  view.unmount()
})

// AT-00-008: routing success cannot hide incomplete physical inspection.
it.each([
  { patch: { physicalAdapterInspectionComplete: false }, variant: 'warning' },
  { patch: { physicalAdapterInspectionComplete: undefined }, variant: 'warning' },
  { patch: { defaultRoutePublicIp: null }, variant: 'warning' },
  { patch: { perAdapter: [] }, variant: 'warning' },
  { patch: {}, variant: 'success' },
  { patch: { physicalAdapterReached: true, physicalAdapterInspectionComplete: false }, variant: 'error' }
])('requires complete protection evidence for toast $variant ($patch)', async ({ patch, variant }) => {
  api.runLeakSelfTest.mockResolvedValue({ summary: 'FAKE-leak', physicalAdapterReached: false, publicIpMismatch: false,
    physicalAdapterInspectionComplete: true, defaultRoutePublicIp: '1.2.3.4', perAdapter: [
      { alias: 'Wi-Fi', ipv4: '192.168.1.2', publicIpViaThisAdapter: null, curlExitCode: 7, curlStderrTail: null }
    ], ...patch })
  const view = await start()
  await act(async () => { resolveRoute({ verdict: 'ok', message: 'FAKE-route' }) })
  expect(useAppStore.getState().globalToasts.at(-1)?.variant).toBe(variant)
  expect(useAppStore.getState().maintenanceLastResult).not.toContain('FAKE-leak')
  if (variant === 'warning') expect(useAppStore.getState().maintenanceLastResult).not.toContain('Проверка защиты пройдена')
  view.unmount()
})

it.each(['dns', 'leak', 'cancelled'])('retains %s evidence in Maintenance result, log and toast', async scenario => {
  api.runLeakSelfTest.mockResolvedValue({ ts: 1, summary: 'OK: stale', physicalAdapterReached: scenario === 'leak', publicIpMismatch: false,
    cancelled: scenario === 'cancelled' ? true : undefined, physicalAdapterInspectionComplete: scenario !== 'cancelled',
    defaultRoutePublicIp: '1.2.3.4', dnsLeakDetail: scenario === 'dns' ? 'Cloudflare видит 5.6.7.8, default-route отдаёт 1.2.3.4' : undefined,
    perAdapter: [{ alias: 'Wi-Fi', ipv4: '192.168.1.2', publicIpViaThisAdapter: scenario === 'leak' ? '5.6.7.8' : null, curlExitCode: 7, curlStderrTail: null }] })
  const view = await start()
  await act(async () => { resolveRoute({ verdict: 'ok', message: 'FAKE-route' }) })
  const state = useAppStore.getState()
  const expected = scenario === 'cancelled' ? 'Тест отменён' : '5.6.7.8'
  expect(state.maintenanceLastResult).toContain(expected)
  expect(state.globalToasts.at(-1)?.description).toContain(expected)
  expect(state.logs.at(-1)?.message).toContain(expected)
  view.unmount()
})

// AT-00-004/008: TUN may start after the page's initial preflight.
it.each(['firewall', 'network-baseline', 'adapter-lockdown', 'orphaned-dns', 'runtime', 'partial-runtime', 'failure'])('shows honest auto-repair outcome for %s', async scenario => {
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  api.getTunStatus.mockResolvedValue({ running: false })
  const refusal = { success: false, blocked: true, skipped: true, error: ipcError('conflict'), message: 'Отключите VPN перед починкой' }
  const partial = { success: false, error: ipcError('internal'), candidates: 2, killed: 1, names: ['vpnte-xray.exe'],
    message: 'Завершены процессы VPNTE runtime: 1 из 2. Не все процессы остановлены; повторите очистку.' }
  const results: Record<string, unknown> = { firewall: { success: true }, 'network-baseline': { success: true },
    'adapter-lockdown': { rolledBack: true }, 'orphaned-dns': { success: true, repaired: false, skipped: true, adapters: [] }, runtime: { success: true, candidates: 0, killed: 0, names: [] } }
  results[scenario === 'partial-runtime' || scenario === 'failure' ? 'runtime' : scenario] = scenario === 'partial-runtime' ? partial
    : scenario === 'failure' ? { success: false, error: ipcError('permission'), message: ipcError('permission').message } : refusal
  Object.assign(api, {
    firewallRepairVpnteRules: vi.fn(async () => results.firewall), rollbackTunNetworkBaseline: vi.fn(async () => results['network-baseline']),
    rollbackAdapterLockdown: vi.fn(async () => results['adapter-lockdown']), repairOrphanedDns: vi.fn(async () => results['orphaned-dns']),
    killStaleSingbox: vi.fn(async () => results.runtime), runSystemDiagnostics: vi.fn(async () => ({ items: [] })),
    firewallRepairHealth: vi.fn(async () => ({ summary: 'ok', services: [], profiles: [], recommendedActions: [], ourRuleCount: 0 }))
  })
  render(<Maintenance />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Починить$/ })) })
  const state = useAppStore.getState(), failed = ['partial-runtime', 'failure'].includes(scenario)
  const step = state.maintenanceRepairSteps?.find(step => step.id === (failed ? 'runtime' : scenario))
  expect(step?.status).toBe(failed ? 'fail' : 'warn')
  expect(state.maintenanceLastResult).toBe(failed ? 'Авто-починка завершена с ошибками' : 'Авто-починка завершена с предупреждениями')
  expect(state.globalToasts.at(-1)?.variant).toBe('warning')
  if (!failed) expect(state.logs.some(log => log.level === 'error')).toBe(false)
  if (scenario === 'partial-runtime') {
    expect(step?.detail).toContain('1 из 2')
    expect(screen.getByText(partial.message)).toBeTruthy()
    expect(state.logs.some(log => log.level === 'error' && log.message.includes('1 из 2'))).toBe(true)
  }
})

// AT-00-004/008: returned domain failures must not become a green repair summary.
it.each(['network-baseline', 'adapter-lockdown', 'orphaned-dns', 'absent'] as const)('shows %s rollback truthfully', async scenario => {
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  api.getTunStatus.mockResolvedValue({ running: false })
  const message = 'Откат выполнен частично; манифест сохранён для повторной попытки'
  const failure = { success: false, error: ipcError('permission'), message }
  Object.assign(api, {
    firewallRepairVpnteRules: vi.fn(async () => ({ success: true })),
    rollbackTunNetworkBaseline: vi.fn(async () => scenario === 'network-baseline' ? { ...failure, restoredSteps: ['internet/ProxyEnable'] } : { success: true, skipped: true }),
    rollbackAdapterLockdown: vi.fn(async () => scenario === 'adapter-lockdown' ? { ...failure, rolledBack: false, restoredAdapters: ['Ethernet'] } : { success: true, rolledBack: false, skipped: true }),
    repairOrphanedDns: vi.fn(async () => scenario === 'orphaned-dns' ? { ...failure, repaired: false, adapters: ['Ethernet'] } : { success: true, repaired: false, skipped: true, adapters: [] }),
    killStaleSingbox: vi.fn(async () => ({ success: true, candidates: 0, killed: 0, names: [] })),
    runSystemDiagnostics: vi.fn(async () => ({ items: [] })),
    firewallRepairHealth: vi.fn(async () => ({ summary: 'ok', services: [], profiles: [], recommendedActions: [], ourRuleCount: 0 }))
  })
  render(<Maintenance />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /^Починить$/ })) })
  const state = useAppStore.getState()
  if (scenario === 'absent') {
    expect(state.maintenanceRepairSteps?.every(step => step.status === 'ok')).toBe(true)
    expect(state.maintenanceLastResult).toBe('Авто-починка завершена')
    expect(state.globalToasts.at(-1)?.variant).toBe('success')
  } else {
    expect(state.maintenanceRepairSteps?.find(step => step.id === scenario)).toMatchObject({ status: 'fail', detail: message })
    expect(screen.getByText(message)).toBeTruthy()
    expect(state.maintenanceLastResult).toBe('Авто-починка завершена с ошибками')
    expect(state.globalToasts.at(-1)?.variant).toBe('warning')
    expect(state.logs.some(log => log.level === 'error' && log.message.includes(message))).toBe(true)
  }
})
