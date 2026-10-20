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
afterEach(cleanup)
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
