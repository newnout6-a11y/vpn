// AT-00-003/008: actual component, requester cancellation and late IPC replies.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { DiagnosticsCard } from './DiagnosticsCard'
import { useAppStore } from '../store'
import { ipcError } from '../../shared/ipc-result'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string, options?: { defaultValue?: string }) => options?.defaultValue ?? key }) }))
let api: Record<string, ReturnType<typeof vi.fn>>
let resolveLeak: (value: unknown) => void, rejectLeak: (error: unknown) => void
const result = { ts: 1, summary: 'FAKE-current', physicalAdapterReached: false, publicIpMismatch: false,
  dnsLeakDetected: false, physicalAdapterInspectionComplete: true, perAdapter: [], defaultRoutePublicIp: '198.51.100.1' }
beforeEach(() => {
  useAppStore.setState({ logs: [], leakSelfTestResult: null, lastMainError: null, exportingDiagnostics: false })
  api = { getTrafficForensicsStatus: vi.fn(async () => ({ running: false, health: {} })), operationsCancelRequest: vi.fn(async () => true),
    runLeakSelfTest: vi.fn(() => new Promise((resolve, reject) => { resolveLeak = resolve; rejectLeak = reject })) }
  Object.assign(window, { electronAPI: api })
})
afterEach(cleanup)
async function start() {
  const view = render(<DiagnosticsCard />)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Активная проверка утечки' })) })
  return view
}
it.each(['success', 'error'])('cancels leak test on unmount and fences late %s', async outcome => {
  const view = await start(), token = api.runLeakSelfTest.mock.calls[0][0]
  expect(token).toMatch(/^[0-9a-f-]{36}$/)
  const beforeLogs = useAppStore.getState().logs.length
  view.unmount()
  expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(token)
  await act(async () => { if (outcome === 'success') resolveLeak(result); else rejectLeak({ name: 'IpcRemoteError', ...ipcError('internal') }) })
  expect(useAppStore.getState().leakSelfTestResult).toBeNull()
  expect(useAppStore.getState().logs).toHaveLength(beforeLogs)
})
it('keeps typed cancellation quiet and allows another successful check', async () => {
  const view = await start()
  await act(async () => { rejectLeak({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
  expect(useAppStore.getState().logs.some(log => log.level === 'error')).toBe(false)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Активная проверка утечки' })) })
  const [first, second] = api.runLeakSelfTest.mock.calls.map(call => call[0])
  expect(second).not.toBe(first)
  await act(async () => { resolveLeak(result) })
  expect(useAppStore.getState().leakSelfTestResult).toEqual(result)
  expect(screen.getByRole('button', { name: 'Активная проверка утечки' }).hasAttribute('disabled')).toBe(false)
  view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
})
it('does not let a previous mounted check overwrite the current result', async () => {
  const first = await start(), oldResolve = resolveLeak
  first.unmount()
  const second = await start()
  await act(async () => { oldResolve({ ...result, summary: 'FAKE-old' }) })
  expect(useAppStore.getState().leakSelfTestResult).toBeNull()
  expect(screen.getByRole('button', { name: 'Активная проверка утечки' }).hasAttribute('disabled')).toBe(true)
  await act(async () => { resolveLeak(result) })
  expect(useAppStore.getState().leakSelfTestResult).toEqual(result)
  second.unmount()
})

// AT-00-008: exercise the real panel, not a source-text assertion.
it.each([
  { patch: { physicalAdapterInspectionComplete: false }, expected: 'inconclusive' },
  { patch: { defaultRoutePublicIp: null }, expected: 'inconclusive' },
  { patch: { perAdapter: [] }, expected: 'inconclusive' },
  { patch: { perAdapter: [{ alias: 'Wi-Fi', ipv4: '192.168.1.2', publicIpViaThisAdapter: null, curlExitCode: null, curlStderrTail: null }] }, expected: 'inconclusive' },
  { patch: {}, expected: 'ok' },
  { patch: { physicalAdapterReached: true, physicalAdapterInspectionComplete: false }, expected: 'leak' }
])('shows measured leak verdict $expected without trusting legacy summary ($patch)', async ({ patch, expected }) => {
  useAppStore.setState({ leakSelfTestResult: { ...result, summary: 'OK: legacy', perAdapter: [
    { alias: 'Wi-Fi', ipv4: '192.168.1.2', publicIpViaThisAdapter: null, curlExitCode: 7, curlStderrTail: null }
  ], ...patch } })
  const view = render(<DiagnosticsCard />)
  await act(async () => {})
  const panel = screen.getByRole('status', { name: 'Результат проверки утечек' })
  expect(panel.getAttribute('data-verdict')).toBe(expected)
  expect(panel.textContent).not.toContain('OK: legacy')
  if (expected === 'inconclusive') {
    expect(panel.textContent).toContain('Защита не подтверждена')
    expect(panel.innerHTML).not.toContain('color-success')
    expect(panel.textContent).not.toContain('OK: legacy')
    expect(panel.textContent).not.toContain('заблокирован')
  }
  if (expected === 'leak') expect(panel.textContent).toContain('Обнаружена утечка')
  view.unmount()
})
