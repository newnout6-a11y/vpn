// AT-00-003 / AT-00-008 / AT-09-009 / F-021: cancellation feedback and late IPC callbacks.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ru from '../i18n/locales/ru.json'

vi.mock('react-i18next', () => ({ useTranslation: () => ({
  t: (key: string, fallback?: string) => key.startsWith('dashboard.')
    ? (ru.dashboard as Record<string, string>)[key.slice(10)] ?? fallback ?? key : fallback ?? key
}) }))
vi.mock('../components/PageTip', () => ({ PageTip: () => null }))
vi.mock('../components/DiagnosticsCard', () => ({ DiagnosticsCard: () => null }))
vi.mock('../components/BrowserIpCard', () => ({ BrowserIpCard: () => null }))
vi.mock('../components/ExternalProxyCard', () => ({ ExternalProxyCard: () => null }))
vi.mock('../components/ProfileSelectorInline', () => ({ ProfileSelectorInline: () => null }))
vi.mock('../components/ForeignVpnBanner', () => ({ ForeignVpnBanner: () => null }))
vi.mock('../components/DashboardSide', () => ({ DashboardSide: () => null }))
vi.mock('../components/CountryFlagIcon', () => ({ CountryFlagIcon: () => null }))

import { Dashboard } from './Dashboard'
import { useAppStore } from '../store'

const defaults = useAppStore.getState().settings
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}

beforeEach(() => {
  useAppStore.setState({ settings: { ...defaults, connectionMode: 'directVpn' },
    connectionBusy: 'connecting', connectionCancelling: false, mode: 'off', tunRunning: false,
    vpnIp: null, publicIp: null, restartingProgress: null, serverSwitchingName: null,
    firewallKillSwitchActive: false, logs: [], competingTun: null })
  ;(window as any).electronAPI = {
    cancelTun: vi.fn().mockResolvedValue({ success: true }),
    getFirewallKillSwitchStatus: vi.fn().mockResolvedValue({ active: false }),
    serversGetActive: vi.fn().mockResolvedValue({ profile: { name: 'fixture' } }),
    saveSettings: vi.fn().mockImplementation(async settings => settings),
    startDirectVpn: vi.fn().mockResolvedValue({ success: true }),
    logRenderer: vi.fn().mockResolvedValue({ success: true })
  }
})
afterEach(() => { cleanup() })

describe('Dashboard cancellation', () => {
  it.each(['indeterminate', 'not-checked'] as const)('shows %s IP evidence without a false leak warning (AT-07-001 / AT-07-006)', verdict => {
    useAppStore.setState({ mode: 'hard', tunRunning: true, connectionBusy: null,
      publicIp: '13.143.217.2', vpnIp: verdict === 'indeterminate' ? '198.51.100.1' : null,
      publicIpVerdict: verdict, isLeak: false })
    render(<Dashboard />)
    expect(screen.getByText('13.143.217.2')).toBeInTheDocument()
    expect(screen.getByText(`— ${verdict === 'indeterminate' ? ru.dashboard.ipChangedUnverified : ru.dashboard.ipNotChecked}`)).toBeInTheDocument()
    expect(screen.queryByText('Виден ваш реальный IP')).not.toBeInTheDocument()
    expect(screen.queryByText('— утечка')).not.toBeInTheDocument()
  })
  it('keeps the explicit leak alarm visible (AT-07-001)', () => {
    useAppStore.setState({ mode: 'hard', tunRunning: true, connectionBusy: null,
      publicIp: '198.51.100.3', vpnIp: '198.51.100.1', publicIpVerdict: 'failed', isLeak: true })
    render(<Dashboard />)
    expect(screen.getByText('Виден ваш реальный IP')).toBeInTheDocument()
    expect(screen.getByText('— утечка')).toBeInTheDocument()
  })
  it('responds immediately, prevents repeated clicks, survives remount and waits for cleanup', async () => {
    const cancellation = deferred<{ success: boolean }>()
    vi.mocked(window.electronAPI.cancelTun).mockReturnValue(cancellation.promise)
    const view = render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    const cancelButton = screen.getByRole('button', { name: 'Отменяем…', busy: true })
    expect(cancelButton).toBeDisabled()
    expect(cancelButton).toHaveAttribute('aria-busy', 'true')
    expect(cancelButton.querySelector('.animate-spin')).not.toBeNull()
    expect(cancelButton).toHaveTextContent('Отменяем…')
    expect(cancelButton).toBeVisible()
    const powerButton = screen.getAllByRole('button', { name: 'Отменяем…' }).find(button => button !== cancelButton)!
    expect(powerButton).toHaveClass('bg-[var(--color-cancellation)]')
    expect(powerButton).not.toHaveClass('bg-[var(--color-accent)]')
    expect(screen.getByRole('status')).toHaveTextContent('Отменяем…')
    expect(screen.getByRole('status')).toHaveClass('sr-only')
    fireEvent.click(cancelButton)
    expect(window.electronAPI.cancelTun).toHaveBeenCalledTimes(1)
    act(() => {
      useAppStore.getState().setTunRunning(false)
      useAppStore.getState().setConnectionBusy(null)
    })
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    view.unmount()
    render(<Dashboard />)
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveClass('sr-only')
    await act(async () => cancellation.resolve({ success: true }))
    expect(useAppStore.getState().connectionCancelling).toBe(false)
    expect(useAppStore.getState().connectionBusy).toBeNull()
    expect(screen.queryByRole('button', { name: 'Отменяем…', busy: true })).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Отключено')
    expect(screen.getByRole('status')).not.toHaveClass('sr-only')
  })

  it('shows recovery warnings as the cancellation outcome', async () => {
    vi.mocked(window.electronAPI.cancelTun).mockResolvedValue({ success: true, warning: 'Recovery not verified' })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    expect(await screen.findByText('Подключение отменено с предупреждениями')).toBeInTheDocument()
    expect(screen.getByText('Recovery not verified')).toBeInTheDocument()
    expect(useAppStore.getState().logs.some(log => log.message.includes('Recovery not verified'))).toBe(true)
  })

  it('cancellation colour overrides a connected tunnel and disappears after cleanup', async () => {
    const cancellation = deferred<{ success: boolean }>()
    vi.mocked(window.electronAPI.cancelTun).mockReturnValue(cancellation.promise)
    useAppStore.setState({ tunRunning: true, mode: 'hard' })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    const powerButton = screen.getAllByRole('button', { name: 'Отменяем…' }).find(button => !button.hasAttribute('aria-busy'))!
    expect(powerButton).toHaveClass('bg-[var(--color-cancellation)]')
    expect(powerButton).not.toHaveClass('bg-[var(--color-success)]')
    await act(async () => cancellation.resolve({ success: true }))
    expect(screen.getByRole('button', { name: 'Отключено' })).toHaveClass('bg-[var(--color-accent)]')
  })

  it.each(['failed result', 'rejected IPC'])('shows %s without claiming the tunnel stopped', async kind => {
    useAppStore.setState({ tunRunning: true, mode: 'hard' })
    if (kind === 'failed result') vi.mocked(window.electronAPI.cancelTun).mockResolvedValue({ success: false, error: 'Cleanup failed' })
    else vi.mocked(window.electronAPI.cancelTun).mockRejectedValue(new Error('Cleanup failed'))
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    expect(await screen.findByText('Не удалось отменить подключение')).toBeInTheDocument()
    expect(useAppStore.getState().tunRunning).toBe(true)
    expect(useAppStore.getState().mode).toBe('hard')
    expect(useAppStore.getState().connectionCancelling).toBe(false)
  })

  it('does not start a tunnel after preparation is cancelled on a remounted Dashboard', async () => {
    const active = deferred<any>()
    vi.mocked(window.electronAPI.serversGetActive).mockReturnValue(active.promise)
    useAppStore.setState({ connectionBusy: null })
    const first = render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отключено' }))
    first.unmount()
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    await waitFor(() => expect(useAppStore.getState().connectionBusy).toBeNull())
    await act(async () => active.resolve({ profile: { name: 'fixture' } }))
    expect(window.electronAPI.saveSettings).not.toHaveBeenCalled()
    expect(window.electronAPI.startDirectVpn).not.toHaveBeenCalled()
  })

  it('ignores a late successful start while cancellation is still pending', async () => {
    const start = deferred<{ success: boolean }>()
    const cancel = deferred<{ success: boolean }>()
    vi.mocked(window.electronAPI.startDirectVpn).mockReturnValue(start.promise)
    vi.mocked(window.electronAPI.cancelTun).mockReturnValue(cancel.promise)
    useAppStore.setState({ connectionBusy: null })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отключено' }))
    await waitFor(() => expect(window.electronAPI.startDirectVpn).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Отменить подключение' }))
    await act(async () => start.resolve({ success: true }))
    expect(useAppStore.getState().tunRunning).toBe(false)
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    await act(async () => cancel.resolve({ success: true }))
    expect(screen.getByText('Подключение отменено')).toBeInTheDocument()
  })
})
