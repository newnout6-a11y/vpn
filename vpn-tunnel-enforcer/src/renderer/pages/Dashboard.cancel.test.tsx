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
import { applyTerminalTunStatus, useAppStore } from '../store'
import { TunnelStateMachine } from '../../main/tunnelStateMachine'
import { ConnectionLifecycle } from '../../main/connectionLifecycle'

const defaults = useAppStore.getState().settings
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}

beforeEach(() => {
  useAppStore.setState({ tunnelSnapshot: null, settings: { ...defaults, connectionMode: 'directVpn' },
    connectionBusy: 'connecting', connectionCancelling: false, mode: 'off', tunRunning: false,
    vpnIp: null, publicIp: null, restartingProgress: null, serverSwitchingName: null,
    firewallKillSwitchStatus: { state: 'inactive', cleanupRequired: false, reason: 'no-owned-protection' }, logs: [], competingTun: null })
  ;(window as any).electronAPI = {
    cancelTun: vi.fn().mockResolvedValue({ success: true }),
    getFirewallKillSwitchStatus: vi.fn().mockResolvedValue({ state: 'inactive', cleanupRequired: false, reason: 'no-owned-protection' }),
    serversGetActive: vi.fn().mockResolvedValue({ profile: { name: 'fixture' } }),
    saveSettings: vi.fn().mockImplementation(async settings => settings),
    startDirectVpn: vi.fn().mockResolvedValue({ success: true }),
    startSoftProtection: vi.fn().mockResolvedValue({ success: true }),
    logRenderer: vi.fn().mockResolvedValue({ success: true })
  }
})
afterEach(() => { cleanup() })

describe('canonical FSM frames (AT-00-008)', () => {
  it('can connect immediately after confirmed cancelled-switch cleanup without an extra disconnect', async () => {
    const evidence = { running: false, pid: null as number | null, softApplied: false }
    const model = new TunnelStateMachine(() => evidence, snapshot => useAppStore.getState().setTunnelSnapshot(snapshot))
    const lane = new ConnectionLifecycle(vi.fn(), undefined, undefined, model)
    useAppStore.setState({ connectionBusy: null })
    await lane.start(async () => { evidence.running = true; evidence.pid = 123; return { success: true } })
    model.nativeStartBegan(1)
    Object.assign(window.electronAPI, { stopTun: vi.fn(),
      startDirectVpn: vi.fn().mockImplementation(() => lane.start(async () => { evidence.running = true; evidence.pid = 456; return { success: true } })) })
    render(<Dashboard />)
    expect(screen.getByRole('button', { name: ru.dashboard.connected })).toBeEnabled()
    await act(async () => {
      useAppStore.getState().setServerSwitchingName('Estonia')
      model.runtimeChanged('adapting')
      evidence.running = false; evidence.pid = null
      model.nativeStartBegan(2)
      model.nativeStartFinished({ generation: 2, success: false })
      model.runtimeChanged('stopped')
      useAppStore.getState().setServerSwitchingName(null)
    })
    expect(screen.getByRole('button', { name: ru.dashboard.tunnelUnknown })).toBeEnabled()
    await act(async () => { model.nativeStopFinished({ generation: 2, preserveNetworkProtection: false,
      result: { success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } } }) })
    fireEvent.click(screen.getByRole('button', { name: ru.dashboard.disconnected }))
    await waitFor(() => expect(window.electronAPI.startDirectVpn).toHaveBeenCalledOnce())
    expect(window.electronAPI.stopTun).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: ru.dashboard.connected })).toBeEnabled()
  })

  it('renders progress until main confirms the connection, and ignores stale native/result setters', async () => {
    const evidence = { running: false, pid: null as number | null, softApplied: false }
    const model = new TunnelStateMachine(() => evidence, snapshot => useAppStore.getState().setTunnelSnapshot(snapshot))
    const lane = new ConnectionLifecycle(vi.fn(), undefined, undefined, model)
    const gate = deferred<void>()
    useAppStore.setState({ connectionBusy: null })
    useAppStore.getState().setTunnelSnapshot(model.snapshot)
    render(<Dashboard />)
    expect(screen.getByRole('button', { name: ru.dashboard.disconnected })).toBeEnabled()
    let start!: Promise<unknown>
    await act(async () => {
      start = lane.start(async owner => {
        evidence.running = true; evidence.pid = 123
        model.runtimeChanged('running')
        await owner.wait(gate.promise)
        return { success: true }
      })
    })
    expect(screen.queryByRole('button', { name: ru.dashboard.connected })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: ru.dashboard.connecting })).toBeDisabled()
    await act(async () => {
      useAppStore.getState().setConnectionBusy(null)
      useAppStore.getState().setTunRunning(true)
    })
    expect(screen.getByRole('button', { name: ru.dashboard.connecting })).toBeDisabled()
    await act(async () => { gate.resolve(); await start })
    expect(screen.getByRole('button', { name: ru.dashboard.connected })).toBeEnabled()
    const staleConnected = model.snapshot
    for (const [state, label] of [['error', ru.dashboard.tunnelError], ['blocked', ru.dashboard.tunnelBlocked], ['unknown', ru.dashboard.tunnelUnknown]] as const) {
      await act(async () => { model.fault(state); model.runtimeChanged('running') })
      await act(async () => {
        useAppStore.getState().setTunnelSnapshot(staleConnected)
        useAppStore.getState().setTunRunning(true)
        useAppStore.getState().setMode('hard')
      })
      expect(screen.getByRole('button', { name: label })).toBeEnabled()
      expect(screen.queryByRole('button', { name: ru.dashboard.connected })).not.toBeInTheDocument()
      expect(useAppStore.getState().mode).toBe('off')
    }
  })

  it('uses the owned Soft channel and a single main stop; env failures remain failures', async () => {
    const proxy = '127.0.0.1:8080'
    useAppStore.setState({ connectionBusy: null, settings: { ...defaults, connectionMode: 'localProxy', routingMode: 'soft', proxyOverride: proxy } })
    Object.assign(window.electronAPI, { applyAutoconfig: vi.fn(), rollbackAutoconfig: vi.fn(),
      stopTun: vi.fn().mockResolvedValue({ success: false, error: 'env recovery unconfirmed' }) })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: ru.dashboard.disconnected }))
    await waitFor(() => expect(window.electronAPI.startSoftProtection).toHaveBeenCalledWith(proxy, defaults.proxyType))
    expect(window.electronAPI.applyAutoconfig).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.getByRole('button', { name: ru.dashboard.connected })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: ru.dashboard.connected }))
    fireEvent.click(screen.getByRole('button', { name: 'Да, отключить' }))
    expect(await screen.findByText('env recovery unconfirmed')).toBeVisible()
    expect(window.electronAPI.rollbackAutoconfig).not.toHaveBeenCalled()
    expect(window.electronAPI.stopTun).toHaveBeenCalledOnce()
  })
})

describe('Dashboard cancellation', () => {
  it('shows failed rollback steps and the retry recommendation instead of success (AT-03-007)', async () => {
    const error = 'baseline auto-rollback: environment/HTTP_PROXY: access denied | kill-switch disable: WFP removal failed. Повторите остановку защиты и проверьте диагностику сети.'
    Object.assign(window.electronAPI, { stopTun: vi.fn().mockResolvedValue({ success: false, error }) })
    useAppStore.setState({ connectionBusy: null, mode: 'hard', tunRunning: true })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: ru.dashboard.connected }))
    fireEvent.click(screen.getByRole('button', { name: 'Да, отключить' }))
    expect(await screen.findByText(error)).toBeVisible()
    expect(screen.getByText(ru.dashboard.connectionError)).toBeVisible()
    expect(screen.queryByText('Защита выключена с предупреждениями')).not.toBeInTheDocument()
    expect(useAppStore.getState().logs.some(log => log.level === 'error' && log.message.includes(error))).toBe(true)
  })
  it('does not present a cleanup alert before status checking has completed (AT-03-001)', () => {
    useAppStore.setState({ connectionBusy: null, firewallKillSwitchStatus: { state: 'unknown', cleanupRequired: true, reason: 'checking' } })
    render(<Dashboard />)
    expect(screen.queryByText(ru.dashboard.firewallUnknownTitle)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Снять блокировку' })).not.toBeInTheDocument()
  })
  it('shows unknown firewall evidence without claiming Internet blocking; recheck can establish absence (AT-03-001/003)', async () => {
    useAppStore.setState({ connectionBusy: null, firewallKillSwitchStatus: { state: 'unknown', cleanupRequired: true, reason: 'read-back-failed' } })
    render(<Dashboard />)
    expect(screen.getByText(ru.dashboard.firewallUnknownTitle)).toBeInTheDocument()
    expect(screen.queryByText('Интернет заблокирован файрволом')).not.toBeInTheDocument()
    expect(screen.queryByText(ru.dashboard.firewallVerifiedTitle)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Снять блокировку' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: ru.dashboard.firewallRecheck }))
    await waitFor(() => expect(screen.queryByText(ru.dashboard.firewallUnknownTitle)).not.toBeInTheDocument())
  })
  it('keeps the warning after a failed manual cleanup and a failed status refresh (AT-03-003/007)', async () => {
    Object.assign(window.electronAPI, { disableFirewallKillSwitch: vi.fn().mockResolvedValue({ success: false, message: 'Partial rollback' }),
      getFirewallKillSwitchStatus: vi.fn().mockRejectedValue(new Error('helper unavailable')) })
    useAppStore.setState({ connectionBusy: null, firewallKillSwitchStatus: { state: 'verified', cleanupRequired: true, reason: 'policy-verified' } })
    render(<Dashboard />)
    expect(screen.getByText(ru.dashboard.firewallVerifiedTitle)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Снять блокировку' }))
    await waitFor(() => expect(useAppStore.getState().firewallKillSwitchStatus.reason).toBe('unavailable'))
    expect(screen.getByText(ru.dashboard.firewallUnknownTitle)).toBeInTheDocument()
    expect(screen.queryByText(ru.dashboard.firewallVerifiedTitle)).not.toBeInTheDocument()
  })
  it('keeps the power button locked if selection settles before cancelTransition replies (AT-00-007)', async () => {
    const acknowledgement = deferred<{ requested: boolean }>()
    Object.assign(window.electronAPI, {
      serversCancelSwitch: vi.fn().mockResolvedValue({ cancelled: true }),
      cancelTransition: vi.fn().mockReturnValue(acknowledgement.promise)
    })
    useAppStore.setState({ connectionBusy: null, mode: 'hard', tunRunning: true, serverSwitchingName: 'Norway' })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить смену сервера' }))
    await waitFor(() => expect(window.electronAPI.cancelTransition).toHaveBeenCalledOnce())
    await act(async () => {
      applyTerminalTunStatus('stopped')
      useAppStore.getState().setServerSwitchingName(null)
    })
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    expect(window.electronAPI.startDirectVpn).not.toHaveBeenCalled()
    await act(async () => acknowledgement.resolve({ requested: true }))
    expect(screen.getByRole('button', { name: 'Отключено' })).toBeInTheDocument()
  })
  it('waits for server-switch cleanup after cancellation acknowledgements and remount (AT-00-003 / AT-00-008)', async () => {
    Object.assign(window.electronAPI, {
      serversCancelSwitch: vi.fn().mockResolvedValue({ cancelled: true }),
      cancelTransition: vi.fn().mockResolvedValue({ requested: true })
    })
    useAppStore.setState({ connectionBusy: null, mode: 'hard', tunRunning: true, serverSwitchingName: 'Norway' })
    const view = render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить смену сервера' }))
    await waitFor(() => expect(window.electronAPI.cancelTransition).toHaveBeenCalledOnce())
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    await act(async () => applyTerminalTunStatus('stopped'))
    view.unmount()
    render(<Dashboard />)
    expect(screen.getByRole('button', { name: 'Отменяем…', busy: true })).toBeDisabled()
    expect(useAppStore.getState().tunRunning).toBe(false)
    await act(async () => useAppStore.getState().setServerSwitchingName(null))
    expect(screen.getByRole('button', { name: 'Отключено' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Отключено')
    expect(window.electronAPI.cancelTun).not.toHaveBeenCalled()
  })

  it('releases cancellation feedback when its request fails, retaining pending selection (AT-00-004)', async () => {
    Object.assign(window.electronAPI, {
      serversCancelSwitch: vi.fn().mockResolvedValue({ cancelled: true }),
      cancelTransition: vi.fn().mockRejectedValue(new Error('IPC unavailable'))
    })
    useAppStore.setState({ connectionBusy: null, mode: 'hard', tunRunning: true, serverSwitchingName: 'Norway' })
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: 'Отменить смену сервера' }))
    await waitFor(() => expect(useAppStore.getState().connectionCancelling).toBe(false))
    expect(useAppStore.getState().serverSwitchingName).toBe('Norway')
    expect(useAppStore.getState().tunRunning).toBe(true)
  })
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
    const cancellation = deferred<{ success: true }>()
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
    await act(async () => {
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
    const cancellation = deferred<{ success: true }>()
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
    if (kind === 'failed result') vi.mocked(window.electronAPI.cancelTun).mockResolvedValue({ success: false, error: 'Cleanup failed', code: 'IPC_INTERNAL_ERROR', category: 'internal' })
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
    const start = deferred<{ success: true }>()
    const cancel = deferred<{ success: true }>()
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
