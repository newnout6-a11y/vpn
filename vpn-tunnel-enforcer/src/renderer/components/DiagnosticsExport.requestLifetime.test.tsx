// AT-00-003/008: actual DiagnosticsCard, Settings and Maintenance export workflows.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcError } from '../../shared/ipc-result'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: 'ru' } }) }))
vi.mock('../providers/ThemeProvider', () => ({ useTheme: () => ({ theme: { id: 'sys', mode: 'system' }, themes: [], setTheme: vi.fn() }) }))
vi.mock('./KillSwitchSettings', () => ({ KillSwitchSettings: () => null }))
vi.mock('./RotationSettings', () => ({ RotationSettings: () => null }))
vi.mock('./DnsSettings', () => ({ DnsSettings: () => null }))
vi.mock('./DomainRouting', () => ({ DomainRouting: () => null }))
vi.mock('./ImportExportSettings', () => ({ ImportExportSettings: () => null }))
vi.mock('./NotificationSettings', () => ({ NotificationSettings: () => null }))
import { DiagnosticsCard } from './DiagnosticsCard'
import { Settings } from '../pages/Settings'
import { Maintenance } from '../pages/Maintenance'
import { useAppStore } from '../store'
let pending: Array<{ resolve(value: unknown): void; reject(error: unknown): void }>
let api: Record<string, ReturnType<typeof vi.fn>>
const surfaces = [['card', DiagnosticsCard, 'Отправить логи разработчику'], ['settings', Settings, 'Экспорт диагностики (ZIP)'], ['maintenance', Maintenance, 'ZIP']] as const
beforeEach(() => {
  useAppStore.setState({ logs: [], globalToasts: [], exportingDiagnostics: false, maintenanceRunningAction: null, maintenanceLastResult: null, maintenanceSystemDiagnostics: null, maintenanceFirewallHealth: null })
  pending = []
  api = { operationsCancelRequest: vi.fn(async () => true),
    exportDiagnostics: vi.fn(() => new Promise((resolve, reject) => pending.push({ resolve, reject }))),
    getTrafficForensicsStatus: vi.fn(async () => ({ running: false })),
    checkOsNotificationState: vi.fn(async () => ({ osNotificationsEnabled: true })),
    smartRouteRuleSetsGetState: vi.fn(async () => ({})), adaptiveBypassGetStatus: vi.fn(async () => null) }
  Object.assign(window, { electronAPI: api })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })
describe('diagnostics ZIP UI ownership', () => {
  it.each(surfaces)('%s cancels on unmount and suppresses late success/error effects', async (_name, Component, label) => {
    const view = render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    const token = api.exportDiagnostics.mock.calls[0][0]
    expect(token).toMatch(/^[0-9a-f-]{36}$/)
    expect(useAppStore.getState().exportingDiagnostics).toBe(true)
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(token)
    expect(useAppStore.getState().exportingDiagnostics).toBe(false)
    const next = render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    const count = useAppStore.getState().logs.length
    await act(async () => { pending[0].resolve({ success: true, path: 'old.zip', warning: 'cleanup-failed' }) })
    expect(useAppStore.getState().logs).toHaveLength(count)
    expect(useAppStore.getState().exportingDiagnostics).toBe(true)
    expect(useAppStore.getState().globalToasts).toEqual([])
    expect(screen.queryByText('old.zip')).toBeNull()
    expect(useAppStore.getState().maintenanceLastResult).toBeNull()
    next.unmount()
    await act(async () => { pending[1].reject(new Error('late error')) })
    expect(useAppStore.getState().logs).toHaveLength(count)
  })
  it.each(surfaces)('%s finishes current export, reports cleanup warning and forgets its token', async (_name, Component, label) => {
    const view = render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    fireEvent.click(screen.getByRole('button', { name: label }))
    expect(api.exportDiagnostics).toHaveBeenCalledOnce()
    await act(async () => { pending[0].resolve({ success: true, path: 'current.zip', warning: 'cleanup-failed' }) })
    expect(useAppStore.getState().exportingDiagnostics).toBe(false)
    expect(useAppStore.getState().logs.some(log => log.message.includes('current.zip'))).toBe(true)
    expect(useAppStore.getState().globalToasts.at(-1)).toMatchObject({ variant: 'warning', title: 'Очистка диагностики не завершена' })
    if (_name === 'card') expect(screen.getByText('current.zip')).toBeTruthy()
    if (_name === 'maintenance') expect(useAppStore.getState().maintenanceLastResult).toBe('Диагностика сохранена: current.zip')
    view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
  it.each(surfaces)('%s keeps typed cancellation quiet and permits retry', async (_name, Component, label) => {
    render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    const count = useAppStore.getState().logs.length
    await act(async () => { pending[0].reject({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
    expect(useAppStore.getState().logs).toHaveLength(count)
    expect(useAppStore.getState().globalToasts).toEqual([])
    expect(useAppStore.getState().exportingDiagnostics).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: label }))
    expect(api.exportDiagnostics).toHaveBeenCalledTimes(2)
    expect(api.exportDiagnostics.mock.calls[0][0]).not.toBe(api.exportDiagnostics.mock.calls[1][0])
    await act(async () => { pending[1].resolve({ cancelled: true, success: false }) })
  })
  it.each(surfaces)('%s reports manual picker dismissal without a failure toast', async (_name, Component, label) => {
    render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[0].resolve({ success: false, cancelled: true }) })
    expect(useAppStore.getState().logs.at(-1)?.message).toBe('Экспорт диагностики отменён пользователем.')
    expect(useAppStore.getState().globalToasts).toEqual([])
    expect(useAppStore.getState().exportingDiagnostics).toBe(false)
  })
  it.each(surfaces)('%s displays the bounded remote error message', async (_name, Component, label) => {
    render(<Component />); await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[0].reject({ name: 'IpcRemoteError', ...ipcError('permission') }) })
    expect(useAppStore.getState().logs.at(-1)?.message).toContain(ipcError('permission').message)
    if (_name === 'maintenance') expect(useAppStore.getState().globalToasts.at(-1)).toMatchObject({ variant: 'error', description: expect.stringContaining(ipcError('permission').message) })
    expect(useAppStore.getState().exportingDiagnostics).toBe(false)
  })
})
