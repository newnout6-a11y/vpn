// AT-00-004/008: partial cleanup and failed histories never display full success.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createInstance } from 'i18next'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import ru from '../i18n/locales/ru.json'
import en from '../i18n/locales/en.json'
import { ipcError, serializeIpcError, IpcFault } from '../../shared/ipc-result'
vi.mock('../components/PageTip', () => ({ PageTip: () => null }))
import { Logs } from './Logs'
import { useAppStore } from '../store'
const row = { id: 'fixture', profileName: 'retained-history', startedAt: 1000, endedAt: 2000, mode: 'direct', bytesDown: 0, bytesUp: 0, disconnectReason: 'user' }
const complete = { success: true, cleared: ['app-log', 'snapshots'], errors: [] }
const partial = { success: false, cleared: ['app-log'], errors: [{ artifact: 'snapshots', error: ipcError('permission') }] }
const deferred = <T,>() => { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r }); return { promise, resolve } }
beforeEach(() => {
  useAppStore.setState({ logs: [], globalToasts: [] })
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  Object.assign(window, { electronAPI: {
    connectionHistoryList: vi.fn().mockResolvedValue([row]), connectionHistoryFilter: vi.fn().mockResolvedValue([row]),
    connectionHistoryStats: vi.fn().mockResolvedValue({ totalTimeMs: 1000, totalBytesDown: 0, totalBytesUp: 0, entryCount: 1 }),
    getFullLogs: vi.fn().mockResolvedValue([]), connectionHistoryClear: vi.fn().mockResolvedValue(undefined),
    trafficHistoryClear: vi.fn().mockResolvedValue(undefined), clearDiagnosticArtifacts: vi.fn().mockResolvedValue(complete),
    clearAppLog: vi.fn().mockResolvedValue(complete)
  } })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })
async function page(locale: 'ru' | 'en' = 'ru') {
  const i18n = createInstance()
  await i18n.use(initReactI18next).init({ resources: { ru: { translation: ru }, en: { translation: en } }, lng: locale, interpolation: { escapeValue: false } })
  const view = render(<I18nextProvider i18n={i18n}><Logs /></I18nextProvider>)
  await screen.findByText('retained-history')
  return { ...view, clear: () => fireEvent.click(screen.getByRole('button', { name: locale === 'ru' ? ru.logs.clear : en.logs.clear })) }
}
describe('Logs cleanup', () => {
  it.each(['ru', 'en'] as const)('shows canonical partial failure in %s and never calls log cleanup twice', async locale => {
    vi.mocked(window.electronAPI.clearDiagnosticArtifacts).mockResolvedValue(partial as any)
    const view = await page(locale); view.clear()
    await waitFor(() => expect(useAppStore.getState().globalToasts).toHaveLength(1))
    const toast = useAppStore.getState().globalToasts[0]
    expect(toast.variant).toBe('error')
    expect(toast.description).toContain(ipcError('permission', locale).message)
    expect(toast.description).toContain(locale === 'ru' ? 'Удалено: 3' : 'Cleared: 3')
    expect(toast.description).toContain(locale === 'ru' ? 'ошибок: 1' : 'failed: 1')
    expect(window.electronAPI.clearAppLog).not.toHaveBeenCalled()
    expect(screen.queryByText('retained-history')).toBeNull()
  })
  it('waits for every clear and retains failed connection history', async () => {
    const pending = deferred<any>()
    vi.mocked(window.electronAPI.clearDiagnosticArtifacts).mockReturnValue(pending.promise)
    vi.mocked(window.electronAPI.connectionHistoryClear).mockRejectedValue(serializeIpcError(new IpcFault('permission'), 'ru'))
    const view = await page(); view.clear()
    await act(async () => {})
    expect(useAppStore.getState().globalToasts).toHaveLength(0)
    expect(screen.getByText('retained-history')).toBeInTheDocument()
    await act(async () => pending.resolve(complete))
    expect(useAppStore.getState().globalToasts[0].variant).toBe('error')
    expect(screen.getByText('retained-history')).toBeInTheDocument()
  })
  it('shows success only after all cleanup completed', async () => {
    const view = await page(); view.clear()
    await waitFor(() => expect(useAppStore.getState().globalToasts[0]?.variant).toBe('success'))
    expect(screen.queryByText('retained-history')).toBeNull()
  })
  it('suppresses a late toast after unmount and blocks duplicate clicks', async () => {
    const pending = deferred<any>()
    vi.mocked(window.electronAPI.clearDiagnosticArtifacts).mockReturnValue(pending.promise)
    const view = await page(); view.clear(); view.clear()
    expect(window.electronAPI.clearDiagnosticArtifacts).toHaveBeenCalledOnce()
    view.unmount()
    await act(async () => pending.resolve(partial))
    expect(useAppStore.getState().globalToasts).toHaveLength(0)
  })
})
