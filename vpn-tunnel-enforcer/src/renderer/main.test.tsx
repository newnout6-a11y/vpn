import { afterEach, expect, it, vi } from 'vitest'
import { ipcError, IpcRemoteError, serializeIpcError } from '../shared/ipc-result'

vi.mock('./App', () => ({ default: () => null }))
vi.mock('./i18n', () => ({}))
vi.mock('react-dom/client', () => ({ default: { createRoot: () => ({ render: vi.fn() }) } }))

afterEach(() => vi.restoreAllMocks())

// AT-00-004: exercise the production listener, including failure of the reporting IPC itself.
it('logs typed rejections readably and contains a rejected logRenderer promise', async () => {
  const listeners = vi.spyOn(window, 'addEventListener')
  const logRenderer = vi.fn().mockRejectedValue(new Error('reporting unavailable'))
  window.electronAPI = { logRenderer } as unknown as typeof window.electronAPI
  await import('./main')
  const registrations = listeners.mock.calls.filter(([name]) => name === 'error' || name === 'unhandledrejection')
  try {
    const rejection = registrations.find(([name]) => name === 'unhandledrejection')![1] as EventListener
    const data = serializeIpcError(new IpcRemoteError(ipcError('permission')), 'en')
    rejection({ reason: data } as unknown as Event)
    expect(logRenderer).toHaveBeenCalledWith('error', '[window.unhandledrejection] Permission denied')
    const ordinary = new Error('local error')
    rejection({ reason: ordinary } as unknown as Event)
    expect(logRenderer).toHaveBeenLastCalledWith('error', `[window.unhandledrejection] ${ordinary.stack}`)
    const windowError = registrations.find(([name]) => name === 'error')![1] as EventListener
    windowError({ error: ordinary } as unknown as Event)
    expect(logRenderer).toHaveBeenLastCalledWith('error', `[window.onerror] ${ordinary.stack}`)
    // Rejected reporting promises must be observed, otherwise Vitest reports an unhandled rejection.
    await new Promise(resolve => setTimeout(resolve, 0))
  } finally {
    for (const [name, listener] of registrations) window.removeEventListener(name, listener)
  }
})
