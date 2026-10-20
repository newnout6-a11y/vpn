import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
// AT-00-004/008: notification failures, partial evidence and component lifetime.
import { ipcError } from '../../shared/ipc-result'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { NotificationSettings } from './NotificationSettings'
import type { NotificationPreferences } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string) => k,
    i18n: { language: 'ru', changeLanguage: vi.fn() }
  })
}))

describe('<NotificationSettings />', () => {
  const mockPrefs: NotificationPreferences = {
    method: 'system',
    sound: true,
    vpnConnect: true,
    vpnDisconnect: true,
    leakDetected: true,
    profileRotation: true,
    scheduleTriggered: false,
    connectionError: true
  }

  beforeEach(() => {
    ;(globalThis as any).window = (globalThis as any).window || {}
    ;(globalThis as any).window.electronAPI = {
      notificationsGetPrefs: vi.fn().mockResolvedValue(mockPrefs),
      notificationsSetPrefs: vi.fn().mockImplementation(async (partial) => ({ ...mockPrefs, ...partial })),
      checkOsNotificationState: vi.fn().mockResolvedValue({ osNotificationsEnabled: true }),
      notificationsResetOsBlock: vi.fn().mockResolvedValue({ cleared: [], errors: [] }),
      notificationsOpenWindowsSettings: vi.fn().mockResolvedValue({ ok: true })
    }
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('renders preferences correctly when IPC succeeds', async () => {
    render(<NotificationSettings />)

    await waitFor(() => {
      expect(screen.getByText('notifications.title')).toBeInTheDocument()
    })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows error banner and retry button when initial load fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.notificationsGetPrefs.mockRejectedValueOnce(new Error('Preferences service unavailable'))

    render(<NotificationSettings />)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByText('Preferences service unavailable')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Повторить|common\.retry/ })).toBeInTheDocument()

    // When clicking retry
    api.notificationsGetPrefs.mockResolvedValueOnce(mockPrefs)
    fireEvent.click(screen.getByRole('button', { name: /Повторить|common\.retry/ }))

    await waitFor(() => {
      expect(screen.getByText('notifications.title')).toBeInTheDocument()
    })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows error banner when updating preferences fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.notificationsSetPrefs.mockRejectedValueOnce(new Error('IPC write failed'))

    render(<NotificationSettings />)

    await waitFor(() => {
      expect(screen.getByText('notifications.title')).toBeInTheDocument()
    })

    // Find sound switch and click it
    const switches = screen.getAllByRole('switch')
    fireEvent.click(switches[0])

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByText('IPC write failed')).toBeInTheDocument()

    // Dismiss error banner
    const dismissBtn = screen.getByRole('button', { name: 'Dismiss error' })
    fireEvent.click(dismissBtn)

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows error banner and allows retry when checkOsNotificationState fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.checkOsNotificationState.mockRejectedValueOnce(new Error('OS notifications check failed'))

    render(<NotificationSettings />)

    await waitFor(() => {
      expect(screen.getByText('OS notifications check failed')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toBeInTheDocument()

    // When clicking retry and check succeeds
    api.checkOsNotificationState.mockResolvedValueOnce({ osNotificationsEnabled: true })
    const retryBtn = screen.getByRole('button', { name: /Повторить|common\.retry/ })
    fireEvent.click(retryBtn)

    await waitFor(() => {
      expect(screen.queryByText('OS notifications check failed')).not.toBeInTheDocument()
    })
  })

  it('allows dismissing OS check error banner', async () => {
    const api = (globalThis as any).window.electronAPI
    api.checkOsNotificationState.mockRejectedValueOnce(new Error('OS status lookup error'))

    render(<NotificationSettings />)

    await waitFor(() => {
      expect(screen.getByText('OS status lookup error')).toBeInTheDocument()
    })

    const dismissBtn = screen.getByRole('button', { name: 'Dismiss OS error' })
    fireEvent.click(dismissBtn)

    expect(screen.queryByText('OS status lookup error')).not.toBeInTheDocument()
  })
  async function renderBlocked() {
    const api = window.electronAPI as any
    api.checkOsNotificationState.mockResolvedValue({ osNotificationsEnabled: false })
    const view = render(<NotificationSettings />)
    await screen.findByText('notifications.resetWindowsBlock')
    return { api, ...view }
  }

  it.each(['notificationsResetOsBlock', 'notificationsOpenWindowsSettings'])('shows canonical rejection from %s', async method => {
    const { api } = await renderBlocked()
    api[method].mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('permission') })
    fireEvent.click(screen.getByText(method === 'notificationsResetOsBlock' ? 'notifications.resetWindowsBlock' : 'notifications.openWindowsSettings'))
    expect(await screen.findByText(ipcError('permission').message)).toBeInTheDocument()
  })

  it('shows a partial reset report even if the next OS check sees enabled', async () => {
    const { api } = await renderBlocked()
    api.notificationsResetOsBlock.mockResolvedValue({ cleared: ['current'], errors: [{ appUserModelId: 'legacy', error: ipcError('permission') }] })
    api.checkOsNotificationState.mockResolvedValue({ osNotificationsEnabled: true })
    fireEvent.click(screen.getByText('notifications.resetWindowsBlock'))
    expect(await screen.findByText(/notifications.resetPartial/)).toBeInTheDocument()
    expect(screen.getByText(/Недостаточно прав/)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('notifications.resetWindowsBlock')).not.toBeInTheDocument())
  })

  it('keeps typed cancellation quiet', async () => {
    const { api } = await renderBlocked()
    api.notificationsResetOsBlock.mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('cancelled') })
    fireEvent.click(screen.getByText('notifications.resetWindowsBlock'))
    await waitFor(() => expect(api.notificationsResetOsBlock).toHaveBeenCalledOnce())
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('does not recheck or schedule delayed work after a pending reset unmounts', async () => {
    const { api, unmount } = await renderBlocked()
    let resolve!: (value: unknown) => void
    api.notificationsResetOsBlock.mockReturnValue(new Promise(r => { resolve = r }))
    fireEvent.click(screen.getByText('notifications.resetWindowsBlock'))
    unmount()
    resolve({ cleared: ['current'], errors: [] })
    await Promise.resolve(); await Promise.resolve()
    expect(api.checkOsNotificationState).toHaveBeenCalledOnce()
  })

  it('ignores an older OS read completing after a newer blocked result', async () => {
    const api = window.electronAPI as any
    let resolve!: (value: unknown) => void
    api.checkOsNotificationState.mockReturnValueOnce(new Promise(r => { resolve = r }))
    render(<NotificationSettings />)
    await screen.findByText('notifications.title')
    api.checkOsNotificationState.mockResolvedValue({ osNotificationsEnabled: false })
    fireEvent(window, new Event('focus'))
    await screen.findByText('notifications.resetWindowsBlock')
    resolve({ osNotificationsEnabled: true })
    await Promise.resolve(); await Promise.resolve()
    expect(screen.getByText('notifications.resetWindowsBlock')).toBeInTheDocument()
  })

  it('disables duplicate resets while pending and clears the delayed poll on unmount', async () => {
    const { api, unmount } = await renderBlocked()
    let resolve!: (value: unknown) => void
    api.notificationsResetOsBlock.mockReturnValue(new Promise(r => { resolve = r }))
    const button = screen.getByText('notifications.resetWindowsBlock')
    fireEvent.click(button)
    fireEvent.click(button)
    expect(api.notificationsResetOsBlock).toHaveBeenCalledOnce()
    expect(button).toBeDisabled()
    vi.useFakeTimers()
    await act(async () => resolve({ cleared: [], errors: [] }))
    expect(api.checkOsNotificationState).toHaveBeenCalledTimes(2)
    unmount()
    await act(async () => { vi.advanceTimersByTime(2000) })
    expect(api.checkOsNotificationState).toHaveBeenCalledTimes(2)
  })

})
