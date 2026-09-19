import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
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
      checkOsNotificationState: vi.fn().mockResolvedValue({ osNotificationsEnabled: true })
    }
  })

  afterEach(() => {
    cleanup()
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
    expect(screen.getByRole('button', { name: 'Повторить' })).toBeInTheDocument()

    // When clicking retry
    api.notificationsGetPrefs.mockResolvedValueOnce(mockPrefs)
    fireEvent.click(screen.getByRole('button', { name: 'Повторить' }))

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
})
