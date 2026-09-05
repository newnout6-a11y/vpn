import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'

// ── Mocks ──────────────────────────────────────────────────────────────────────
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string) => k, i18n: { language: 'ru', changeLanguage: vi.fn() } }),
}))
vi.mock('../providers/ThemeProvider', () => ({
  useTheme: () => ({ theme: { id: 'sys', mode: 'system' }, themes: [], setTheme: vi.fn() }),
}))
vi.mock('../components/KillSwitchSettings', () => ({ KillSwitchSettings: () => null }))
vi.mock('../components/RotationSettings', () => ({ RotationSettings: () => null }))
vi.mock('../components/DnsSettings', () => ({ DnsSettings: () => null }))
vi.mock('../components/DomainRouting', () => ({ DomainRouting: () => null }))
vi.mock('../components/ImportExportSettings', () => ({ ImportExportSettings: () => null }))
vi.mock('../components/NotificationSettings', () => ({ NotificationSettings: () => null }))

import { Settings } from './Settings'
import { useAppStore } from '../store'

const DEFAULTS = useAppStore.getState().settings

beforeEach(() => {
  useAppStore.setState({ settings: { ...DEFAULTS }, logs: [], globalToasts: [] as any })
  ;(globalThis as any).window.electronAPI = {
    checkOsNotificationState: vi.fn().mockResolvedValue({ osNotificationsEnabled: true }),
    smartRouteRuleSetsGetState: vi.fn().mockResolvedValue({
      managedComplete: false, lastRefreshFinishedAt: null, lastRefreshOk: null, lastRefreshError: null,
    }),
    adaptiveBypassGetStatus: vi.fn().mockResolvedValue({ message: '', mode: 'baseline', phase: 'idle' }),
    saveSettings: vi.fn().mockImplementation(async (partial: any) => ({
      ...useAppStore.getState().settings, ...partial,
    })),
    applyLocationPrivacy: vi.fn().mockResolvedValue({ applied: true }),
    rollbackLocationPrivacy: vi.fn().mockResolvedValue({ applied: false }),
  }
})
afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const bar = () => screen.queryByText('Есть несохранённые изменения')
const switchInRow = (labelRe: RegExp) => {
  const row = screen.getByText(labelRe).closest('div')!.parentElement!
  return within(row).getByRole('switch')
}

describe('<Settings/> save bar', () => {
  it('is hidden on first render', async () => {
    render(<Settings />)
    await screen.findByText('settings.title')
    expect(bar()).not.toBeInTheDocument()
  })

  it('appears after toggling a switch, and Reset restores the control + hides it', async () => {
    render(<Settings />)
    await screen.findByText('settings.title')

    const toggle = switchInRow(/Жёсткая блокировка адаптеров/) // strictAdapterLockdown: true by default
    expect(toggle).toHaveAttribute('aria-checked', 'true')

    fireEvent.click(toggle)
    await waitFor(() => expect(bar()).toBeInTheDocument())
    expect(switchInRow(/Жёсткая блокировка адаптеров/)).toHaveAttribute('aria-checked', 'false')

    fireEvent.click(screen.getByRole('button', { name: 'Сбросить несохранённые изменения' }))
    await waitFor(() => expect(bar()).not.toBeInTheDocument())
    expect(switchInRow(/Жёсткая блокировка адаптеров/)).toHaveAttribute('aria-checked', 'true')
  })

  it('instant-apply location toggle shows a toast and never raises the save bar', async () => {
    render(<Settings />)
    await screen.findByText('settings.title')

    fireEvent.click(switchInRow(/Скрывать местоположение Windows/))

    await waitFor(() => expect(window.electronAPI.applyLocationPrivacy).toHaveBeenCalled())
    await waitFor(() =>
      expect(useAppStore.getState().globalToasts.some((t: any) => /Местоположение Windows/.test(t.title))).toBe(true),
    )
    expect(bar()).not.toBeInTheDocument()
  })

  it('persists on Save and then hides', async () => {
    render(<Settings />)
    await screen.findByText('settings.title')

    fireEvent.click(switchInRow(/Совместимость с публичным Wi-Fi/)) // publicWifiCompatibility: true → false
    await waitFor(() => expect(bar()).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Сохранить и применить/ }))

    await waitFor(() =>
      expect(window.electronAPI.saveSettings).toHaveBeenCalledWith(
        expect.objectContaining({ publicWifiCompatibility: false }),
      ),
    )
    await waitFor(() => expect(bar()).not.toBeInTheDocument())
  })
})
