// AT-08-004/005, F-198: unknown provider cleanup must not be advertised as stopped.
import { act, cleanup, render, screen } from '@testing-library/react'
import { createInstance } from 'i18next'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import ru from '../i18n/locales/ru.json'
import en from '../i18n/locales/en.json'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
const fixture = vi.hoisted(() => ({ status: vi.fn() }))
vi.mock('../store', () => ({ useAppStore: (select: (state: any) => unknown) => select({
  leakSelfTestResult: null, lastMainError: null, exportingDiagnostics: false,
  addLog: vi.fn(), setLeakSelfTestResult: vi.fn(), setExportingDiagnostics: vi.fn()
}) }))
vi.mock('../design-system', () => ({
  MacCard: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  MacButton: ({ children, onClick, disabled }: { children: ReactNode; onClick: () => void; disabled?: boolean }) => <button onClick={onClick} disabled={disabled}>{children}</button>
}))
import { DiagnosticsCard } from './DiagnosticsCard'
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function renderCard(locale: 'ru' | 'en' = 'ru') {
  const i18n = createInstance()
  await i18n.use(initReactI18next).init({
    resources: { ru: { translation: ru }, en: { translation: en } }, lng: locale,
    interpolation: { escapeValue: false }, react: { useSuspense: false }
  })
  await act(async () => { render(<I18nextProvider i18n={i18n}><DiagnosticsCard /></I18nextProvider>) })
  return i18n
}

describe('capture cleanup visibility', () => {
  it.each(['ru', 'en'] as const)('localizes the legacy warning and follows language changes (%s)', async locale => {
    fixture.status.mockResolvedValue({ cleanupPending: true, lastError: 'LegacyCaptureCleanupRequired: русский текст backend' })
    const previous = window.electronAPI
    Object.assign(window, { electronAPI: { getTrafficForensicsStatus: fixture.status } })
    try {
      const i18n = await renderCard(locale)
      const strings = (locale === 'ru' ? ru : en).diagnosticsCapture
      expect(await screen.findByText(strings.pendingLabel)).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toBe(strings.legacyCleanupRequired)
      const nextLocale = locale === 'ru' ? 'en' : 'ru'
      await act(async () => { await i18n.changeLanguage(nextLocale) })
      expect(screen.getByRole('alert').textContent).toBe((nextLocale === 'ru' ? ru : en).diagnosticsCapture.legacyCleanupRequired)
      expect(screen.queryByText('LegacyCaptureCleanupRequired: русский текст backend')).toBeNull()
    } finally { Object.assign(window, { electronAPI: previous }) }
  })
  it.each(['ru', 'en'] as const)('localizes unknown cleanup when the status request fails (%s)', async locale => {
    fixture.status.mockRejectedValue(new Error('inspection failed'))
    const previous = window.electronAPI
    Object.assign(window, { electronAPI: { getTrafficForensicsStatus: fixture.status } })
    try {
      await renderCard(locale)
      const strings = (locale === 'ru' ? ru : en).diagnosticsCapture
      expect(await screen.findByText(strings.pendingLabel)).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toBe(strings.statusUnavailable)
      expect(screen.queryByText(strings.stoppedLabel)).toBeNull()
    } finally { Object.assign(window, { electronAPI: previous }) }
  })
  it.each([true, false])('shows unconfirmed cleanup instead of success when running=%s', async running => {
    fixture.status.mockResolvedValue({ running, enabled: false, cleanupPending: true, lastError: 'Capture stop remains unconfirmed', health: {} })
    const api = { getTrafficForensicsStatus: fixture.status }
    const previous = window.electronAPI
    Object.assign(window, { electronAPI: api })
    try {
      await renderCard()
      expect(await screen.findByText('ОСТАНОВКА НЕ ПОДТВЕРЖДЕНА')).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toContain('Capture stop remains unconfirmed')
      expect(screen.queryByText('СБОР ОСТАНОВЛЕН')).toBeNull()
    } finally { Object.assign(window, { electronAPI: previous }) }
  })
})
