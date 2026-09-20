import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { FirstRunWizard } from './FirstRunWizard'
import { useAppStore } from '../store'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string) => k,
    i18n: { language: 'en', changeLanguage: vi.fn() }
  })
}))

// framer-motion mock to render contents simply
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
    button: ({ children, ...props }: any) => <button {...props}>{children}</button>
  },
  AnimatePresence: ({ children }: any) => <>{children}</>
}))

describe('<FirstRunWizard /> save error handling', () => {
  beforeEach(() => {
    useAppStore.setState({
      settings: { ...useAppStore.getState().settings, firstRunComplete: false },
      logs: []
    })
    ;(globalThis as any).window = (globalThis as any).window || {}
    ;(globalThis as any).window.electronAPI = {
      saveSettings: vi.fn().mockResolvedValue({}),
      detectHapp: vi.fn().mockResolvedValue(null),
      themeSetActive: vi.fn().mockResolvedValue(true),
      i18nSetLocale: vi.fn().mockResolvedValue(true),
      killSwitchSetLevel: vi.fn().mockResolvedValue(true)
    }
  })

  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it('navigates to completion step and blocks onComplete when saveSettings fails', async () => {
    const onComplete = vi.fn()
    const onSkip = vi.fn()
    const api = (globalThis as any).window.electronAPI
    api.saveSettings.mockRejectedValueOnce(new Error('Disk full: unable to save settings'))

    render(<FirstRunWizard onComplete={onComplete} onSkip={onSkip} />)

    // Navigate through all steps to the complete step (5 Next clicks)
    for (let i = 0; i < 5; i++) {
      const nextBtn = screen.getByText('onboarding.next')
      fireEvent.click(nextBtn)
    }

    // Now on complete step, finish button should be visible
    const finishBtn = await screen.findByText('onboarding.finish')
    expect(finishBtn).toBeInTheDocument()

    // Click finish
    fireEvent.click(finishBtn)

    // Alert should appear with the error message
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByText('Disk full: unable to save settings')).toBeInTheDocument()

    // onComplete MUST NOT have been called!
    expect(onComplete).not.toHaveBeenCalled()
    // Local store must not consider firstRunComplete
    expect(useAppStore.getState().settings.firstRunComplete).toBe(false)
  })

  it('calls onComplete when saveSettings succeeds', async () => {
    const onComplete = vi.fn()
    const onSkip = vi.fn()

    render(<FirstRunWizard onComplete={onComplete} onSkip={onSkip} />)

    for (let i = 0; i < 5; i++) {
      const nextBtn = screen.getByText('onboarding.next')
      fireEvent.click(nextBtn)
    }

    const finishBtn = await screen.findByText('onboarding.finish')
    fireEvent.click(finishBtn)

    await waitFor(() => {
      expect(onComplete).toHaveBeenCalled()
    })
    expect(useAppStore.getState().settings.firstRunComplete).toBe(true)
  })

  it('blocks onComplete and shows alert when killSwitchSetLevel fails', async () => {
    const onComplete = vi.fn()
    const onSkip = vi.fn()
    const api = (globalThis as any).window.electronAPI
    api.killSwitchSetLevel.mockRejectedValueOnce(new Error('Kill switch save failed'))

    render(<FirstRunWizard onComplete={onComplete} onSkip={onSkip} />)

    for (let i = 0; i < 5; i++) {
      const nextBtn = screen.getByText('onboarding.next')
      fireEvent.click(nextBtn)
    }

    const finishBtn = await screen.findByText('onboarding.finish')
    fireEvent.click(finishBtn)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByText('Kill switch save failed')).toBeInTheDocument()
    expect(onComplete).not.toHaveBeenCalled()
    expect(useAppStore.getState().settings.firstRunComplete).toBe(false)
  })
})
