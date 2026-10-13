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

    // Navigate through all steps to the complete step (7 Next clicks)
    for (let i = 0; i < 7; i++) {
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

    for (let i = 0; i < 7; i++) {
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

    for (let i = 0; i < 7; i++) {
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
  it.each(['themeSetActive', 'i18nSetLocale'])('keeps onboarding incomplete if %s fails', async method => {
    const api = window.electronAPI as any
    api[method].mockRejectedValueOnce(new Error('Preference failed'))
    const onComplete = vi.fn()
    render(<FirstRunWizard onComplete={onComplete} onSkip={vi.fn()} />)
    for (let i = 0; i < 7; i++) fireEvent.click(screen.getByText('onboarding.next'))
    fireEvent.click(await screen.findByText('onboarding.finish'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Preference failed')
    expect(api.saveSettings).not.toHaveBeenCalled()
    expect(onComplete).not.toHaveBeenCalled()
  })


  // AT-09-014: optional key import and autostart steps.
  const next = (times: number) => { for (let i = 0; i < times; i++) fireEvent.click(screen.getByText('onboarding.next')) }

  it('imports a validated key and enables autostart on finish', async () => {
    const api = window.electronAPI as any
    api.inspectVpnInput = vi.fn().mockResolvedValue({ count: 1, protocols: { vless: 1 }, profiles: [], fetched: false, source: 'text' })
    api.setLoginItem = vi.fn().mockResolvedValue({})
    const onComplete = vi.fn()
    render(<FirstRunWizard onComplete={onComplete} onSkip={vi.fn()} />)
    next(5)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: ' vless://key ' } })
    fireEvent.click(screen.getByText('onboarding.importKeyButton'))
    expect(await screen.findByRole('status')).toBeInTheDocument()
    next(1)
    fireEvent.click(screen.getByRole('checkbox'))
    next(1)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    await waitFor(() => expect(onComplete).toHaveBeenCalled())
    expect(api.inspectVpnInput).toHaveBeenCalledTimes(1)
    expect(api.setLoginItem).toHaveBeenCalledWith(true)
    expect(api.saveSettings).toHaveBeenCalledWith(expect.objectContaining({ directVpnInput: 'vless://key' }))
  })

  it('does not keep a key the app rejected, and an edit drops a previous validation', async () => {
    const api = window.electronAPI as any
    api.inspectVpnInput = vi.fn().mockResolvedValueOnce({ count: 1, protocols: {}, profiles: [], fetched: false, source: 'text' }).mockResolvedValueOnce({ count: 0, protocols: {}, profiles: [], fetched: false, source: 'text' })
    render(<FirstRunWizard onComplete={vi.fn()} onSkip={vi.fn()} />)
    next(5)
    const box = screen.getByRole('textbox')
    fireEvent.change(box, { target: { value: 'vless://good' } })
    fireEvent.click(screen.getByText('onboarding.importKeyButton'))
    await screen.findByRole('status')
    fireEvent.change(box, { target: { value: 'garbage' } })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('onboarding.importKeyButton'))
    expect(await screen.findByRole('alert')).toHaveTextContent('onboarding.keyInvalid')
    next(2)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    await waitFor(() => expect(api.saveSettings).toHaveBeenCalled())
    expect(api.saveSettings.mock.calls[0][0]).not.toHaveProperty('directVpnInput')
  })

  it('ignores an inspection result that arrives after the text was edited', async () => {
    const api = window.electronAPI as any
    let resolveInspect: (value: unknown) => void = () => {}
    api.inspectVpnInput = vi.fn().mockReturnValue(new Promise((resolve) => { resolveInspect = resolve }))
    render(<FirstRunWizard onComplete={vi.fn()} onSkip={vi.fn()} />)
    next(5)
    const box = screen.getByRole('textbox')
    fireEvent.change(box, { target: { value: 'vless://old' } })
    fireEvent.click(screen.getByText('onboarding.importKeyButton'))
    fireEvent.change(box, { target: { value: 'vless://new' } })
    resolveInspect({ count: 1, protocols: {}, profiles: [], fetched: false, source: 'text' })
    await Promise.resolve(); await Promise.resolve()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    next(2)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    await waitFor(() => expect(api.saveSettings).toHaveBeenCalled())
    expect(api.saveSettings.mock.calls[0][0]).not.toHaveProperty('directVpnInput')
  })

  it('keeps onboarding incomplete when the chosen autostart cannot be enabled', async () => {
    const api = window.electronAPI as any
    api.setLoginItem = vi.fn().mockRejectedValue(new Error('schtasks refused'))
    const onComplete = vi.fn()
    render(<FirstRunWizard onComplete={onComplete} onSkip={vi.fn()} />)
    next(6)
    fireEvent.click(screen.getByRole('checkbox'))
    next(1)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    expect(await screen.findByRole('alert')).toHaveTextContent('schtasks refused')
    expect(api.saveSettings).not.toHaveBeenCalled()
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('restores the previous autostart when saving onboarding completion fails afterwards', async () => {
    const api = window.electronAPI as any
    api.setLoginItem = vi.fn().mockResolvedValue({})
    api.saveSettings.mockRejectedValueOnce(new Error('Disk full'))
    render(<FirstRunWizard onComplete={vi.fn()} onSkip={vi.fn()} />)
    next(6)
    fireEvent.click(screen.getByRole('checkbox'))
    next(1)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Disk full')
    expect(api.setLoginItem).toHaveBeenNthCalledWith(1, true)
    expect(api.setLoginItem).toHaveBeenNthCalledWith(2, false)
  })

  it('skipping both optional steps changes nothing', async () => {
    const api = window.electronAPI as any
    api.setLoginItem = vi.fn()
    render(<FirstRunWizard onComplete={vi.fn()} onSkip={vi.fn()} />)
    next(7)
    fireEvent.click(await screen.findByText('onboarding.finish'))
    await waitFor(() => expect(api.saveSettings).toHaveBeenCalled())
    expect(api.setLoginItem).not.toHaveBeenCalled()
    expect(api.saveSettings.mock.calls[0][0]).not.toHaveProperty('directVpnInput')
  })

})
