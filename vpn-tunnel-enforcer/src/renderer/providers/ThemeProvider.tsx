/**
 * ThemeProvider — React context provider for theme management.
 *
 * Responsibilities:
 * - Fetches active theme from main process via IPC on mount
 * - Applies CSS custom properties to document root based on ThemeConfig.colors
 * - Listens for theme change events from main process (system theme changes)
 * - Provides theme context to children (current theme, setTheme function, all themes)
 */

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import type { ThemeConfig } from '../../shared/ipc-types'

// ─── Context Types ───────────────────────────────────────────────────────────

interface ThemeContextValue {
  theme: ThemeConfig | null
  themes: ThemeConfig[]
  setTheme: (id: string) => Promise<void>
  loading: boolean
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: null,
  themes: [],
  setTheme: async () => {},
  loading: true
})

// ─── CSS Custom Property Application ─────────────────────────────────────────

/**
 * Convert a hex colour ("#1d1d1f" or "#fff") into space-separated RGB channels
 * ("29 29 31") so Tailwind's `/<alpha>` modifier can splice in opacity.
 *
 * Falls back to "0 0 0" for malformed input rather than throwing — a bad theme
 * value should not blow up rendering.
 */
function hexToRgbChannels(hex: string): string {
  const trimmed = hex.trim().replace(/^#/, '')
  const expanded = trimmed.length === 3
    ? trimmed.split('').map((c) => c + c).join('')
    : trimmed
  if (!/^[0-9a-fA-F]{6}$/.test(expanded)) return '0 0 0'
  const r = parseInt(expanded.slice(0, 2), 16)
  const g = parseInt(expanded.slice(2, 4), 16)
  const b = parseInt(expanded.slice(4, 6), 16)
  return `${r} ${g} ${b}`
}

/**
 * Apply theme colours to the document root by writing RGB-channel triples to
 * `--rgb-*` custom properties. The CSS-ready `--color-*` aliases derive from
 * those automatically (see globals.css), so writing `--rgb-bg` is enough to
 * propagate the change everywhere.
 */
function applyThemeToDocument(theme: ThemeConfig): void {
  const root = document.documentElement

  const tokenMap: Record<string, string> = {
    '--rgb-bg': theme.colors.background,
    '--rgb-card': theme.colors.cardBackground,
    '--rgb-accent': theme.colors.accent,
    '--rgb-text': theme.colors.text,
    '--rgb-text-secondary': theme.colors.textSecondary,
    '--rgb-sidebar': theme.colors.sidebar,
    '--rgb-border': theme.colors.border
  }

  for (const [cssVar, hex] of Object.entries(tokenMap)) {
    root.style.setProperty(cssVar, hexToRgbChannels(hex))
  }

  // Set data-theme attribute for CSS selectors
  const effectiveMode = theme.mode === 'system'
    ? (isSystemDark() ? 'dark' : 'light')
    : theme.mode
  root.setAttribute('data-theme', effectiveMode)
}

function isSystemDark(): boolean {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
}

// ─── Provider Component ──────────────────────────────────────────────────────

interface ThemeProviderProps {
  children: React.ReactNode
}

export function ThemeProvider({ children }: ThemeProviderProps): React.ReactElement {
  const [theme, setThemeState] = useState<ThemeConfig | null>(null)
  const [themes, setThemes] = useState<ThemeConfig[]>([])
  const [loading, setLoading] = useState(true)

  // Fetch initial theme and theme list from main process
  useEffect(() => {
    let cancelled = false

    async function init(): Promise<void> {
      try {
        const api = (window as any).electronAPI
        if (!api) {
          // Fallback: no electron API available (e.g., in tests or web mode)
          setLoading(false)
          return
        }

        const [activeTheme, allThemes] = await Promise.all([
          api.themeGetActive?.() as Promise<ThemeConfig | undefined>,
          api.themeList?.() as Promise<ThemeConfig[] | undefined>
        ])

        if (cancelled) return

        if (activeTheme) {
          setThemeState(activeTheme)
          applyThemeToDocument(activeTheme)
        }
        if (allThemes) {
          setThemes(allThemes)
        }
      } catch (err) {
        console.warn('[ThemeProvider] Failed to load theme:', err)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    init()
    return () => { cancelled = true }
  }, [])

  // Listen for theme changes from main process (e.g., system theme change)
  useEffect(() => {
    const api = (window as any).electronAPI
    if (!api?.onThemeChanged) return

    const unsubscribe = api.onThemeChanged((newTheme: ThemeConfig) => {
      setThemeState(newTheme)
      applyThemeToDocument(newTheme)
    })

    return () => {
      if (typeof unsubscribe === 'function') unsubscribe()
    }
  }, [])

  // Set theme by ID
  const setTheme = useCallback(async (id: string) => {
    try {
      const api = (window as any).electronAPI
      if (!api?.themeSetActive) return

      await api.themeSetActive(id)

      // Fetch the updated active theme
      const activeTheme = await api.themeGetActive?.()
      if (activeTheme) {
        setThemeState(activeTheme)
        applyThemeToDocument(activeTheme)
      }

      // Refresh themes list in case something changed
      const allThemes = await api.themeList?.()
      if (allThemes) {
        setThemes(allThemes)
      }
    } catch (err) {
      console.warn('[ThemeProvider] Failed to set theme:', err)
    }
  }, [])

  const contextValue: ThemeContextValue = {
    theme,
    themes,
    setTheme,
    loading
  }

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  )
}

// ─── Hook ────────────────────────────────────────────────────────────────────

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext)
}
