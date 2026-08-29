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
 *
 * EVERY level is written, not a subset. This used to push seven properties and
 * leave `--rgb-card-elevated`, `--rgb-border-strong`, `--rgb-text-muted` and the
 * state colours at their globals.css values — which had been tuned for a canvas
 * much darker than the built-in dark theme shipped. Half the palette came from
 * the theme and half from a stylesheet that disagreed with it, so surfaces
 * collapsed into one flat field and state colours could not be themed at all.
 */
function applyThemeToDocument(theme: ThemeConfig): void {
  const root = document.documentElement

  const tokenMap: Record<string, string | undefined> = {
    '--rgb-bg': theme.colors.background,
    '--rgb-sidebar': theme.colors.sidebar,
    '--rgb-card': theme.colors.cardBackground,
    '--rgb-card-elevated': theme.colors.cardElevated,
    '--rgb-accent': theme.colors.accent,
    '--rgb-text': theme.colors.text,
    '--rgb-text-secondary': theme.colors.textSecondary,
    '--rgb-text-muted': theme.colors.textMuted,
    '--rgb-border': theme.colors.border,
    '--rgb-border-strong': theme.colors.borderStrong,
    '--rgb-success': theme.colors.success,
    '--rgb-warning': theme.colors.warning,
    '--rgb-danger': theme.colors.danger
  }

  for (const [cssVar, hex] of Object.entries(tokenMap)) {
    // A theme stored before this palette was widened can still be missing a
    // level. Leave the stylesheet default in place rather than writing "0 0 0".
    if (!hex) continue
    root.style.setProperty(cssVar, hexToRgbChannels(hex))
  }

  // `--rgb-accent-hover` is derived rather than themed: asking every theme
  // author to supply a matching hover shade invites mismatches.
  if (theme.colors.accent) {
    root.style.setProperty('--rgb-accent-hover', shiftForHover(theme.colors.accent, theme.mode))
  }

  // Set data-theme attribute for CSS selectors
  const effectiveMode = theme.mode === 'system'
    ? (isSystemDark() ? 'dark' : 'light')
    : theme.mode
  root.setAttribute('data-theme', effectiveMode)
}

/**
 * Hover shade for the accent: lighter in dark mode, darker in light mode, so the
 * hover always moves *away* from the surface it sits on.
 */
function shiftForHover(hex: string, mode: ThemeConfig['mode']): string {
  const channels = hexToRgbChannels(hex).split(' ').map(Number)
  const towardsLight = mode === 'light'
    ? false
    : mode === 'dark'
      ? true
      : isSystemDark()
  const shifted = channels.map((c) =>
    towardsLight
      ? Math.min(255, Math.round(c + (255 - c) * 0.28))
      : Math.max(0, Math.round(c * 0.78))
  )
  return shifted.join(' ')
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
