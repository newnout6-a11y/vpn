/**
 * Theme Manager — main process module for theme persistence and system theme detection.
 *
 * Responsibilities:
 * - Defines built-in light and dark themes
 * - Detects system theme (Windows dark mode via nativeTheme)
 * - Persists active theme and custom themes in electron-store
 * - Registers IPC handlers: theme:list, theme:get-active, theme:set-active, theme:create, theme:delete
 * - Listens for system theme changes and notifies renderer
 */

import { ipcMain, nativeTheme, BrowserWindow } from 'electron'
import Store from 'electron-store'
import type { ThemeConfig } from '../shared/ipc-types'

// ─── Built-in Themes ─────────────────────────────────────────────────────────
//
// SURFACE LADDER. The previous palettes were flat: dark shipped background
// #1c1c1e with sidebar #1c1c1e — byte-identical, so the nav rail had no edge at
// all — and cardBackground #2c2c2e, 16 levels up, with no elevated level defined
// anywhere. Light was similar: #f5f5f7 canvas under #ffffff cards.
//
// Both ladders below keep a deliberate, visible step between every level, and
// the sidebar is its own level rather than a copy of the canvas:
//
//   dark:   background → sidebar → card → cardElevated   (each step ~+7..+12)
//   light:  background → sidebar (darker) → card (near-white) → cardElevated
//
// Light inverts the direction on purpose: on a light canvas, cards read as cards
// by being LIGHTER than their surroundings, so the canvas is tinted down and the
// card goes to near-white. Commit 40d9063 already pushed the light canvas darker
// for this reason; this continues it rather than reverting it.

const LIGHT_THEME: ThemeConfig = {
  id: 'builtin-light',
  name: 'Light',
  mode: 'light',
  isCustom: false,
  colors: {
    background: '#e6e9f0',
    sidebar: '#dde1eb',
    cardBackground: '#fbfcfe',
    cardElevated: '#ffffff',
    accent: '#0060c0',
    text: '#14161c',
    textSecondary: '#5a616f',
    textMuted: '#8a91a0',
    border: '#ced4e0',
    borderStrong: '#b0b8c8',
    success: '#1e9b3c',
    warning: '#b87200',
    danger: '#c62d23'
  }
}

const DARK_THEME: ThemeConfig = {
  id: 'builtin-dark',
  name: 'Dark',
  mode: 'dark',
  isCustom: false,
  // Surfaces, text and accent follow VS Code's "Dark Modern"
  // (extensions/theme-defaults/themes/dark_modern.json):
  //   #1f1f1f editor.background   #181818 sideBar/panel/statusBar.background
  //   #313131 input/dropdown.bg   #3c3c3c input.border
  //   #cccccc foreground          #9d9d9d descriptionForeground
  //   #0078d4 button.background / focusBorder
  //
  // Two things this buys us. The greys are NEUTRAL — the previous dark palette
  // carried a blue cast (13/14/18, 31/33/41), which is what made it read as a
  // generic dark theme rather than a considered one. And the rail is genuinely
  // darker than the canvas, the way editor chrome sits behind its document,
  // instead of being a near-copy of it.
  //
  // #0078d4 is the Fluent/Windows blue rather than Apple's #0a84ff: same family,
  // markedly less electric, and it belongs on the platform this app runs on.
  //
  // FOUR VALUES ARE DELIBERATELY NOT DARK MODERN, because that theme has no
  // equivalent of our layout. VS Code paints panels edge-to-edge at
  // editor.background and separates them with borders; we stack rounded cards on
  // a canvas, so a card must differ from the canvas by luminance, not just by a
  // hairline. Measured contrast ratios drove each choice:
  //   cardBackground #2d2d2d  — Dark Modern's own #262626 gives only 1.09:1
  //                             against the canvas, i.e. invisible as a surface;
  //                             this gives 1.20:1.
  //   cardElevated   #383838  — 1.17:1 over the card (its #313131 is 1.09:1).
  //   border         #3c3c3c  — input.border, not panel.border #2b2b2b, which
  //                             sat at 1.03:1 on the card and vanished.
  //   textSecondary  #a3a3a3  — #9d9d9d clears AA on the canvas and card but
  //                             lands at 4.32:1 on cardElevated, and secondary
  //                             text does appear inside inputs and inner panels.
  // Everything here clears WCAG AA on every surface it is used on; see
  // themePalette.test.ts, which pins the ladder ordering.
  colors: {
    background: '#1f1f1f',
    sidebar: '#181818',
    cardBackground: '#2d2d2d',
    cardElevated: '#383838',
    accent: '#0078d4',
    text: '#cccccc',
    textSecondary: '#a3a3a3',
    textMuted: '#7a7a7a',
    border: '#3c3c3c',
    borderStrong: '#4d4d4d',
    success: '#30d158',
    warning: '#ffd60a',
    danger: '#ff453a'
  }
}

const SYSTEM_THEME: ThemeConfig = {
  id: 'builtin-system',
  name: 'System',
  mode: 'system',
  isCustom: false,
  colors: nativeTheme.shouldUseDarkColors ? { ...DARK_THEME.colors } : { ...LIGHT_THEME.colors }
}

// ─── Store ───────────────────────────────────────────────────────────────────

interface ThemeStoreSchema {
  activeThemeId: string
  customThemes: ThemeConfig[]
}

const themeStore = new Store<ThemeStoreSchema>({
  name: 'themes',
  defaults: {
    activeThemeId: 'builtin-system',
    customThemes: []
  }
})

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Fill in palette levels a stored theme predates.
 *
 * Custom themes persisted before the palette was widened carry only the original
 * seven colours. Returning those as-is would leave `--rgb-card-elevated`,
 * `--rgb-border-strong`, `--rgb-text-muted` and the state colours unset, and the
 * renderer would silently fall back to whatever the previous theme had written —
 * so switching to an old custom theme would inherit half of another palette.
 * Missing levels borrow from the built-in theme matching the stored mode.
 */
function withFullPalette(theme: ThemeConfig): ThemeConfig {
  const base = theme.mode === 'light' ? LIGHT_THEME.colors : DARK_THEME.colors
  const stored = (theme.colors ?? {}) as Partial<ThemeConfig['colors']>
  return {
    ...theme,
    colors: {
      background: stored.background ?? base.background,
      sidebar: stored.sidebar ?? base.sidebar,
      cardBackground: stored.cardBackground ?? base.cardBackground,
      cardElevated: stored.cardElevated ?? base.cardElevated,
      accent: stored.accent ?? base.accent,
      text: stored.text ?? base.text,
      textSecondary: stored.textSecondary ?? base.textSecondary,
      textMuted: stored.textMuted ?? base.textMuted,
      border: stored.border ?? base.border,
      borderStrong: stored.borderStrong ?? base.borderStrong,
      success: stored.success ?? base.success,
      warning: stored.warning ?? base.warning,
      danger: stored.danger ?? base.danger
    }
  }
}

function getBuiltinThemes(): ThemeConfig[] {
  return [LIGHT_THEME, DARK_THEME, getSystemTheme()]
}

function getSystemTheme(): ThemeConfig {
  const isDark = nativeTheme.shouldUseDarkColors
  return {
    ...SYSTEM_THEME,
    colors: isDark ? { ...DARK_THEME.colors } : { ...LIGHT_THEME.colors }
  }
}

function getAllThemes(): ThemeConfig[] {
  const customThemes = (themeStore.get('customThemes') || []).map(withFullPalette)
  return [...getBuiltinThemes(), ...customThemes]
}

function getActiveTheme(): ThemeConfig {
  const activeId = themeStore.get('activeThemeId') || 'builtin-system'
  const allThemes = getAllThemes()
  const found = allThemes.find((t) => t.id === activeId)
  if (!found) {
    // Fallback to system theme if active theme was deleted
    return getSystemTheme()
  }
  // If the active theme is the system theme, resolve its colors dynamically
  if (found.id === 'builtin-system') {
    return getSystemTheme()
  }
  return found
}

function generateId(): string {
  return `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const themeManager = {
  getAllThemes,
  getActiveTheme,

  setActiveTheme(id: string): void {
    const allThemes = getAllThemes()
    const exists = allThemes.some((t) => t.id === id)
    if (!exists) return
    themeStore.set('activeThemeId', id)
  },

  createTheme(theme: Omit<ThemeConfig, 'id' | 'isCustom'>): ThemeConfig {
    const newTheme: ThemeConfig = {
      ...theme,
      id: generateId(),
      isCustom: true
    }
    const customThemes = themeStore.get('customThemes') || []
    customThemes.push(newTheme)
    themeStore.set('customThemes', customThemes)
    return newTheme
  },

  deleteTheme(id: string): void {
    // Cannot delete built-in themes
    if (id.startsWith('builtin-')) return
    const customThemes = (themeStore.get('customThemes') || []).filter((t) => t.id !== id)
    themeStore.set('customThemes', customThemes)
    // If the deleted theme was active, fall back to system
    if (themeStore.get('activeThemeId') === id) {
      themeStore.set('activeThemeId', 'builtin-system')
    }
  }
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerThemeIpcHandlers(): void {
  ipcMain.handle('theme:list', () => {
    return themeManager.getAllThemes()
  })

  ipcMain.handle('theme:get-active', () => {
    return themeManager.getActiveTheme()
  })

  ipcMain.handle('theme:set-active', (_event, id: string) => {
    themeManager.setActiveTheme(id)
    // Notify all renderer windows about the theme change
    const activeTheme = themeManager.getActiveTheme()
    for (const win of BrowserWindow.getAllWindows()) {
      if (!win.isDestroyed()) {
        win.webContents.send('theme-changed', activeTheme)
      }
    }
  })

  ipcMain.handle('theme:create', (_event, theme: Omit<ThemeConfig, 'id' | 'isCustom'>) => {
    return themeManager.createTheme(theme)
  })

  ipcMain.handle('theme:delete', (_event, id: string) => {
    themeManager.deleteTheme(id)
  })

  // Listen for system theme changes and notify renderer
  nativeTheme.on('updated', () => {
    const activeId = themeStore.get('activeThemeId')
    if (activeId === 'builtin-system') {
      const activeTheme = themeManager.getActiveTheme()
      for (const win of BrowserWindow.getAllWindows()) {
        if (!win.isDestroyed()) {
          win.webContents.send('theme-changed', activeTheme)
        }
      }
    }
  })
}
