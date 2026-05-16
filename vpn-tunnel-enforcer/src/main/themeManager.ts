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

const LIGHT_THEME: ThemeConfig = {
  id: 'builtin-light',
  name: 'Light',
  mode: 'light',
  isCustom: false,
  colors: {
    background: '#f5f5f7',
    cardBackground: '#ffffff',
    accent: '#007aff',
    text: '#1d1d1f',
    textSecondary: '#86868b',
    sidebar: '#f0f0f2',
    border: '#e5e5ea'
  }
}

const DARK_THEME: ThemeConfig = {
  id: 'builtin-dark',
  name: 'Dark',
  mode: 'dark',
  isCustom: false,
  colors: {
    background: '#1c1c1e',
    cardBackground: '#2c2c2e',
    accent: '#0a84ff',
    text: '#f5f5f7',
    textSecondary: '#98989d',
    sidebar: '#1c1c1e',
    border: '#38383a'
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
  const customThemes = themeStore.get('customThemes') || []
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
        win.webContents.send('theme:changed', activeTheme)
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
          win.webContents.send('theme:changed', activeTheme)
        }
      }
    }
  })
}
