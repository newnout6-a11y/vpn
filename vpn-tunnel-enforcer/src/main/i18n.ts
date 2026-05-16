/**
 * i18n Backend — main process module for locale detection and persistence.
 *
 * Responsibilities:
 * - Detects system locale on Windows (via app.getLocale())
 * - Persists user locale choice in electron-store
 * - Registers IPC handlers: i18n:get-locale, i18n:set-locale, i18n:get-system-locale
 */

import { app, ipcMain, BrowserWindow } from 'electron'
import Store from 'electron-store'
import type { Locale } from '../shared/ipc-types'

// ─── Constants ───────────────────────────────────────────────────────────────

const SUPPORTED_LOCALES: Locale[] = ['en', 'ru']
const DEFAULT_LOCALE: Locale = 'en'

// ─── Store ───────────────────────────────────────────────────────────────────

interface I18nStoreSchema {
  locale: Locale
}

const i18nStore = new Store<I18nStoreSchema>({
  name: 'i18n',
  defaults: {
    locale: detectSystemLocale()
  }
})

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Detects the system locale and maps it to a supported Locale.
 * Uses Electron's app.getLocale() which returns BCP 47 language tags (e.g. "ru", "en-US").
 * Falls back to 'en' if the system locale is not supported.
 */
function detectSystemLocale(): Locale {
  try {
    const systemLocale = app.getLocale()
    const lang = systemLocale.split('-')[0].toLowerCase()
    if (SUPPORTED_LOCALES.includes(lang as Locale)) {
      return lang as Locale
    }
  } catch {
    // app.getLocale() may throw if called before app is ready in some edge cases
  }
  return DEFAULT_LOCALE
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const i18nBackend = {
  /**
   * Returns the currently persisted locale.
   */
  getLocale(): Locale {
    const stored = i18nStore.get('locale')
    if (SUPPORTED_LOCALES.includes(stored)) {
      return stored
    }
    return DEFAULT_LOCALE
  },

  /**
   * Sets and persists the locale. Only accepts supported locales.
   */
  setLocale(locale: Locale): void {
    if (!SUPPORTED_LOCALES.includes(locale)) return
    i18nStore.set('locale', locale)
  },

  /**
   * Returns the detected system locale mapped to a supported Locale.
   */
  getSystemLocale(): Locale {
    return detectSystemLocale()
  }
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerI18nIpcHandlers(): void {
  ipcMain.handle('i18n:get-locale', () => {
    return i18nBackend.getLocale()
  })

  ipcMain.handle('i18n:set-locale', (_event, locale: Locale) => {
    i18nBackend.setLocale(locale)
    // Notify all renderer windows about the locale change
    for (const win of BrowserWindow.getAllWindows()) {
      if (!win.isDestroyed()) {
        win.webContents.send('i18n:locale-changed', locale)
      }
    }
  })

  ipcMain.handle('i18n:get-system-locale', () => {
    return i18nBackend.getSystemLocale()
  })
}
