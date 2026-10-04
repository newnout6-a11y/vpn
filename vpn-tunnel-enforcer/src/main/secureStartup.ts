import { settingsStore, type AppSettings } from './settings'
import { serverPickerStore, serverGroupsStore } from './sharedStores'

/** AT-01-001/010: open every startup secret store before recovery or automation.
 * A failed read must take the startup-refusal path, not ordinary VPN shutdown. */
export function readSecureStartupSettings(): AppSettings {
  const settings = settingsStore.get()
  serverPickerStore.get('profiles')
  serverGroupsStore.get('groups')
  return settings
}

/** Do not inspect exception text/properties: startup errors may contain secrets. */
export function startupFailureDetail(error: unknown, stage: 'secure-store-preflight' | 'startup'): {
  code: 'SECURE_STORE_PREFLIGHT_FAILED' | 'STARTUP_FAILED'
  type: 'Error' | 'NonError'
} {
  return {
    code: stage === 'secure-store-preflight' ? 'SECURE_STORE_PREFLIGHT_FAILED' : 'STARTUP_FAILED',
    type: error instanceof Error ? 'Error' : 'NonError'
  }
}

/** AT-01-001/010: let app.quit() flush Chromium keys, without network cleanup. */
export function handleSecureStartupBeforeQuit(refused: boolean, markQuitting: () => void): boolean {
  if (!refused) return false
  markQuitting()
  return true
}
