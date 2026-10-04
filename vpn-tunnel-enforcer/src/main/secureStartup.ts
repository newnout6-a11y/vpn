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
