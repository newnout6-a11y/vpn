/**
 * Thin wrapper around Electron's Notification class.
 *
 * Behaviour:
 *  - Respects the user's `desktopNotifications` setting. When off, every call
 *    is a no-op.
 *  - If the platform doesn't support notifications (some headless envs), we
 *    just log and move on instead of crashing.
 *  - Coalesces duplicate notifications fired within 1.5s. sing-box can
 *    rapid-fire crash/restart cycles and we don't want to spam the user with
 *    five identical toasts.
 *  - Checks Windows OS notification state for the app. If the user disabled
 *    notifications in Windows Settings, we skip showing and the renderer UI
 *    surfaces a warning banner so the in-app toggle stays honest.
 */
import { Notification, app } from 'electron'
import { exec } from 'child_process'
import { promisify } from 'util'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'

export type NotificationLevel = 'info' | 'warn' | 'error'

interface PendingKey {
  title: string
  body: string
  ts: number
}

let lastNotification: PendingKey | null = null
const COALESCE_MS = 1500

// ─── Windows OS notification state detection ────────────────────────────────

interface OsNotificationState {
  /** true when Windows is allowed to show notifications for this app */
  enabled: boolean
  /** which AppUserModelID was found in the registry (or null if none matched) */
  appUserModelId: string | null
}

let _osState: OsNotificationState | null = null
let _osStateTs = 0
const OS_STATE_TTL_MS = 30_000

/** Known candidate AppUserModelIDs this app may use (dev and packaged). */
function candidateModelIds(): string[] {
  const ids: string[] = []
  try {
    ids.push(app.getName())
  } catch { /* app might not be ready */ }
  ids.push('com.vpntunnelenforcer.app')
  // Deduplicate
  return [...new Set(ids.filter(Boolean))]
}

/**
 * Windows stores per-app notification allow/block state in the registry at:
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\{AppUserModelID}
 * with a DWORD value named "Enabled" (1 = allowed, 0 = blocked, absent = default-allowed).
 *
 * We try every known candidate AppUserModelID for this app and return the
 * first match.  If none is found we assume notifications are enabled.
 */
const execAsync = promisify(exec)

export async function getWindowsNotificationState(): Promise<OsNotificationState> {
  const now = Date.now()
  if (_osState && now - _osStateTs < OS_STATE_TTL_MS) {
    return _osState
  }

  // Default: enabled
  const result: OsNotificationState = { enabled: true, appUserModelId: null }

  for (const modelId of candidateModelIds()) {
    const regPath = `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\${modelId}`
    try {
      const { stdout } = await execAsync(
        `reg query "${regPath}" /v Enabled`,
        { timeout: 3000, windowsHide: true }
      )
      // reg output looks like:
      //   "...\Settings\vpn-tunnel-enforcer\r\n    Enabled    REG_DWORD    0x0"
      const match = stdout.match(/Enabled\s+REG_DWORD\s+(0x[0-9a-f]+)/i)
      if (match) {
        const value = parseInt(match[1], 16)
        result.enabled = value !== 0
        result.appUserModelId = modelId
        break
      }
    } catch {
      // Key doesn't exist → Windows default (enabled), try next candidate
      continue
    }
  }

  _osState = result
  _osStateTs = now
  return result
}

/** Invalidate the cached OS state so the next call re-reads the registry. */
export function invalidateOsNotificationStateCache(): void {
  _osState = null
  _osStateTs = 0
}

// ─── Notify ─────────────────────────────────────────────────────────────────

export async function notify(level: NotificationLevel, title: string, body: string): Promise<void> {
  try {
    const settings = settingsStore.get()
    if (!settings.desktopNotifications) return

    // Drop duplicates fired right after each other.
    const now = Date.now()
    if (
      lastNotification &&
      lastNotification.title === title &&
      lastNotification.body === body &&
      now - lastNotification.ts < COALESCE_MS
    ) {
      return
    }
    lastNotification = { title, body, ts: now }

    if (!Notification.isSupported()) {
      logEvent('debug', 'notify', 'platform does not support notifications', { level, title })
      return
    }

    // Check if Windows itself blocks notifications for this app.
    const osState = await getWindowsNotificationState()
    if (!osState.enabled) {
      logEvent('debug', 'notify', 'skipped — Windows blocks notifications for this app')
      return
    }

    const n = new Notification({
      title,
      body,
      urgency: level === 'error' ? 'critical' : level === 'warn' ? 'normal' : 'low',
      silent: level === 'info'
    })
    n.show()
  } catch (err) {
    logEvent('warn', 'notify', 'failed to show notification', { err: (err as Error)?.message, level, title })
  }
}
