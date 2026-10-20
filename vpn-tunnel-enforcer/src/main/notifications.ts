/**
 * Thin wrapper around Electron's Notification class.
 *
 * Behaviour:
 *  - Respects the user's `desktopNotifications` setting. When off, every call
 *    is a no-op.
 *  - If the platform doesn't support notifications (some headless envs), we
 *    fall back to an in-app toast via the registered fallback callback so the
 *    user still sees the message instead of silently losing it.
 *  - Coalesces duplicate notifications fired within 1.5s. sing-box can
 *    rapid-fire crash/restart cycles and we don't want to spam the user with
 *    five identical toasts.
 *  - Checks Windows OS notification state for the app. If the user disabled
 *    notifications in Windows Settings (or clicked "Don't show notifications"
 *    on a toast), we skip the OS toast and route through the in-app fallback;
 *    the renderer UI surfaces a warning banner with a "Reset Windows block"
 *    button so the in-app toggle stays honest.
 */
import { Notification, app } from 'electron'
import { notificationRegistry } from './notificationRegistry'
import { logEvent } from './appLogger'
import { settingsStore } from './settings'
import type { NotificationResetReport } from '../shared/ipc-types'
import { classifyIpcError, ipcError, IpcFault } from '../shared/ipc-result'

export type NotificationLevel = 'info' | 'warn' | 'error'

/**
 * Notification event categories the user can individually toggle in Settings →
 * Notifications. When a `notify()` call passes one of these, we consult the
 * per-event preferences (and the system/inapp/both method) before showing the
 * toast. Calls that omit it (eventType === undefined) always show, gated only
 * by the global desktopNotifications switch — used for messages that don't map
 * to a category.
 */
export type NotificationEventType =
  | 'vpnConnect'
  | 'vpnDisconnect'
  | 'leakDetected'
  | 'profileRotation'
  | 'scheduleTriggered'
  | 'connectionError'

interface PendingKey {
  title: string
  body: string
  ts: number
}

let lastNotification: PendingKey | null = null
const COALESCE_MS = 1500

// ─── In-app fallback callback ───────────────────────────────────────────────
//
// The main process registers a callback (in index.ts) that forwards the
// notification to the renderer over IPC, where it's surfaced as an in-app
// toast. This is the safety net for the case where the OS blocks our toasts
// or doesn't support them at all — without it, every notification would be
// silently swallowed once the user clicked "Don't show notifications".

type InAppFallbackCallback = (level: NotificationLevel, title: string, body: string) => void
let inAppFallbackCb: InAppFallbackCallback | null = null

/** Register the renderer-bound fallback. Called once from main during whenReady. */
export function setInAppFallbackCallback(cb: InAppFallbackCallback): void {
  inAppFallbackCb = cb
}

// ─── Per-event notification preferences provider ────────────────────────────
//
// notificationPrefs.ts registers this at startup. We invert the dependency
// (provider pattern, like the in-app fallback above) so notifications.ts never
// imports notificationPrefs.ts — that would be circular, since notificationPrefs
// imports notify() from here. The provider returns the current preferences, or
// null when none registered (tests / very early startup), in which case notify()
// behaves as before (gated only by the global desktopNotifications switch).

interface NotifyPrefsLike {
  method?: 'system' | 'inapp' | 'both'
  [eventType: string]: unknown
}
type PrefsProvider = () => NotifyPrefsLike | null
let prefsProvider: PrefsProvider | null = null

export function setNotificationPrefsProvider(provider: PrefsProvider): void {
  prefsProvider = provider
}

// ─── Windows OS notification state detection ────────────────────────────────

interface OsNotificationState {
  /** true when Windows is allowed to show notifications for this app */
  enabled: boolean
  /** which AppUserModelID was found in the registry (or null if none matched) */
  appUserModelId: string | null
}

let _osState: OsNotificationState | null = null
let _osStateTs = 0
let osStateRevision = 0
let osStateError: { error: IpcFault; ts: number } | null = null
let osStatePending: { revision: number; promise: Promise<OsNotificationState> } | null = null
const OS_STATE_TTL_MS = 30_000

/**
 * Known candidate AppUserModelIDs this app may use. Order matters: the AUMID
 * we EXPLICITLY set in main/index.ts (`com.vpntunnelenforcer.app`) takes
 * priority. The legacy `app.getName()` fallback is kept so users upgrading
 * from older builds — where Electron used the auto-generated id — can still
 * see their previously-applied registry block. That legacy block now has to
 * be cleared via `resetWindowsNotificationBlock()`, which iterates over
 * every entry in this list.
 */
function candidateModelIds(): string[] {
  return ['com.vpntunnelenforcer.app', (() => {
    try { return app.getName() } catch { return '' }
  })()].filter((s, i, a) => s && a.indexOf(s) === i)
}

/**
 * Windows stores per-app notification allow/block state in the registry at:
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\{AppUserModelID}
 * with a DWORD value named "Enabled" (1 = allowed, 0 = blocked, absent = default-allowed).
 *
 * We try every known candidate AppUserModelID for this app and return the
 * first match.  If none is found we assume notifications are enabled.
 */
export async function getWindowsNotificationState(force = false): Promise<OsNotificationState> {
  if (process.platform !== 'win32') return { enabled: true, appUserModelId: null }
  if (force) invalidateOsNotificationStateCache()
  const now = Date.now()
  const revision = osStateRevision
  if (_osState && now - _osStateTs < OS_STATE_TTL_MS) return _osState
  if (osStateError && now - osStateError.ts < OS_STATE_TTL_MS) throw osStateError.error
  if (osStatePending?.revision === revision) return osStatePending.promise
  const promise = (async () => {
    try {
      const result: OsNotificationState = { enabled: true, appUserModelId: null }
      for (const modelId of candidateModelIds()) {
        const { value } = await notificationRegistry(modelId)
        if (value === null) continue
        result.enabled = value !== 0
        result.appUserModelId = modelId
        break
      }
      if (revision === osStateRevision) { _osState = result; _osStateTs = Date.now(); osStateError = null }
      return result
    } catch (error) {
      logEvent('warn', 'notify', 'notification registry read failed', error)
      const fault = new IpcFault(classifyIpcError(error))
      if (revision === osStateRevision) osStateError = { error: fault, ts: Date.now() }
      throw fault
    } finally {
      if (osStatePending?.revision === revision) osStatePending = null
    }
  })()
  osStatePending = { revision, promise }
  return promise
}

/** Invalidate the cached OS state so the next call re-reads the registry. */
export function invalidateOsNotificationStateCache(): void {
  ++osStateRevision
  _osState = null
  _osStateTs = 0
  osStateError = null
}

/**
 * Delete the Windows-side notification block for this app. The block is a
 * DWORD `Enabled = 0x0` under
 *   HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\<AppUserModelID>.
 * We clear values for EVERY known AUMID candidate so old blocks from previous
 * builds (back when Electron auto-generated the AUMID) are also cleared.
 *
 * Implementation note: we delete only `Enabled` when it is explicitly `0`.
 * That clears the block without erasing an explicit allow-state or any other
 * settings Windows might have stored under that AUMID node.
 *
 * After this, the OS treats us as default-allowed; Windows Settings will
 * repopulate our entry the next time we show a toast.
 *
 * Returns the list of AUMIDs that were cleared (empty if no block existed)
 * and canonical per-AUMID errors. The caller can show
 * a friendly result regardless of registry state.
 */
export async function resetWindowsNotificationBlock(): Promise<NotificationResetReport> {
  const report: NotificationResetReport = { cleared: [], errors: [] }
  if (process.platform !== 'win32') return report
  for (const modelId of candidateModelIds()) {
    try {
      if ((await notificationRegistry(modelId, true)).cleared) report.cleared.push(modelId)
    } catch (error) {
      logEvent('warn', 'notify', 'notification reset diagnostic', error)
      report.errors.push({ appUserModelId: modelId, error: ipcError(classifyIpcError(error)) })
    }
  }
  invalidateOsNotificationStateCache()
  logEvent(report.errors.length ? 'warn' : 'info', 'notify', 'reset Windows notification block', report)
  return report
}

// ─── Notify ─────────────────────────────────────────────────────────────────

export async function notify(level: NotificationLevel, title: string, body: string, eventType?: NotificationEventType): Promise<void> {
  try {
    const settings = settingsStore.get()
    if (!settings.desktopNotifications) return

    // Per-event-type gating. When the caller categorises the notification, we
    // honour the user's individual toggles + delivery method from the
    // notification-prefs store. Read it lazily (require) to avoid a circular
    // import with notificationPrefs.ts. Failures here never block the toast —
    // we fall back to "show via system".
    let method: 'system' | 'inapp' | 'both' = 'system'
    if (eventType) {
      try {
        const prefs = prefsProvider ? prefsProvider() : null
        if (prefs && typeof prefs === 'object') {
          // Event disabled → drop entirely.
          if (prefs[eventType] === false) return
          if (prefs.method === 'inapp' || prefs.method === 'both' || prefs.method === 'system') {
            method = prefs.method
          }
        }
      } catch {
        /* prefs unavailable — fall through with method='system' */
      }
    }

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

    // 'inapp' method → never show an OS toast, always route to the in-app
    // fallback. (When no eventType is given, method stays 'system'.)
    if (method === 'inapp') {
      inAppFallbackCb?.(level, title, body)
      return
    }

    if (!Notification.isSupported()) {
      logEvent('debug', 'notify', 'platform does not support notifications — using in-app fallback', { level, title })
      inAppFallbackCb?.(level, title, body)
      return
    }

    // Delivery never waits for registry/PowerShell. Unknown status remains
    // unknown in the strict Settings API; attempt OS delivery plus fallback.
    const osState = _osState && Date.now() - _osStateTs < OS_STATE_TTL_MS ? _osState : null
    if (!osState) void getWindowsNotificationState().catch(() => {})
    if (osState?.enabled === false) {
      logEvent('debug', 'notify', 'Windows blocks notifications — using in-app fallback', { level, title })
      inAppFallbackCb?.(level, title, body)
      return
    }

    const n = new Notification({
      title,
      body,
      urgency: level === 'error' ? 'critical' : level === 'warn' ? 'normal' : 'low',
      silent: level === 'info'
    })
    n.show()

    // 'both' → also surface in-app alongside the OS toast.
    if (method === 'both' || !osState) {
      try { inAppFallbackCb?.(level, title, body) } catch { /* swallow */ }
    }
  } catch (err) {
    logEvent('warn', 'notify', 'failed to show notification — using in-app fallback', { err: (err as Error)?.message, level, title })
    // Last-ditch: try to surface in-app even when the OS path threw. If the
    // fallback itself throws (e.g. main window torn down), there's nothing
    // sensible left to do.
    try { inAppFallbackCb?.(level, title, body) } catch { /* swallow */ }
  }
}
