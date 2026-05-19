/**
 * Lightweight global navigation bus.
 *
 * The app uses imperative `setPage` state inside App.tsx instead of a router,
 * so deep components (selector dropdowns, inline links, error banners) can't
 * navigate by themselves. Rather than threading a callback through every
 * component, we dispatch a CustomEvent that App.tsx listens for once and
 * translates into a `setPage(...)` call.
 *
 * Usage from anywhere in the renderer:
 *
 *   import { navigateTo } from '../nav'
 *   navigateTo('servers')
 *
 * In App.tsx:
 *
 *   useEffect(() => {
 *     const handler = (e: Event) => setPage((e as CustomEvent).detail)
 *     window.addEventListener('vpnte:navigate', handler)
 *     return () => window.removeEventListener('vpnte:navigate', handler)
 *   }, [])
 */

export type AppPage =
  | 'dashboard'
  | 'apps'
  | 'servers'
  | 'speedtest'
  | 'availability'
  | 'trafficHistory'
  | 'schedule'
  | 'maintenance'
  | 'settings'
  | 'logs'

export const NAV_EVENT = 'vpnte:navigate'

export function navigateTo(page: AppPage): void {
  window.dispatchEvent(new CustomEvent(NAV_EVENT, { detail: page }))
}

/**
 * Broadcast that the active server changed. Components that surface the
 * current profile name (HeroStatus, StatusWidget, ProfileSelectorInline,
 * DashboardSide) listen for this and re-fetch from the picker store
 * immediately, so the UI updates as soon as the user clicks Select.
 */
export const SERVER_CHANGED_EVENT = 'vpnte:server-changed'

export function emitServerChanged(): void {
  window.dispatchEvent(new CustomEvent(SERVER_CHANGED_EVENT))
}
