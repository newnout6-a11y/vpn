/**
 * Pure navigation-policy decision for the main BrowserWindow, kept in its own
 * module so it can be unit-tested without importing the whole electron app
 * (index.ts runs app.whenReady side-effects at import time).
 *
 * Security context: `webPageUrl` (and other link targets) can originate from a
 * subscription's `profile-web-page-url` HTTP header — i.e. the VPN provider,
 * not the user, controls them. Without a guard a hostile panel could navigate
 * our trusted, preload-bearing window to a phishing page or launch another
 * program via a custom scheme. This function is the single source of truth for
 * what is allowed.
 */

export type NavigationVerdict = 'allow-internal' | 'open-external' | 'block'

/**
 * Given a target URL and the renderer's dev-server URL (undefined in
 * production), decide what to do:
 *   - 'allow-internal' : same-origin as our renderer → let it navigate.
 *   - 'open-external'  : http(s) to a different origin → hand to OS browser.
 *   - 'block'          : anything else (file:// elsewhere, custom schemes,
 *                        javascript:, data:, malformed input).
 */
export function classifyNavigation(
  target: string,
  devUrl: string | undefined
): NavigationVerdict {
  let u: URL
  try {
    u = new URL(target)
  } catch {
    return 'block'
  }

  // Internal origin check first.
  if (devUrl) {
    try {
      if (u.origin === new URL(devUrl).origin) return 'allow-internal'
    } catch {
      /* malformed dev URL — fall through to external handling */
    }
  } else if (u.protocol === 'file:') {
    // Production: our renderer is loaded from a host-less local file:// URL.
    // A file:// URL WITH a host (file://remote-host/share/…) is a UNC/remote
    // path and must never be treated as internal — block it.
    return u.host === '' ? 'allow-internal' : 'block'
  }

  // External: only http(s) may leave to the OS browser. Everything else
  // (javascript:, data:, vbscript:, ms-*:, custom app schemes) is blocked.
  if (u.protocol === 'http:' || u.protocol === 'https:') return 'open-external'
  return 'block'
}
