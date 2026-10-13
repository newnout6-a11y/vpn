// AT-09-014: what inspecting a VPN key may persist. Inspecting is not accepting: the raw text is never written to
// directVpnInput here (the caller does that once the user confirms), only the inspection cache is touched.
import type { AppSettings } from './settings'

export type InspectionCachePatch = Partial<Pick<AppSettings,
  'directVpnCachedInput' | 'directVpnCachedSource' | 'directVpnCachedAt' | 'directVpnCachedProfiles'>>

/**
 * Only overwrite the cached profile list when the probe actually produced something: a typo or a not-yet-supported
 * share link must not silently wipe the user's previously imported servers. The last-checked timestamp is always
 * updated so the UI shows that an inspection took place.
 */
export function cacheInspectionResult(
  save: (patch: InspectionCachePatch) => unknown,
  input: string,
  resolved: { profiles: AppSettings['directVpnCachedProfiles']; source: string },
  now: number = Date.now()
): void {
  if (resolved.profiles.length > 0) {
    save({
      directVpnCachedInput: input.trim(),
      directVpnCachedSource: resolved.source,
      directVpnCachedAt: now,
      directVpnCachedProfiles: resolved.profiles
    })
  } else {
    save({ directVpnCachedAt: now })
  }
}
