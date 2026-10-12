// AT-06-008 / F-076: path-based matching for split tunneling. Pure helpers, no Electron or tunController imports.

/**
 * Normalize an application path for path-based matching. Only an absolute Windows path (drive letter or UNC)
 * qualifies; relative paths, bare names and `..` segments return null, because matching them would silently
 * degrade into name matching.
 */
export function normalizeProcessPath(input: string): string | null {
  const BS = String.fromCharCode(92)
  let s = String(input ?? '').trim().replace(/^["']+|["']+$/g, '').trim()
  if (!s) return null
  s = s.split('/').join(BS)
  const unc = s.startsWith(BS + BS)
  const body = unc ? s.slice(2) : s
  if (!unc && (!/^[a-zA-Z]:/.test(s) || s[2] !== BS)) return null
  if (/[<>"|?*]/.test(unc ? body : body.slice(2))) return null
  const parts = body.split(BS).filter((part, index) => part !== '' || index === 0)
  if (parts.some(part => part === '..' || part === '.')) return null
  const joined = (unc ? BS + BS : '') + parts.join(BS)
  return /\.[a-z0-9]+$/i.test(joined) ? joined : null
}

/** Case-insensitive, fully anchored sing-box `process_path_regex` for one normalized path. */
export function processPathRegex(path: string): string {
  return '(?i)^' + path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'
}
