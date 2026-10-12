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

/**
 * The spellings under which Windows can report one executable: the stored path and its canonical long form
 * (8.3 short names expanded, links followed, `\?\` prefix removed). The process path sing-box sees comes from the
 * system and may differ from what discovery stored, so the rule must cover both; each stays an exact anchored match.
 * `resolve` is injectable for tests; a failure to resolve leaves just the stored spelling.
 */
export function windowsPathSpellings(path: string, resolve: (value: string) => string): string[] {
  const BS = String.fromCharCode(92)
  const spellings = [path]
  let canonical: string | null = null
  try { canonical = resolve(path) } catch { canonical = null }
  if (canonical) {
    const verbatim = BS + BS + '?' + BS
    if (canonical.startsWith(verbatim + 'UNC' + BS)) canonical = BS + canonical.slice(verbatim.length + 3)
    else if (canonical.startsWith(verbatim)) canonical = canonical.slice(verbatim.length)
    const normalized = normalizeProcessPath(canonical)
    if (normalized && !spellings.some((known) => known.toLowerCase() === normalized.toLowerCase())) spellings.push(normalized)
  }
  return spellings
}
