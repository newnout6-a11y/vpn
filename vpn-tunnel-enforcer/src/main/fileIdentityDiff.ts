// AT-01-009 / AT-08-001: names WHICH stat field differed (numbers only, never a path), so a "file changed" refusal
// on an unusual filesystem or under an antivirus scan can be told apart from a real swap.
import type { Stats } from 'fs'

const FIELDS = ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'nlink'] as const

export function identityDiff(before: Stats, after: Stats): string {
  const changed = FIELDS.filter(field => before[field] !== after[field]).map(field => `${field} ${before[field]}≠${after[field]}`)
  return changed.length > 0 ? changed.join(', ') : 'no stat field differs'
}
