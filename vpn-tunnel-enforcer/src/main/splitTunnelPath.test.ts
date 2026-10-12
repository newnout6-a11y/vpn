// AT-06-008 / F-076: path normalization and the sing-box path regex.
import { describe, expect, it } from 'vitest'
import { normalizeProcessPath, processPathRegex, windowsPathSpellings } from './splitTunnelPath'

const BS = String.fromCharCode(92)
const win = (...parts: string[]) => parts.join(BS)

/** Same match semantics as sing-box (Go RE2): `(?i)` is a leading inline flag, the rest is plain syntax. */
const matches = (regex: string, path: string) => new RegExp(regex.replace(/^\(\?i\)/, ''), 'i').test(path)

describe('normalizeProcessPath', () => {
  it('accepts absolute drive and UNC paths and unifies separators', () => {
    expect(normalizeProcessPath('C:/Apps/app.exe')).toBe(win('C:', 'Apps', 'app.exe'))
    expect(normalizeProcessPath(' "C:' + BS + 'Apps' + BS + BS + 'app.exe" ')).toBe(win('C:', 'Apps', 'app.exe'))
    expect(normalizeProcessPath(BS + BS + 'srv' + BS + 'share' + BS + 'app.exe')).toBe(BS + BS + 'srv' + BS + 'share' + BS + 'app.exe')
  })

  it.each(['app.exe', 'Apps/app.exe', 'C:app.exe', win('C:', 'Apps', '..', 'app.exe'), win('C:', 'Apps'), '', win('C:', 'a*b', 'x.exe')])(
    'refuses %j: a path that is not absolute and exact must never degrade into name matching', input => {
      expect(normalizeProcessPath(input)).toBeNull()
    })
})

describe('processPathRegex', () => {
  it('produces the exact escaped, anchored, case-insensitive pattern', () => {
    // Every regex metacharacter is escaped with one backslash; the path separators double as escaped backslashes.
    const expected = '(?i)^C:' + BS + BS + 'Program Files ' + BS + '(x86' + BS + ')' + BS + BS + 'App' + BS + '+1' + BS + BS + 'app' + BS + '.exe$'
    expect(processPathRegex(win('C:', 'Program Files (x86)', 'App+1', 'app.exe'))).toBe(expected)
  })

  const path = win('C:', 'Program Files (x86)', 'App+1', 'app.exe')
  const regex = processPathRegex(path)

  it('matches the same file in any letter case', () => {
    expect(matches(regex, path)).toBe(true)
    expect(matches(regex, path.toUpperCase())).toBe(true)
  })

  it('does not match a copy of the file in another directory or a path that only ends the same way', () => {
    expect(matches(regex, win('D:', 'Other', 'app.exe'))).toBe(false)
    expect(matches(regex, win('C:', 'Temp', 'C:', 'Program Files (x86)', 'App+1', 'app.exe'))).toBe(false)
    expect(matches(regex, path + '.bak')).toBe(false)
  })

  it('treats regex metacharacters in the path literally', () => {
    expect(matches(processPathRegex(win('C:', 'a.b', 'x.exe')), win('C:', 'aXb', 'x.exe'))).toBe(false)
  })
})

describe('windowsPathSpellings', () => {
  const short = win('C:', 'PROGRA~1', 'App', 'app.exe')
  const long = win('C:', 'Program Files', 'App', 'app.exe')

  it('adds the canonical long path next to the stored 8.3 spelling', () => {
    expect(windowsPathSpellings(short, () => long)).toEqual([short, long])
  })

  it('strips the verbatim prefix and converts a verbatim UNC path', () => {
    expect(windowsPathSpellings(short, () => BS + BS + '?' + BS + long)).toEqual([short, long])
    expect(windowsPathSpellings(win('C:', 'x', 'a.exe'), () => BS + BS + '?' + BS + 'UNC' + BS + 'srv' + BS + 'share' + BS + 'a.exe'))
      .toEqual([win('C:', 'x', 'a.exe'), BS + BS + 'srv' + BS + 'share' + BS + 'a.exe'])
  })

  it('keeps one spelling when both are the same (any case) or resolution fails', () => {
    expect(windowsPathSpellings(long, () => long.toUpperCase())).toEqual([long])
    expect(windowsPathSpellings(long, () => { throw new Error('ENOENT') })).toEqual([long])
  })

  it('does not widen the match: each spelling is its own anchored regex', () => {
    const regexes = windowsPathSpellings(short, () => long).map(processPathRegex)
    expect(regexes.some((regex) => matches(regex, win('C:', 'Program Files', 'Other', 'app.exe')))).toBe(false)
    expect(regexes.some((regex) => matches(regex, long))).toBe(true)
  })
})
