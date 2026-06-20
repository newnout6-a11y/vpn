/**
 * Contract test: every IPC channel the renderer can invoke (via the preload
 * bridge) must have a handler registered somewhere in the main process.
 *
 * This guards against "dead buttons": a preload method that calls
 * `ipcRenderer.invoke('foo')` with no matching `ipcMain.handle('foo', ...)` in
 * main. Such a call rejects at runtime with "No handler registered for 'foo'",
 * so the button silently fails. (This is exactly what happened to the Smart-RU
 * rule-set refresh/state channels.)
 *
 * A channel is considered "handled" if its quoted name appears anywhere under
 * src/main — this covers both literal `ipcMain.handle('foo', ...)` and the
 * generic registration loops where channel names live in a map/array.
 */
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { describe, it, expect } from 'vitest'

const MAIN_DIR = __dirname
const PRELOAD_FILE = join(__dirname, '..', 'preload', 'index.ts')

function collectMainSources(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      out.push(...collectMainSources(full))
    } else if (entry.endsWith('.ts') && !entry.endsWith('.test.ts') && !entry.endsWith('.itest.ts')) {
      out.push(full)
    }
  }
  return out
}

describe('IPC channel contract (preload invoke -> main handler)', () => {
  it('every invoked channel has a handler reference in main', () => {
    const preload = readFileSync(PRELOAD_FILE, 'utf8')
    const invoked = new Set<string>()
    for (const m of preload.matchAll(/invoke\('([^']+)'/g)) {
      invoked.add(m[1])
    }
    expect(invoked.size).toBeGreaterThan(0)

    const mainBlob = collectMainSources(MAIN_DIR)
      .map(f => readFileSync(f, 'utf8'))
      .join('\n')

    const dead = [...invoked].filter(ch => !mainBlob.includes(`'${ch}'`) && !mainBlob.includes(`"${ch}"`))
    expect(dead, `Channels invoked by preload but never handled in main: ${dead.join(', ')}`).toEqual([])
  })
})
