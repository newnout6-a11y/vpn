import { describe, expect, it } from 'vitest'
import { readFileSync } from 'fs'
import { resolve } from 'path'

describe('renderer production boundary', () => {
  it('ships an effective file:// CSP (AT-01-006)', () => {
    const html = readFileSync(resolve(__dirname, '../renderer/index.html'), 'utf8')
    expect(html).toContain('http-equiv="Content-Security-Policy"')
    expect(html).toContain("script-src 'self'")
    expect(html).toContain("object-src 'none'")
  })

  it('enables the same Chromium sandbox in dev and production (AT-01-007)', () => {
    const main = readFileSync(resolve(__dirname, 'index.ts'), 'utf8')
    const webPreferences = main.slice(main.indexOf('webPreferences:'), main.indexOf('backgroundColor:', main.indexOf('webPreferences:')))
    expect(webPreferences).toContain('contextIsolation: true')
    expect(webPreferences).toContain('nodeIntegration: false')
    expect(webPreferences).toContain('sandbox: true')
    expect(webPreferences).toContain('devTools: !app.isPackaged')
    expect(webPreferences).not.toMatch(/(?:sandbox|nodeIntegration|contextIsolation):\s*(?:!?app\.|process\.)/)
  })
})
