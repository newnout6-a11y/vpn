import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const appSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'App.tsx'), 'utf8')

describe('App source regressions', () => {
  it('marks restarting before clearing the busy flag on terminal statuses', () => {
    const source = appSource()
    const handlerStart = source.indexOf('onTunStatusChanged')
    const setRestarting = source.indexOf('store.setRestarting', handlerStart)
    const clearBusy = source.indexOf('store.setConnectionBusy(null)', handlerStart)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(setRestarting).toBeGreaterThan(handlerStart)
    expect(setRestarting).toBeLessThan(clearBusy)
  })

  it('backs off periodic Happ detection failures', () => {
    const source = appSource()

    expect(source).toContain('detectHappFailureCountRef')
    expect(source).toContain('detectHappNextAllowedAtRef')
    expect(source).toContain('Date.now() < detectHappNextAllowedAtRef.current')
    expect(source).toContain('90_000 * (2 ** failures)')
  })
})
