// AT-10-003 / AT-10-006 / AT-07-012: entrypoint wiring complements executable
// cancellation, provider, IPC-selection and protected-transition tests.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
const source = readFileSync('src/main/index.ts', 'utf8')
describe('adaptive profile transition wiring', () => {
  it('invalidates and aborts old verification before waiting for a dispatched transition', () => {
    const begin = source.slice(source.indexOf('setProfileSwitchHooks({'), source.indexOf('let activeAdaptiveContext:'))
    expect(begin.indexOf('adaptiveVerificationGeneration += 1')).toBeLessThan(begin.indexOf('await adaptiveTransitionInFlight'))
    expect(begin.indexOf('adaptiveVerificationAbort?.abort()')).toBeLessThan(begin.indexOf('await adaptiveTransitionInFlight'))
    expect(begin).toContain('activeAdaptiveContext = null')
    expect(begin).toContain('ensureAdaptiveMonitoringForRunningTunnel()')
  })
  it('fences probes to the runtime and uses the shared IP barrier for every adaptive restart', () => {
    const verify = source.slice(source.indexOf('async function verifyAdaptiveConnection'), source.indexOf('// Global guards'))
    expect(verify).toContain('activeAdaptiveContext === context')
    expect(verify).toContain('tunController.getStatus().startedAt === initialStartedAt')
    expect(verify).toContain('collectAdaptiveSamples(isCurrent, controller.signal')
    expect(verify.match(/await restartAdaptiveWithFreshIp\(/g)).toHaveLength(3)
    expect(verify).not.toContain('await tunController.restartForAdaptiveChange(')
  })
  it('commits the actual fallback profile and notifies the existing renderer channel under the same owner', () => {
    const restart = source.slice(source.indexOf('async function restartAdaptiveWithFreshIp'), source.indexOf('function scheduleAdaptiveVerification'))
    expect(restart).toContain('withProtectedIpTransition({')
    expect(restart).toContain('if (sibling && isOwner())')
    expect(restart).toContain('serverPicker.selectProfile(sibling.id)')
    expect(restart).toContain("sendToMainWindow('server-active-changed', { profileId: sibling.id, profileName: sibling.profile.name })")
  })
})
