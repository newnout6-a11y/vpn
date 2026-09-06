import { describe, it, expect } from 'vitest'
import {
  outcomeKindToDisconnectReason,
  buildOutcomeHeadline,
  makeOutcome,
  isNodeSwitchRestartReason
} from './sessionOutcome'
import type { SessionOutcomeKind } from '../shared/ipc-types'

describe('outcomeKindToDisconnectReason', () => {
  it('maps every kind to a legacy bucket', () => {
    const all: SessionOutcomeKind[] = [
      'user-stop', 'app-quit', 'server-switch', 'rotation', 'schedule',
      'proxy-unreachable', 'server-rejected-key', 'server-down', 'singbox-crash',
      'killswitch', 'tun-setup-failed', 'network-lost', 'system-sleep',
      'start-failed', 'unknown'
    ]
    for (const k of all) {
      expect(['user', 'error', 'rotation', 'schedule', 'crash']).toContain(outcomeKindToDisconnectReason(k))
    }
  })

  it('keeps intentional stops under "user"', () => {
    expect(outcomeKindToDisconnectReason('user-stop')).toBe('user')
    expect(outcomeKindToDisconnectReason('app-quit')).toBe('user')
    expect(outcomeKindToDisconnectReason('server-switch')).toBe('user')
  })

  it('routes rotation / schedule to their own buckets', () => {
    expect(outcomeKindToDisconnectReason('rotation')).toBe('rotation')
    expect(outcomeKindToDisconnectReason('schedule')).toBe('schedule')
  })

  it('kill-switch is a "crash" for the legacy filter', () => {
    expect(outcomeKindToDisconnectReason('killswitch')).toBe('crash')
  })
})

describe('buildOutcomeHeadline', () => {
  it('is deterministic for the same input', () => {
    const a = buildOutcomeHeadline('singbox-crash', { singboxExitCode: 1, autoRestartAttempts: 3 })
    const b = buildOutcomeHeadline('singbox-crash', { singboxExitCode: 1, autoRestartAttempts: 3 })
    expect(a).toBe(b)
  })

  it('folds the exit code and retry count into the crash sentence', () => {
    const h = buildOutcomeHeadline('singbox-crash', { singboxExitCode: 1, autoRestartAttempts: 3 })
    expect(h).toContain('код 1')
    expect(h).toContain('3 попыток')
  })

  it('pluralises the retry count (genitive after "после")', () => {
    expect(buildOutcomeHeadline('singbox-crash', { autoRestartAttempts: 1 })).toContain('1 попытки')
    expect(buildOutcomeHeadline('singbox-crash', { autoRestartAttempts: 2 })).toContain('2 попыток')
    expect(buildOutcomeHeadline('singbox-crash', { autoRestartAttempts: 5 })).toContain('5 попыток')
  })

  it('names the concrete outbound fault when known', () => {
    expect(buildOutcomeHeadline('server-rejected-key', { outboundFault: 'reality-key-mismatch' }))
      .toContain('ключ REALITY')
    expect(buildOutcomeHeadline('server-down', { outboundFault: 'upstream-unreachable' }))
      .toContain('недоступен')
  })

  it('uses the network transition text for network-lost', () => {
    expect(buildOutcomeHeadline('network-lost', { networkTransition: 'адаптер отключился' }))
      .toContain('адаптер отключился')
  })

  it('has a sentence for every kind', () => {
    const all: SessionOutcomeKind[] = [
      'user-stop', 'app-quit', 'server-switch', 'rotation', 'schedule',
      'proxy-unreachable', 'server-rejected-key', 'server-down', 'singbox-crash',
      'killswitch', 'tun-setup-failed', 'network-lost', 'system-sleep',
      'start-failed', 'unknown'
    ]
    for (const k of all) {
      expect(buildOutcomeHeadline(k).length).toBeGreaterThan(5)
    }
  })
})

describe('makeOutcome', () => {
  it('auto-composes the headline and strips empty evidence', () => {
    const o = makeOutcome('user-stop', { egressIp: null, egressCountry: '', leakDetectedDuringSession: false })
    expect(o.kind).toBe('user-stop')
    expect(o.headline).toBe('Вы отключили защиту')
    // false is a real value, null/'' are dropped
    expect(o.evidence).toEqual({ leakDetectedDuringSession: false })
  })

  it('drops the evidence key entirely when nothing survives', () => {
    const o = makeOutcome('app-quit', { egressIp: null })
    expect(o.evidence).toBeUndefined()
  })

  it('honours a headline override', () => {
    const o = makeOutcome('unknown', {}, 'Прокси 127.0.0.1:1080 не отвечает')
    expect(o.headline).toBe('Прокси 127.0.0.1:1080 не отвечает')
  })
})

describe('isNodeSwitchRestartReason', () => {
  it('recognises rotation and server-switch reason strings', () => {
    expect(isNodeSwitchRestartReason('profile rotation to Netherlands #2')).toBe('rotation')
    expect(isNodeSwitchRestartReason('server switch')).toBe('server-switch')
  })

  it('ignores adaptive / config-change restarts', () => {
    expect(isNodeSwitchRestartReason('adaptive transition to mtu-compatibility: probe failed')).toBeNull()
    expect(isNodeSwitchRestartReason('config change: split tunnel')).toBeNull()
  })
})
