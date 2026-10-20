// AT-00-008: incomplete observations cannot certify protection.
import { describe, expect, it } from 'vitest'
import { adapterLeakVerdict, leakSelfTestMessage, leakSelfTestVerdict, type LeakSelfTestResult } from './leak-self-test'

const blocked = { alias: 'Wi-Fi', ipv4: '192.168.1.2', publicIpViaThisAdapter: null, curlExitCode: 7, curlStderrTail: null }
const complete: LeakSelfTestResult = { ts: 1, physicalAdapterReached: false, publicIpMismatch: false,
  defaultRoutePublicIp: '1.2.3.4', perAdapter: [blocked], physicalAdapterInspectionComplete: true, summary: 'OK: legacy' }

describe('leak evidence verdict', () => {
  it('requires explicit complete coverage, a valid default IP and completed adapter probes', () => {
    expect(leakSelfTestVerdict(complete)).toBe('ok')
    for (const patch of [
      { physicalAdapterInspectionComplete: false }, { physicalAdapterInspectionComplete: undefined },
      { defaultRoutePublicIp: null }, { defaultRoutePublicIp: '999.1.2.3' }, { perAdapter: [] },
      ...[null, -1, 0, 6, 35, 60].map(curlExitCode => ({ perAdapter: [{ ...blocked, curlExitCode }] }))
    ]) expect(leakSelfTestVerdict({ ...complete, ...patch })).toBe('inconclusive')
  })
  it.each([7, 28])('accepts a measured unreachable adapter (curl %s)', curlExitCode => {
    expect(adapterLeakVerdict({ ...blocked, curlExitCode })).toBe('not-reached')
    expect(leakSelfTestVerdict({ ...complete, perAdapter: [{ ...blocked, curlExitCode }] })).toBe('ok')
  })
  it.each(['physicalAdapterReached', 'publicIpMismatch', 'dnsLeakDetected'] as const)('preserves %s with incomplete remaining evidence', field => {
    expect(leakSelfTestVerdict({ ...complete, [field]: true, physicalAdapterInspectionComplete: false, defaultRoutePublicIp: null })).toBe('leak')
  })
  it('preserves adapter evidence even if aggregate flags are stale', () => {
    expect(leakSelfTestVerdict({ ...complete, physicalAdapterInspectionComplete: false,
      perAdapter: [{ ...blocked, curlExitCode: -1, publicIpViaThisAdapter: '5.6.7.8' }] })).toBe('leak')
  })
  it('derives copy from evidence instead of a contradictory legacy summary', () => {
    expect(leakSelfTestMessage(complete)).toContain('В IPv4-проверке')
    expect(leakSelfTestMessage({ ...complete, physicalAdapterInspectionComplete: false })).toContain('не полностью')
    expect(leakSelfTestMessage({ ...complete, defaultRoutePublicIp: null })).toContain('не определён')
    expect(leakSelfTestMessage({ ...complete, perAdapter: [] })).toContain('нет физических IPv4')
    expect(leakSelfTestMessage({ ...complete, perAdapter: [{ ...blocked, curlExitCode: -1 }] })).toContain('не все пробы')
    expect(leakSelfTestMessage({ ...complete, physicalAdapterReached: true })).toBe('Обнаружена утечка')
  })
  it('preserves a conflicting IP reading in the user message', () => {
    expect(leakSelfTestMessage({ ...complete, dnsLeakDetail: 'Cloudflare видит 5.6.7.8, default-route отдаёт 1.2.3.4' }))
      .toContain('Cloudflare видит 5.6.7.8, default-route отдаёт 1.2.3.4')
  })
  it('preserves positive adapter and IP evidence in the user message', () => {
    const message = leakSelfTestMessage({ ...complete, perAdapter: [{ ...blocked, publicIpViaThisAdapter: '5.6.7.8' }] })
    expect(message).toContain('Wi-Fi')
    expect(message).toContain('5.6.7.8')
    expect(message).toContain('1.2.3.4')
  })
  it('shows explicit cancellation as an inconclusive cancelled check', () => {
    const cancelled = { ...complete, cancelled: true as const, physicalAdapterInspectionComplete: false, defaultRoutePublicIp: null, perAdapter: [] }
    expect(leakSelfTestVerdict(cancelled)).toBe('inconclusive')
    expect(leakSelfTestMessage(cancelled)).toContain('Тест отменён')
    expect(leakSelfTestMessage(cancelled)).not.toContain('не полностью')
  })
})
