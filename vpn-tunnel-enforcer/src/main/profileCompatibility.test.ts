// AT-00-001/004: the production dispatcher consumes the versioned compatibility decision.
import { describe, expect, expectTypeOf, it } from 'vitest'
import { resolveProfileCompatibility, resolveProxyEngine } from './proxyEngine'
import type { ProfileCompatibility } from '../shared/profile-compatibility'
import type { CheckResult, LeakCheckItem, LeakCheckResult, SystemDiagnosticItem, SystemDiagnosticResult } from '../shared/diagnostics'

const native = { version: 1, selectedTag: 'entry', entry: { outboundTag: 'entry' }, outbounds: [] }
const cases = [
  { outbound: null, setting: 'auto', engine: 'sing-box', reason: 'default' },
  { outbound: { type: 'hysteria2' }, setting: 'xray', engine: 'sing-box', reason: 'protocol' },
  { outbound: { type: 'vless' }, setting: 'auto', engine: 'sing-box', reason: 'default' },
  { outbound: { type: 'vless' }, setting: 'xray', engine: 'xray', reason: 'preference' },
  { outbound: { type: 'vless', tls: { reality: {} } }, setting: 'auto', engine: 'xray', reason: 'reality' },
  { outbound: { type: 'vless', tls: { reality: {} } }, setting: 'sing-box', engine: 'sing-box', reason: 'preference' },
  { outbound: { type: 'vless', tls: { reality: { enabled: false } } }, setting: 'auto', engine: 'sing-box', reason: 'default' },
  { outbound: { type: 'vless', transport: { type: 'xhttp' } }, setting: 'auto', engine: 'xray', reason: 'xray-transport' },
  { outbound: { type: 'trojan', transport: { type: 'grpc', multi_mode: false } }, setting: 'auto', engine: 'xray', reason: 'xray-transport' },
  { outbound: { vpnte_xray: native }, setting: 'auto', engine: 'xray', reason: 'native-xray' }
] as const

describe('canonical domain contracts', () => {
  it.each(cases)('retains $reason dispatch under $setting', ({ outbound, setting, engine, reason }) => {
    const input = JSON.stringify(outbound)
    const decision: ProfileCompatibility = resolveProfileCompatibility(outbound, setting)
    expect(decision).toEqual({ version: 1, status: 'selected', engine, reason })
    expect(resolveProxyEngine(outbound, setting)).toBe(engine)
    expect(JSON.parse(JSON.stringify(decision))).toEqual(decision)
    expect(JSON.stringify(outbound)).toBe(input)
  })

  it.each([
    { outbound: { vpnte_xray: native }, reason: 'native-xray', message: 'Этот JSON-профиль содержит настройки Xray; выберите Auto или Xray для сохранения маршрута.' },
    { outbound: { type: 'vless', transport: { type: 'splithttp' } }, reason: 'xray-transport', message: 'Параметры транспорта требуют Xray; выберите Auto или Xray.' }
  ])('preserves the $reason refusal without serializing credentials', ({ outbound, reason, message }) => {
    const profile = { ...outbound, password: 'SYNTHETIC_SECRET' }
    const decision = resolveProfileCompatibility(profile, 'sing-box')
    expect(decision).toEqual({ version: 1, status: 'rejected', engine: null, reason })
    expect(JSON.stringify(decision)).not.toContain('SYNTHETIC_SECRET')
    expect(() => resolveProxyEngine(profile, 'sing-box')).toThrow(message)
  })

  it('does not admit an invalid preserved profile through the new contract', () => {
    const outbound = { vpnte_xray: { ...native, version: 2 } }
    expect(() => resolveProfileCompatibility(outbound)).toThrow('Invalid preserved Xray profile')
    expect(() => resolveProxyEngine(outbound)).toThrow('Invalid preserved Xray profile')
  })

  it('binds existing diagnostic producer payloads to CheckResult without a wire change', () => {
    expectTypeOf<LeakCheckResult>().toEqualTypeOf<CheckResult<LeakCheckItem>>()
    expectTypeOf<SystemDiagnosticResult>().toEqualTypeOf<CheckResult<SystemDiagnosticItem>>()
  })
})
