import { describe, expect, it } from 'vitest'
import {
  formatInterfaceAlias,
  formatThroughputRouteLabel,
  handshakeChangeLabel,
  interfaceAliasTitle,
  routeDiagnosticStatus
} from './liveServerPresentation'

describe('live-server presentation helpers', () => {
  it('warns when tracert ran successfully but did not reach the target', () => {
    expect(routeDiagnosticStatus({
      status: 'ok',
      durationMs: 10,
      reachedTarget: false,
      hops: 1
    })).toBe('warning')

    expect(routeDiagnosticStatus({
      status: 'ok',
      durationMs: 10,
      reachedTarget: true
    })).toBe('ok')
  })

  it('describes the profile and underlay route without claiming the download bypassed the profile', () => {
    expect(formatThroughputRouteLabel('physical-direct'))
      .toBe('через профиль; к его endpoint — по физической сети (вне TUN)')
    expect(formatThroughputRouteLabel('physical-direct', true)).toBe('профиль / физ. сеть')
    expect(formatThroughputRouteLabel('active-tunnel')).toBe('через уже работающий активный туннель')
    expect(formatThroughputRouteLabel('active-tunnel', true)).toBe('активный туннель')
    expect(formatThroughputRouteLabel('active-tunnel-direct-detour', true)).toBe('профиль / обход TUN')
    expect(formatThroughputRouteLabel(undefined)).toBe('—')
  })

  it('distinguishes a recovered handshake and masks irrecoverably corrupted saved interface names', () => {
    expect(handshakeChangeLabel('ok')).toBe('Handshake восстановлен')
    expect(handshakeChangeLabel('transport_failed')).toBe('Статус handshake изменился')
    expect(formatInterfaceAlias('Ethernet')).toBe('Ethernet')
    expect(formatInterfaceAlias(undefined, 12)).toBe('Index 12')
    expect(formatInterfaceAlias('Ethernet\uFFFD')).toBe('Имя повреждено в старой проверке')
    expect(interfaceAliasTitle('Ethernet\uFFFD')).toContain('старой ошибки кодировки')
  })
})
