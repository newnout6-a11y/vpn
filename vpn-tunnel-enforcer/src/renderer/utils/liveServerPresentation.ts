import type {
  LiveThroughputDiagnostics,
  RouteDiagnostics,
  TunnelHandshakeResult
} from '../../shared/ipc-types'

/** A successful tracert process is not proof that the destination was reached. */
export function routeDiagnosticStatus(route: RouteDiagnostics): RouteDiagnostics['status'] | 'warning' {
  return route.status === 'ok' && route.reachedTarget === false
    ? 'warning'
    : route.status
}

/** The throughput request uses the selected profile SOCKS in every route mode. */
export function formatThroughputRouteLabel(
  route: LiveThroughputDiagnostics['route'],
  compact = false
): string {
  if (route === 'physical-direct') {
    return compact
      ? 'профиль / физ. сеть'
      : 'через профиль; к его endpoint — по физической сети (вне TUN)'
  }
  if (route === 'active-tunnel') {
    return compact ? 'активный туннель' : 'через уже работающий активный туннель'
  }
  if (route === 'active-profile-self') {
    return compact ? 'активный профиль' : 'через активный профиль'
  }
  if (route === 'active-tunnel-direct-detour') {
    return compact
      ? 'профиль / обход TUN'
      : 'через проверяемый профиль в обход активного TUN (direct-detour)'
  }
  return '—'
}

export function handshakeChangeLabel(status?: TunnelHandshakeResult['status']): string {
  return status === 'ok'
    ? 'Handshake восстановлен'
    : 'Статус handshake изменился'
}

export function formatInterfaceAlias(alias?: string, interfaceIndex?: number): string {
  if (!alias) return `Index ${interfaceIndex ?? '—'}`
  return alias.includes('\uFFFD')
    ? 'Имя повреждено в старой проверке'
    : alias
}

export function interfaceAliasTitle(alias?: string): string | undefined {
  if (!alias) return undefined
  return alias.includes('\uFFFD')
    ? 'Имя интерфейса повреждено из-за старой ошибки кодировки. Повторная проверка сохранит его в UTF-8.'
    : alias
}
