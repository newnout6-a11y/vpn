/** Evidence from IPv4 probes; no claim about unmeasured DNS/WebRTC/IPv6 paths. */
export interface LeakSelfTestAdapter {
  alias: string
  ipv4: string | null
  publicIpViaThisAdapter: string | null
  curlExitCode: number | null
  curlStderrTail: string | null
}

export interface LeakSelfTestResult {
  ts: number
  physicalAdapterReached: boolean
  publicIpMismatch: boolean
  defaultRoutePublicIp: string | null
  perAdapter: LeakSelfTestAdapter[]
  summary: string
  dnsLeakDetected?: boolean
  dnsLeakDetail?: string
  /** Missing on older results. Only explicit true confirms enumeration. */
  physicalAdapterInspectionComplete?: boolean
}

export function isLeakProbeIpv4(value: string | null): value is string {
  return typeof value === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
    && value.split('.').every(part => Number(part) <= 255)
}

export function adapterLeakVerdict(adapter: LeakSelfTestAdapter): 'reached' | 'not-reached' | 'inconclusive' {
  if (isLeakProbeIpv4(adapter.publicIpViaThisAdapter)) return 'reached'
  // curl 7 = failed to connect, 28 = timed out. Neither proves a firewall rule.
  // DNS/TLS/launch/invalid-response failures do not establish unreachable egress.
  return adapter.curlExitCode === 7 || adapter.curlExitCode === 28 ? 'not-reached' : 'inconclusive'
}

export function leakSelfTestVerdict(result: LeakSelfTestResult): 'leak' | 'ok' | 'inconclusive' {
  if (result.physicalAdapterReached || result.publicIpMismatch || result.dnsLeakDetected
    || result.perAdapter?.some(adapter => adapterLeakVerdict(adapter) === 'reached')) return 'leak'
  if (result.physicalAdapterInspectionComplete !== true || !isLeakProbeIpv4(result.defaultRoutePublicIp)
    || !result.perAdapter?.length || result.perAdapter.some(adapter => adapterLeakVerdict(adapter) !== 'not-reached')) return 'inconclusive'
  return 'ok'
}

/** Derive status copy from evidence, including legacy results with stale summary. */
export function leakSelfTestMessage(result: LeakSelfTestResult): string {
  const verdict = leakSelfTestVerdict(result)
  if (verdict === 'leak') return 'Обнаружена утечка'
  if (verdict === 'ok') return 'В IPv4-проверке утечек не обнаружено'
  const reason = result.physicalAdapterInspectionComplete !== true ? 'физические адаптеры проверены не полностью'
    : !isLeakProbeIpv4(result.defaultRoutePublicIp) ? 'публичный IP через TUN не определён'
      : !result.perAdapter?.length ? 'нет физических IPv4-адресов для проверки'
        : 'не все пробы физических адаптеров дали определённый результат'
  return `Защита не подтверждена: ${reason}`
}
