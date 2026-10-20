import type * as T from '../shared/ipc-types'
import { matchesIpcArgument, type IpcArgumentSchema as Schema } from '../shared/ipc-contract'
import { isIpcCorrelationId } from '../shared/ipc-result'
import { isConnectionProvenance } from '../shared/connection-provenance'

const text: Schema = { type: 'string', max: 65536 }
const number: Schema = { type: 'number' }
const duration: Schema = { type: 'number', min: 0 }
const boolean: Schema = { type: 'boolean' }
const strings: Schema = { type: 'strings', max: 4096 }
const port: Schema = { type: 'integer', min: 1, max: 65535 }
const optional = (schema: Schema): Schema => ({ ...schema, optional: true })
const oneOf = (...values: string[]): Schema => ({ type: 'enum', values })
const array = (items: Schema): Schema => ({ type: 'array', items, max: 4096 })
const object = <V extends object>(fields: Record<keyof V, Schema>): Schema => ({ type: 'object', fields, closed: true, max: 2 * 1024 * 1024 })
const status = oneOf('ok', 'unavailable', 'error', 'skipped')
const timed = { status, durationMs: duration, error: optional(text) }
const asn = object<T.AsnInfo>({ asn: text, org: text, network: text, country: text })
const changes = object<NonNullable<T.InfrastructureHints['changesFromPrevious']>>({
  ipChanged: optional(boolean), asnChanged: optional(boolean), tlsCertChanged: optional(boolean),
  countryChanged: optional(boolean), portsChanged: optional(boolean), latencySpike: optional(boolean),
  handshakeChanged: optional(boolean), egressChanged: optional(boolean), pmtuChanged: optional(boolean), throughputChanged: optional(boolean)
})
const schema = object<T.LiveServerCheck>({
  id: text, operationKey: optional(text), correlationId: optional(text), requestId: optional(text), profileId: optional(text),
  provenance: optional({ type: 'object' }),
  host: text, port, mode: oneOf('basic', 'extended'), startedAt: text, finishedAt: text,
  durationMs: duration, cancelled: optional(boolean), error: optional(text), reverseDns: optional(strings), asn: optional(asn),
  dns: object<T.DnsDiagnostics>({ ...timed, a: strings, aaaa: strings, cnameChain: strings, ttl: optional(number), resolverUsed: optional(text),
    records: optional(array(object<T.DnsRecordEntry>({ name: text, type: oneOf('A', 'AAAA', 'CNAME', 'PTR'), value: text, ttl: optional(number), observedAt: text, resolverId: text, transport: oneOf('system', 'doh') }))),
    resolvers: optional(array(object<T.DnsResolverComparison>({ resolverId: text, resolverName: text, endpoint: text,
      status: oneOf('ok', 'partial', 'error', 'timeout', 'skipped'), durationMs: duration, error: optional(text), authenticatedData: optional(boolean),
      records: array(object<T.DnsRecordEntry>({ name: text, type: oneOf('A', 'AAAA', 'CNAME', 'PTR'), value: text, ttl: optional(number), observedAt: text, resolverId: text, transport: oneOf('system', 'doh') })),
      truncated: optional(boolean), rcode: optional(number), aStatus: optional(oneOf('ok', 'nxdomain', 'servfail', 'refused', 'error', 'timeout')),
      aaaaStatus: optional(oneOf('ok', 'nxdomain', 'servfail', 'refused', 'error', 'timeout')) }))),
    discrepancies: optional(strings), timings: optional(object<NonNullable<T.DnsDiagnostics['timings']>>({ aMs: optional(duration), aaaaMs: optional(duration), cnameMs: optional(duration) })) }),
  reachability: object<T.ReachabilityDiagnostics>({ ...timed, tcpReachable: boolean, port }),
  latency: optional(object<T.LiveLatencyStats>({ min: number, avg: number, median: number, max: number, jitter: number, loss: number,
    connectionFailureRate: optional(number), samples: array(number), samplesAttempted: number, samplesSucceeded: optional(number),
    pathType: optional(oneOf('direct', 'tun', 'os-selected')), tunRunning: optional(boolean), method: oneOf('tcp') })),
  tls: optional(object<T.LiveTlsCertInfo>({ ...timed, hostnameVerified: optional(boolean), authorized: optional(boolean), authorizationError: optional(text),
    subject: optional(text), issuer: optional(text), validFrom: optional(text), validTo: optional(text), daysRemaining: optional(number), fingerprint: optional(text),
    sans: optional(strings), protocol: optional(text), cipher: optional(text), alpn: optional(text), alpnProtocol: optional(text) })),
  http: optional(object<T.HttpProbeResult>({ ...timed, statusCode: optional(number), protocol: optional(text), serverHeader: optional(text), viaHeader: optional(text),
    locationHeader: optional(text), contentType: optional(text), bodySize: optional(number), targetPort: optional(port), isTls: optional(boolean), confidence: oneOf('low') })),
  openPorts: optional(array(object<T.LivePortScanItem>({ port, open: boolean, state: oneOf('open', 'closed', 'filtered', 'timeout'), service: optional(text) }))),
  portsError: optional(text), route: optional(object<T.RouteDiagnostics>({ ...timed, hops: optional(number), reachedTarget: optional(boolean), commandFinished: optional(boolean),
    partial: optional(boolean), hopDetails: optional(strings), mtu: optional(number), mtuStatus: optional(oneOf('measured', 'unavailable', 'skipped')), routeMethod: optional(text) })),
  infrastructure: optional(object<T.InfrastructureHints>({ status, error: optional(text), egressSource: optional(oneOf('profile-cache')),
    egressObservedAt: optional({ ...text, nullable: true }), asn: optional(asn), egressIp: optional(text), egressCountry: optional(text), endpointCountry: optional(text),
    activeTunnelMatchesProfile: optional(boolean), sharedCidrWithProfiles: optional(strings), changesFromPrevious: optional(changes) })),
  handshake: optional(object<T.TunnelHandshakeResult>({ status: oneOf('ok', 'auth_failed', 'transport_failed', 'timeout', 'skipped', 'unsupported'), durationMs: duration,
    protocol: optional(text), error: optional(text), evidence: optional(object<NonNullable<T.TunnelHandshakeResult['evidence']>>({ transport: optional(text), alpn: optional(text), tlsVersion: optional(text), detail: optional(text), inboundPort: optional(port) })) })),
  egress: optional(object<T.LiveEgressResult>({ status: oneOf('ok', 'partial', 'error', 'skipped', 'timeout'), durationMs: duration,
    exitIpv4: optional(text), exitIpv6: optional(text), ipv6Status: optional(oneOf('ok', 'unsupported', 'error')), country: optional(text),
    reflectors: array(object<T.EgressReflectorResult>({ source: text, ip: optional(text), family: optional({ type: 'integer', min: 4, max: 6 }), country: optional(text), durationMs: duration,
      status: oneOf('ok', 'error', 'timeout', 'unsupported'), error: optional(text) })), endpointIp: optional(text), matchesEndpoint: optional(boolean),
    underlayPath: optional(oneOf('direct', 'nested', 'unknown', 'route-selected')), error: optional(text) })),
  pathDiagnostics: optional(object<T.PathDiagnostics>({ status: oneOf('ok', 'error', 'skipped'), durationMs: duration, destination: text,
    activeInterfaceIndex: optional(number), activeInterfaceAlias: optional(text), activeLocalIp: optional(text), nextHop: optional(text), isTunInterface: boolean,
    underlayInterfaceAlias: optional(text), evidenceKind: oneOf('etw-corroborated', 'route-policy', 'net-route', 'os-unverified'), error: optional(text) })),
  pmtu: optional(object<T.PmtuDiagnostics>({ status: oneOf('ok', 'lower_bound', 'blackhole_suspected', 'icmp_blocked', 'skipped'), durationMs: duration,
    destination: text, family: optional({ type: 'integer', min: 4, max: 6 }), interfaceAlias: optional(text), method: oneOf('icmp-df', 'interface-nlmtu', 'fallback'),
    pmtu: optional(number), minTested: optional(number), maxTested: optional(number), lossRate: optional(number), detail: optional(text), error: optional(text) })),
  mediaStream: optional(object<T.LiveMediaStreamDiagnostics>({ status: oneOf('ok', 'warning', 'error', 'skipped'), durationMs: duration,
    twitchHlsReachable: optional(boolean), quicFallbackGuarded: optional(boolean), error2000Risk: optional(boolean),
    testedEndpoints: optional(array(object<NonNullable<T.LiveMediaStreamDiagnostics['testedEndpoints']>[number]>({ endpoint: text, reachable: boolean, latencyMs: optional(number), protocol: optional(text), error: optional(text) }))),
    detail: optional(text), error: optional(text) })),
  throughput: optional(object<T.LiveThroughputDiagnostics>({ status: oneOf('ok', 'warning', 'error', 'skipped'), durationMs: duration, endpoint: optional(text),
    route: optional(oneOf('physical-direct', 'active-tunnel-direct-detour', 'active-profile-self', 'active-tunnel')),
    samples: array(object<T.LiveThroughputSample>({ index: number, bytes: number, durationMs: duration, throughputMbps: number, ttfbMs: optional(number), stallCount: number, maxInterChunkGapMs: number })),
    medianMbps: optional(number), minMbps: optional(number), maxMbps: optional(number), variabilityPct: optional(number), stallCount: optional(number), maxInterChunkGapMs: optional(number), detail: optional(text), error: optional(text) })),
  splitTunnel: optional(object<T.LiveSplitTunnelDiagnostics>({ status: oneOf('ok', 'warning', 'error', 'skipped'), enabled: boolean, directProcessNames: strings,
    vpnProcessNames: strings, duplicateProcessNames: strings, directRuleCount: number, vpnRuleCount: number, defaultOutbound: oneOf('proxy-out', 'unknown'), detail: optional(text), error: optional(text) })),
  findings: array(object<T.LiveCheckFinding>({ code: text, severity: oneOf('info', 'warning', 'error'), title: text, detail: text, evidence: optional({ type: 'object' }) }))
})

/** Validate every rendered diagnostic before sanitization or use as a baseline.
 * Legacy receipt IDs remain readable; new correlation fields are optional. */
export function isStoredLiveCheck(value: unknown): value is T.LiveServerCheck {
  if (!matchesIpcArgument(schema, value)) return false
  const check = value as T.LiveServerCheck
  return check.id.length > 0 && check.host.length > 0
    && Number.isFinite(Date.parse(check.startedAt)) && Number.isFinite(Date.parse(check.finishedAt))
    && (check.correlationId === undefined || isIpcCorrelationId(check.correlationId))
    && (check.operationKey === undefined || (/^op_/.test(check.operationKey) && isIpcCorrelationId(check.operationKey)))
    && (check.provenance === undefined || isConnectionProvenance(check.provenance))
    && check.findings.every(finding => !finding.evidence || Object.values(finding.evidence).every(v =>
      typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))))
    && [check.egress?.reflectors.map(r => r.family) ?? [], [check.pmtu?.family]].flat().every(family => family === undefined || family === 4 || family === 6)
}
