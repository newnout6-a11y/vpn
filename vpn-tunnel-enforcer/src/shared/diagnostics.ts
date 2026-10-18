import type { AsnInfo } from './ipc-types'
/** Shared data returned by diagnostic IPC handlers. No main-process dependencies. */

export interface ProxyInfo {
  host: string
  port: number
  type: 'socks5' | 'http'
  verified: boolean
  publicIpViaProxy: string | null
}

export type AdaptiveBypassMode =
  | 'baseline'
  | 'tls-compatibility'
  | 'mtu-compatibility'
  | 'external-managed'

export type AdaptiveBypassPhase =
  | 'idle'
  | 'connecting'
  | 'verifying'
  | 'adapting'
  | 'connected'
  | 'failed'

export interface AdaptiveCapabilities {
  canUseTlsCompatibility: boolean
  canUseMtuCompatibility: boolean
  externallyManaged: boolean
  reason: string | null
}

export interface AdaptiveBypassStatus {
  phase: AdaptiveBypassPhase
  mode: AdaptiveBypassMode
  attempts: number
  message: string
  updatedAt: number
  reason: string | null
}

export type RoutingPlanStatus = 'ready' | 'protected' | 'blocked' | 'broken'

export type RecommendedMode = 'off' | 'soft' | 'hard' | 'external'

export interface TunnelInfo {
  name: string
  description: string
  address: string
  isVpnte: boolean
}

export interface ProxyListenerInfo {
  host: string
  port: number
  process: string
  pid: number
}

export interface RoutingPlanStep {
  label: string
  before: string
  after: string
  status: 'ok' | 'warn' | 'fail' | 'info'
}

export interface RoutingPlan {
  ranAt: number
  status: RoutingPlanStatus
  recommendedMode: RecommendedMode
  title: string
  explanation: string
  before: string
  after: string
  canStartHard: boolean
  proxy: ProxyInfo | null
  activeTunnels: TunnelInfo[]
  proxyListeners: ProxyListenerInfo[]
  blockers: string[]
  steps: RoutingPlanStep[]
}

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info'

export interface LeakCheckItem {
  id: string
  label: string
  status: CheckStatus
  value: string
  details?: string
}

export interface LeakCheckResult {
  ranAt: number
  summary: CheckStatus
  items: LeakCheckItem[]
}

export interface SystemDiagnosticItem {
  id: string
  category: string
  label: string
  status: CheckStatus
  value: string
  details?: string
}

export interface SystemDiagnosticResult {
  ranAt: number
  summary: CheckStatus
  items: SystemDiagnosticItem[]
}

export interface LogFileSnapshot {
  name: string
  path: string
  exists: boolean
  size: number
  truncated: boolean
  content: string
}

export interface PathReport {
  /** True if the URL was reachable along this path. */
  available: boolean
  /** End-to-end wall-clock ms (DNS + TCP + TLS + HTTP). null if unreachable. */
  totalMs: number | null
  /** Why it failed, if it did. Human-readable for the UI. */
  errorStage: 'dns' | 'tcp' | 'tls' | 'http' | 'api' | null
  errorMessage: string | null
  /** Full per-stage breakdown. Only populated for the native path. */
  dns: {
    resolved: boolean
    ips: string[]
    ms: number | null
    /** True if the resolver returned 0.0.0.0 / a known RKN landing IP. */
    poisoned: boolean
  } | null
  tcp: { connected: boolean; ms: number | null } | null
  tls: { handshakeOk: boolean; ms: number | null; cipher: string | null; protocol: string | null } | null
  http: { status: number | null; ms: number | null; server: string | null } | null
  /** ASN/geo of the resolved IP, best-effort. */
  asn: { country: string; org: string } | null
  /** Set to true if the website returned 200 OK but the HTML body contains GeoBlock markers (e.g. Gemini). */
  geoBlocked?: boolean
  /** How the measurement was taken — useful for telling apart full probe
   *  results from "clash API delay only" approximations. */
  source: 'native' | 'clash-direct-out'
}

export interface UrlAvailabilityResult {
  id: string
  url: string
  testedAt: number
  tunnelActive: boolean
  /** Full report through the tunnel (when VPN is on). null otherwise. */
  tunnel: PathReport | null
  /** Report without the tunnel — native when VPN off, clash-direct when on. */
  direct: PathReport | null
  /** High-level conclusion. */
  verdict:
    | 'works-both'
    | 'works-only-with-vpn'
    | 'works-only-without-vpn'
    | 'blocked-everywhere'
    | 'unknown'
  /** Human-readable next step for the user. */
  recommendation: string
}

export interface ServerProbeResult {
  host: string
  resolvedIps: string[]
  reverseDns: string | null
  asn: AsnInfo | null
  latency: LatencyStats | null
  openPorts: PortScanResult[]
  tlsCert: TlsCertInfo | null
  httpBanner: string | null
}

export interface LatencyStats {
  min: number
  avg: number
  max: number
  jitter: number   // stddev
  loss: number     // 0..1 (packets lost / total)
  samples: number[]
}

export interface PortScanResult {
  port: number
  open: boolean
  service?: string  // best guess (ssh, http, https, etc.)
}

export interface TlsCertInfo {
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  fingerprint: string
  sans: string[]
  protocol: string  // TLSv1.2, TLSv1.3
  cipher: string
}
