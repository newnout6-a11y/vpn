export interface DomainEnrichment {
  status: 'pending' | 'ready' | 'unavailable'
  source: 'website'
  siteName: string | null
  title: string | null
  description: string | null
  canonicalUrl: string | null
  faviconUrl: string | null
  fetchedAt: number
}

export interface TrafficHistoryEntry {
  domain: string
  firstSeen: number
  lastSeen: number
  count: number
  // The user's public IP at the time of the session (best-effort)
  vpnIp: string | null
  // Bytes attributed to this domain by the Clash-API connection sampler.
  // Absent for entries recovered only from the sing-box log.
  bytesUp?: number
  bytesDown?: number
  enrichment?: DomainEnrichment
}

export interface TrafficHistorySession {
  startedAt: number
  endedAt: number | null
  vpnIp: string | null
  domains: TrafficHistoryEntry[]
}

export type TrafficForensicsEngine = 'pktmon' | 'netsh'

export interface TrafficForensicsStatus {
  enabled: boolean
  running: boolean
  cleanupPending?: boolean
  engine: TrafficForensicsEngine | null
  sessionId: string | null
  sessionDir: string | null
  mode: 'localProxy' | 'directVpn' | null
  target: string | null
  startedAt: number | null
  stoppedAt: number | null
  maxSizeMb: number
  retainSessions: number
  stopReason: string | null
  lastError: string | null
  schemaVersion: number | null
  summaryPath: string | null
  summaryGeneratedAt: number | null
  summary: {
    verdicts?: Record<string, boolean>
    counts?: Record<string, number>
    parserErrors?: string[]
  } | null
  sidecar: TrafficForensicsSidecarStatus | null
  artifactFiles: TrafficForensicsArtifactFile[]
  health: {
    artifactCount: number
    etlBytes: number
    liveEtlBytes: number
    eventsBytes: number
    liveSnapshotAt: number | null
    sidecarEvents: number
    sidecarDataEvents: number
    sidecarOnlyLifecycle: boolean
    sidecarWarmingUp: boolean
    pktmonStatusBytes: number
    pktmonLiveCountersBytes: number
    sidecarEngine: string | null
    sidecarCategoryCounts: Record<string, number>
    sidecarWfpBlocks: number
    sidecarTopDomains: Array<{ name: string; count: number }>
    sidecarTopRemotes: Array<{ address: string; count: number }>
    sidecarLastEventAt: number | null
    warnings: string[]
  }
}

export interface TrafficForensicsArtifactFile {
  name: string
  size: number
  mtimeMs: number
}

export interface TrafficForensicsSidecarStatus {
  available: boolean
  running: boolean
  executablePath: string | null
  eventsPath: string | null
  startedAt: number | null
  stoppedAt: number | null
  pid: number | null
  lastError: string | null
}
