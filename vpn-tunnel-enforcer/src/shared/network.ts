import type { RoutingPlan } from './diagnostics'
import type { AppSettings } from './settings'

export interface AutoconfigTarget {
  id: string
  name: string
  applied: boolean
  scope?: 'user-global' | 'app-global' | 'project-local'
  warning?: string
  managedPath?: string
  backupPath?: string
}

export interface AutoPilotStep {
  label: string
  before: string
  after: string
  status: 'ok' | 'warn' | 'fail' | 'info'
}

export interface AutoPilotResult {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail'
  mode: 'off' | 'external' | 'hard' | 'soft'
  title: string
  message: string
  changed: boolean
  steps: AutoPilotStep[]
  plan: RoutingPlan
}

export interface BrowserHardeningResult {
  success: boolean
  changed: boolean
  restartRequired: boolean
  message: string
  details: string[]
}

export interface LocationPrivacyStatus {
  userDenied: boolean
  policyDisabled: boolean
  applied: boolean
  details: string[]
}

export interface SystemNetworkResult {
  success: boolean
  operationId?: string
  message: string
  details?: string
  warnings?: string[]
  skipped?: boolean
}

export interface FirewallKillSwitchResult {
  success: boolean
  message: string
  details?: string
  // True iff the call was a no-op because there was nothing to do (kill-switch
  // already inactive). The renderer uses this to suppress the noisy
  // "Kill-switch снят вручную" warn log that fired every stop because main
  // had already auto-disabled before the user-driven IPC arrived.
  skipped?: boolean
  state?: 'unknown'
}

export interface FirewallRepairHealth {
  platform: 'win32' | 'other'
  protectedTunnelActive?: boolean
  manifestPresent: boolean
  ourRuleCount: number
  stuckBlockDefault: boolean
  services: Array<{ name: string; status: string }>
  profiles: Array<{ name: string; enabled: string; defaultInbound: string; defaultOutbound: string }>
  summary: 'ok' | 'warn' | 'fail'
  message: string
  recommendedActions: string[]
}

export interface RuleSetFileMetadata {
  tag: string
  fileName: string
  url: string
  lastCheckedAt: number | null
  lastUpdatedAt: number | null
  size: number | null
  sha256: string | null
  lastError: string | null
  lastRoute: string | null
}

export interface SmartRouteRuleSetFileState extends RuleSetFileMetadata {
  label: string
  exists: boolean
  path: string
}

export interface SmartRouteRuleSetState {
  mode: AppSettings['smartRuRuleSetMode']
  autoUpdate: boolean
  useProxy: boolean
  updateIntervalHours: number
  activeSource: 'bundled' | 'managed'
  managedComplete: boolean
  managedDir: string
  bundledDir: string
  lastRefreshStartedAt: number | null
  lastRefreshFinishedAt: number | null
  lastRefreshOk: boolean | null
  lastRefreshError: string | null
  files: SmartRouteRuleSetFileState[]
}
