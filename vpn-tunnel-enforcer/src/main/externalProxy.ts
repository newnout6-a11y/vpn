import { app } from 'electron'
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http'
import { access, copyFile, mkdir, stat, writeFile } from 'fs/promises'
import { join } from 'path'
import { randomBytes, timingSafeEqual } from 'crypto'
import { lookup } from 'dns/promises'
import { isIP } from 'net'
import { serverPicker } from './serverPicker'
import { logEvent } from './appLogger'
import { cleanupManagedChildPidFile, removeManagedChildPidFile, writeManagedChildPidFile } from './managedChildProcess'
import { ensureKillSwitchProgramAllowed } from './firewallKillSwitch'
import {
  externalProxyHealthErrorMessage,
  isRecoverableExternalProxyTransportError,
  probeExternalProxy
} from './externalProxyHealth'
import type { ExternalProxyBatchStartResult, ServerProfile } from '../shared/ipc-types'

const CONTROL_HOST = '127.0.0.1'
export const EXTERNAL_PROXY_CONTROL_PORT = 17873
export const DEFAULT_EXTERNAL_PROXY_PORT = 17990
// Every default slot maps to a distinct valid TCP port. This is a transport
// boundary, not a product limit: slot 100 is port 18089.
export const MAX_EXTERNAL_PROXY_SLOT = 65535 - DEFAULT_EXTERNAL_PROXY_PORT + 1
const DEFAULT_PROXY_SLOT = 1
const RUNTIME_EXE_NAME = 'vpnte-external-proxy.exe'
export const EXTERNAL_PROXY_CONTROL_TOKEN_HEADER = 'x-vpnte-control-token'
const CONTROL_TOKEN_FILE = 'external-proxy-control-token'
const CONTROL_ENDPOINT_FILE = 'external-proxy-control-endpoint.json'
const EXTERNAL_PROXY_PID_FILE = 'external-proxy.pid'

type ExternalProxyAction = 'start' | 'rotate' | 'connect' | 'trigger'

/**
 * `health` is deliberately route-facing rather than a child-process flag.
 * A route is usable by Buyer Search only when it reports `healthy` and is
 * additionally fresh, unique and ready (see `isBuyerSearchRouteReady`).
 */
export type ExternalProxyHealth =
  | 'stopped'
  | 'starting'
  | 'healthy'
  | 'degraded'
  | 'rotating'
  | 'quarantined'
  | 'failed'

export type ExternalProxyLifecycle =
  | 'stopped'
  | 'starting'
  | 'ready'
  | 'healthy'
  | 'degraded'
  | 'rotating'
  | 'quarantined'
  | 'failed'

export interface ExternalProxyAggregate {
  total: number
  running: number
  ready: number
  healthy: number
  uniqueEgress: number
  duplicateEgress: number
  starting: number
  degraded: number
  quarantined: number
}

export interface ExternalProxyLease {
  slot: number
  leaseToken: string
  owner: string
  expiresAt: number
}

export interface ReserveExternalProxyOptions {
  owner: string
  ttlSeconds?: number
  preferredEgressIp?: string | null
  preferredSlot?: number | null
  /** A strict slot request. A busy slot returns Conflict. */
  slot?: number | null
  allowFallback?: boolean
}

export interface ExternalProxyReservation {
  leaseToken: string
  owner: string
  expiresAt: string
  slot: number
  proxyUrl: string | null
  egressIp: string | null
  generation: number
  instance: ExternalProxyInstanceStatus
}

export interface ExternalProxyInstanceStatus {
  slot: number
  /** True only after a complete, fresh data-plane probe succeeds. */
  running: boolean
  /** Technical child-process state, retained for diagnostics and controls. */
  processRunning: boolean
  /** Buyer Search readiness: healthy + fresh egress + no duplicate collision. */
  ready: boolean
  health: ExternalProxyHealth
  state: ExternalProxyLifecycle
  generation: number
  egressIp: string | null
  latencyMs: number | null
  lastCheckedAt: number | null
  lastSuccessAt: number | null
  egressCheckedAt: string | null
  updatedAt: string | null
  lastError: string | null
  lastErrorAt: string | null
  degradationReason: string | null
  consecutiveFailures: number
  nextCheckAt: string | null
  lastRotateReason: string | null
  autoDisabled: boolean
  host: string
  port: number | null
  proxyUrl: string | null
  profileId: string | null
  profileName: string | null
  country: string | null
  pid: number | null
  startedAt: string | null
}

export interface ExternalProxyStatus extends ExternalProxyInstanceStatus {
  controlHost: string
  controlPort: number | null
  controlUrl: string | null
  maxInstances: null
  instances: ExternalProxyInstanceStatus[]
  aggregate: ExternalProxyAggregate
}

export interface ExternalProxyProfileRow {
  id: string
  name: string
  country: string | null
  protocol: string
  server: string
  port: number
  groupId: string | null
  active: boolean
  activeSlots: number[]
}

export interface StartExternalProxyOptions {
  slot?: number | null
  country?: string | null
  profileId?: string | null
  port?: number | null
  action?: ExternalProxyAction
  idempotencyKey?: string | null
  rotateReason?: string | null
}

interface StopExternalProxyOptions {
  preserveHealth?: boolean
  preserveMetadata?: boolean
}

interface ExternalProxyState {
  slot: number
  configured: boolean
  process: ChildProcessWithoutNullStreams | null
  port: number | null
  profileId: string | null
  profileName: string | null
  country: string | null
  startedAt: number | null
  lastCountryQuery: string | null
  health: ExternalProxyHealthState
  lifecycle: ExternalProxyLifecycle
  generation: number
  updatedAt: number
  degradationReason: string | null
  lastErrorAt: number | null
  lastRotateReason: string | null
  rotationPreviousEgressIp: string | null
  autoDisabled: boolean
}

interface ExternalProxyHealthState {
  status: ExternalProxyHealth
  egressIp: string | null
  latencyMs: number | null
  lastCheckedAt: number | null
  lastSuccessAt: number | null
  lastError: string | null
  consecutiveFailures: number
  checkPromise: Promise<void> | null
  checkTimer: ReturnType<typeof setTimeout> | null
  autoDisableTimer: ReturnType<typeof setTimeout> | null
  lastTransportSignalAt: number
  lastRuntimeLogAt: number
  suppressedRuntimeLogs: number
  nextCheckAt: number | null
}

interface HealthCheckJob {
  slot: number
  generation: number
  promise: Promise<void>
  complete: () => void
}

interface ExternalProxyConfigMember {
  slot: number
  port: number
  profile: ServerProfile
  inboundTag: string
  outboundTag: string
}

const states = new Map<number, ExternalProxyState>()
const leasesBySlot = new Map<number, ExternalProxyLease>()
const leaseExpiryTimers = new Map<number, ReturnType<typeof setTimeout>>()
const ownerRouteHistory = new Map<string, { slot: number; egressIp: string; generation: number }>()
const rotationIdempotency = new Map<number, Map<string, ExternalProxyInstanceStatus>>()
const firewallAllowCache = new Map<string, { checkedAt: number; result: Awaited<ReturnType<typeof ensureKillSwitchProgramAllowed>> }>()
const firewallAllowInFlight = new Map<string, Promise<Awaited<ReturnType<typeof ensureKillSwitchProgramAllowed>>>>()
const endpointResolutionCache = new Map<string, { address: string; expiresAt: number }>()

const EXTERNAL_PROXY_DNS_TAG = 'dns-bootstrap'
const EXTERNAL_PROXY_DNS_STRATEGY = 'ipv4_only'
const ENDPOINT_RESOLUTION_TTL_MS = 5 * 60_000
const ENDPOINT_RESOLUTION_TIMEOUT_MS = 2_500
const HEALTH_CHECK_CONCURRENCY = 3
const HEALTH_CHECK_INTERVAL_MS = 60_000
const HEALTH_CHECK_INITIAL_DELAY_MS = 750
const HEALTH_FAILURE_COOLDOWN_MS = [15_000, 30_000, 60_000] as const
const HEALTH_FAILURE_AUTO_DISABLE_THRESHOLD = HEALTH_FAILURE_COOLDOWN_MS.length + 1
const HEALTH_LEASED_RECHECK_MS = 5 * 60_000
const TRANSPORT_SIGNAL_MIN_INTERVAL_MS = 30_000
const TRANSPORT_SIGNAL_PROBE_DELAY_MS = 15_000
const RUNTIME_WARNING_LOG_INTERVAL_MS = 30_000

const healthCheckQueue: HealthCheckJob[] = []
let activeHealthChecks = 0

let controlServer: Server | null = null
let controlToken: string | null = null
let operationLock: Promise<void> = Promise.resolve()
let controlServerStarting = false
let controlServerPort: number | null = null

function externalRuntimeDir(): string {
  return join(app.getPath('userData'), 'external-proxy-runtime')
}

export function externalProxyPortForSlot(slot: number): number {
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_EXTERNAL_PROXY_SLOT) {
    throw new RangeError(`external proxy slot must be between 1 and ${MAX_EXTERNAL_PROXY_SLOT}`)
  }
  return DEFAULT_EXTERNAL_PROXY_PORT + slot - 1
}

function parseExternalProxySlot(raw: unknown, fallback = DEFAULT_PROXY_SLOT): number {
  if (raw === undefined || raw === null || raw === '') return fallback
  const slot = Number(raw)
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_EXTERNAL_PROXY_SLOT) {
    throw new RangeError(`external proxy slot must be between 1 and ${MAX_EXTERNAL_PROXY_SLOT}`)
  }
  return slot
}

function stateForSlot(slot: number): ExternalProxyState {
  const existing = states.get(slot)
  if (existing) return existing

  const state: ExternalProxyState = {
    slot,
    configured: false,
    process: null,
    port: null,
    profileId: null,
    profileName: null,
    country: null,
    startedAt: null,
    lastCountryQuery: null,
    health: {
      status: 'stopped',
      egressIp: null,
      latencyMs: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      lastError: null,
      consecutiveFailures: 0,
      checkPromise: null,
      checkTimer: null,
      autoDisableTimer: null,
      lastTransportSignalAt: Number.NEGATIVE_INFINITY,
      lastRuntimeLogAt: Number.NEGATIVE_INFINITY,
      suppressedRuntimeLogs: 0,
      nextCheckAt: null
    },
    lifecycle: 'stopped',
    generation: 0,
    updatedAt: Date.now(),
    degradationReason: null,
    lastErrorAt: null,
    lastRotateReason: null,
    rotationPreviousEgressIp: null,
    autoDisabled: false
  }
  states.set(slot, state)
  return state
}

const MAX_LEASE_TTL_SECONDS = 60 * 60

class ExternalProxyApiError extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message)
    this.name = 'ExternalProxyApiError'
  }
}

function isoAt(timestamp: number | null): string | null {
  return timestamp === null ? null : new Date(timestamp).toISOString()
}

function touchExternalProxyState(state: ExternalProxyState): void {
  state.updatedAt = Date.now()
}

function isFreshExternalProxyEgress(state: ExternalProxyState, now = Date.now()): boolean {
  return Boolean(
    state.health.egressIp &&
    state.health.lastSuccessAt &&
    now - state.health.lastSuccessAt < HEALTH_CHECK_INTERVAL_MS
  )
}

function isHealthyExternalProxyRoute(state: ExternalProxyState, now = Date.now()): boolean {
  return Boolean(
    isExternalProxyStateRunning(state) &&
    state.lifecycle === 'ready' &&
    state.health.status === 'healthy' &&
    isFreshExternalProxyEgress(state, now)
  )
}

function duplicateExternalProxyEgressSlots(state: ExternalProxyState, now = Date.now()): number[] {
  if (!state.health.egressIp) return []
  return [...states.values()]
    .filter((candidate) => candidate.slot !== state.slot)
    .filter((candidate) => isHealthyExternalProxyRoute(candidate, now))
    .filter((candidate) => candidate.health.egressIp === state.health.egressIp)
    .map((candidate) => candidate.slot)
}

function isBuyerSearchRouteReady(state: ExternalProxyState, now = Date.now()): boolean {
  return isHealthyExternalProxyRoute(state, now) && duplicateExternalProxyEgressSlots(state, now).length === 0
}

function clearExternalProxyLeaseTimer(slot: number): void {
  const timer = leaseExpiryTimers.get(slot)
  if (timer) clearTimeout(timer)
  leaseExpiryTimers.delete(slot)
}

function forgetExternalProxyLease(slot: number, leaseToken?: string): ExternalProxyLease | null {
  const lease = leasesBySlot.get(slot)
  if (!lease || (leaseToken && lease.leaseToken !== leaseToken)) return null
  leasesBySlot.delete(slot)
  clearExternalProxyLeaseTimer(slot)
  return lease
}

function releaseExpiredExternalProxyLeases(now = Date.now()): void {
  for (const lease of leasesBySlot.values()) {
    if (lease.expiresAt <= now) {
      forgetExternalProxyLease(lease.slot, lease.leaseToken)
      logEvent('info', 'external-proxy', 'expired Buyer Search proxy lease released', {
        slot: lease.slot,
        owner: lease.owner
      })
    }
  }
}

function scheduleExternalProxyLeaseExpiry(lease: ExternalProxyLease): void {
  clearExternalProxyLeaseTimer(lease.slot)
  const timer = setTimeout(() => {
    void withExternalProxyOperation(async () => {
      const current = leasesBySlot.get(lease.slot)
      if (current?.leaseToken === lease.leaseToken && current.expiresAt <= Date.now()) {
        forgetExternalProxyLease(lease.slot, lease.leaseToken)
        logEvent('info', 'external-proxy', 'expired Buyer Search proxy lease released', {
          slot: lease.slot,
          owner: lease.owner
        })
      }
    })
  }, Math.max(0, lease.expiresAt - Date.now()))
  timer.unref?.()
  leaseExpiryTimers.set(lease.slot, timer)
}

function activeExternalProxyLease(slot: number): ExternalProxyLease | null {
  releaseExpiredExternalProxyLeases()
  return leasesBySlot.get(slot) ?? null
}

function rememberExternalProxyRoute(owner: string, state: ExternalProxyState): void {
  if (!state.health.egressIp) return
  ownerRouteHistory.set(owner, {
    slot: state.slot,
    egressIp: state.health.egressIp,
    generation: state.generation
  })
}

function externalProxyReservation(lease: ExternalProxyLease): ExternalProxyReservation {
  const instance = getExternalProxyInstanceStatus(lease.slot)
  return {
    leaseToken: lease.leaseToken,
    owner: lease.owner,
    expiresAt: new Date(lease.expiresAt).toISOString(),
    slot: instance.slot,
    proxyUrl: instance.proxyUrl,
    egressIp: instance.egressIp,
    generation: instance.generation,
    instance
  }
}

function normalizeLeaseTtlSeconds(value: number | undefined): number {
  if (value === undefined) return 120
  if (!Number.isFinite(value) || value < 1 || value > MAX_LEASE_TTL_SECONDS) {
    throw new RangeError(`ttlSeconds must be between 1 and ${MAX_LEASE_TTL_SECONDS}`)
  }
  return Math.floor(value)
}

function firstEligibleExternalProxyRoute(candidates: Iterable<ExternalProxyState>): ExternalProxyState | null {
  for (const state of candidates) {
    if (!isBuyerSearchRouteReady(state) || activeExternalProxyLease(state.slot)) continue
    return state
  }
  return null
}

export async function reserveExternalProxy(options: ReserveExternalProxyOptions): Promise<ExternalProxyReservation> {
  return withExternalProxyOperation(async () => {
    const owner = String(options.owner ?? '').trim()
    if (!owner) throw new RangeError('owner is required')
    const ttlSeconds = normalizeLeaseTtlSeconds(options.ttlSeconds)
    const allowFallback = options.allowFallback !== false
    const strictSlot = options.slot === undefined || options.slot === null
      ? null
      : parseExternalProxySlot(options.slot)
    const preferredSlot = options.preferredSlot === undefined || options.preferredSlot === null
      ? null
      : parseExternalProxySlot(options.preferredSlot)
    const preferredEgressIp = String(options.preferredEgressIp ?? '').trim() || null

    releaseExpiredExternalProxyLeases()
    const alreadyLeased = [...leasesBySlot.values()].find((lease) => lease.owner === owner)
    if (alreadyLeased) {
      throw new ExternalProxyApiError(`Owner already has an active lease for slot ${alreadyLeased.slot}`, 409)
    }

    const chooseStrictSlot = (): ExternalProxyState | null => {
      if (strictSlot === null) return null
      if (activeExternalProxyLease(strictSlot)) {
        throw new ExternalProxyApiError(`Slot ${strictSlot} is already leased`, 409)
      }
      const state = states.get(strictSlot)
      if (state && isBuyerSearchRouteReady(state)) return state
      if (!allowFallback) throw new ExternalProxyApiError(`Slot ${strictSlot} is not a healthy ready route`, 409)
      return null
    }

    let selected = chooseStrictSlot()
    if (!selected) {
      const history = ownerRouteHistory.get(owner)
      if (history) {
        const state = states.get(history.slot)
        if (state && state.generation === history.generation && state.health.egressIp === history.egressIp) {
          selected = firstEligibleExternalProxyRoute([state])
        }
      }
    }
    if (!selected && preferredEgressIp) {
      selected = firstEligibleExternalProxyRoute(
        [...states.values()]
          .filter((state) => state.health.egressIp === preferredEgressIp)
          .sort((a, b) => a.slot - b.slot)
      )
    }
    if (!selected && preferredSlot !== null) {
      if (activeExternalProxyLease(preferredSlot) && !allowFallback) {
        throw new ExternalProxyApiError(`Slot ${preferredSlot} is already leased`, 409)
      }
      const state = states.get(preferredSlot)
      if (state) selected = firstEligibleExternalProxyRoute([state])
    }
    if (!selected && allowFallback) {
      selected = firstEligibleExternalProxyRoute(
        [...states.values()].sort((a, b) => a.slot - b.slot)
      )
    }
    if (!selected) {
      throw new ExternalProxyApiError('No free healthy route with a fresh unique egress IP is available', 503)
    }

    const lease: ExternalProxyLease = {
      slot: selected.slot,
      leaseToken: randomBytes(32).toString('hex'),
      owner,
      expiresAt: Date.now() + ttlSeconds * 1_000
    }
    leasesBySlot.set(lease.slot, lease)
    scheduleExternalProxyLeaseExpiry(lease)
    rememberExternalProxyRoute(owner, selected)
    logEvent('info', 'external-proxy', 'Buyer Search route reserved', {
      slot: lease.slot,
      owner: lease.owner,
      egressIp: selected.health.egressIp,
      generation: selected.generation
    })
    return externalProxyReservation(lease)
  })
}

export async function renewExternalProxyReservation(leaseToken: string, ttlSeconds?: number): Promise<ExternalProxyReservation> {
  return withExternalProxyOperation(async () => {
    releaseExpiredExternalProxyLeases()
    const token = String(leaseToken ?? '').trim()
    const lease = [...leasesBySlot.values()].find((candidate) => candidate.leaseToken === token)
    if (!lease) throw new ExternalProxyApiError('Unknown or expired lease token', 403)
    lease.expiresAt = Date.now() + normalizeLeaseTtlSeconds(ttlSeconds) * 1_000
    scheduleExternalProxyLeaseExpiry(lease)
    return externalProxyReservation(lease)
  })
}

export async function releaseExternalProxyReservation(leaseToken: string): Promise<{ released: true; slot: number }> {
  return withExternalProxyOperation(async () => {
    releaseExpiredExternalProxyLeases()
    const token = String(leaseToken ?? '').trim()
    const lease = [...leasesBySlot.values()].find((candidate) => candidate.leaseToken === token)
    if (!lease) throw new ExternalProxyApiError('Unknown or expired lease token', 403)
    forgetExternalProxyLease(lease.slot, token)
    logEvent('info', 'external-proxy', 'Buyer Search route released', { slot: lease.slot, owner: lease.owner })
    return { released: true, slot: lease.slot }
  })
}

function externalProxyPidFilePath(slot: number): string {
  const fileName = slot === DEFAULT_PROXY_SLOT
    ? EXTERNAL_PROXY_PID_FILE
    : `external-proxy-${slot}.pid`
  return join(externalRuntimeDir(), fileName)
}

function externalProxyConfigPath(slot: number): string {
  return join(externalRuntimeDir(), slot === DEFAULT_PROXY_SLOT ? 'external-proxy.json' : `external-proxy-${slot}.json`)
}

function brandedControlDiscoveryDir(): string {
  return join(app.getPath('appData'), 'VPN Tunnel Enforcer')
}

function controlDiscoveryDirs(): string[] {
  return [...new Set([app.getPath('userData'), brandedControlDiscoveryDir()])]
}

function controlTokenPath(dir = app.getPath('userData')): string {
  return join(dir, CONTROL_TOKEN_FILE)
}

function controlEndpointPath(dir = app.getPath('userData')): string {
  return join(dir, CONTROL_ENDPOINT_FILE)
}

async function writeControlTokenFiles(token: string): Promise<void> {
  const [primary, ...compat] = controlDiscoveryDirs()
  await mkdir(primary, { recursive: true })
  await writeFile(controlTokenPath(primary), token + '\n', { encoding: 'utf8', mode: 0o600 })

  await Promise.all(compat.map(async (dir) => {
    try {
      await mkdir(dir, { recursive: true })
      await writeFile(controlTokenPath(dir), token + '\n', { encoding: 'utf8', mode: 0o600 })
    } catch (err) {
      logEvent('warn', 'external-proxy', 'failed to write compatibility control token file', {
        path: controlTokenPath(dir),
        error: err instanceof Error ? err.message : String(err)
      })
    }
  }))
}

async function ensureControlToken(): Promise<string> {
  if (controlToken) return controlToken
  controlToken = randomBytes(32).toString('hex')
  await writeControlTokenFiles(controlToken)
  return controlToken
}

async function writeControlEndpoint(port: number): Promise<void> {
  const endpointFor = (dir: string): string => JSON.stringify({
    host: CONTROL_HOST,
    port,
    url: `http://${CONTROL_HOST}:${port}`,
    tokenFile: controlTokenPath(dir),
    updatedAt: Date.now()
  }, null, 2) + '\n'

  const [primary, ...compat] = controlDiscoveryDirs()
  await mkdir(primary, { recursive: true })
  await writeFile(controlEndpointPath(primary), endpointFor(primary), { encoding: 'utf8', mode: 0o600 })

  await Promise.all(compat.map(async (dir) => {
    try {
      await mkdir(dir, { recursive: true })
      await writeFile(controlEndpointPath(dir), endpointFor(dir), { encoding: 'utf8', mode: 0o600 })
    } catch (err) {
      logEvent('warn', 'external-proxy', 'failed to write compatibility control endpoint file', {
        path: controlEndpointPath(dir),
        error: err instanceof Error ? err.message : String(err)
      })
    }
  }))
}

function bundledResource(name: string): string {
  if (app.isPackaged) return join(process.resourcesPath, name)
  return join(app.getAppPath(), 'resources', name)
}

async function copyIfStale(src: string, dst: string): Promise<void> {
  try {
    const [srcStat, dstStat] = await Promise.all([stat(src), stat(dst)])
    if (srcStat.size === dstStat.size && srcStat.mtimeMs === dstStat.mtimeMs) return
  } catch {
    // Missing destination or stat failure: copy below.
  }
  await copyFile(src, dst)
}

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '').trim().toLowerCase()
}

const COUNTRY_ALIASES: Record<string, string[]> = {
  ru: ['ru', 'rus', 'russia', 'россия', 'рф'],
  de: ['de', 'deu', 'germany', 'германия', 'немец'],
  nl: ['nl', 'nld', 'netherlands', 'holland', 'нидерланды', 'голланд'],
  gb: ['gb', 'uk', 'united kingdom', 'great britain', 'britain', 'англия', 'британия', 'великобритания'],
  us: ['us', 'usa', 'united states', 'america', 'сша', 'америка'],
  se: ['se', 'swe', 'sweden', 'швеция'],
  fi: ['fi', 'fin', 'finland', 'финляндия'],
  fr: ['fr', 'fra', 'france', 'франция'],
  tr: ['tr', 'turkey', 'турция'],
  jp: ['jp', 'jpn', 'japan', 'япония'],
  sg: ['sg', 'singapore', 'сингапур'],
  kz: ['kz', 'kazakhstan', 'казахстан']
}

function countryNeedles(query: string | null | undefined): string[] {
  const q = normalizeText(query)
  if (!q) return []
  const fromAlias = Object.values(COUNTRY_ALIASES).find((aliases) => aliases.includes(q))
  return fromAlias ?? [q]
}

function profileMatchesCountry(profile: ServerProfile, countryQuery: string | null | undefined): boolean {
  const needles = countryNeedles(countryQuery)
  if (!needles.length) return true
  const haystack = normalizeText(`${profile.country ?? ''} ${profile.name ?? ''}`)
  return needles.some((needle) => haystack.includes(needle))
}

function usableProfiles(countryQuery?: string | null): ServerProfile[] {
  return serverPicker
    .getProfiles()
    .filter((profile) => profile.enabled !== false && profile.outbound && typeof profile.outbound === 'object')
    .filter((profile) => profileMatchesCountry(profile, countryQuery))
}

export function listExternalProxyProfiles(countryQuery?: string | null): ExternalProxyProfileRow[] {
  const activeSlotsByProfileId = new Map<string, number[]>()
  for (const [slot, state] of states) {
    if (!state.configured || !state.profileId) continue
    const activeSlots = activeSlotsByProfileId.get(state.profileId) ?? []
    activeSlots.push(slot)
    activeSlotsByProfileId.set(state.profileId, activeSlots)
  }

  return usableProfiles(countryQuery).map((profile) => {
    const activeSlots = activeSlotsByProfileId.get(profile.id) ?? []
    return {
      id: profile.id,
      name: profile.name,
      country: profile.country ?? null,
      protocol: profile.protocol,
      server: profile.server,
      port: profile.port,
      groupId: profile.groupId ?? null,
      active: activeSlots.length > 0,
      activeSlots
    }
  })
}

export function pickExternalProxyProfile(
  profiles: ServerProfile[],
  opts: { profileId?: string | null; country?: string | null; currentProfileId?: string | null; action?: ExternalProxyAction } = {}
): ServerProfile | null {
  const usable = profiles
    .filter((profile) => profile.enabled !== false && profile.outbound && typeof profile.outbound === 'object')
    .filter((profile) => profileMatchesCountry(profile, opts.country))
  if (!usable.length) return null

  const explicit = String(opts.profileId ?? '').trim()
  if (explicit) {
    return usable.find((profile) => profile.id === explicit) ?? null
  }

  if (opts.action === 'connect' || opts.action === 'trigger') return null

  if (opts.action === 'rotate' && opts.currentProfileId) {
    const currentIndex = usable.findIndex((profile) => profile.id === opts.currentProfileId)
    return usable[(currentIndex >= 0 ? currentIndex + 1 : 0) % usable.length] ?? usable[0]
  }

  const active = serverPicker.getActiveProfile()
  if (active && usable.some((profile) => profile.id === active.id)) return active
  return usable[0]
}

function pickProfileForSlot(
  profiles: ServerProfile[],
  opts: { profileId?: string | null; country?: string | null; currentProfileId?: string | null; action?: ExternalProxyAction },
  slot: number
): ServerProfile | null {
  const explicitProfileId = String(opts.profileId ?? '').trim()
  if (explicitProfileId) return pickExternalProxyProfile(profiles, opts)

  const usedProfileIds = new Set(
    [...states.values()]
      .filter((state) => state.slot !== slot && state.configured && state.profileId)
      .map((state) => state.profileId as string)
  )
  if (!usedProfileIds.size) return pickExternalProxyProfile(profiles, opts)

  const unusedProfiles = profiles.filter((profile) => !usedProfileIds.has(profile.id))
  if (opts.action === 'rotate' && opts.currentProfileId) {
    const rotationCandidates = profiles.filter((profile) => profile.id === opts.currentProfileId || !usedProfileIds.has(profile.id))
    if (rotationCandidates.length > 1) return pickExternalProxyProfile(rotationCandidates, opts)
  } else if (unusedProfiles.length) {
    return pickExternalProxyProfile(unusedProfiles, opts)
  }

  return pickExternalProxyProfile(profiles, opts)
}

function isDomainServer(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const server = value.trim()
  if (!server) return false
  const unbracketed = server.startsWith('[') && server.endsWith(']')
    ? server.slice(1, -1)
    : server
  return isIP(unbracketed) === 0
}

function cloneExternalProxyOutbound(
  profile: ServerProfile,
  tag = 'proxy-out'
): { outbound: Record<string, unknown>; needsBootstrapDns: boolean } {
  const outbound = JSON.parse(JSON.stringify(profile.outbound)) as Record<string, unknown>
  const legacyStrategy = typeof outbound.domain_strategy === 'string' && outbound.domain_strategy.trim()
    ? outbound.domain_strategy.trim()
    : null
  const existingDomainResolver = outbound.domain_resolver
  const existingStrategy =
    existingDomainResolver && typeof existingDomainResolver === 'object' &&
      typeof (existingDomainResolver as { strategy?: unknown }).strategy === 'string' &&
      (existingDomainResolver as { strategy: string }).strategy.trim()
      ? (existingDomainResolver as { strategy: string }).strategy.trim()
      : null

  delete outbound.domain_strategy
  delete outbound.domain_resolver

  const needsBootstrapDns = isDomainServer(outbound.server)
  if (needsBootstrapDns) {
    outbound.domain_resolver = {
      server: EXTERNAL_PROXY_DNS_TAG,
      strategy: existingStrategy || legacyStrategy || EXTERNAL_PROXY_DNS_STRATEGY
    }
  }
  outbound.tag = tag
  return { outbound, needsBootstrapDns }
}

function timeoutLookup<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`System DNS lookup timed out after ${timeoutMs}ms`)), timeoutMs)
    timer.unref?.()
    operation.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (error) => {
        clearTimeout(timer)
        reject(error)
      }
    )
  })
}

async function resolveExternalProxyEndpoint(profile: ServerProfile): Promise<ServerProfile> {
  const rawServer = (profile.outbound as Record<string, unknown> | undefined)?.server
  if (!isDomainServer(rawServer)) return profile

  const hostname = rawServer.trim()
  const cacheKey = hostname.toLowerCase()
  const cached = endpointResolutionCache.get(cacheKey)
  let address = cached && cached.expiresAt > Date.now() ? cached.address : null
  if (!address) {
    try {
      const addresses = await timeoutLookup(lookup(hostname, { all: true, verbatim: false }), ENDPOINT_RESOLUTION_TIMEOUT_MS)
      const selected = addresses.find((entry) => entry.family === 4) ?? addresses[0]
      if (!selected?.address) throw new Error('System DNS returned no addresses')
      address = selected.address
      endpointResolutionCache.set(cacheKey, { address, expiresAt: Date.now() + ENDPOINT_RESOLUTION_TTL_MS })
      logEvent('debug', 'external-proxy', 'resolved proxy endpoint through system DNS', { hostname, address })
    } catch (error) {
      logEvent('warn', 'external-proxy', 'system DNS endpoint resolution failed; using direct DNS bootstrap fallback', {
        hostname,
        error: error instanceof Error ? error.message : String(error)
      })
      return profile
    }
  }

  const outbound = JSON.parse(JSON.stringify(profile.outbound)) as Record<string, unknown>
  outbound.server = address
  if (outbound.tls && typeof outbound.tls === 'object') {
    const tls = outbound.tls as Record<string, unknown>
    if (tls.enabled !== false && (typeof tls.server_name !== 'string' || !tls.server_name.trim())) {
      tls.server_name = hostname
    }
  }
  return { ...profile, outbound }
}

function buildExternalProxyConfigForMembers(members: readonly ExternalProxyConfigMember[]): Record<string, unknown> {
  if (members.length === 0) throw new Error('External proxy configuration requires at least one slot')
  const prepared = members.map((member) => ({
    ...member,
    ...cloneExternalProxyOutbound(member.profile, member.outboundTag)
  }))
  const needsBootstrapDns = prepared.some((member) => member.needsBootstrapDns)

  return {
    log: { level: 'warn' },
    ...(needsBootstrapDns
      ? {
        // This resolver is only for the VPN endpoint's domain_resolver. It has
        // no proxy detour, so resolving proxy-out cannot depend on proxy-out.
        dns: {
          servers: [
            { type: 'udp', tag: EXTERNAL_PROXY_DNS_TAG, server: '1.1.1.1' },
            { type: 'udp', tag: `${EXTERNAL_PROXY_DNS_TAG}-backup`, server: '8.8.8.8' }
          ],
          strategy: EXTERNAL_PROXY_DNS_STRATEGY,
          final: EXTERNAL_PROXY_DNS_TAG
        }
      }
      : {}),
    inbounds: members.map((member) => ({
      type: 'mixed',
      tag: member.inboundTag,
      listen: CONTROL_HOST,
      listen_port: member.port
    })),
    outbounds: [
      ...prepared.map((member) => member.outbound),
      { type: 'direct', tag: 'direct-out' },
      { type: 'block', tag: 'block-out' }
    ],
    route: {
      rules: [
        { action: 'sniff' },
        { domain: ['localhost'], outbound: 'direct-out' },
        { domain_suffix: ['localhost'], outbound: 'direct-out' },
        { ip_cidr: ['127.0.0.0/8', '::1/128'], outbound: 'direct-out' },
        { ip_is_private: true, outbound: 'direct-out' },
        ...members.map((member) => ({
          inbound: member.inboundTag,
          protocol: 'dns',
          outbound: member.outboundTag
        })),
        ...members.map((member) => ({ inbound: member.inboundTag, outbound: member.outboundTag }))
      ],
      // Every public request from an external inbound is matched above. Any
      // unmatched traffic fails closed instead of falling back to direct.
      final: 'block-out',
      auto_detect_interface: false,
      ...(needsBootstrapDns ? { default_domain_resolver: EXTERNAL_PROXY_DNS_TAG } : {})
    }
  }
}

export function buildExternalProxyConfig(profile: ServerProfile, port: number): Record<string, unknown> {
  return buildExternalProxyConfigForMembers([{
    slot: DEFAULT_PROXY_SLOT,
    port,
    profile,
    inboundTag: 'external-mixed-in',
    outboundTag: 'proxy-out'
  }])
}

function isExternalProxyStateConfigured(state: ExternalProxyState): boolean {
  return state.configured && state.port !== null && Boolean(state.profileId)
}

function parsePort(raw: unknown, fallback: number): number {
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return fallback
  return n
}

async function ensureExternalProxyFirewallAllowed(exe: string): Promise<Awaited<ReturnType<typeof ensureKillSwitchProgramAllowed>>> {
  const cached = firewallAllowCache.get(exe)
  if (cached && Date.now() - cached.checkedAt < 30_000 && cached.result.success) return cached.result
  const pending = firewallAllowInFlight.get(exe)
  if (pending) return pending
  const firewallBypass = ensureKillSwitchProgramAllowed(
    exe,
    'external-proxy',
    'VPN Tunnel Enforcer kill-switch: allow external proxy sing-box outbound.'
  )
  firewallAllowInFlight.set(exe, firewallBypass)
  try {
    const result = await firewallBypass
    if (result.success) firewallAllowCache.set(exe, { checkedAt: Date.now(), result })
    return result
  } finally {
    firewallAllowInFlight.delete(exe)
  }
}

async function assertPortIsAvailable(slot: number, port: number): Promise<void> {
  if (controlServerPort === port) {
    throw new Error(`Port ${port} is reserved for the external proxy Control API`)
  }

  const conflictingState = [...states.values()].find((state) =>
    state.slot !== slot && state.configured && state.port === port
  )
  if (conflictingState) {
    throw new Error(`Port ${port} is already used by external proxy slot ${conflictingState.slot}`)
  }

  const currentState = states.get(slot)
  if (currentState?.configured && currentState.port === port) return

  await new Promise<void>((resolve, reject) => {
    const probe = createServer()
    const fail = (err: Error) => {
      probe.close(() => undefined)
      reject(new Error(`Port ${port} is unavailable: ${err.message}`))
    }
    probe.once('error', fail)
    probe.listen(port, CONTROL_HOST, () => {
      probe.close((err) => {
        if (err) reject(err)
        else resolve()
      })
    })
  })
}

async function withExternalProxyOperation<T>(fn: () => Promise<T>): Promise<T> {
  const previous = operationLock
  let release!: () => void
  operationLock = new Promise<void>((resolve) => {
    release = resolve
  })
  await previous.catch(() => undefined)
  try {
    return await fn()
  } finally {
    release()
  }
}

async function stageExternalProxyRuntime(
  slot: number,
  profile: ServerProfile,
  port: number
): Promise<{ exe: string; config: string; cwd: string }> {
  const runtimeDir = externalRuntimeDir()
  await mkdir(runtimeDir, { recursive: true })
  const src = bundledResource('sing-box.exe')
  const exe = join(runtimeDir, RUNTIME_EXE_NAME)
  const config = externalProxyConfigPath(slot)
  await access(src)
  await copyIfStale(src, exe)
  const resolvedProfile = await resolveExternalProxyEndpoint(profile)
  await writeFile(config, JSON.stringify(buildExternalProxyConfig(resolvedProfile, port), null, 2), 'utf8')
  return { exe, config, cwd: runtimeDir }
}

async function stopExternalProxyProcessUnlocked(state: ExternalProxyState, reason: string): Promise<void> {
  const proc = state.process
  invalidateExternalProxyHealthWork(state)
  state.process = null
  state.startedAt = null
  state.health.nextCheckAt = null
  if (proc && !proc.killed) {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 1_500)
      proc.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
      try {
        proc.kill()
      } catch (error) {
        clearTimeout(timer)
        logEvent('warn', 'external-proxy', 'failed to stop external proxy instance', {
          slot: state.slot,
          error: externalProxyHealthErrorMessage(error)
        })
        resolve()
      }
    })
  }
  await removeManagedChildPidFile(externalProxyPidFilePath(state.slot), proc?.pid)
  if (proc) logEvent('info', 'external-proxy', 'instance process stopped', { slot: state.slot, pid: proc.pid, reason })
}

function markExternalProxyProcessFailure(state: ExternalProxyState, message: string): void {
  state.lifecycle = 'failed'
  state.health.status = 'failed'
  state.health.egressIp = null
  state.health.latencyMs = null
  state.health.lastCheckedAt = Date.now()
  state.health.lastError = message
  state.lastErrorAt = state.health.lastCheckedAt
  state.degradationReason = 'process-failed'
  state.health.nextCheckAt = null
  touchExternalProxyState(state)
}

function logExternalProxyRuntimeWarning(state: ExternalProxyState, message: string): void {
  const now = Date.now()
  if (now - state.health.lastRuntimeLogAt < RUNTIME_WARNING_LOG_INTERVAL_MS) {
    state.health.suppressedRuntimeLogs += 1
    return
  }

  const suppressedRuntimeLogs = state.health.suppressedRuntimeLogs
  state.health.lastRuntimeLogAt = now
  state.health.suppressedRuntimeLogs = 0
  logEvent('warn', 'external-proxy', message, {
    slot: state.slot,
    ...(suppressedRuntimeLogs > 0 ? { suppressedRuntimeLogs } : {})
  })
}

async function startExternalProxyProcessUnlocked(
  state: ExternalProxyState,
  profile: ServerProfile,
  reason: string
): Promise<void> {
  try {
    const runtime = await stageExternalProxyRuntime(state.slot, profile, state.port!)
    await new Promise<void>((resolve, reject) => {
      const check = spawn(runtime.exe, ['check', '-c', runtime.config], { cwd: runtime.cwd, windowsHide: true })
      let stderr = ''
      check.stderr.on('data', (chunk) => { stderr += String(chunk) })
      check.once('error', reject)
      check.once('exit', (code) => {
        if (code === 0) resolve()
        else reject(new Error(stderr.trim() || `sing-box check failed with exit code ${code}`))
      })
    })
    const firewallBypass = await ensureExternalProxyFirewallAllowed(runtime.exe)
    if (!firewallBypass.success) throw new Error(firewallBypass.details || firewallBypass.message)

    await stopExternalProxyProcessUnlocked(state, `${reason}: replace`)
    const proc = spawn(runtime.exe, ['run', '-c', runtime.config], { cwd: runtime.cwd, windowsHide: true })
    state.process = proc
    state.startedAt = Date.now()
    scheduleExternalProxyHealthCheck(state.slot, HEALTH_CHECK_INITIAL_DELAY_MS + (state.slot % 5) * 100)
    await writeManagedChildPidFile(externalProxyPidFilePath(state.slot), {
      owner: 'external-proxy',
      pid: proc.pid ?? 0,
      exePath: runtime.exe,
      configPath: runtime.config,
      createdAt: state.startedAt
    }).catch((error) => {
      logEvent('warn', 'external-proxy', 'failed to write external proxy pidfile', {
        slot: state.slot,
        error: externalProxyHealthErrorMessage(error)
      })
    })

    proc.stdout.on('data', (chunk) => {
      const message = String(chunk).trim()
      if (message) logEvent('debug', 'external-proxy', message, { slot: state.slot })
    })
    proc.stderr.on('data', (chunk) => {
      const message = String(chunk).trim()
      if (!message) return
      logExternalProxyRuntimeWarning(state, message)
      recordExternalProxyTransportSignal(state.slot, message)
    })
    proc.once('error', (error) => {
      if (state.process !== proc) return
      markExternalProxyProcessFailure(state, externalProxyHealthErrorMessage(error))
    })
    proc.once('exit', (code, signal) => {
      if (state.process !== proc) return
      state.process = null
      state.startedAt = null
      invalidateExternalProxyHealthWork(state)
      markExternalProxyProcessFailure(state, `External proxy instance exited (${code ?? signal ?? 'unknown'})`)
      void removeManagedChildPidFile(externalProxyPidFilePath(state.slot), proc.pid)
    })
    logEvent('info', 'external-proxy', 'instance started', {
      slot: state.slot,
      pid: proc.pid,
      port: state.port,
      profileId: state.profileId,
      reason
    })
  } catch (error) {
    await stopExternalProxyProcessUnlocked(state, `${reason}: failed to start`)
    markExternalProxyProcessFailure(state, externalProxyHealthErrorMessage(error))
    throw error
  }
}

function clearExternalProxyHealthTimers(state: ExternalProxyState): void {
  if (state.health.checkTimer) {
    clearTimeout(state.health.checkTimer)
    state.health.checkTimer = null
  }
  if (state.health.autoDisableTimer) {
    clearTimeout(state.health.autoDisableTimer)
    state.health.autoDisableTimer = null
  }
}

function invalidateExternalProxyHealthWork(state: ExternalProxyState): void {
  clearExternalProxyHealthTimers(state)
  state.health.checkPromise = null
}

function beginExternalProxyHealthRun(state: ExternalProxyState): void {
  invalidateExternalProxyHealthWork(state)
  state.autoDisabled = false
  state.health = {
    status: state.lifecycle === 'rotating' ? 'rotating' : 'starting',
    egressIp: null,
    latencyMs: null,
    lastCheckedAt: null,
    lastSuccessAt: null,
    lastError: null,
    consecutiveFailures: 0,
    checkPromise: null,
    checkTimer: null,
    autoDisableTimer: null,
    lastTransportSignalAt: Number.NEGATIVE_INFINITY,
    lastRuntimeLogAt: Number.NEGATIVE_INFINITY,
    suppressedRuntimeLogs: 0,
    nextCheckAt: null
  }
  state.degradationReason = null
  state.lastErrorAt = null
  touchExternalProxyState(state)
}

function scheduleExternalProxyHealthCheck(slot: number, delayMs: number): void {
  const state = states.get(slot)
  if (!state || !isExternalProxyStateRunning(state)) return
  if (state.health.checkTimer) clearTimeout(state.health.checkTimer)
  const generation = state.generation
  const timer = setTimeout(() => {
    if (state.health.checkTimer === timer) state.health.checkTimer = null
    if (state.generation !== generation || !isExternalProxyStateRunning(state)) return
    void queueExternalProxyHealthCheck(slot)
  }, delayMs)
  timer.unref?.()
  state.health.checkTimer = timer
  state.health.nextCheckAt = Date.now() + delayMs
  touchExternalProxyState(state)
}

function completeHealthCheckJob(job: HealthCheckJob): void {
  const state = states.get(job.slot)
  if (state?.health.checkPromise === job.promise) state.health.checkPromise = null
  job.complete()
}

function externalProxyFailureCooldownMs(consecutiveFailures: number): number {
  const index = Math.min(Math.max(0, consecutiveFailures - 1), HEALTH_FAILURE_COOLDOWN_MS.length - 1)
  return HEALTH_FAILURE_COOLDOWN_MS[index]
}

/**
 * A failed data-plane probe almost always means the remote route or the
 * Internet path is unavailable. Restarting the same sing-box config only
 * creates a new burst of failing handshakes, so exhausted slots are stopped
 * instead. A manual start/rotate remains the explicit recovery mechanism.
 */
function scheduleExternalProxyAutoDisable(slot: number): void {
  const state = states.get(slot)
  if (!state || !isExternalProxyStateRunning(state) || state.health.autoDisableTimer) return

  const generation = state.generation
  const timer = setTimeout(() => {
    if (state.health.autoDisableTimer === timer) state.health.autoDisableTimer = null
    void withExternalProxyOperation(async () => {
      const current = states.get(slot)
      if (!current || current.generation !== generation || !isExternalProxyStateRunning(current)) return

      if (activeExternalProxyLease(slot)) {
        current.lifecycle = 'degraded'
        current.health.status = 'degraded'
        current.degradationReason = 'leased-route-recovery-blocked'
        current.health.lastError = current.health.lastError || 'Automatic stop is blocked while a Buyer Search lease is active'
        current.lastErrorAt = Date.now()
        touchExternalProxyState(current)
        scheduleExternalProxyHealthCheck(slot, HEALTH_LEASED_RECHECK_MS)
        return
      }

      current.autoDisabled = true
      current.lifecycle = 'failed'
      current.health.status = 'failed'
      current.health.lastError = current.health.lastError || 'External proxy disabled after repeated transport failures'
      current.lastErrorAt = Date.now()
      current.degradationReason = 'health-failure-budget-exhausted'
      current.health.nextCheckAt = null
      touchExternalProxyState(current)
      logEvent('error', 'external-proxy', 'disabled after repeated health-check transport failures', {
        slot,
        profileId: current.profileId,
        failures: current.health.consecutiveFailures,
        error: current.health.lastError
      })
      await stopExternalProxyUnlocked(slot, 'health failure budget exhausted', { preserveHealth: true, preserveMetadata: true })
    })
  }, 0)
  timer.unref?.()
  state.health.autoDisableTimer = timer
}

function markExternalProxyDegraded(
  state: ExternalProxyState,
  reason: string,
  message: string,
  quarantined = false
): void {
  if (state.health.checkTimer) {
    clearTimeout(state.health.checkTimer)
    state.health.checkTimer = null
  }
  if (state.health.autoDisableTimer) {
    clearTimeout(state.health.autoDisableTimer)
    state.health.autoDisableTimer = null
  }
  state.lifecycle = quarantined ? 'quarantined' : 'degraded'
  state.health.status = quarantined ? 'quarantined' : 'degraded'
  state.degradationReason = reason
  state.health.lastError = message
  state.lastErrorAt = Date.now()
  state.health.nextCheckAt = null
  touchExternalProxyState(state)
}

async function runExternalProxyHealthCheck(job: HealthCheckJob): Promise<void> {
  const state = states.get(job.slot)
  const proc = state?.process
  if (!state || state.generation !== job.generation || !proc || proc.killed || !state.port) return

  try {
    const result = await probeExternalProxy(`http://${CONTROL_HOST}:${state.port}`)
    if (state.generation !== job.generation || state.process !== proc || proc.killed) return
    if (isIP(result.egressIp) === 0) {
      throw new Error(`External proxy probe returned an invalid egress IP: ${result.egressIp}`)
    }
    const previousEgressIp = state.health.egressIp
    const checkedAt = Date.now()
    if (previousEgressIp && previousEgressIp !== result.egressIp) {
      state.health.egressIp = result.egressIp
      state.health.latencyMs = result.latencyMs
      state.health.lastCheckedAt = checkedAt
      state.health.lastSuccessAt = checkedAt
      markExternalProxyDegraded(
        state,
        'egress-ip-changed-without-rotation',
        `Egress IP changed from ${previousEgressIp} to ${result.egressIp} without a route rotation`
      )
      return
    }
    if (state.rotationPreviousEgressIp && state.rotationPreviousEgressIp === result.egressIp) {
      state.health.egressIp = result.egressIp
      state.health.latencyMs = result.latencyMs
      state.health.lastCheckedAt = checkedAt
      state.health.lastSuccessAt = checkedAt
      markExternalProxyDegraded(
        state,
        'rotation-did-not-change-egress-ip',
        `Rotation kept the previous egress IP ${result.egressIp}`
      )
      return
    }
    state.health.status = 'healthy'
    state.lifecycle = 'ready'
    state.health.egressIp = result.egressIp
    state.health.latencyMs = result.latencyMs
    state.health.lastCheckedAt = checkedAt
    state.health.lastSuccessAt = checkedAt
    state.health.lastError = null
    state.health.consecutiveFailures = 0
    state.degradationReason = null
    state.lastErrorAt = null
    state.rotationPreviousEgressIp = null

    const duplicateSlots = duplicateExternalProxyEgressSlots(state, checkedAt)
    if (duplicateSlots.length > 0) {
      const duplicateStates = duplicateSlots
        .map((slot) => states.get(slot))
        .filter((candidate): candidate is ExternalProxyState => Boolean(candidate))
      const currentHasLease = Boolean(activeExternalProxyLease(state.slot))
      const leasedPeer = duplicateStates.find((candidate) => activeExternalProxyLease(candidate.slot))
      const peerToKeep = leasedPeer ?? duplicateStates.sort((a, b) => a.slot - b.slot)[0]
      if (currentHasLease && !leasedPeer && peerToKeep) {
        markExternalProxyDegraded(
          peerToKeep,
          'duplicate-egress-ip',
          `Duplicate egress IP ${result.egressIp} also reported by slot ${state.slot}`,
          true
        )
      } else {
        markExternalProxyDegraded(
          state,
          'duplicate-egress-ip',
          `Duplicate egress IP ${result.egressIp} already belongs to slot ${peerToKeep?.slot ?? duplicateSlots[0]}`,
          true
        )
        return
      }
    }
    touchExternalProxyState(state)
    scheduleExternalProxyHealthCheck(job.slot, HEALTH_CHECK_INTERVAL_MS + (job.slot % 5) * 250)
  } catch (error) {
    if (state.generation !== job.generation || state.process !== proc || proc.killed) return
    const message = externalProxyHealthErrorMessage(error)
    state.lifecycle = 'degraded'
    state.health.status = 'degraded'
    state.health.egressIp = null
    state.health.latencyMs = null
    state.health.lastCheckedAt = Date.now()
    state.health.lastError = message
    state.lastErrorAt = state.health.lastCheckedAt
    state.degradationReason = 'egress-probe-failed'
    state.health.nextCheckAt = null
    if (isRecoverableExternalProxyTransportError(error)) {
      state.health.consecutiveFailures += 1
      if (state.health.consecutiveFailures >= HEALTH_FAILURE_AUTO_DISABLE_THRESHOLD) {
        scheduleExternalProxyAutoDisable(job.slot)
      } else {
        scheduleExternalProxyHealthCheck(job.slot, externalProxyFailureCooldownMs(state.health.consecutiveFailures))
      }
    } else {
      state.health.consecutiveFailures = 0
      scheduleExternalProxyHealthCheck(job.slot, HEALTH_CHECK_INTERVAL_MS)
    }
    touchExternalProxyState(state)
    logEvent('warn', 'external-proxy', 'health check failed', {
      slot: job.slot,
      profileId: state.profileId,
      error: message,
      consecutiveFailures: state.health.consecutiveFailures
    })
  }
}

function drainExternalProxyHealthCheckQueue(): void {
  while (activeHealthChecks < HEALTH_CHECK_CONCURRENCY && healthCheckQueue.length > 0) {
    const job = healthCheckQueue.shift()!
    activeHealthChecks += 1
    void runExternalProxyHealthCheck(job)
      .catch((error) => {
        logEvent('warn', 'external-proxy', 'health check worker failed', {
          slot: job.slot,
          error: externalProxyHealthErrorMessage(error)
        })
      })
      .finally(() => {
        activeHealthChecks -= 1
        completeHealthCheckJob(job)
        drainExternalProxyHealthCheckQueue()
      })
  }
}

function queueExternalProxyHealthCheck(slot: number, force = false): Promise<void> {
  const state = states.get(slot)
  if (!state || !isExternalProxyStateRunning(state)) return Promise.resolve()
  if (state.health.checkPromise) return state.health.checkPromise
  if (!force && state.health.status === 'healthy' && state.health.lastCheckedAt && Date.now() - state.health.lastCheckedAt < HEALTH_CHECK_INTERVAL_MS) {
    return Promise.resolve()
  }
  if (force && state.health.checkTimer) {
    clearTimeout(state.health.checkTimer)
    state.health.checkTimer = null
  }

  const generation = state.generation
  let complete!: () => void
  const promise = new Promise<void>((resolve) => {
    complete = resolve
  })
  state.health.checkPromise = promise
  healthCheckQueue.push({ slot, generation, promise, complete })
  drainExternalProxyHealthCheckQueue()
  return promise
}

function recordExternalProxyTransportSignal(slot: number, message: string): void {
  const state = states.get(slot)
  if (!state || !isExternalProxyStateRunning(state)) return
  if (!/(context deadline exceeded|timeout|timed out|eof|socket hang up|econnreset)/i.test(message)) return
  const now = Date.now()
  if (
    state.health.status !== 'healthy' ||
    now - state.health.lastTransportSignalAt < TRANSPORT_SIGNAL_MIN_INTERVAL_MS
  ) return
  state.health.lastTransportSignalAt = now
  const requestedAt = now + TRANSPORT_SIGNAL_PROBE_DELAY_MS
  if (state.health.nextCheckAt === null || requestedAt < state.health.nextCheckAt) {
    scheduleExternalProxyHealthCheck(slot, TRANSPORT_SIGNAL_PROBE_DELAY_MS)
  }
}

export async function checkExternalProxyHealth(slot: number | null | undefined = DEFAULT_PROXY_SLOT): Promise<ExternalProxyInstanceStatus> {
  const normalizedSlot = parseExternalProxySlot(slot)
  await queueExternalProxyHealthCheck(normalizedSlot, true)
  return getExternalProxyInstanceStatus(normalizedSlot)
}

async function stopExternalProxyUnlocked(
  slot: number,
  reason = 'requested',
  options: StopExternalProxyOptions = {}
): Promise<ExternalProxyStatus> {
  const state = stateForSlot(slot)
  await stopExternalProxyProcessUnlocked(state, reason)
  state.configured = false
  state.port = null
  if (!options.preserveMetadata) {
    state.profileId = null
    state.profileName = null
    state.country = null
  }
  if (!options.preserveHealth) {
    state.autoDisabled = false
    state.lifecycle = 'stopped'
    state.health.status = 'stopped'
    state.health.egressIp = null
    state.health.latencyMs = null
    state.health.lastCheckedAt = Date.now()
    state.health.lastSuccessAt = null
    state.health.lastError = null
    state.health.consecutiveFailures = 0
    state.health.nextCheckAt = null
    state.degradationReason = null
    state.lastErrorAt = null
    state.rotationPreviousEgressIp = null
  }
  forgetExternalProxyLease(slot)
  touchExternalProxyState(state)
  logEvent('info', 'external-proxy', 'slot stopped', { slot, reason })
  return getExternalProxyStatus(slot)
}

async function stopExternalProxy(slot: number | null | undefined = DEFAULT_PROXY_SLOT, reason = 'requested'): Promise<ExternalProxyStatus> {
  const normalizedSlot = parseExternalProxySlot(slot)
  return withExternalProxyOperation(async () => {
    if (activeExternalProxyLease(normalizedSlot)) {
      throw new ExternalProxyApiError(`Slot ${normalizedSlot} cannot stop while a Buyer Search lease is active`, 409)
    }
    return stopExternalProxyUnlocked(normalizedSlot, reason)
  })
}

async function stopAllExternalProxies(reason = 'requested'): Promise<ExternalProxyStatus> {
  return withExternalProxyOperation(async () => {
    releaseExpiredExternalProxyLeases()
    if (leasesBySlot.size > 0) {
      throw new ExternalProxyApiError('Cannot stop all external proxies while Buyer Search leases are active', 409)
    }
    for (const state of [...states.values()]) {
      await stopExternalProxyUnlocked(state.slot, reason)
    }
    logEvent('info', 'external-proxy', 'all external proxy instances stopped', { reason })
    return getExternalProxyStatus(DEFAULT_PROXY_SLOT)
  })
}

async function startExternalProxyUnlocked(options: StartExternalProxyOptions = {}): Promise<ExternalProxyStatus> {
  const slot = parseExternalProxySlot(options.slot)
  const state = stateForSlot(slot)
  const action = options.action ?? 'start'
  if (action === 'start' && state.configured) {
    if (isExternalProxyStateRunning(state)) return getExternalProxyStatus(slot)
    if (activeExternalProxyLease(slot)) {
      throw new ExternalProxyApiError(`Slot ${slot} cannot restart while a Buyer Search lease is active`, 409)
    }
  }
  if (activeExternalProxyLease(slot)) {
    throw new ExternalProxyApiError(`Slot ${slot} cannot change route while a Buyer Search lease is active`, 409)
  }

  const defaultPort = externalProxyPortForSlot(slot)
  const port = parsePort(options.port ?? state.port ?? defaultPort, defaultPort)
  if (!state.configured) {
    await cleanupManagedChildPidFile(externalProxyPidFilePath(slot), 'external-proxy', (message, details) => {
      logEvent('warn', 'external-proxy', message, details)
    })
  }
  await assertPortIsAvailable(slot, port)
  const country = options.country ?? state.lastCountryQuery
  const profiles = usableProfiles(country)
  const profile = pickProfileForSlot(profiles, {
    profileId: options.profileId,
    country,
    currentProfileId: state.profileId,
    action
  }, slot)
  if ((action === 'connect' || action === 'trigger') && options.profileId && !profile) {
    throw new Error(`VPN profile not found or unusable: ${options.profileId}`)
  }
  if (!profile) {
    throw new Error(country ? `No VPN profiles found for country: ${country}` : 'No VPN profiles with outbound config found')
  }

  const previousEgressIp = state.health.egressIp
  state.configured = true
  state.port = port
  state.profileId = profile.id
  state.profileName = profile.name
  state.country = profile.country ?? null
  state.startedAt = null
  state.lastCountryQuery = country ?? null
  state.autoDisabled = false
  state.lifecycle = action === 'rotate' ? 'rotating' : 'starting'
  state.generation += 1
  state.rotationPreviousEgressIp = action === 'rotate' ? previousEgressIp : null
  if (action === 'rotate') state.lastRotateReason = options.rotateReason?.trim() || 'manual'
  beginExternalProxyHealthRun(state)
  await startExternalProxyProcessUnlocked(
    state,
    profile,
    action === 'rotate' ? 'rotate' : action === 'connect' || action === 'trigger' ? 'connect' : 'start'
  )

  return getExternalProxyStatus(slot)
}

async function startExternalProxy(options: StartExternalProxyOptions = {}): Promise<ExternalProxyStatus> {
  if (options.action === 'rotate') return rotateExternalProxy(options)
  return withExternalProxyOperation(() => startExternalProxyUnlocked(options))
}

async function rotateExternalProxy(options: StartExternalProxyOptions = {}): Promise<ExternalProxyStatus> {
  const slot = parseExternalProxySlot(options.slot)
  const idempotencyKey = String(options.idempotencyKey ?? '').trim()
  return withExternalProxyOperation(async () => {
    const prior = idempotencyKey ? rotationIdempotency.get(slot)?.get(idempotencyKey) : null
    if (prior) return getExternalProxyStatus(slot)
    const status = await startExternalProxyUnlocked({
      ...options,
      slot,
      action: 'rotate',
      rotateReason: options.rotateReason
    })
    await queueExternalProxyHealthCheck(slot, true)
    const completed = getExternalProxyStatus(slot)
    if (!completed.ready || !completed.egressIp) {
      throw new ExternalProxyApiError(`Rotation for slot ${slot} did not produce a fresh unique egress IP`, 503)
    }
    if (idempotencyKey) {
      const byKey = rotationIdempotency.get(slot) ?? new Map<string, ExternalProxyInstanceStatus>()
      byKey.set(idempotencyKey, getExternalProxyInstanceStatus(slot))
      rotationIdempotency.set(slot, byKey)
    }
    return completed
  })
}

function isExternalProxyStateRunning(state: ExternalProxyState): boolean {
  return Boolean(state.process && !state.process.killed)
}

function firstAvailableExternalProxySlot(excludedSlots: ReadonlySet<number> = new Set()): number {
  const occupiedSlots = new Set(
    [...states.values()]
      .filter(isExternalProxyStateConfigured)
      .map((state) => state.slot)
  )

  for (let slot = DEFAULT_PROXY_SLOT; slot <= MAX_EXTERNAL_PROXY_SLOT; slot += 1) {
    if (!occupiedSlots.has(slot) && !excludedSlots.has(slot)) return slot
  }
  throw new Error('No TCP ports are available for another external proxy')
}

async function startExternalProxyProfiles(profileIds: readonly string[]): Promise<ExternalProxyBatchStartResult> {
  const requestedIds = [...new Set(profileIds.map((profileId) => String(profileId).trim()).filter(Boolean))]

  return withExternalProxyOperation(async () => {
    const profilesById = new Map(usableProfiles().map((profile) => [profile.id, profile]))
    const activeVpnProfileId = serverPicker.getActiveProfileId()
    const runningProfileIds = new Set(
      [...states.values()]
        .filter(isExternalProxyStateConfigured)
        .map((state) => state.profileId)
        .filter((profileId): profileId is string => Boolean(profileId))
    )
    const result: ExternalProxyBatchStartResult = {
      requested: requestedIds.length,
      started: [],
      alreadyRunningProfileIds: [],
      skipped: [],
      failed: []
    }
    const rejectedSlots = new Set<number>()
    for (const profileId of requestedIds) {
      if (profileId === activeVpnProfileId) {
        result.skipped.push({ profileId, reason: 'active-vpn' })
        continue
      }
      if (runningProfileIds.has(profileId)) {
        result.alreadyRunningProfileIds.push(profileId)
        continue
      }
      if (!profilesById.has(profileId)) {
        result.skipped.push({ profileId, reason: 'unavailable' })
        continue
      }

      const slot = firstAvailableExternalProxySlot(rejectedSlots)
      try {
        const status = await startExternalProxyUnlocked({ slot, profileId, action: 'connect' })
        runningProfileIds.add(profileId)
        result.started.push(status)
      } catch (err) {
        rejectedSlots.add(slot)
        const error = err instanceof Error ? err.message : String(err)
        result.failed.push({ profileId, error })
        logEvent('warn', 'external-proxy', 'batch start failed for profile', { profileId, slot, error })
      }
    }
    result.started.sort((a, b) => a.slot - b.slot)
    return result
  })
}

export async function prewarmExternalProxyInstances(
  count: number,
  options: { country?: string | null } = {}
): Promise<{ requested: number; started: ExternalProxyInstanceStatus[]; instances: ExternalProxyInstanceStatus[]; aggregate: ExternalProxyAggregate; ready: boolean }> {
  if (!Number.isInteger(count) || count < 1 || count > MAX_EXTERNAL_PROXY_SLOT) {
    throw new RangeError(`count must be between 1 and ${MAX_EXTERNAL_PROXY_SLOT}`)
  }
  return withExternalProxyOperation(async () => {
    const profiles = usableProfiles(options.country)
    const activeVpnProfileId = serverPicker.getActiveProfileId()
    const usedProfileIds = new Set(
      [...states.values()]
        .filter(isExternalProxyStateConfigured)
        .map((state) => state.profileId)
        .filter((profileId): profileId is string => Boolean(profileId))
    )
    const started: ExternalProxyInstanceStatus[] = []
    for (const profile of profiles) {
      if (getExternalProxyInstances().length >= count) break
      if (profile.id === activeVpnProfileId || usedProfileIds.has(profile.id)) continue
      const slot = firstAvailableExternalProxySlot()
      await startExternalProxyUnlocked({
        slot,
        profileId: profile.id,
        country: options.country ?? null,
        action: 'connect'
      })
      usedProfileIds.add(profile.id)
      started.push(getExternalProxyInstanceStatus(slot))
    }
    await Promise.all(
      getExternalProxyInstances()
        .filter((instance) => instance.processRunning)
        .map((instance) => queueExternalProxyHealthCheck(instance.slot, true))
    )
    const instances = getExternalProxyInstances()
    const aggregate = getExternalProxyAggregate(instances)
    return {
      requested: count,
      started: started.map((instance) => getExternalProxyInstanceStatus(instance.slot)),
      instances,
      aggregate,
      ready: aggregate.ready >= count && aggregate.uniqueEgress >= count && aggregate.duplicateEgress === 0
    }
  })
}

export function getExternalProxyInstancesBatch(slots?: readonly number[]): { instances: ExternalProxyInstanceStatus[]; aggregate: ExternalProxyAggregate } {
  const requestedSlots = slots?.map((slot) => parseExternalProxySlot(slot))
  const instances = requestedSlots
    ? requestedSlots.map((slot) => getExternalProxyInstanceStatus(slot))
    : getExternalProxyInstances()
  return { instances, aggregate: getExternalProxyAggregate(instances) }
}

export function getExternalProxyInstanceStatus(slot: number | null | undefined = DEFAULT_PROXY_SLOT): ExternalProxyInstanceStatus {
  const normalizedSlot = parseExternalProxySlot(slot)
  const state = states.get(normalizedSlot)
  const processRunning = Boolean(state?.process && !state.process.killed)
  const health = state?.health.status ?? 'stopped'
  const exposeMetadata = state?.configured === true || state?.autoDisabled === true
  const ready = state ? isBuyerSearchRouteReady(state) : false
  return {
    slot: normalizedSlot,
    running: processRunning && ready,
    processRunning,
    ready,
    health,
    state: state?.lifecycle ?? 'stopped',
    generation: state?.generation ?? 0,
    egressIp: state?.health.egressIp ?? null,
    latencyMs: state?.health.latencyMs ?? null,
    lastCheckedAt: state?.health.lastCheckedAt ?? null,
    lastSuccessAt: state?.health.lastSuccessAt ?? null,
    egressCheckedAt: isoAt(state?.health.lastSuccessAt ?? null),
    updatedAt: isoAt(state?.updatedAt ?? null),
    lastError: state?.health.lastError ?? null,
    lastErrorAt: isoAt(state?.lastErrorAt ?? null),
    degradationReason: state?.degradationReason ?? null,
    consecutiveFailures: state?.health.consecutiveFailures ?? 0,
    nextCheckAt: isoAt(state?.health.nextCheckAt ?? null),
    lastRotateReason: state?.lastRotateReason ?? null,
    autoDisabled: state?.autoDisabled === true,
    host: CONTROL_HOST,
    port: state?.configured ? state.port ?? null : null,
    proxyUrl: state?.configured && state.port ? `http://${CONTROL_HOST}:${state.port}` : null,
    profileId: exposeMetadata ? state?.profileId ?? null : null,
    profileName: exposeMetadata ? state?.profileName ?? null : null,
    country: exposeMetadata ? state?.country ?? null : null,
    pid: processRunning ? state?.process?.pid ?? null : null,
    startedAt: processRunning ? isoAt(state?.startedAt ?? null) : null,
  }
}

export function getExternalProxyInstances(): ExternalProxyInstanceStatus[] {
  releaseExpiredExternalProxyLeases()
  return [...states.values()]
    .filter((state) => state.configured || state.autoDisabled)
    .map((state) => getExternalProxyInstanceStatus(state.slot))
    .sort((a, b) => a.slot - b.slot)
}

export function getExternalProxyAggregate(instances = getExternalProxyInstances()): ExternalProxyAggregate {
  const freshEgresses = new Map<string, ExternalProxyInstanceStatus[]>()
  for (const instance of instances) {
    if (!instance.processRunning || !instance.egressIp || !instance.egressCheckedAt) continue
    const checkedAt = Date.parse(instance.egressCheckedAt)
    if (!Number.isFinite(checkedAt) || Date.now() - checkedAt >= HEALTH_CHECK_INTERVAL_MS) continue
    const group = freshEgresses.get(instance.egressIp) ?? []
    group.push(instance)
    freshEgresses.set(instance.egressIp, group)
  }
  const duplicateEgress = [...freshEgresses.values()]
    .reduce((duplicates, group) => duplicates + Math.max(0, group.length - 1), 0)
  return {
    total: instances.length,
    running: instances.filter((instance) => instance.processRunning).length,
    ready: instances.filter((instance) => instance.ready).length,
    healthy: instances.filter((instance) => instance.health === 'healthy' && instance.ready).length,
    uniqueEgress: new Set(instances.filter((instance) => instance.ready).map((instance) => instance.egressIp)).size,
    duplicateEgress,
    starting: instances.filter((instance) => instance.state === 'starting' || instance.state === 'rotating').length,
    degraded: instances.filter((instance) => instance.state === 'degraded' || instance.state === 'failed').length,
    quarantined: instances.filter((instance) => instance.state === 'quarantined').length
  }
}

export function getExternalProxyStatus(slot: number | null | undefined = DEFAULT_PROXY_SLOT): ExternalProxyStatus {
  const instance = getExternalProxyInstanceStatus(slot)
  const instances = getExternalProxyInstances()
  return {
    ...instance,
    controlHost: CONTROL_HOST,
    controlPort: controlServerPort,
    controlUrl: controlServerPort ? `http://${CONTROL_HOST}:${controlServerPort}` : null,
    maxInstances: null,
    instances,
    aggregate: getExternalProxyAggregate(instances)
  }
}

function formatProfileListText(rows: ExternalProxyProfileRow[]): string {
  return rows
    .map((row) => [
      row.id,
      row.country ?? '',
      row.protocol,
      `${row.server}:${row.port}`,
      row.active ? 'active' : '',
      row.name
    ].join('\t'))
    .join('\n')
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (chunk: Buffer) => {
      raw += String(chunk)
      if (raw.length > 64 * 1024) req.destroy()
    })
    req.on('end', () => {
      if (!raw.trim()) return resolve({})
      try {
        resolve(JSON.parse(raw))
      } catch {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

function send(res: ServerResponse, status: number, payload: unknown, text = false): void {
  const body = text ? String(payload) : JSON.stringify(payload, null, 2)
  res.writeHead(status, {
    'Content-Type': text ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': 'http://127.0.0.1',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': `Content-Type, ${EXTERNAL_PROXY_CONTROL_TOKEN_HEADER}, Authorization`,
    'Vary': 'Origin'
  })
  res.end(body + (text ? '\n' : ''))
}

function controlError(error: string, detail = error): { ok: false; error: string; detail: string } {
  return { ok: false, error, detail }
}

export function isExternalProxyMutationPath(path: string): boolean {
  return path === '/start' || path === '/rotate' || path === '/connect' || path === '/connect-profiles' || path === '/trigger' || path === '/stop' || path === '/healthcheck' || path === '/instances/prewarm' || path === '/instances/status-batch' || path === '/instances/reserve' || path === '/instances/renew' || path === '/instances/release'
}

export function isValidExternalProxyControlToken(expected: string | null, provided: string | null | undefined): boolean {
  if (!expected || !provided) return false
  const expectedBuffer = Buffer.from(expected)
  const providedBuffer = Buffer.from(provided)
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer)
}

function requestControlToken(req: IncomingMessage): string | null {
  const header = req.headers[EXTERNAL_PROXY_CONTROL_TOKEN_HEADER]
  if (Array.isArray(header)) return header[0] ?? null
  if (typeof header === 'string' && header.trim()) return header.trim()
  const auth = req.headers.authorization
  if (typeof auth === 'string') {
    const match = auth.match(/^Bearer\s+(.+)$/i)
    if (match) return match[1].trim()
  }
  return null
}

async function handleControlRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') return send(res, 204, '', true)
  const url = new URL(req.url ?? '/', `http://${CONTROL_HOST}:${EXTERNAL_PROXY_CONTROL_PORT}`)
  const path = url.pathname.replace(/^\/api\/external-proxy/, '')
  const wantsText = url.searchParams.get('format') === 'text' || url.searchParams.get('text') === '1'

  if (isExternalProxyMutationPath(path)) {
    if (req.method !== 'POST') {
      return send(res, 405, wantsText ? 'method-not-allowed' : controlError('method-not-allowed'), wantsText)
    }
    if (!isValidExternalProxyControlToken(controlToken, requestControlToken(req))) {
      return send(res, 401, wantsText ? 'unauthorized' : controlError('unauthorized'), wantsText)
    }
  } else if (req.method !== 'GET') {
    return send(res, 405, wantsText ? 'method-not-allowed' : controlError('method-not-allowed'), wantsText)
  }

  const body = req.method === 'POST' ? await readBody(req) : {}
  const param = (name: string): string | null => {
    const fromQuery = url.searchParams.get(name)
    if (fromQuery !== null) return fromQuery
    const fromBody = body[name]
    return typeof fromBody === 'string' || typeof fromBody === 'number' ? String(fromBody) : null
  }

  try {
    if (path === '/status' || path === '/') {
      const status = getExternalProxyStatus(parseExternalProxySlot(param('slot')))
      return send(res, 200, wantsText ? (status.proxyUrl ?? 'stopped') : status, wantsText)
    }
    if (path === '/instances') {
      for (const state of states.values()) {
        const stale = !state.health.lastCheckedAt || Date.now() - state.health.lastCheckedAt >= HEALTH_CHECK_INTERVAL_MS
        if (isExternalProxyStateRunning(state) && stale) void queueExternalProxyHealthCheck(state.slot)
      }
      const instances = getExternalProxyInstances()
      const text = instances
        .filter((instance) => instance.running && instance.proxyUrl)
        .map((instance) => `${instance.slot}\t${instance.proxyUrl}`)
        .join('\n') || 'stopped'
      return send(res, 200, wantsText ? text : {
        maxInstances: null,
        instances,
        aggregate: getExternalProxyAggregate(instances),
        controlUrl: controlServerPort ? `http://${CONTROL_HOST}:${controlServerPort}` : null
      }, wantsText)
    }
    if (path === '/healthcheck') {
      const status = await checkExternalProxyHealth(parseExternalProxySlot(param('slot')))
      return send(res, 200, wantsText ? status.health : status, wantsText)
    }
    if (path === '/list') {
      const rows = listExternalProxyProfiles(param('country'))
      return send(res, 200, wantsText ? formatProfileListText(rows) : { profiles: rows }, wantsText)
    }
    if (path === '/connect-profiles') {
      const profileIds = Array.isArray(body.profileIds)
        ? body.profileIds.filter((value): value is string => typeof value === 'string').map((value) => value.trim()).filter(Boolean)
        : []
      if (profileIds.length === 0) throw new RangeError('profileIds must be a non-empty array of profile IDs')
      const result = await startExternalProxyProfiles(profileIds)
      const text = result.started.map((instance) => instance.proxyUrl).filter(Boolean).join('\n')
      return send(res, 200, wantsText ? text : result, wantsText)
    }
    if (path === '/instances/prewarm') {
      const count = Number(param('count'))
      const result = await prewarmExternalProxyInstances(count, { country: param('country') })
      return send(res, 200, wantsText ? String(result.aggregate.ready) : result, wantsText)
    }
    if (path === '/instances/status-batch') {
      const slots = Array.isArray(body.slots)
        ? body.slots.map((value) => parseExternalProxySlot(value))
        : undefined
      const result = getExternalProxyInstancesBatch(slots)
      return send(res, 200, wantsText ? String(result.aggregate.ready) : result, wantsText)
    }
    if (path === '/instances/reserve') {
      const allowFallbackRaw = body.allowFallback ?? param('allowFallback')
      const result = await reserveExternalProxy({
        owner: param('owner') ?? '',
        ttlSeconds: param('ttlSeconds') === null ? undefined : Number(param('ttlSeconds')),
        preferredEgressIp: param('preferredEgressIp'),
        preferredSlot: param('preferredSlot') === null ? null : Number(param('preferredSlot')),
        slot: param('slot') === null ? null : Number(param('slot')),
        allowFallback: !(allowFallbackRaw === false || String(allowFallbackRaw).toLowerCase() === 'false')
      })
      return send(res, 200, wantsText ? result.instance.proxyUrl ?? '' : result, wantsText)
    }
    if (path === '/instances/renew') {
      const result = await renewExternalProxyReservation(
        param('leaseToken') ?? '',
        param('ttlSeconds') === null ? undefined : Number(param('ttlSeconds'))
      )
      return send(res, 200, wantsText ? result.instance.proxyUrl ?? '' : result, wantsText)
    }
    if (path === '/instances/release') {
      const result = await releaseExternalProxyReservation(param('leaseToken') ?? '')
      return send(res, 200, wantsText ? 'released' : result, wantsText)
    }
    if (path === '/start' || path === '/rotate' || path === '/connect' || path === '/trigger') {
      const slot = parseExternalProxySlot(param('slot'))
      const status = await startExternalProxy({
        slot,
        action: path === '/rotate' ? 'rotate' : path === '/connect' ? 'connect' : path === '/trigger' ? 'trigger' : 'start',
        country: param('country'),
        profileId: param('profileId') ?? param('id'),
        port: param('port') ? parsePort(param('port'), externalProxyPortForSlot(slot)) : null,
        idempotencyKey: param('idempotencyKey'),
        rotateReason: param('reason')
      })
      return send(res, 200, wantsText ? status.proxyUrl ?? '' : status, wantsText)
    }
    if (path === '/stop') {
      const status = await stopExternalProxy(parseExternalProxySlot(param('slot')), 'api')
      return send(res, 200, wantsText ? 'stopped' : status, wantsText)
    }
    return send(res, 404, controlError('not-found'))
  } catch (err: any) {
    const detail = err?.message || String(err)
    logEvent('warn', 'external-proxy', 'control request failed', { path, error: detail })
    const status = err instanceof ExternalProxyApiError ? err.statusCode : err instanceof RangeError ? 400 : 500
    const error = status === 409 ? 'conflict' : status === 403 ? 'forbidden' : 'external-proxy-error'
    return send(res, status, wantsText ? detail : controlError(error, detail), wantsText)
  }
}

export function registerExternalProxyControlServer(): void {
  if (controlServer || controlServerStarting) return
  controlServerStarting = true
  const configuredPort = Number(process.env.VPNTE_CONTROL_PORT || EXTERNAL_PROXY_CONTROL_PORT)
  const port = Number.isInteger(configuredPort) && configuredPort > 0 && configuredPort <= 65535
    ? configuredPort
    : EXTERNAL_PROXY_CONTROL_PORT
  const allowEphemeralFallback = !process.env.VPNTE_CONTROL_PORT

  const createControlServer = (): Server => createServer((req, res) => {
      handleControlRequest(req, res).catch((err) => {
        const detail = err?.message || String(err)
        send(res, 500, controlError('external-proxy-error', detail))
      })
    })

  const listen = (server: Server, listenPort: number): Promise<number> => new Promise((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException) => {
      server.off('listening', onListening)
      reject(err)
    }
    const onListening = () => {
      server.off('error', onError)
      const address = server.address()
      resolve(typeof address === 'object' && address ? address.port : listenPort)
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(listenPort, CONTROL_HOST)
  })

  ensureControlToken().then(async () => {
    let server = createControlServer()
    let actualPort = port
    try {
      actualPort = await listen(server, port)
    } catch (err: any) {
      if (err?.code !== 'EADDRINUSE' || !allowEphemeralFallback) throw err
      logEvent('warn', 'external-proxy', 'control port is busy, falling back to an ephemeral port', {
        host: CONTROL_HOST,
        port
      })
      try { server.close() } catch { /* ignore */ }
      server = createControlServer()
      actualPort = await listen(server, 0)
    }

    controlServer = server
    controlServerPort = actualPort
    controlServerStarting = false
    await writeControlEndpoint(actualPort).catch((err) => {
      logEvent('warn', 'external-proxy', 'failed to write control endpoint file', err)
    })
    controlServer.on('error', (err) => {
      logEvent('warn', 'external-proxy', 'control server failed', err)
      controlServer = null
      controlServerPort = null
    })
    logEvent('info', 'external-proxy', 'control server listening', {
      host: CONTROL_HOST,
      port: actualPort,
      tokenFile: controlTokenPath(),
      endpointFile: controlEndpointPath()
    })
  }).catch((err) => {
    controlServerStarting = false
    logEvent('warn', 'external-proxy', 'failed to initialize control token', { error: (err as Error).message })
  })
}

export const externalProxy = {
  start: startExternalProxy,
  rotate: rotateExternalProxy,
  startProfiles: startExternalProxyProfiles,
  prewarm: prewarmExternalProxyInstances,
  stop: stopExternalProxy,
  stopAll: stopAllExternalProxies,
  status: getExternalProxyStatus,
  checkHealth: checkExternalProxyHealth,
  instances: getExternalProxyInstances,
  aggregate: getExternalProxyAggregate,
  statusBatch: getExternalProxyInstancesBatch,
  reserve: reserveExternalProxy,
  renew: renewExternalProxyReservation,
  release: releaseExternalProxyReservation,
  list: listExternalProxyProfiles,
  registerControlServer: registerExternalProxyControlServer
}
