import { createHmac, randomBytes } from 'crypto'
import { networkInterfaces } from 'os'
import { safeStorage } from 'electron'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { decryptSecret, encryptSecret, SECRET_REF_KIND } from './secretStorage'
import { ALL_KNOWN_ALIASES, getTunAdapterAlias, isOwnTunAddress } from './tunAdapter'
import { isIP } from 'net'
import { readAdaptiveNetworkIdentity, type AdaptiveNetworkIdentity } from './adaptiveNetworkIdentity'

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

interface AdaptiveLearningRecord {
  mode: Extract<AdaptiveBypassMode, 'tls-compatibility' | 'mtu-compatibility'>
  learnedAt: number
  lastUsedAt: number
  expiresAt: number
}

interface AdaptiveBypassStoreSchema {
  encryptedInstallSecret?: string
  fallbackInstallSecret?: string
  learning: Record<string, AdaptiveLearningRecord>
}

const LEARNING_TTL_MS = 30 * 24 * 60 * 60 * 1000
const MAX_LEARNING_RECORDS = 24
const LEARNING_KEY_VERSION = 'v2:'
let activeLearningKey: string | null = null
let activeLearningNetwork: string | null = null
let learningGeneration = 0

const store = new Store<AdaptiveBypassStoreSchema>({
  name: 'adaptive-bypass',
  defaults: { learning: {} }
})

let cachedInstallSecret: string | null = null
let currentStatus: AdaptiveBypassStatus = {
  phase: 'idle',
  mode: 'baseline',
  attempts: 0,
  message: 'Готово к подключению',
  updatedAt: Date.now(),
  reason: null
}

function getInstallSecret(): string {
  if (cachedInstallSecret) return cachedInstallSecret

  const encrypted = store.get('encryptedInstallSecret')
  if (encrypted) {
    if (!safeStorage?.isEncryptionAvailable?.()) throw new Error('Adaptive secure storage unavailable; saved identity was left unchanged')
    cachedInstallSecret = decryptSecret({ __vpnteSecretRef: SECRET_REF_KIND, ciphertext: encrypted })
    return cachedInstallSecret
  }

  const fallback = store.get('fallbackInstallSecret')
  if (fallback) {
    if (!safeStorage?.isEncryptionAvailable?.()) throw new Error('Adaptive secret migration requires secure storage; saved identity was left unchanged')
    const protectedSecret = encryptSecret(fallback)
    if (decryptSecret(protectedSecret) !== fallback) throw new Error('Adaptive secret read-back failed')
    store.store = { learning: store.get('learning') ?? {}, encryptedInstallSecret: protectedSecret.ciphertext }
    cachedInstallSecret = fallback
    return fallback
  }

  const secret = randomBytes(32).toString('base64')
  if (safeStorage?.isEncryptionAvailable?.()) {
    const protectedSecret = encryptSecret(secret)
    if (decryptSecret(protectedSecret) !== secret) throw new Error('Adaptive secret read-back failed')
    store.set('encryptedInstallSecret', protectedSecret.ciphertext)
  } else {
    // No plaintext fallback. An ephemeral identity cannot reuse saved learning
    // after restart, but keeps non-secret discovery available in this session.
    logEvent('warn', 'adaptive', 'secure storage unavailable; using session-only identity')
  }
  cachedInstallSecret = secret
  return secret
}

function hmac(value: string): string {
  return createHmac('sha256', getInstallSecret()).update(value).digest('base64url')
}

export function isTunOrVpnAdapter(name: string): boolean {
  if (!name) return false
  const lower = name.toLowerCase()
  if (lower === getTunAdapterAlias().toLowerCase()) return true
  if (ALL_KNOWN_ALIASES.some((a) => a.toLowerCase() === lower)) return true
  return /wintun|sing-box|singbox|sing-tun|\btun\b|wireguard|openvpn|tap-windows|vpnte/i.test(name)
}

function canonicalJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .filter(key => value[key] !== undefined).map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  return JSON.stringify(value) ?? 'null'
}

export function networkFingerprint(customInterfaces?: NodeJS.Dict<import('os').NetworkInterfaceInfo[]>, identity: AdaptiveNetworkIdentity[] = []): string {
  const interfaces = Object.entries(customInterfaces ?? networkInterfaces())
    .flatMap(([name, values]) => {
      if (isTunOrVpnAdapter(name)) return []
      return (values ?? [])
        .filter(value => !value.internal && value.mac && value.mac !== '00:00:00:00:00:00' && !isOwnTunAddress(value.address))
        .filter(value => isIP(value.address) === 4 || !(values ?? []).some(v => !v.internal && isIP(v.address) === 4 && !isOwnTunAddress(v.address)))
        .map(value => {
          // DHCP host-address changes and IPv6 privacy addresses are not a new network.
          const prefix = isIP(value.address) === 4 && isIP(value.netmask) === 4
            ? value.address.split('.').map((part, i) => Number(part) & Number(value.netmask.split('.')[i])).join('.') + '/' + value.netmask
            : ''
          return `${name}:${value.mac.toLowerCase()}:${prefix}`
        })
    })
    .sort()

  const networks = identity.map(row => ({ ...row, profiles: [...row.profiles].sort(), gateways: [...row.gateways].sort() }))
    .sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)))
  return hmac(canonicalJson({ interfaces: [...new Set(interfaces)], networks }))
}

export async function readAdaptiveNetworkFingerprint(): Promise<string | null> {
  const started = performance.now()
  const identity = await readAdaptiveNetworkIdentity()
  const fingerprint = identity?.length ? networkFingerprint(undefined, identity) : null
  logEvent('info', 'adaptive-bypass', 'Network identity read completed', {
    reader: 'cim', durationMs: Math.round(performance.now() - started), known: fingerprint !== null
  })
  return fingerprint
}

export function profileFingerprint(profile: Record<string, any> | undefined): string {
  if (!profile) return hmac('local-proxy')
  const outbound = profile.outbound && typeof profile.outbound === 'object' ? profile.outbound : profile
  const connection = { ...outbound }
  for (const key of ['tag', 'detour', 'bind_interface', 'domain_strategy', 'domain_resolver']) delete connection[key]
  return hmac(canonicalJson({ connection, clientDevice: profile.clientDevice ?? null,
    clientFingerprint: profile.clientFingerprint ?? null }))
}

function learningKey(profile: Record<string, any> | undefined, network: string): string {
  return `${LEARNING_KEY_VERSION}${network}:${profileFingerprint(profile)}`
}

function compactLearning(now = Date.now()): Record<string, AdaptiveLearningRecord> {
  const fresh = Object.entries(store.get('learning') ?? {})
    .filter(([key, value]) => key.startsWith(LEARNING_KEY_VERSION) && value && value.expiresAt > now)
    .sort(([, a], [, b]) => b.lastUsedAt - a.lastUsedAt)
    .slice(0, MAX_LEARNING_RECORDS)
  const next = Object.fromEntries(fresh)
  store.set('learning', next)
  return next
}

export function resolveAdaptiveCapabilities(
  mode: 'localProxy' | 'directVpn',
  profile?: Record<string, any>
): AdaptiveCapabilities {
  if (mode === 'localProxy') {
    return {
      canUseTlsCompatibility: false,
      canUseMtuCompatibility: false,
      externallyManaged: true,
      reason: 'Шифрование управляется внешним локальным прокси'
    }
  }

  const outbound = profile?.outbound && typeof profile.outbound === 'object' ? profile.outbound : profile
  const tls = outbound?.tls
  const reality = tls?.reality && typeof tls.reality === 'object' && tls.reality.enabled !== false
  const hasTls = tls && typeof tls === 'object'
  return {
    canUseTlsCompatibility: Boolean(hasTls && !reality),
    canUseMtuCompatibility: true,
    externallyManaged: false,
    reason: reality ? 'Reality не использует фрагментацию TLS' : null
  }
}

export function nextAdaptiveMode(
  current: AdaptiveBypassMode,
  capabilities: AdaptiveCapabilities
): AdaptiveBypassMode | null {
  if (capabilities.externallyManaged) return null
  if (current === 'baseline' && capabilities.canUseTlsCompatibility) return 'tls-compatibility'
  if (current === 'baseline' && capabilities.canUseMtuCompatibility) return 'mtu-compatibility'
  if (current === 'tls-compatibility' && capabilities.canUseMtuCompatibility) return 'mtu-compatibility'
  return null
}

function setStatus(patch: Partial<AdaptiveBypassStatus>): AdaptiveBypassStatus {
  learningGeneration++ // Fence late learning publication after any lifecycle status change.
  currentStatus = { ...currentStatus, ...patch, updatedAt: Date.now() }
  return getAdaptiveBypassStatus()
}

export function beginAdaptiveConnection(input: {
  enabled: boolean
  legacyStealthMode: boolean
  mode: 'localProxy' | 'directVpn'
  profile?: Record<string, any>
  networkIdentity?: string | null
}): { mode: AdaptiveBypassMode; capabilities: AdaptiveCapabilities } {
  const capabilities = resolveAdaptiveCapabilities(input.mode, input.profile)
  let mode: AdaptiveBypassMode = capabilities.externallyManaged ? 'external-managed' : 'baseline'
  learningGeneration++
  activeLearningNetwork = input.networkIdentity || null
  activeLearningKey = input.enabled && !capabilities.externallyManaged && activeLearningNetwork
    ? learningKey(input.profile, activeLearningNetwork) : null
  let reusedLearning = false

  if (!capabilities.externallyManaged && input.enabled) {
    const learning = compactLearning()
    const learned = activeLearningKey ? learning[activeLearningKey] : undefined
    if (learned && (learned.mode === 'mtu-compatibility' && capabilities.canUseMtuCompatibility
      || learned.mode === 'tls-compatibility' && capabilities.canUseTlsCompatibility)) {
      mode = learned.mode
      reusedLearning = true
      learning[activeLearningKey!] = { ...learned, lastUsedAt: Date.now() }
      store.set('learning', learning)
    } else if (input.legacyStealthMode) {
      mode = capabilities.canUseTlsCompatibility ? 'tls-compatibility' : 'mtu-compatibility'
    }
  }

  logEvent('info', 'adaptive-bypass', 'learning decision', { version: 2, knownNetwork: Boolean(activeLearningNetwork), reused: reusedLearning, mode })
  setStatus({
    phase: 'connecting',
    mode,
    attempts: 0,
    reason: capabilities.reason,
    message: mode === 'external-managed'
      ? 'Внешний прокси управляет совместимостью'
      : 'Подключаемся...'
  })
  return { mode, capabilities }
}

export function markAdaptiveVerifying(): AdaptiveBypassStatus {
  return setStatus({ phase: 'verifying', message: 'Проверяем соединение...' })
}

export async function markAdaptiveSuccess(profile?: Record<string, any>): Promise<AdaptiveBypassStatus> {
  const status = currentStatus
  const generation = learningGeneration, key = activeLearningKey, network = activeLearningNetwork
  if (key && network && (status.mode === 'tls-compatibility' || status.mode === 'mtu-compatibility')) {
    const currentNetwork = await readAdaptiveNetworkFingerprint()
    if (generation !== learningGeneration) return getAdaptiveBypassStatus()
    if (currentNetwork !== network || key !== learningKey(profile, network)) {
      activeLearningKey = null
      logEvent('info', 'adaptive-bypass', 'skipped learning after connection identity changed')
      return setStatus({ phase: 'connected', message: 'Соединение работает', reason: status.reason })
    }
    const now = Date.now()
    const learning = compactLearning(now)
    learning[key] = {
      mode: status.mode,
      learnedAt: now,
      lastUsedAt: now,
      expiresAt: now + LEARNING_TTL_MS
    }
    const compacted = Object.fromEntries(
      Object.entries(learning)
        .sort(([, a], [, b]) => b.lastUsedAt - a.lastUsedAt)
        .slice(0, MAX_LEARNING_RECORDS)
    )
    store.set('learning', compacted)
  }
  return setStatus({ phase: 'connected', message: 'Соединение работает', reason: status.reason })
}

export function markAdaptiveFailure(reason: string): AdaptiveBypassStatus {
  return setStatus({ phase: 'failed', message: 'Не удалось подобрать совместимый режим', reason })
}

export function markAdaptiveTransition(nextMode: AdaptiveBypassMode): AdaptiveBypassStatus {
  return setStatus({
    phase: 'adapting',
    mode: nextMode,
    attempts: currentStatus.attempts + 1,
    message: 'Подстраиваем соединение под эту сеть...'
  })
}

export function markAdaptiveServerFallback(): AdaptiveBypassStatus {
  return setStatus({
    phase: 'adapting',
    message: 'Ищем более доступный сервер...'
  })
}

export function getAdaptiveBypassStatus(): AdaptiveBypassStatus {
  return { ...currentStatus }
}

export function resetAdaptiveBypassStatus(): AdaptiveBypassStatus {
  invalidateAdaptiveLearningContext()
  return setStatus({
    phase: 'idle',
    mode: 'baseline',
    attempts: 0,
    reason: null,
    message: 'Готово к подключению'
  })
}

export function resetAdaptiveBypassLearning(): void {
  invalidateAdaptiveLearningContext()
  store.set('learning', {})
  logEvent('info', 'adaptive-bypass', 'cleared learned compatibility decisions')
}

export function invalidateAdaptiveLearningContext(): void {
  learningGeneration++
  activeLearningKey = null
  activeLearningNetwork = null
}
