import { createHmac, randomBytes } from 'crypto'
import { networkInterfaces } from 'os'
import { safeStorage } from 'electron'
import Store from 'electron-store'
import { logEvent } from './appLogger'

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
  if (encrypted && safeStorage?.isEncryptionAvailable?.()) {
    try {
      cachedInstallSecret = safeStorage.decryptString(Buffer.from(encrypted, 'base64'))
      return cachedInstallSecret
    } catch {
      store.delete('encryptedInstallSecret')
    }
  }

  const fallback = store.get('fallbackInstallSecret')
  if (fallback) {
    cachedInstallSecret = fallback
    return fallback
  }

  const secret = randomBytes(32).toString('base64')
  cachedInstallSecret = secret
  if (safeStorage?.isEncryptionAvailable?.()) {
    store.set('encryptedInstallSecret', safeStorage.encryptString(secret).toString('base64'))
  } else {
    // Development and unsupported platforms do not provide DPAPI/Keychain.
    // This value is only a local HMAC key and never leaves the machine.
    store.set('fallbackInstallSecret', secret)
  }
  return secret
}

function hmac(value: string): string {
  return createHmac('sha256', getInstallSecret()).update(value).digest('base64url')
}

function networkFingerprint(): string {
  const interfaces = Object.entries(networkInterfaces())
    .flatMap(([name, values]) => (values ?? [])
      .filter(value => !value.internal && value.mac && value.mac !== '00:00:00:00:00:00')
      .map(value => `${name}:${value.mac}`))
    .sort()

  return hmac(interfaces.join('|') || 'unknown-network')
}

function profileFingerprint(profile: Record<string, any> | undefined): string {
  if (!profile) return hmac('local-proxy')
  const outbound = profile.outbound && typeof profile.outbound === 'object' ? profile.outbound : profile
  return hmac([
    String(outbound.type || ''),
    String(outbound.server || ''),
    String(outbound.server_port || ''),
    String(outbound.tls?.server_name || '')
  ].join('|'))
}

function learningKey(profile: Record<string, any> | undefined): string {
  return `${networkFingerprint()}:${profileFingerprint(profile)}`
}

function compactLearning(now = Date.now()): Record<string, AdaptiveLearningRecord> {
  const fresh = Object.entries(store.get('learning') ?? {})
    .filter(([, value]) => value && value.expiresAt > now)
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
  currentStatus = { ...currentStatus, ...patch, updatedAt: Date.now() }
  return getAdaptiveBypassStatus()
}

export function beginAdaptiveConnection(input: {
  enabled: boolean
  legacyStealthMode: boolean
  mode: 'localProxy' | 'directVpn'
  profile?: Record<string, any>
}): { mode: AdaptiveBypassMode; capabilities: AdaptiveCapabilities } {
  const capabilities = resolveAdaptiveCapabilities(input.mode, input.profile)
  let mode: AdaptiveBypassMode = capabilities.externallyManaged ? 'external-managed' : 'baseline'

  if (!capabilities.externallyManaged && input.enabled) {
    const learned = compactLearning()[learningKey(input.profile)]
    if (learned) {
      mode = learned.mode
      const learning = compactLearning()
      learning[learningKey(input.profile)] = { ...learned, lastUsedAt: Date.now() }
      store.set('learning', learning)
    } else if (input.legacyStealthMode) {
      mode = capabilities.canUseTlsCompatibility ? 'tls-compatibility' : 'mtu-compatibility'
    }
  }

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

export function markAdaptiveSuccess(profile?: Record<string, any>): AdaptiveBypassStatus {
  const status = currentStatus
  if (status.mode === 'tls-compatibility' || status.mode === 'mtu-compatibility') {
    const now = Date.now()
    const learning = compactLearning(now)
    learning[learningKey(profile)] = {
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

export function resetAdaptiveBypassLearning(): void {
  store.set('learning', {})
  logEvent('info', 'adaptive-bypass', 'cleared learned compatibility decisions')
}
