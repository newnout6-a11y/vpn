/**
 * Session outcome helpers — turn a {@link SessionOutcomeKind} + evidence into
 * the coarse `disconnectReason` bucket and a human one-liner.
 *
 * Kept dependency-free and pure so it is trivially testable and can run on
 * either side of the IPC boundary.
 */
import type {
  ConnectionLogEntry,
  SessionOutcome,
  SessionOutcomeEvidence,
  SessionOutcomeKind
} from '../shared/ipc-types'

type DisconnectReason = ConnectionLogEntry['disconnectReason']

/**
 * Collapse the fine-grained kind onto the 5 legacy buckets the filter chips and
 * CSV export still use.
 */
export function outcomeKindToDisconnectReason(kind: SessionOutcomeKind): DisconnectReason {
  switch (kind) {
    case 'user-stop':
    case 'app-quit':
    case 'server-switch':
      return 'user'
    case 'rotation':
      return 'rotation'
    case 'schedule':
      return 'schedule'
    case 'killswitch':
      return 'crash'
    case 'proxy-unreachable':
    case 'server-rejected-key':
    case 'server-down':
    case 'singbox-crash':
    case 'tun-setup-failed':
    case 'network-lost':
    case 'system-sleep':
    case 'start-failed':
    case 'unknown':
      return 'error'
    default:
      return 'error'
  }
}

const ADAPTIVE_MODE_RU: Record<NonNullable<SessionOutcomeEvidence['adaptiveMode']>, string> = {
  baseline: 'обычный',
  'tls-compatibility': 'совместимость TLS',
  'mtu-compatibility': 'совместимость MTU',
  'external-managed': 'внешний прокси'
}

const OUTBOUND_FAULT_RU: Record<NonNullable<SessionOutcomeEvidence['outboundFault']>, string> = {
  'reality-key-mismatch': 'сервер отклонил ключ REALITY',
  'tls-handshake-failed': 'сервер оборвал TLS-рукопожатие',
  'upstream-unreachable': 'узел недоступен (нет ответа)'
}

/**
 * Compose the localized headline for an outcome. Deterministic — the same kind
 * and evidence always produce the same sentence.
 */
export function buildOutcomeHeadline(
  kind: SessionOutcomeKind,
  evidence: SessionOutcomeEvidence = {}
): string {
  const fault = evidence.outboundFault ? OUTBOUND_FAULT_RU[evidence.outboundFault] : null
  const restarts = evidence.autoRestartAttempts ?? 0
  // "после N …" takes the genitive: singular for 1, plural for everything else.
  const restartsTail =
    restarts > 0 ? ` после ${restarts} ${restarts === 1 ? 'попытки' : 'попыток'} авто-перезапуска` : ''

  switch (kind) {
    case 'user-stop':
      return 'Вы отключили защиту'
    case 'app-quit':
      return 'Приложение закрыто — защита отключена'
    case 'server-switch':
      return 'Смена сервера'
    case 'rotation':
      return 'Авторотация сервера'
    case 'schedule':
      return 'Отключение по расписанию'
    case 'proxy-unreachable':
      return 'Прокси-сервер перестал отвечать — трафик заблокирован в туннеле, чтобы не утёк мимо VPN'
    case 'server-rejected-key':
      return fault
        ? `Сервер отклонил подключение: ${fault}`
        : 'Сервер отклонил подключение (ключ, SNI или сертификат не совпали)'
    case 'server-down':
      return fault ? `Узел недоступен: ${fault}` : 'Узел недоступен — соединение отклонено или истёк тайм-аут'
    case 'singbox-crash': {
      const code =
        typeof evidence.singboxExitCode === 'number' ? ` (код ${evidence.singboxExitCode})` : ''
      const faultTail = fault ? `. Последняя ошибка: ${fault}` : ''
      return `Ядро VPN (sing-box) неожиданно завершилось${code}${restartsTail}${faultTail}`
    }
    case 'killswitch': {
      const faultTail = fault ? ` Причина обрыва: ${fault}.` : ''
      return `Kill-switch удержал трафик после обрыва туннеля${restartsTail}.${faultTail}`.trim()
    }
    case 'tun-setup-failed':
      return 'Не удалось поднять сетевой туннель (Wintun, маршруты или DNS)'
    case 'network-lost':
      return evidence.networkTransition
        ? `Сеть изменилась под туннелем: ${evidence.networkTransition}`
        : 'Физическая сеть пропала или сменилась под туннелем'
    case 'system-sleep':
      return 'Компьютер уходил в сон — туннель был пересоздан'
    case 'start-failed':
      return evidence.hint ? `Не удалось запустить: ${evidence.hint}` : 'Не удалось запустить защиту'
    case 'unknown':
    default:
      return 'Туннель завершился по неизвестной причине'
  }
}

/** Build a complete outcome object (headline auto-composed unless overridden). */
export function makeOutcome(
  kind: SessionOutcomeKind,
  evidence: SessionOutcomeEvidence = {},
  headlineOverride?: string
): SessionOutcome {
  const cleaned: SessionOutcomeEvidence = {}
  for (const [k, v] of Object.entries(evidence)) {
    if (v !== undefined && v !== null && v !== '') {
      ;(cleaned as Record<string, unknown>)[k] = v
    }
  }
  return {
    kind,
    headline: headlineOverride?.trim() || buildOutcomeHeadline(kind, evidence),
    ...(Object.keys(cleaned).length > 0 ? { evidence: cleaned } : {})
  }
}

/** true for a protected-restart `reason` string that swaps to a different node. */
export function isNodeSwitchRestartReason(reason: string): 'rotation' | 'server-switch' | null {
  if (/^profile rotation to /i.test(reason)) return 'rotation'
  if (/^server switch$/i.test(reason)) return 'server-switch'
  return null
}
