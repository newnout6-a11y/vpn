/**
 * Utilities for sanitizing and formatting traceroute hop lines
 * across different OS locales and encodings (Russian OEM 866, Windows-1251, UTF-8),
 * and formatting live check infrastructure error messages.
 */

/**
 * Sanitizes a single traceroute hop line:
 * - Converts Russian "мс" or raw replacement chars \uFFFD after RTT numbers/comparators into standard "ms"
 * - Cleans up rogue replacement characters (\uFFFD) caused by OEM 866 decoding artifacts
 * - Normalizes Russian timeout message "Превышен интервал ожидания для запроса." to "Request timed out."
 * - Normalizes redundant whitespace
 */
export function sanitizeHopLine(line: string): string {
  if (!line || typeof line !== 'string') return ''
  return line
    // Convert Russian "мс", "ms", or \uFFFD after numbers / comparators (e.g. "<1 \uFFFD\uFFFD", "<1 мс", "14 мс") to "ms"
    .replace(/([<>]?\s*\d+)\s*(?:\u043c\u0441|ms|\uFFFD+)/gi, (_m, g1) => `${g1} ms`)
    // Remove any trailing or rogue replacement characters
    .replace(/\uFFFD+/g, '')
    // Normalize localized Russian timeout message to canonical English message
    .replace(/Превышен интервал ожидания для запроса\.?/gi, 'Request timed out.')
    // Collapse excessive whitespace while preserving single-space separation
    .replace(/[ \t]+/g, ' ')
    .trim()
}

/**
 * Formats infrastructure and GeoIP error messages to avoid leaking raw Axios / HTTP status errors
 * (such as "Request failed with status code 429") directly into the UI.
 */
export function formatInfrastructureError(err?: string | null): string {
  if (!err || typeof err !== 'string') return ''
  const trimmed = err.trim()
  if (/429|too many requests|ratelimited|rate.?limit/i.test(trimmed)) {
    return 'Превышен лимит запросов к сервису геолокации (429). Повторите попытку позже.'
  }
  if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|Network Error|timed out/i.test(trimmed)) {
    return 'Не удалось подключиться к сервису геолокации.'
  }
  if (/aborted|cancelled|canceled/i.test(trimmed)) {
    return 'Проверка отменена'
  }
  return trimmed
}
