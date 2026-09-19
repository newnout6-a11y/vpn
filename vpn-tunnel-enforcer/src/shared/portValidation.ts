/**
 * Unified runtime port validation and normalization across main, renderer,
 * and IPC boundaries.
 */

export function isValidPort(port: unknown): port is number {
  return typeof port === 'number' && Number.isInteger(port) && port >= 1 && port <= 65535
}

export function isValidTimeout(timeoutMs: unknown): timeoutMs is number {
  return typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0
}

export function normalizeServerPort(port: unknown, fallback?: number): number | null {
  if (typeof port === 'number') {
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : (fallback !== undefined ? fallback : null)
  }
  if (typeof port === 'string') {
    const trimmed = port.trim()
    if (!trimmed) return fallback !== undefined ? fallback : null
    const n = Number(trimmed)
    return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : (fallback !== undefined ? fallback : null)
  }
  return fallback !== undefined ? fallback : null
}

export function requireValidPort(port: unknown, label = 'server_port'): number {
  const normalized = normalizeServerPort(port)
  if (normalized === null) {
    throw new Error(`Invalid ${label}: must be an integer from 1 to 65535, received ${String(port ?? '')}`)
  }
  return normalized
}
