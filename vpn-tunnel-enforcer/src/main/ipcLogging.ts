import { redactSensitiveConfig } from './vpnProfiles'

export function compactForIpcLog(value: unknown): string {
  try {
    const raw = JSON.stringify(redactSensitiveConfig(value))
    if (!raw) return ''
    return raw.length > 2000 ? `${raw.slice(0, 2000)}...<truncated>` : raw
  } catch {
    return String(value)
  }
}
