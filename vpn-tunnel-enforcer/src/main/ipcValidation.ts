export function requireString(value: unknown, field: string, options: { allowEmpty?: boolean; maxLength?: number } = {}): string {
  if (typeof value !== 'string') throw new Error(`Invalid IPC payload: ${field} must be a string`)
  const result = value.trim()
  if (!options.allowEmpty && !result) throw new Error(`Invalid IPC payload: ${field} must not be empty`)
  if (options.maxLength && result.length > options.maxLength) {
    throw new Error(`Invalid IPC payload: ${field} is too long`)
  }
  return result
}

export function optionalString(value: unknown, field: string, options: { allowEmpty?: boolean; maxLength?: number } = {}): string | undefined {
  if (value === undefined || value === null) return undefined
  return requireString(value, field, options)
}

export function requireStringArray(value: unknown, field: string, options: { maxItems?: number; itemMaxLength?: number } = {}): string[] {
  if (!Array.isArray(value)) throw new Error(`Invalid IPC payload: ${field} must be an array`)
  if (options.maxItems && value.length > options.maxItems) throw new Error(`Invalid IPC payload: ${field} has too many items`)
  return value.map((item, index) => requireString(item, `${field}[${index}]`, { maxLength: options.itemMaxLength }))
}

export function requireEnum<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new Error(`Invalid IPC payload: ${field} must be one of: ${allowed.join(', ')}`)
  }
  return value as T
}

export function requirePlainObject(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid IPC payload: ${field} must be an object`)
  }
  return value as Record<string, unknown>
}

export function optionalPlainObject(value: unknown, field: string): Record<string, unknown> | undefined {
  if (value === undefined || value === null) return undefined
  return requirePlainObject(value, field)
}

export function requirePort(value: unknown, field: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid IPC payload: ${field} must be an integer port from 1 to 65535`)
  }
  return value
}

export function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`Invalid IPC payload: ${field} must be a boolean`)
  return value
}

export function requireNumber(
  value: unknown,
  field: string,
  options: { integer?: boolean; min?: number; max?: number } = {}
): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`Invalid IPC payload: ${field} must be a finite number`)
  }
  if (options.integer && !Number.isInteger(value)) {
    throw new Error(`Invalid IPC payload: ${field} must be an integer`)
  }
  if (options.min !== undefined && value < options.min) {
    throw new Error(`Invalid IPC payload: ${field} is too small`)
  }
  if (options.max !== undefined && value > options.max) {
    throw new Error(`Invalid IPC payload: ${field} is too large`)
  }
  return value
}
