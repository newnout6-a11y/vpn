import { describe, expect, it } from 'vitest'
import { isValidPort, isValidTimeout, normalizeServerPort, requireValidPort } from './portValidation'

describe('unified port validation', () => {
  it('validates port bounds and integer types', () => {
    expect(isValidPort(1)).toBe(true)
    expect(isValidPort(80)).toBe(true)
    expect(isValidPort(443)).toBe(true)
    expect(isValidPort(65535)).toBe(true)

    expect(isValidPort(0)).toBe(false)
    expect(isValidPort(-1)).toBe(false)
    expect(isValidPort(65536)).toBe(false)
    expect(isValidPort(443.5)).toBe(false)
    expect(isValidPort('443')).toBe(false)
    expect(isValidPort(null)).toBe(false)
    expect(isValidPort(undefined)).toBe(false)
    expect(isValidPort(NaN)).toBe(false)
  })

  it('validates timeoutMs', () => {
    expect(isValidTimeout(1)).toBe(true)
    expect(isValidTimeout(1000)).toBe(true)
    expect(isValidTimeout(0.5)).toBe(true)

    expect(isValidTimeout(0)).toBe(false)
    expect(isValidTimeout(-100)).toBe(false)
    expect(isValidTimeout(Infinity)).toBe(false)
    expect(isValidTimeout(NaN)).toBe(false)
    expect(isValidTimeout('1000')).toBe(false)
  })

  it('normalizes numbers and string port inputs', () => {
    expect(normalizeServerPort(443)).toBe(443)
    expect(normalizeServerPort('  443  ')).toBe(443)
    expect(normalizeServerPort('8080')).toBe(8080)
    expect(normalizeServerPort(65535)).toBe(65535)

    expect(normalizeServerPort(0)).toBeNull()
    expect(normalizeServerPort(-1)).toBeNull()
    expect(normalizeServerPort(70000)).toBeNull()
    expect(normalizeServerPort('invalid')).toBeNull()
    expect(normalizeServerPort('')).toBeNull()
    expect(normalizeServerPort(null)).toBeNull()
    expect(normalizeServerPort(undefined)).toBeNull()

    // With fallback
    expect(normalizeServerPort(0, 443)).toBe(443)
    expect(normalizeServerPort('invalid', 443)).toBe(443)
    expect(normalizeServerPort(undefined, 443)).toBe(443)
  })

  it('requireValidPort returns port or throws with descriptive message', () => {
    expect(requireValidPort(443)).toBe(443)
    expect(requireValidPort('8443')).toBe(8443)

    expect(() => requireValidPort(0)).toThrow('Invalid server_port: must be an integer from 1 to 65535')
    expect(() => requireValidPort(70000, 'outbound.port')).toThrow('Invalid outbound.port: must be an integer from 1 to 65535')
  })
})
