import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const source = readFileSync(join(process.cwd(), 'src/main/serverProbe.ts'), 'utf8')

describe('server probe time limits', () => {
  it('bounds DNS lookups and the IPC result', () => {
    expect(source).toContain('const DNS_LOOKUP_TIMEOUT_MS = 2500')
    expect(source).toContain('settleWithin(dns.resolve4(host), [] as string[], DNS_LOOKUP_TIMEOUT_MS)')
    expect(source).toContain('settleWithin(dns.reverse(ip), [] as string[], DNS_LOOKUP_TIMEOUT_MS)')
    expect(source).toContain('PROBE_RESULT_TIMEOUT_MS')
  })
})
