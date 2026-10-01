// AT-03-003/007/012: run the production reader with fake transport boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { RecoveryWorkerError } from './recoveryPsWorker'
import { validateRecoveryRequest, type RecoveryRequest } from './recoveryPsProtocol'

const source = readFileSync(join(process.cwd(), 'src/main/physicalAdapterLockdown.ts'), 'utf8')
const ast = ts.createSourceFile('physicalAdapterLockdown.ts', source, ts.ScriptTarget.Latest, true)
const reader = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'snapshotDnsRegistryPolicy')
if (!reader) throw new Error('Production DNS policy reader not found')
const compiled = ts.transpileModule(reader.getText(ast) + '\nreturn snapshotDnsRegistryPolicy;', {
  compilerOptions: { target: ts.ScriptTarget.ES2022 }
}).outputText
const rows = () => [
  { tag: 'smartNameResolution', exists: false, type: null, data: null },
  { tag: 'parallelAandAAAA', exists: true, type: 'REG_DWORD', data: '0xffffffff' }
]
function harness() {
  const deps = {
    executeRecoveryOperation: vi.fn(async () => JSON.stringify(rows())),
    RecoveryWorkerError,
    DNS_POLICY_SNAPSHOT_SCRIPT: 'FIXED_READ_ONLY_SCRIPT',
    runPS: vi.fn(async () => JSON.stringify(rows())),
    logEvent: vi.fn()
  }
  const read = new Function(...Object.keys(deps), compiled)(...Object.values(deps)) as () => Promise<unknown>
  return { ...deps, read }
}

describe('fresh DNS registry baseline transport', () => {
  it('uses a closed worker operation on every read without another PowerShell', async () => {
    const h = harness()
    expect(await h.read()).toEqual({
      smartNameResolution: { exists: false },
      parallelAandAAAA: { exists: true, type: 'REG_DWORD', data: '0xffffffff' }
    })
    const changed = rows()
    changed[1].data = '0x0'
    h.executeRecoveryOperation.mockResolvedValue(JSON.stringify(changed))
    expect(await h.read()).toMatchObject({ parallelAandAAAA: { data: '0x0' } })
    expect(h.executeRecoveryOperation).toHaveBeenCalledTimes(2)
    expect(h.executeRecoveryOperation).toHaveBeenCalledWith({ op: 'inspect-dns-policy' })
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('preserves the existing fixed reader only when worker is unavailable before dispatch', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError('unavailable', 'not elevated'))
    expect(await h.read()).toMatchObject({ parallelAandAAAA: { data: '0xffffffff' } })
    expect(h.runPS).toHaveBeenCalledExactlyOnceWith('FIXED_READ_ONLY_SCRIPT', 15000)
  })
  it.each(['timeout', 'exited', 'protocol', 'rejected', 'busy', 'closed'] as const)('does not replay a %s worker operation', async code => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError(code, 'fixture failure'))
    await expect(h.read()).rejects.toThrow('DNS registry baseline could not be verified')
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('does not accept an unclassified error with a forged unavailable property', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(Object.assign(new Error('unknown'), { code: 'unavailable' }))
    await expect(h.read()).rejects.toThrow('DNS registry baseline could not be verified')
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it.each([
    [], rows().slice(0, 1), [...rows(), rows()[0]], [rows()[0], rows()[0]],
    [rows()[0], { ...rows()[1], tag: 'unexpected' }],
    [rows()[0], { ...rows()[1], type: 'REG_SZ' }],
    [rows()[0], { ...rows()[1], data: '0x100000000' }],
    [rows()[0], { ...rows()[1], data: '1; injected' }],
    [{ ...rows()[0], exists: 'false' }, rows()[1]],
    [{ ...rows()[0], data: '0x1' }, rows()[1]],
    [rows()[0], { ...rows()[1], extra: 'unexpected' }],
    [null, rows()[1]], { rows: rows() }
  ].map(evidence => ({ evidence })))('rejects incomplete, duplicate or unsupported registry evidence: %j', async ({ evidence }) => {
    const h = harness()
    h.executeRecoveryOperation.mockResolvedValue(JSON.stringify(evidence))
    await expect(h.read()).rejects.toThrow('DNS registry baseline could not be verified')
    expect(h.runPS).not.toHaveBeenCalled()
  })
  it('rejects malformed JSON and an invalid fixed fallback result', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockResolvedValue('not json')
    await expect(h.read()).rejects.toThrow('DNS registry baseline could not be verified')
    h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError('unavailable', 'fixture'))
    h.runPS.mockResolvedValue(JSON.stringify(rows().slice(0, 1)))
    await expect(h.read()).rejects.toThrow('DNS registry baseline could not be verified')
  })
  it('accepts only the closed no-argument request at the main boundary', () => {
    expect(() => validateRecoveryRequest({ op: 'inspect-dns-policy' })).not.toThrow()
    for (const request of [
      { op: 'inspect-dns-policy', key: 'HKLM\\arbitrary' },
      { op: 'inspect-dns-policy', path: 'C:\\arbitrary' },
      { op: 'inspect-dns-policy', script: 'Get-Process' },
      { op: 'inspect-dns-policy', name: 'firewall.json' },
      { op: 'INSPECT-DNS-POLICY' }
    ]) expect(() => validateRecoveryRequest(request as RecoveryRequest)).toThrow('Invalid recovery worker request')
  })
})
