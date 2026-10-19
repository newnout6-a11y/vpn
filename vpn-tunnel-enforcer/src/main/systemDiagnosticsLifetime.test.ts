// AT-00-003/005: execute the production collector with controlled readonly tasks.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import ts from 'typescript'
import { IpcFault } from '../shared/ipc-result'
const source = readFileSync(join(process.cwd(), 'src/main/systemDiagnostics.ts'), 'utf8')
const ast = ts.createSourceFile('systemDiagnostics.ts', source, ts.ScriptTarget.Latest, true)
const fn = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'runSystemDiagnostics')!
const compiled = ts.transpileModule(fn.getText(ast).replace(/^export /, '') + '\nreturn runSystemDiagnostics', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
function harness() {
  let release!: () => void
  const held = new Promise<unknown[]>(done => { release = () => done([]) })
  const tasks = ['getBinaryItems', 'getProxyItems', 'getWindowsNetworkItems', 'getProcessAndListenerItems', 'getEndpointItems',
    'getServiceItems', 'getEventLogItem', 'getLogItems', 'getTrafficForensicsItems', 'getSmartRouteRuleSetItems', 'buildActiveProfileDiagnosticItems', 'getRoutingItems']
  const deps = { ...Object.fromEntries(tasks.map(name => [name, vi.fn(async () => [])])), getRuntimeItems: () => held,
    logEvent: vi.fn(), process: { platform: 'linux' }, item: (...args: unknown[]) => args,
    getBootRecoveryRegistrationStatus: vi.fn(() => ({ status: 'verified' })), combineStatus: () => 'ok' }
  const run = new Function(...Object.keys(deps), compiled)(...Object.values(deps)) as (assertActive?: () => void) => Promise<unknown>
  return { ...deps, run, release }
}
describe('nested diagnostic collector lifetime', () => {
  it('does not report completion or start recovery lookup after its owner is cancelled', async () => {
    const h = harness(), controller = new AbortController()
    const result = h.run(() => { if (controller.signal.aborted) throw new IpcFault('cancelled') })
    controller.abort(); h.release()
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    expect(h.getBootRecoveryRegistrationStatus).not.toHaveBeenCalled()
    expect(h.logEvent).toHaveBeenCalledExactlyOnceWith('info', 'diagnostics', 'full system diagnostics started')
  })
  it('keeps normal unowned collection completion unchanged', async () => {
    const h = harness(), result = h.run()
    h.release()
    await expect(result).resolves.toMatchObject({ summary: 'ok' })
    expect(h.logEvent).toHaveBeenCalledWith('info', 'diagnostics', 'full system diagnostics finished', expect.objectContaining({ summary: 'ok' }))
  })
})
