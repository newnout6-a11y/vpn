import { describe, expect, it } from 'vitest'
import ts from 'typescript'
import { checkIpcContract } from '../../scripts/check-ipc-contract.mjs'
import { checkIpcResults, inspectIpcResults } from '../../scripts/check-ipc-results.mjs'

function fixture(listener: string, result = '{ value: number }', registration = "ipcMain.handle('one', LISTENER)") {
  const files: Record<string, string> = {
    '/fixture/main.ts': `declare const ipcMain: { handle(channel: string, listener: (...args: any[]) => any): void }; ${registration.replace('LISTENER', listener)}`,
    '/fixture/api.ts': `interface ElectronAPI { getOne(): Promise<${result}> }`
  }
  const options: ts.CompilerOptions = { strict: true, target: ts.ScriptTarget.ES2022 }
  const host = ts.createCompilerHost(options), original = host.getSourceFile.bind(host)
  host.getSourceFile = (path, languageVersion, onError, createNew) => files[path] === undefined
    ? original(path, languageVersion, onError, createNew)
    : ts.createSourceFile(path, files[path], languageVersion, true)
  const program = ts.createProgram(Object.keys(files), options, host)
  return inspectIpcResults(program, { declared: [{ channel: 'one', method: 'getOne' }], mainFiles: ['/fixture/main.ts'], apiFile: '/fixture/api.ts' })
}

describe('listener result parity (AT-00-001; F-138)', () => {
  it('checks all production listeners and removes diagnostic legacy any', () => {
    const inventory = checkIpcContract()
    const result = checkIpcResults(process.cwd(), inventory)
    expect(result.problems).toEqual([])
    expect(result.checked).toHaveLength(inventory.registered.length)
    const typed = ['detect-happ', 'adaptive-bypass:get-status', 'adaptive-bypass:retry', 'adaptive-bypass:reset-learning',
      'run-leak-check', 'run-system-diagnostics', 'get-routing-plan', 'get-full-logs',
      'url-availability:check', 'url-availability:history', 'speed-test:run', 'speed-test:history', 'renderer-log', 'clear-app-log',
      'get-autoconfig-status', 'smart-route:rule-sets-state', 'smart-route:rule-sets-refresh',
      'apply-browser-leak-protection', 'rollback-browser-leak-protection', 'run-auto-pilot',
      'rollback-tun-network-baseline', 'firewall:repair-health', 'firewall:repair-vpnte-rules',
      'get-location-privacy', 'apply-location-privacy', 'rollback-location-privacy',
      'network:repair-orphaned-dns', 'network:rollback-adapter-lockdown',
      'get-traffic-forensics-status', 'restart-traffic-forensics', 'traffic-history:list', 'server:probe',
      'split-tunnel:get-apps', 'split-tunnel:refresh-apps', 'split-tunnel:get-config', 'split-tunnel:add-app', 'split-tunnel:add-process',
      'groups:list', 'groups:get', 'groups:rename', 'groups:refresh', 'groups:set-refresh-policy']
    for (const channel of typed) expect(result.legacy, channel).not.toContain(channel)
  }, 30_000)
  it('accepts asynchronous results through a local registration wrapper', () => {
    const registration = "function handle(channel: string, listener: () => unknown) { ipcMain.handle(channel, listener) }; handle('one', LISTENER)"
    expect(fixture('async () => ({ value: 1 })', undefined, registration).problems).toEqual([])
  })
  it.each([
    ['() => ({ value: "wrong" })', '{ value: number }'],
    ['async () => ({ nested: { count: "wrong" } })', '{ nested: { count: number } }'],
    ['() => Math.random() ? { value: 1 } : null', '{ value: number }'],
    ['() => ({ success: false as const })', '{ success: true }'],
    ['() => undefined as any', '{ value: number }'],
    ['() => ({ nested: { value: undefined as any } })', '{ nested: { value: number } }']
  ])('names an incompatible result instead of accepting channel parity: %s', (listener, result) => {
    expect(fixture(listener, result).problems).toEqual([expect.stringContaining('IPC result mismatch: one:')])
  })
  it('fails closed on a missing listener signature or uninspected declaration', () => {
    expect(fixture('42').problems).toContain('Unresolved IPC result: one')
    expect(fixture('42', undefined, '').problems).toContain('Unchecked IPC result: one')
  })
  it('reports nested public any while preserving existing legacy channels', () => {
    expect(fixture('() => ({ value: [] })', '{ value: Array<{ nested: any }> }').legacy).toEqual(['one'])
    expect(fixture('() => ({ value: {} })', '{ value: Record<string, any> }').legacy).toEqual(['one'])
  })
})
