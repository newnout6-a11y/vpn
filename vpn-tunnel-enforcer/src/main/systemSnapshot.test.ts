import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it, vi } from 'vitest'
import { execFile as nativeExecFile } from 'node:child_process'
import { promisify } from 'node:util'
import ts from 'typescript'

const source = readFileSync(join(process.cwd(), 'src', 'main', 'systemSnapshot.ts'), 'utf-8')

// AT-00-003/005, AT-08-001 (collection subset): production functions, fake
// process/filesystem boundaries. Native tests execute only readonly scripts.
const ast = ts.createSourceFile('systemSnapshot.ts', source, ts.ScriptTarget.Latest, true)
const functions = new Set(['tryPS', 'buildCombinedPSScript', 'parseCombinedPSSections', 'sectionToStringOrError',
  'sectionToProxyResult', 'sectionToElevated', 'capturePlatformDumps', 'tryGetSingboxRunning', 'captureSnapshot'])
const variables = new Set(['PS_EMPTY_MARKER', 'snapshotCaptureQueue', 'pendingSnapshotCaptures'])
const text = ast.statements.filter(node =>
  (ts.isFunctionDeclaration(node) && functions.has(node.name?.text || '')) ||
  (ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration => variables.has(declaration.name.getText(ast))))
).map(node => node.getText(ast).replace(/^export /, '')).join('\n')
const compiled = ts.transpileModule(text + '\nreturn { read: tryPS, build: buildCombinedPSScript, parse: parseCombinedPSSections, collect: capturePlatformDumps, capture: captureSnapshot };', {
  compilerOptions: { target: ts.ScriptTarget.ES2022 }
}).outputText
const sections = ['ADAPTERS', 'IPCONFIG', 'ROUTES4', 'ROUTES6', 'DNS_SERVERS', 'NRPT', 'DNS_CACHE',
  'BINDING_IPV6', 'FIREWALL_RULES', 'FIREWALL_PROFILES', 'WINHTTP_PROXY', 'PROXY_10808', 'PROXY_10809', 'ELEVATED']
const fixtureOutput = () => sections.map(name => `###${name}###\n${name === 'ELEVATED' ? 'False' : name === 'PROXY_10808' ? '__VPNTE_EMPTY__' : 'fixture-' + name}`).join('\n')
function harness(platform = 'win32', native = false) {
  const deps = {
    process: { platform }, Buffer,
    exec: vi.fn(async (_command: string, _options: object) => ({ stdout: '' })),
    execFile: vi.fn(native ? promisify(nativeExecFile) : async (_file: string, _args: string[], _options: object) => ({ stdout: fixtureOutput() })),
    logEvent: vi.fn(),
    captureSnapshotNow: vi.fn(async (_reason: string) => 'fixture-path')
  }
  const api = new Function(...Object.keys(deps), compiled)(...Object.values(deps)) as {
    read(script: string, deadline?: number): Promise<string | { error: string }>
    build(): string
    parse(output: string): Map<string, string>
    collect(): Promise<Record<string, unknown>>
    capture(reason: string): Promise<string | null>
  }
  return { ...deps, ...api }
}

describe('system snapshot scheduling', () => {
  it('rate-limits periodic collection and serializes it with explicit captures', () => {
    expect(source).toContain('export const PERIODIC_SNAPSHOT_INTERVAL_MS = 5 * 60_000')
    expect(source).toContain('Math.max(PERIODIC_SNAPSHOT_INTERVAL_MS, Math.floor(intervalMs))')
    expect(source).toContain("if (reason === 'periodic' && pendingSnapshotCaptures > 0)")
    expect(source).toContain('const capture = snapshotCaptureQueue.then(() => captureSnapshotNow(reason))')
    expect(source).toContain("'skipped periodic snapshot while capture is in progress'")
  })
  it('serializes explicit captures and skips periodic work while native collection is pending', async () => {
    const h = harness()
    let finish!: (path: string) => void
    h.captureSnapshotNow.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const first = h.capture('manual')
    const second = h.capture('tun-post-start')
    await Promise.resolve()
    expect(h.captureSnapshotNow.mock.calls).toEqual([['manual']])
    expect(await h.capture('periodic')).toBeNull()
    finish('first-path')
    expect(await first).toBe('first-path')
    expect(await second).toBe('fixture-path')
    expect(h.captureSnapshotNow.mock.calls).toEqual([['manual'], ['tun-post-start']])
    expect(await h.capture('periodic')).toBe('fixture-path')
  })
  it('releases the queue after a failed capture', async () => {
    const h = harness()
    h.captureSnapshotNow.mockRejectedValueOnce(new Error('write failed'))
    await expect(h.capture('manual')).rejects.toThrow('write failed')
    expect(await h.capture('tun-post-stop')).toBe('fixture-path')
    expect(await h.capture('periodic')).toBe('fixture-path')
  })
})

describe('direct PowerShell diagnostic collection', () => {
  it('passes the full oversized combined command as one direct argument, preserving all 14 sections', async () => {
    const h = harness()
    const result = await h.collect()
    expect(h.execFile).toHaveBeenCalledOnce()
    const [file, args, options] = h.execFile.mock.calls[0] as unknown as [string, string[], Record<string, unknown>]
    expect(file).toBe('powershell.exe')
    expect(args.slice(0, -1)).toEqual(['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand'])
    expect(args.join(' ').length).toBeGreaterThan(8191)
    const decoded = Buffer.from(args.at(-1)!, 'base64').toString('utf16le')
    expect(decoded).toContain('[Console]::OutputEncoding=[System.Text.Encoding]::UTF8')
    expect(decoded).toContain("$ProgressPreference='SilentlyContinue'")
    expect(decoded.endsWith(h.build())).toBe(true)
    expect([...h.parse(await h.read(h.build()) as string).keys()]).toEqual(sections)
    expect(options).toEqual({ windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 })
    expect(options).not.toHaveProperty('shell')
    expect(result).toMatchObject({
      netAdapters: 'fixture-ADAPTERS', netIPConfiguration: 'fixture-IPCONFIG', netRouteIPv4: 'fixture-ROUTES4', netRouteIPv6: 'fixture-ROUTES6',
      dnsClientServerAddresses: 'fixture-DNS_SERVERS', dnsClientNrptRules: 'fixture-NRPT', dnsClientCache: 'fixture-DNS_CACHE',
      netAdapterBindingsIPv6: 'fixture-BINDING_IPV6', firewallVpnteRules: 'fixture-FIREWALL_RULES', firewallProfile: 'fixture-FIREWALL_PROFILES',
      netshWinhttp: 'fixture-WINHTTP_PROXY', proxyOwnersPort10808: { empty: true }, proxyOwnersPort10809: 'fixture-PROXY_10809',
      isElevated: false, singboxRunning: { running: false }
    })
    expect(h.exec.mock.calls[0][0]).toMatch(/^tasklist /)
    expect(h.exec.mock.calls.every(([command]) => !/powershell|cmd\.exe/i.test(command))).toBe(true)
  })
  it('keeps explicit/default deadlines and trims successful output', async () => {
    const h = harness()
    h.execFile.mockResolvedValue({ stdout: '  сеть ☃\r\n' } as any)
    expect(await h.read('fixture')).toBe('сеть ☃')
    expect(h.execFile).toHaveBeenLastCalledWith('powershell.exe', expect.any(Array), expect.objectContaining({ timeout: 15000 }))
    await h.read('fixture', 250)
    expect(h.execFile).toHaveBeenLastCalledWith('powershell.exe', expect.any(Array), expect.objectContaining({ timeout: 250 }))
  })
  it.each(['deadline exceeded', 'stdout maxBuffer exceeded', 'PowerShell unavailable'])('reports whole-process failure in each diagnostic field: %s', async message => {
    const h = harness()
    h.execFile.mockRejectedValue(new Error(message))
    const result = await h.collect()
    for (const [key, value] of Object.entries(result)) {
      if (key === 'isElevated') expect(value).toBeNull()
      else if (key === 'singboxRunning') expect(value).toEqual({ running: false })
      else expect(value).toEqual({ error: message })
    }
    expect(h.execFile).toHaveBeenCalledOnce()
  })
  it('keeps other sections on a single cmdlet error or a missing section', async () => {
    const h = harness()
    h.execFile.mockResolvedValue({ stdout: fixtureOutput().replace('fixture-DNS_SERVERS', 'ERROR: DNS fixture failed').replace('###DNS_CACHE###\nfixture-DNS_CACHE\n', '') } as any)
    const result = await h.collect()
    expect(result).toMatchObject({ dnsClientServerAddresses: { error: 'DNS fixture failed' }, dnsClientCache: { error: 'no output' },
      netAdapters: 'fixture-ADAPTERS', firewallProfile: 'fixture-FIREWALL_PROFILES', proxyOwnersPort10808: { empty: true } })
  })
  it('skips Windows process launches on other platforms', async () => {
    const h = harness('linux')
    expect(await h.read('fixture')).toEqual({ error: 'platform is not Windows' })
    expect(await h.collect()).toMatchObject({ netAdapters: { error: 'not Windows' }, isElevated: null })
    expect(h.execFile).not.toHaveBeenCalled()
    expect(h.exec).not.toHaveBeenCalled()
  })
  it.skipIf(process.platform !== 'win32')('executes the actual oversized readonly script with all native section markers', async () => {
    const h = harness('win32', true)
    const output = await h.read(h.build(), 30000)
    if (typeof output !== 'string') throw new Error('Native diagnostic process failed')
    expect([...h.parse(output).keys()]).toEqual(sections)
    // Do not print adapter, route, DNS or process payloads in test output.
    expect(await h.read("Write-Output 'сеть ☃ — проверка'")).toBe('сеть ☃ — проверка')
  }, 40000)
  it.skipIf(process.platform !== 'win32')('returns a diagnostic error on an actual direct-process timeout', async () => {
    const h = harness('win32', true)
    const result = await h.read('Start-Sleep -Seconds 10', 100)
    expect(typeof result).toBe('object')
    expect(result).toHaveProperty('error')
  }, 5000)
})
