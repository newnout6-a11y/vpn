import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

let tmpRoot: string

vi.mock('electron', () => ({
  app: {
    getPath: () => tmpRoot
  },
  shell: { openPath: vi.fn() }
}))

const waitForLogContent = async (logPath: string): Promise<string> => {
  for (let i = 0; i < 50; i++) {
    try {
      const content = readFileSync(logPath, 'utf8')
      if (content.length > 0) return content
    } catch {
      // File not created yet
    }
    await new Promise((resolve) => setTimeout(resolve, 30))
  }
  return readFileSync(logPath, 'utf8')
}

describe('appLogger topology redaction', () => {
  it('retains browser failure traceback and context through the production diagnostic producer (AT-00-004/005)', async () => {
    const { logEvent, getAppLogPath, flushAppLog } = await import('./appLogger')
    const { classifyIpcError, ipcError } = await import('../shared/ipc-result')
    const ts = await import('typescript')
    const source = ts.createSourceFile('browserHardening.ts', readFileSync('src/main/browserHardening.ts', 'utf8'), ts.ScriptTarget.Latest, true)
    const functions = source.statements.filter(node => ts.isFunctionDeclaration(node)
      && ['classifyBrowserError', 'recordFailure'].includes(node.name?.text ?? ''))
    expect(functions).toHaveLength(2)
    const js = ts.transpileModule(functions.map(node => node.getText(source)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const report = new Function('logEvent', 'classifyIpcError', 'ipcError', js + '\nreturn recordFailure;')(logEvent, classifyIpcError, ipcError)
    const error = new Error('Preference write failed token=PRIVATE-TOKEN')
    error.stack = error.message + '\n    at writeFile (browserHardening.ts:350:5)\n    at C:\\Users\\PrivateUser\\vpn\\main.js:20:4'
    report([], 'firefox-preferences', error, { path: 'C:\\Users\\PrivateUser\\Firefox\\user.js' })
    await flushAppLog()
    const raw = readFileSync(getAppLogPath(), 'utf8')
    expect(raw).toContain('firefox-preferences')
    expect(raw).toContain('Preference write failed')
    expect(raw).toContain('browserHardening.ts:350:5')
    expect(raw).not.toMatch(/PRIVATE-TOKEN|PrivateUser/)
  })
  it('retains subscription cause and failure location while redacting credentials (AT-00-004/005)', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    const error = new Error('HTTP 403; TLS verification failed; Could not resolve host: private.example.test token=PRIVATE-TOKEN https://sub.example.test/PRIVATE-URL')
    error.stack = `${error.message}\n    at refreshGroupUnlocked (serverGroups.ts:463:5)\n    at C:\\Users\\PrivateUser\\vpn\\main.js:20:4`
    logEvent('warn', 'server-groups', 'refresh diagnostic', error)
    const raw = await waitForLogContent(getAppLogPath())
    expect(raw).toContain('HTTP 403')
    expect(raw).toContain('TLS verification failed')
    expect(raw).toContain('Could not resolve host:')
    expect(raw).toContain('serverGroups.ts:463:5')
    expect(raw).not.toMatch(/PRIVATE-TOKEN|PRIVATE-URL|private\.example\.test|PrivateUser/)
  })
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vpnte-log-redact-'))
    vi.resetModules()
  })

  afterEach(() => {
    try { rmSync(tmpRoot, { recursive: true, force: true }) } catch { /* ignore */ }
  })

  it('redacts network topology in messages and details', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    logEvent('info', 'test', 'adapter 192.0.2.44 saw mac aa:bb:cc:dd:ee:ff', {
      publicIpViaProxy: '203.0.113.10',
      adapterAlias: 'Ethernet 7',
      routeCount: 2,
      keptCounter: 3
    })

    const raw = await waitForLogContent(getAppLogPath())
    expect(raw).not.toContain('192.0.2.44')
    expect(raw).not.toContain('203.0.113.10')
    expect(raw).not.toContain('aa:bb:cc:dd:ee:ff')
    expect(raw).not.toContain('Ethernet 7')
    expect(raw).toContain('<redacted-ip>')
    expect(raw).toContain('<redacted-mac>')
    expect(raw).toContain('"keptCounter":3')
    expect(raw).toContain('"routeCount":2')
  })

  it('preserves numeric fields like port, interfaceMetric, timeoutMs, ifindex', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    logEvent('info', 'test-numeric', 'metrics report', {
      port: 10808,
      interfaceMetric: 5,
      routeCount: 14,
      timeoutMs: 5000,
      ifindex: 42
    })

    const raw = await waitForLogContent(getAppLogPath())
    expect(raw).toContain('"port":10808')
    expect(raw).toContain('"interfaceMetric":5')
    expect(raw).toContain('"routeCount":14')
    expect(raw).toContain('"timeoutMs":5000')
    expect(raw).toContain('"ifindex":42')
  })
  it('preserves safe failure stage/code metadata in the actual log (AT-08-001)', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    logEvent('warn', 'server-picker', 'tunnel failure path diagnostics', {
      schemaVersion: 1, assessment: 'UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED',
      engineHttps: { ok: false, stage: 'tls', code: 'ETIMEDOUT', elapsedMs: 3000 },
      outcomes: [{ target: 'cloudflare-ip-trace', code: 'ECONNRESET' }],
      xray: { dialing: 27, protocolRequests: 1, denied: 0 }
    })
    const raw = await waitForLogContent(getAppLogPath())
    expect(raw).toContain('"stage":"tls"')
    expect(raw).toContain('"code":"ETIMEDOUT"')
    expect(raw).toContain('"target":"cloudflare-ip-trace"')
    expect(raw).toContain('UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED')
  })
})
