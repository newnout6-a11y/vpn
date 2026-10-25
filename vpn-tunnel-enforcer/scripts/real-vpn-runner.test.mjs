// AT-00-003/005, AT-01-001: local-run boundary, deterministic seeding and secret-safe failures.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { EventEmitter } from 'node:events'
import { mkdtempSync, writeFileSync, appendFileSync, renameSync, readFileSync, rmSync, mkdirSync } from 'node:fs'
import { requireHostedWindows, readScenarioSecret, seedScenario, hostedLaunchArgs, verifyNativeTunOwnership, verifySelectorTlsFlow, safeWindowsOracleError, runtimeFailureKinds, snapshotRuntimeLogs, inspectRuntimeFailures } from './real-vpn-runner.mjs'
import { safeActionResult } from './real-vpn-log.mjs'

test('Windows oracle failures expose only a fixed stage, never private command output (AT-00-005)', () => {
  for (const stage of ['RUNTIME_INVENTORY', 'CONFIG_READ', 'ADAPTER_INVENTORY', 'ADDRESS_INVENTORY', 'SELECTOR_IDENTITY', 'TUN_IDENTITY', 'SLOT_IDENTITY', 'ENDPOINT_ROUTE']) {
    const error = safeWindowsOracleError({ stderr: `FAKE-PRIVATE-key 10.0.0.1 VPNTE_ORACLE_${stage}\nC:\\private\\profile.json`, stdout: 'FAKE-PRIVATE-key', message: 'FAKE-PRIVATE-key' })
    assert.equal(error.message, `Windows oracle/shutdown failed [VPNTE_ORACLE_${stage}]; command output omitted`)
    assert.deepEqual(safeActionResult(error), { oracleCode: `VPNTE_ORACLE_${stage}` })
    assert.ok(!JSON.stringify(error).includes('FAKE-PRIVATE'))
  }
  for (const stderr of ['FAKE-PRIVATE-key', 'VPNTE_ORACLE_FAKE_PRIVATE', 'VPNTE_ORACLE_CONFIG_READ_SUFFIX']) {
    const error = safeWindowsOracleError({ stderr })
    assert.equal(error.message, 'Windows oracle/shutdown failed; command output omitted')
    assert.deepEqual(safeActionResult(error), {})
  }
  assert.deepEqual(safeActionResult({ oracleCode: 'VPNTE_ORACLE_CONFIG_READ\nFAKE-PRIVATE-key' }), {})
})

test('runtime failure inspection returns bounded fixed kinds without raw private logs (AT-00-005)', async () => {
  const temporary = resolve(dirname(fileURLToPath(import.meta.url)), '../.tmp')
  mkdirSync(temporary, { recursive: true })
  const dir = mkdtempSync(resolve(temporary, 'real-vpn-log-kinds-'))
  try {
    assert.deepEqual(runtimeFailureKinds('FAKE-PRIVATE-key private.test 10.0.0.1'), [])
    const baseline = await snapshotRuntimeLogs(dir)
    writeFileSync(resolve(dir, 'xray-a.log'), 'FAKE-PRIVATE-key '.repeat(10000) + '\nfailed to retrieve response for private.test > connection reset by peer > tls handshake failed')
    const result = await inspectRuntimeFailures(dir, baseline)
    assert.deepEqual(result, [
      { file: 'xray-a.log', checked: true, bytesRead: 65536, kinds: ['dns-failed', 'tls-rejected', 'connection-reset'] },
      { file: 'xray-b.log', checked: false, kinds: [] }, { file: 'xray.log', checked: false, kinds: [] }
    ])
    assert.ok(!JSON.stringify(result).includes('FAKE-PRIVATE'))
    assert.ok(!JSON.stringify(result).includes('private.test'))
  } finally { assert.equal(dirname(dir), temporary); rmSync(dir, { recursive: true, force: true }) }
})

test('runtime hints classify only the current step and refuse unknown or rotated log boundaries (AT-00-005)', async () => {
  const temporary = resolve(dirname(fileURLToPath(import.meta.url)), '../.tmp')
  mkdirSync(temporary, { recursive: true })
  const dir = mkdtempSync(resolve(temporary, 'real-vpn-log-boundary-'))
  const file = resolve(dir, 'xray-a.log')
  try {
    writeFileSync(file, 'connection reset by peer from previous cancelled step\n')
    const before = await snapshotRuntimeLogs(dir)
    assert.deepEqual((await inspectRuntimeFailures(dir, before))[0], { file: 'xray-a.log', checked: true, bytesRead: 0, kinds: [] })
    appendFileSync(file, 'connection refused in this step\n')
    assert.deepEqual((await inspectRuntimeFailures(dir, before))[0].kinds, ['connection-refused'])
    assert.equal((await inspectRuntimeFailures(dir))[0].checked, false)
    writeFileSync(file, 'unexpected eof')
    assert.equal((await inspectRuntimeFailures(dir, before))[0].checked, false, 'Truncation cannot include prior bytes')
    writeFileSync(resolve(dir, 'replacement.log'), 'network is unreachable'.repeat(20))
    renameSync(file, resolve(dir, 'old.log')); renameSync(resolve(dir, 'replacement.log'), file)
    assert.equal((await inspectRuntimeFailures(dir, before))[0].checked, false, 'Replacement cannot inherit an old offset')
    assert.equal((await inspectRuntimeFailures(dir, [{ file: 'xray-a.log', state: 'unavailable' }]))[0].checked, false)
  } finally { assert.equal(dirname(dir), temporary); rmSync(dir, { recursive: true, force: true }) }
})

test('common Xray terminal hints retain only fixed categories (AT-00-005)', () => {
  assert.deepEqual(runtimeFailureKinds('private.test FAKE-PRIVATE-key > failed to process outbound traffic > failed to transfer request > failed to read response header > io: read/write on closed pipe'),
    ['outbound-transfer-failed', 'response-header-failed', 'closed-pipe'])
})

test('Windows oracle distinguishes no TUN from unreadable configuration without echoing it (AT-00-005)', { skip: process.platform !== 'win32', timeout: 20000 }, () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), temporary = resolve(root, '.tmp')
  mkdirSync(temporary, { recursive: true })
  const dir = mkdtempSync(resolve(temporary, 'real-vpn-before-tun-'))
  const config = resolve(dir, 'sing-box.json')
  const run = () => spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File',
    resolve(root, 'scripts/real-vpn-windows.ps1'), '-RuntimeDir', dir, '-ExpectedPid', '0'],
    { encoding: 'utf8', windowsHide: true, timeout: 8000 })
  try {
    const absent = run()
    assert.equal(absent.status, 0)
    const result = JSON.parse(absent.stdout.trim())
    assert.equal(result.runtimeProcessCount, 0)
    assert.equal(result.adapterUp, false)
    writeFileSync(config, '{"password":"FAKE-PRIVATE-key", invalid-json')
    const failed = run()
    assert.notEqual(failed.status, 0)
    assert.match(failed.stderr, /VPNTE_ORACLE_CONFIG_READ/)
    assert.ok(!failed.stderr.includes('FAKE-PRIVATE-key'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

const selectorConfig = () => ({ outbounds: [{ tag: 'proxy-out', type: 'selector', outbounds: ['vpnte-upstream-a', 'vpnte-upstream-b'] }],
  experimental: { clash_api: { external_controller: '127.0.0.1:25551', secret: 'a'.repeat(32) } } })
function flowFixture(patch = {}) {
  const socket = Object.assign(new EventEmitter(), { localPort: 34567, authorized: true, closed: false,
    destroy() { this.closed = true; this.emit('close') } })
  const calls = []
  return { socket, calls, dependencies: {
    dial(options, ready) { calls.push(options); queueMicrotask(ready); return socket },
    async readJson(_api, path) {
      if (patch.reject) throw new Error('FAKE-PRIVATE-PAYLOAD')
      return path === '/proxies/proxy-out'
        ? { type: 'Selector', now: 'vpnte-upstream-b', all: ['vpnte-upstream-a', 'vpnte-upstream-b'] }
        : { connections: [{ metadata: { sourcePort: '34567', destinationIP: '1.1.1.1', destinationPort: '443' },
          chains: patch.chains ?? ['vpnte-upstream-b', 'proxy-out'] }] }
    }, pause: async () => {}
  } }
}
test('ordinary TLS oracle verifies the exact live selector chain and closes its socket', async () => {
  const f = flowFixture()
  assert.deepEqual(await verifySelectorTlsFlow(selectorConfig(), f.dependencies),
    { applicable: true, tlsVerified: true, proxyOutChainVerified: true })
  assert.deepEqual(f.calls, [{ host: '1.1.1.1', port: 443, servername: 'cloudflare-dns.com',
    rejectUnauthorized: true, minVersion: 'TLSv1.2', signal: f.calls[0].signal }])
  assert.equal(f.socket.closed, true)
})
test('ordinary TLS oracle refuses direct, wrong-slot and unavailable evidence without private output', async () => {
  for (const patch of [{ chains: ['direct-out'] }, { chains: ['vpnte-upstream-a', 'proxy-out'] }, { reject: true }]) {
    const f = flowFixture(patch)
    await assert.rejects(verifySelectorTlsFlow(selectorConfig(), f.dependencies), error =>
      error.message === 'Selector ordinary TLS flow was not confirmed; private details omitted')
  }
  const f = flowFixture(); f.socket.authorized = false
  await assert.rejects(verifySelectorTlsFlow(selectorConfig(), f.dependencies))
  assert.equal(f.socket.closed, true)
})
test('legacy configurations do not run selector TLS traffic or expose private config', async () => {
  const f = flowFixture()
  assert.deepEqual(await verifySelectorTlsFlow({ outbounds: [{ type: 'direct', password: 'FAKE-PRIVATE-PAYLOAD' }] }, f.dependencies), { applicable: false })
  assert.deepEqual(f.calls, [])
  for (const controller of [{ external_controller: 'example.test:443', secret: 'FAKE-PRIVATE-PAYLOAD' },
    { external_controller: '127.0.0.1:65536', secret: 'a'.repeat(32) }]) {
    const config = selectorConfig(); config.experimental.clash_api = controller
    await assert.rejects(verifySelectorTlsFlow(config, f.dependencies), error => !error.message.includes('FAKE-PRIVATE-PAYLOAD'))
  }
})
test('ordinary TLS oracle has a bounded deadline and consumes a late read', async () => {
  const f = flowFixture()
  let finish
  f.dependencies.readJson = () => new Promise(resolve => { finish = resolve })
  await assert.rejects(verifySelectorTlsFlow(selectorConfig(), { ...f.dependencies, timeoutMs: 5 }), /private details omitted/)
  finish({ type: 'Selector', now: 'vpnte-upstream-a', all: ['vpnte-upstream-a', 'vpnte-upstream-b'] })
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(f.calls, [], 'Late controller read must not open a socket')
})

test('endpoint OS-route oracle checks both private slot configs using synthetic Windows reads', { skip: process.platform !== 'win32', timeout: 20000 }, () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), temporary = resolve(root, '.tmp')
  mkdirSync(temporary, { recursive: true })
  const dir = mkdtempSync(resolve(temporary, 'real-vpn-route-fixture-'))
  try {
    const guid = '01234567-89ab-cdef-0123-456789abcdef'
    const config = { ...selectorConfig(), inbounds: [{ type: 'tun', interface_name: 'Ethernet 5' }] }
    for (const [i, slot] of ['a', 'b'].entries()) {
      config.outbounds.push({ tag: `vpnte-upstream-${slot}`, type: 'socks', server: '127.0.0.1', server_port: 25551 + i,
        username: `FAKE-PRIVATE-user-${slot}`, password: 'FAKE-PRIVATE-password' })
      writeFileSync(resolve(dir, `xray-${slot}.json`), JSON.stringify({ inbounds: [{ protocol: 'socks', listen: '127.0.0.1', port: 25551 + i,
        settings: { auth: 'password', accounts: [{ user: `FAKE-PRIVATE-user-${slot}`, pass: 'FAKE-PRIVATE-password' }] } }],
      outbounds: [{ protocol: 'vless', settings: { vnext: [{ address: `192.0.2.${i + 1}`, port: 443 }] } }] }))
    }
    writeFileSync(resolve(dir, 'sing-box.json'), JSON.stringify(config))
    const quote = value => "'" + value.replaceAll("'", "''") + "'"
    const fixture = resolve(dir, 'fixture.ps1')
    writeFileSync(fixture, `param([string]$RuntimeDir,[string]$Mode)
function Get-CimInstance { param($ClassName,$Filter) [pscustomobject]@{Name='vpnte-sing-box.exe';ExecutablePath=(Join-Path $RuntimeDir 'vpnte-sing-box.exe');ProcessId=123;CommandLine=(Join-Path $RuntimeDir 'sing-box.json')} }
function Get-NetAdapter { param([switch]$IncludeHidden) [pscustomobject]@{Name='Ethernet 5';Status='Up';ifIndex=7;InterfaceGuid='${guid}';DriverDescription='Wintun';PnPDeviceID='SWD\\Wintun\\fixture'} }
function Get-NetIPAddress { param($InterfaceIndex) [pscustomobject]@{IPAddress='192.168.250.253';PrefixLength=30} }
function Get-Content { param($LiteralPath,[switch]$Raw)
 if($LiteralPath -like '*tun-owner.json'){ '{"schemaVersion":1,"owner":"VPNTE","alias":"Ethernet 5","interfaceGuid":"${guid}"}' }
 else { Microsoft.PowerShell.Management\\Get-Content -LiteralPath $LiteralPath -Raw }
}
function Find-NetRoute { [CmdletBinding()] param($RemoteIPAddress)
 if($Mode -eq 'failed'){throw 'FAKE-PRIVATE-PAYLOAD'}
 [pscustomobject]@{InterfaceIndex=$(if($Mode -eq 'physical' -and $RemoteIPAddress -eq '192.0.2.2'){8}else{7})}
}
& ${quote(resolve(root, 'scripts/real-vpn-windows.ps1'))} -RuntimeDir $RuntimeDir -ExpectedPid 123 -RequireEndpointPair
`)
    const originalSlot = readFileSync(resolve(dir, 'xray-b.json'), 'utf8')
    for (const mode of ['ok', 'physical', 'failed', 'bad-auth', 'hostname', 'missing-slot']) {
      writeFileSync(resolve(dir, 'xray-b.json'), originalSlot)
      if (mode === 'missing-slot') rmSync(resolve(dir, 'xray-b.json'))
      if (mode === 'bad-auth' || mode === 'hostname') {
        const broken = JSON.parse(originalSlot)
        if (mode === 'bad-auth') broken.inbounds[0].settings.accounts[0].pass = 'FAKE-PRIVATE-wrong'
        else broken.outbounds[0].settings.vnext[0].address = 'FAKE-PRIVATE.example'
        writeFileSync(resolve(dir, 'xray-b.json'), JSON.stringify(broken))
      }
      const child = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', fixture, '-RuntimeDir', dir, '-Mode', mode],
        { encoding: 'utf8', windowsHide: true, timeout: 8000 })
      assert.doesNotMatch(child.stdout + child.stderr, /FAKE-PRIVATE|192\.0\.2\./)
      if (mode === 'ok') {
        assert.equal(child.status, 0)
        assert.deepEqual(JSON.parse(child.stdout).endpointOsRoutes,
          { applicable: true, configuredSlots: 2, endpointCount: 2, tunRouteCount: 2, allViaOwnedTun: true })
      } else assert.notEqual(child.status, 0)
    }
  } finally {
    assert.equal(dirname(resolve(dir)), temporary)
    rmSync(dir, { recursive: true, force: true })
  }
})

const hosted = { GITHUB_ACTIONS: 'true', RUNNER_OS: 'Windows', RUNNER_ENVIRONMENT: 'github-hosted',
  GITHUB_EVENT_NAME: 'workflow_dispatch', RUNNER_TEMP: 'C:\\runner-temp', APPDATA: 'C:\\runner-profile' }
const seed = { schemaVersion: 1, settings: { connectionMode: 'directVpn', routingMode: 'hard', firewallKillSwitch: true },
  profiles: [{ input: 'FAKE-A', clientDevice: 'pc' }, { input: 'FAKE-B' }] }

test('hosted native oracle requires a positive real CIM comparison, with no network mutation', async () => {
  const result = await verifyNativeTunOwnership(async (args, env) => {
    assert.deepEqual(args, ['run', '--mode', 'integration', 'src/main/native/ownedTunInterfaceCore.itest.ts', '--reporter=dot'])
    assert.equal(env.VPNTE_REQUIRE_TUN_OWNERSHIP_COMPARISON, '1')
    return 'Vitest output\n{"fixture":"owned-tun-read-only","comparisons":2,"positive":1}\n'
  })
  assert.deepEqual(result, { status: 'PASS', comparisons: 2, positive: 1 })
})
test('empty, skipped, missing or malformed native comparison never counts as positive', async () => {
  for (const value of [null, {}, { comparisons: 0, positive: 0 }, { comparisons: 1, positive: 0 },
    { comparisons: 1, positive: 2 }, { comparisons: '1', positive: 1 }, { comparisons: 5000, positive: 1 }]) {
    await assert.rejects(verifyNativeTunOwnership(async () => JSON.stringify({ fixture: 'owned-tun-read-only', ...value })))
  }
  await assert.rejects(verifyNativeTunOwnership(async () => '2 tests skipped'))
})

test('native oracle accepts Vitest ANSI reset prefixes on the exact JSON line', async () => {
  const result = await verifyNativeTunOwnership(async () => '\u001b[90mstdout\u001b[2m | integration\n'
    + '\u001b[22m\u001b[39m{"fixture":"owned-tun-read-only","comparisons":1,"positive":1}\n')
  assert.deepEqual(result, { status: 'PASS', comparisons: 1, positive: 1 })
  await assert.rejects(verifyNativeTunOwnership(async () => '\u001b[22mPRIVATE {"fixture":"owned-tun-read-only","comparisons":1,"positive":1}'))
})
test('native comparison process failure cannot expose raw output or credentials', async () => {
  await assert.rejects(verifyNativeTunOwnership(async () => { throw new Error('FAKE-PRIVATE-PAYLOAD') }),
    error => !error.message.includes('FAKE-PRIVATE-PAYLOAD'))
})

test('hosted launch exposes only a valid loopback inspector and preserves sandbox/graphics', () => {
  for (const port of [1, 65535]) assert.deepEqual(hostedLaunchArgs(port), [`--inspect=127.0.0.1:${port}`])
  for (const port of [0, 65536, -1, 1.5, '127.0.0.1:123', NaN]) assert.throws(() => hostedLaunchArgs(port))
})

test('only an explicitly dispatched GitHub-hosted Windows run is admitted', () => {
  requireHostedWindows(hosted, 'win32')
  for (const patch of [{ GITHUB_ACTIONS: undefined }, { RUNNER_ENVIRONMENT: 'self-hosted' },
    { GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_EVENT_NAME: 'push' }, { RUNNER_OS: 'Linux' },
    { RUNNER_TEMP: undefined }, { APPDATA: undefined }, { VPNTE_DISABLE_NATIVE_NET: '1' },
    { ELECTRON_RENDERER_URL: 'http://example.test' }, { ELECTRON_RUN_AS_NODE: '1' }]) {
    assert.throws(() => requireHostedWindows({ ...hosted, ...patch }, 'win32'))
  }
  assert.throws(() => requireHostedWindows(hosted, 'linux'))
})

test('the real CLI refuses a local run before inspecting an executable or reading a secret', () => {
  const env = { ...process.env, VPNTE_REAL_SCENARIO: '{FAKE-PRIVATE-PAYLOAD' }
  delete env.GITHUB_ACTIONS
  const result = spawnSync(process.execPath, ['scripts/test-real-vpn.mjs', '--exe', 'missing.exe'], {
    cwd: resolve(dirname(fileURLToPath(import.meta.url)), '..'), env, encoding: 'utf8', timeout: 5000, windowsHide: true })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /local execution is blocked/)
  assert.ok(!result.stderr.includes('FAKE-PRIVATE-PAYLOAD'))
  assert.ok(!result.stderr.includes('ENOENT'))
})

test('invalid/missing secret, settings, profile counts and device fail without echoing credentials', () => {
  assert.deepEqual(readScenarioSecret(JSON.stringify(seed)), seed)
  for (const raw of [undefined, '{FAKE-PRIVATE-PAYLOAD', JSON.stringify({ ...seed, schemaVersion: 2 }),
    JSON.stringify({ ...seed, settings: { connectionMode: 'localProxy' } }),
    JSON.stringify({ ...seed, profiles: [] }), JSON.stringify({ ...seed, profiles: [{ input: '' }, seed.profiles[1]] }),
    JSON.stringify({ ...seed, profiles: [{ input: 'FAKE-PRIVATE-PAYLOAD', clientDevice: 'bad' }, seed.profiles[1]] }),
    'FAKE-PRIVATE-PAYLOAD'.repeat(4000)]) {
    assert.throws(() => readScenarioSecret(raw), error => !error.message.includes('FAKE-PRIVATE-PAYLOAD'))
  }
})

function fixture({ existing = false, running = false, importCount = 1, duplicate = false, changedSettings = false } = {}) {
  let settings = {}, activeId, imports = 0
  const calls = []
  return { calls, async invoke(method, ...args) {
    calls.push([method, ...args])
    if (method === 'serversList') return existing ? [{ id: 'old' }] : []
    if (method === 'getTunStatus') return { running }
    if (method === 'getSettings') return changedSettings ? {} : settings
    if (method === 'saveSettings') { settings = args[0]; return settings }
    if (method === 'serversAdd') return Array.from({ length: importCount }, () => ({ id: duplicate ? 'a' : String(++imports) }))
    if (method === 'serversSelect') { activeId = args[0]; return }
    if (method === 'serversGetActive') return { activeId }
    throw new Error('Unexpected seed API')
  } }
}

test('fresh runner receives actual settings and imports A/B using production public APIs', async () => {
  const f = fixture()
  const pair = await seedScenario(f.invoke, seed)
  assert.equal(pair.original.id, '1')
  assert.equal(pair.target.id, '2')
  assert.deepEqual(pair.settings, seed.settings)
  assert.deepEqual(f.calls.filter(([m]) => m === 'serversAdd'), [
    ['serversAdd', 'FAKE-A', { clientDevice: 'pc' }], ['serversAdd', 'FAKE-B', undefined] ])
  assert.ok(!f.calls.some(([m]) => ['startDirectVpn', 'stopTun', 'cancelTun'].includes(m)))
})

test('existing profile/tunnel is refused before saving settings or importing credentials', async () => {
  for (const options of [{ existing: true }, { running: true }]) {
    const f = fixture(options)
    await assert.rejects(seedScenario(f.invoke, seed))
    assert.ok(!f.calls.some(([m]) => ['saveSettings', 'serversAdd'].includes(m)))
  }
})

test('multiple imported profiles, duplicate A/B and changed settings never count as configured', async () => {
  for (const options of [{ importCount: 0 }, { importCount: 2 }, { duplicate: true }, { changedSettings: true }]) {
    const f = fixture(options)
    await assert.rejects(seedScenario(f.invoke, seed))
    assert.ok(!f.calls.some(([m]) => m === 'serversSelect'))
  }
})

test('Windows oracle publishes only separated fixed stages and native read categories (AT-00-005)', () => {
  for (const stage of ['PID_IDENTITY', 'SELECTOR_READ', 'REPORT_SERIALIZE']) {
    for (const native of ['ADDRESS_NOT_FOUND', 'ACCESS_DENIED', 'READ_FAILED']) {
      const error = safeWindowsOracleError({ stderr: `FAKE-PRIVATE-key VPNTE_ORACLE_${stage} VPNTE_NATIVE_${native}` })
      assert.deepEqual(safeActionResult(error), { oracleCode: `VPNTE_ORACLE_${stage}`, oracleNativeCode: `VPNTE_NATIVE_${native}` })
      assert.ok(!JSON.stringify(error).includes('FAKE-PRIVATE'))
    }
  }
  for (const native of ['READ_FAILED_PRIVATE', 'PRIVATE', 'ACCESS_DENIED\nFAKE-PRIVATE']) {
    const value = safeActionResult({ oracleCode: 'VPNTE_ORACLE_ADDRESS_INVENTORY', oracleNativeCode: `VPNTE_NATIVE_${native}` })
    assert.deepEqual(value, { oracleCode: 'VPNTE_ORACLE_ADDRESS_INVENTORY' })
  }
})

test('Windows address inventory failure stays fatal and emits its fixed native category (AT-00-005)', { skip: process.platform !== 'win32', timeout: 15000 }, () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), temporary = resolve(root, '.tmp')
  mkdirSync(temporary, { recursive: true })
  const dir = mkdtempSync(resolve(temporary, 'real-vpn-address-fault-'))
  try {
    const quote = value => "'" + value.replaceAll("'", "''") + "'"
    const fixture = resolve(dir, 'fixture.ps1')
    writeFileSync(fixture, `param([string]$RuntimeDir)
function Get-CimInstance { param($ClassName,$Filter) }
function Get-NetAdapter { param([switch]$IncludeHidden) [pscustomobject]@{Name='Ethernet 5';Status='Up';ifIndex=7} }
function Get-NetIPAddress { [CmdletBinding()] param($InterfaceIndex)
  throw [Management.Automation.ErrorRecord]::new([Exception]::new('FAKE-PRIVATE-key'), 'CmdletizationQuery_NotFound_InterfaceIndex,Get-NetIPAddress', [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
}
& ${quote(resolve(root, 'scripts/real-vpn-windows.ps1'))} -RuntimeDir $RuntimeDir -ExpectedPid 0 -TunAlias 'Ethernet 5'
`)
    const child = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', fixture, '-RuntimeDir', dir],
      { encoding: 'utf8', windowsHide: true, timeout: 8000 })
    assert.notEqual(child.status, 0)
    assert.match(child.stderr, /VPNTE_ORACLE_ADDRESS_INVENTORY VPNTE_NATIVE_ADDRESS_NOT_FOUND/)
    assert.doesNotMatch(child.stdout + child.stderr, /FAKE-PRIVATE-key/)
  } finally {
    assert.equal(dirname(resolve(dir)), temporary)
    rmSync(dir, { recursive: true, force: true })
  }
})
