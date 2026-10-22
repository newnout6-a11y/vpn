// AT-00-003/005, AT-01-001: local-run boundary, deterministic seeding and secret-safe failures.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { requireHostedWindows, readScenarioSecret, seedScenario, hostedLaunchArgs, verifyNativeTunOwnership } from './real-vpn-runner.mjs'

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
