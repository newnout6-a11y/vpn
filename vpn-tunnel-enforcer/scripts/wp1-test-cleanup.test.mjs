// AT-01-001/010: runner failure semantics; no Electron, network or elevated effects.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { runWithCleanup, removeWp1WorkDirectory } from './wp1-test-cleanup.mjs'

const helperUrl = new URL('./wp1-test-cleanup.mjs', import.meta.url).href
function sandbox(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'vpnte-wp1-cleanup-test-'))
  t.after(() => { t.mock.restoreAll(); fs.rmSync(root, { recursive: true, force: true }) })
  const parent = join(root, '.tmp')
  fs.mkdirSync(parent)
  const work = fs.mkdtempSync(join(parent, 'wp1-native-'))
  fs.writeFileSync(join(work, 'canary.txt'), 'FAKE-OWNED')
  return { root, parent, work }
}

test('returns operation result only after successful cleanup', async () => {
  const calls = []
  const result = await runWithCleanup(async () => { calls.push('run'); return 'PASS' }, async () => { calls.push('cleanup') })
  assert.equal(result, 'PASS')
  assert.deepEqual(calls, ['run', 'cleanup'])
})

test('preserves the primary failure when cleanup succeeds, including thrown undefined', async () => {
  for (const primary of [new Error('primary failure'), undefined]) {
    let cleaned = false
    await assert.rejects(runWithCleanup(() => { throw primary }, () => { cleaned = true }), error => error === primary)
    assert.equal(cleaned, true)
  }
})

test('rejects successful operation when cleanup fails', async () => {
  const cleanup = new Error('cleanup failure')
  await assert.rejects(runWithCleanup(() => 'PASS', () => { throw cleanup }), error => error === cleanup)
})

test('preserves both failures and primary cause in order', async () => {
  const primary = new Error('primary failure'), cleanup = new Error('cleanup failure')
  await assert.rejects(runWithCleanup(async () => { throw primary }, async () => { throw cleanup }), error => {
    assert.ok(error instanceof AggregateError)
    assert.deepEqual(error.errors, [primary, cleanup])
    assert.equal(error.cause, primary)
    return true
  })
})

test('cleanup-only and combined failures exit nonzero without an overall PASS', () => {
  for (const failPrimary of [false, true]) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import { runWithCleanup } from ${JSON.stringify(helperUrl)};
       await runWithCleanup(() => { if (${failPrimary}) throw new Error('PRIMARY_FAILURE'); return 'PASS' },
         () => { throw new Error('CLEANUP_FAILURE') });
       console.log('OVERALL_PASS');`], { encoding: 'utf8', timeout: 10000 })
    assert.ifError(result.error)
    assert.notEqual(result.status, 0)
    assert.ok(!result.stdout.includes('OVERALL_PASS'))
    assert.ok(result.stderr.includes('CLEANUP_FAILURE'))
    if (failPrimary) assert.ok(result.stderr.includes('PRIMARY_FAILURE'))
  }
})

test('removes only an owned direct child and preserves parent/siblings', t => {
  const { parent, work } = sandbox(t)
  const sibling = fs.mkdtempSync(join(parent, 'wp1-migration-'))
  fs.writeFileSync(join(sibling, 'keep.txt'), 'FAKE-KEEP')
  removeWp1WorkDirectory(work, parent)
  assert.ok(!fs.existsSync(work))
  assert.ok(fs.existsSync(parent))
  assert.equal(fs.readFileSync(join(sibling, 'keep.txt'), 'utf8'), 'FAKE-KEEP')
})

test('rejects parent, outside, relative, non-owned and nested cleanup paths without deletion', t => {
  const { root, parent, work } = sandbox(t)
  const outside = fs.mkdtempSync(join(root, 'wp1-native-'))
  const notOwned = join(parent, 'keep'); fs.mkdirSync(notOwned)
  const nested = fs.mkdtempSync(join(work, 'wp1-native-'))
  for (const path of [parent, root, outside, notOwned, nested, 'relative/wp1-native-abcdef']) {
    assert.throws(() => removeWp1WorkDirectory(path, parent), /Unexpected WP1 cleanup path/)
  }
  assert.ok(fs.existsSync(work))
  assert.ok(fs.existsSync(outside))
  assert.ok(fs.existsSync(notOwned))
})

test('rejects link/junction metadata on child or parent before rm (mocked, no link creation)', t => {
  const { parent, work } = sandbox(t)
  const original = fs.lstatSync
  for (const linked of [parent, work]) {
    const remove = t.mock.method(fs, 'rmSync', () => { assert.fail('unsafe rm') })
    t.mock.method(fs, 'lstatSync', path => path === linked
      ? { isDirectory: () => true, isSymbolicLink: () => true } : original(path))
    assert.throws(() => removeWp1WorkDirectory(work, parent), /real directories/)
    assert.equal(remove.mock.callCount(), 0)
    t.mock.restoreAll()
  }
})

test('rejects redirected real paths on parent or child before rm', t => {
  const { root, parent, work } = sandbox(t)
  const original = fs.realpathSync
  for (const redirected of [parent, work]) {
    const remove = t.mock.method(fs, 'rmSync', () => { assert.fail('unsafe rm') })
    t.mock.method(fs, 'realpathSync', path => path === redirected ? root : original(path))
    assert.throws(() => removeWp1WorkDirectory(work, parent), /redirected/)
    assert.equal(remove.mock.callCount(), 0)
    t.mock.restoreAll()
  }
})

test('real cleanup deletion failure propagates and retains the work directory', t => {
  const { parent, work } = sandbox(t)
  const failure = new Error('synthetic access denied')
  t.mock.method(fs, 'rmSync', () => { throw failure })
  assert.throws(() => removeWp1WorkDirectory(work, parent), error => error === failure)
  assert.ok(fs.existsSync(work))
})
