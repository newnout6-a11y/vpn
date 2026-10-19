// AT-01-001/010: real electron-store and native DPAPI, cross-process restart.
// Fault injection replaces safeStorage only at this isolated fixture boundary.
import { app, safeStorage } from 'electron'
import Store from 'electron-store'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

const work = process.env.VPNTE_WP1_WORK!
app.setPath('userData', join(work, 'userData'))
app.setPath('sessionData', join(work, 'sessionData'))
const phase = process.env.VPNTE_WP1_PHASE!
const marker = 'FAKE-WP1-NATIVE-SECRET'
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')
async function waitForMigrationAudit(expected: 'error' | 'success'): Promise<void> {
  const path = join(app.getPath('userData'), 'logs', 'app.log')
  for (let attempt = 0; attempt < 100; attempt++) {
    const raw = existsSync(path) ? readFileSync(path, 'utf8') : ''
    const lines = raw.slice(0, raw.lastIndexOf('\n') + 1).split('\n').filter(Boolean).map(line => JSON.parse(line))
    const events = lines.filter(line => line.scope === 'store-migration' && line.details?.status === expected)
    if (expected === 'error' && events.some(line => line.details.stage === 'prepare')) return
    if (expected === 'success' && events.length === 3) {
      assert.deepEqual(events.map(line => line.details.store).sort(), ['server-groups', 'server-picker', 'settings'])
      for (const event of events) assert.equal(event.details.migrationStep, 'safe-storage-v1')
      assert.ok(!JSON.stringify(lines).includes(marker), 'migration audit contains plaintext')
      return
    }
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  throw new Error(`Migration ${expected} JSONL audit was not written`)
}
app.whenReady().then(async () => {
  if (phase === 'seed42' || phase === 'seed44') {
    assert.ok(process.versions.electron.startsWith(phase === 'seed42' ? '42.' : '44.'))
    new Store({ name: 'settings' }).store = { schemaVersion: 0, settings: {
      directVpnInput: `vless://${marker}@vpn.test:443`, directVpnCachedInput: marker,
      directVpnCachedSource: `https://subscription.test/${marker}`, directVpnCachedProfiles: [{ name: 'Fixture', protocol: 'vless', outbound: { uuid: marker } }],
      proxyOverride: `http://user:${marker}@127.0.0.1:8080`
    } }
    new Store({ name: 'server-picker' }).store = { schemaVersion: 0, activeProfileId: 'p1', profiles: [
      { id: 'p1', name: 'Fixture', protocol: 'vless', server: 'vpn.test', port: 443,
        sourceUri: `vless://${marker}@vpn.test:443`, outbound: { type: 'vless', uuid: marker } }
    ] }
    new Store({ name: 'server-groups' }).store = { groups: [{ id: 'g1', name: 'Fixture', sourceUrl: `https://subscription.test/${marker}` }] }
    writeFileSync(join(work, 'electron42.dpapi'), safeStorage.encryptString(marker))
    // A pre-existing plaintext backup from the old release is also migrated.
    const profileFile = join(app.getPath('userData'), 'server-picker.json')
    writeFileSync(profileFile + '.pre-safe-storage-v1.bak', readFileSync(profileFile))
    writeFileSync(join(work, 'seed-digests.json'), JSON.stringify(Object.fromEntries(
      ['settings', 'server-picker', 'server-groups'].map(name => [name, digest(readFileSync(join(app.getPath('userData'), `${name}.json`)))])
    )))
  } else {
    assert.ok(process.versions.electron.startsWith('44.'))
    if (phase === 'fail44') {
      const original = safeStorage.encryptString.bind(safeStorage)
      let calls = 0
      safeStorage.encryptString = value => { if (++calls === 3) throw new Error('injected mid-migration failure'); return original(value) }
    }
    if (phase === 'unavailable44') safeStorage.isEncryptionAvailable = () => false
    const before = readFileSync(join(app.getPath('userData'), 'server-picker.json'))
    const { serverPickerStore, serverGroupsStore } = await import('../../src/main/sharedStores')
    if (phase === 'fail44' || phase === 'unavailable44') {
      assert.throws(() => serverPickerStore.get('profiles'), phase === 'fail44' ? /injected/ : /unavailable/)
      assert.deepEqual(readFileSync(serverPickerStore.path), before)
      if (phase === 'fail44') await waitForMigrationAudit('error')
      if (phase === 'unavailable44') {
        const settingsBefore = readFileSync(join(app.getPath('userData'), 'settings.json'))
        const { settingsStore } = await import('../../src/main/settings')
        assert.throws(() => settingsStore.get(), /unavailable/)
        assert.deepEqual(readFileSync(join(app.getPath('userData'), 'settings.json')), settingsBefore)
      }
    } else {
      assert.equal(safeStorage.decryptString(readFileSync(join(work, 'electron42.dpapi'))), marker)
      assert.equal(serverPickerStore.get('profiles')[0].outbound?.uuid, marker)
      assert.ok(serverGroupsStore.get('groups')[0].sourceUrl?.includes(marker))
      const { settingsStore } = await import('../../src/main/settings')
      assert.ok(settingsStore.get().directVpnInput.includes(marker))
      assert.ok(settingsStore.get().proxyOverride.includes(marker))
      for (const name of readdirSync(app.getPath('userData'))) {
        if (!/\.json(?:\.pre-safe-storage-v1\.bak)?$/.test(name)) continue
        assert.ok(!readFileSync(join(app.getPath('userData'), name), 'utf8').includes(marker), name + ' contains plaintext')
      }
      assert.equal(JSON.parse(readFileSync(serverPickerStore.path, 'utf8')).schemaVersion, 2)
      const { decryptSecret } = await import('../../src/main/secretStorage')
      const originalDigests = JSON.parse(readFileSync(join(work, 'seed-digests.json'), 'utf8'))
      for (const name of ['settings', 'server-picker', 'server-groups']) {
        const path = join(app.getPath('userData'), `${name}.json`)
        const migrated = JSON.parse(readFileSync(path, 'utf8'))
        assert.equal(migrated.migrationHistory.length, 1, `${name}: duplicate/missing step after restart`)
        const [step] = migrated.migrationHistory
        assert.equal(step.id, 'safe-storage-v1')
        assert.equal(step.from, 0)
        assert.equal(step.to, name === 'server-groups' ? 1 : 2)
        assert.equal(step.status, 'success')
        assert.match(step.inputChecksum, /^[a-f0-9]{64}$/)
        assert.equal(step.backupChecksum, originalDigests[name])
        const { migrationHistory: _history, ...output } = migrated
        assert.equal(step.outputChecksum, digest(JSON.stringify(output)))
        const backup = JSON.parse(readFileSync(path + step.backupSuffix, 'utf8'))
        assert.equal(digest(decryptSecret(backup.contents)), originalDigests[name], `${name}: original backup changed`)
      }
      await waitForMigrationAudit('success')
    }
  }
  console.log('WP1_MIGRATION_PASS', JSON.stringify({ phase, electron: process.versions.electron }))
  return 0
}).catch(error => { console.error(error); return 1 }).then(code => {
  // Electron must flush Chromium's Local State encryption key before the next
  // process opens the encrypted files. app.exit() skips that graceful shutdown.
  process.exitCode = code
  app.quit()
})
