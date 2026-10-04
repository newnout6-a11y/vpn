// AT-01-001/010: real electron-store and native DPAPI, cross-process restart.
// Fault injection replaces safeStorage only at this isolated fixture boundary.
import { app, safeStorage } from 'electron'
import Store from 'electron-store'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const work = process.env.VPNTE_WP1_WORK!
app.setPath('userData', join(work, 'userData'))
app.setPath('sessionData', join(work, 'sessionData'))
const phase = process.env.VPNTE_WP1_PHASE!
const marker = 'FAKE-WP1-NATIVE-SECRET'
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
