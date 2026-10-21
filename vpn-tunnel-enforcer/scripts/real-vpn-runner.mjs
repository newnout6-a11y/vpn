// Runner policy and seeding. No Electron, filesystem or network side effects on import.
import assert from 'node:assert/strict'

export function requireHostedWindows(env = process.env, platform = process.platform) {
  assert.ok(platform === 'win32' && env.GITHUB_ACTIONS === 'true'
    && env.RUNNER_OS === 'Windows' && env.RUNNER_ENVIRONMENT === 'github-hosted'
    && env.GITHUB_EVENT_NAME === 'workflow_dispatch' && env.RUNNER_TEMP && env.APPDATA,
  'Real VPN switching is allowed only in the manual GitHub-hosted Windows workflow; local execution is blocked')
  for (const key of ['VPNTE_DISABLE_NATIVE_NET', 'ELECTRON_RENDERER_URL', 'ELECTRON_RUN_AS_NODE']) {
    assert.ok(!env[key], 'Development/mock Electron/network environment is not allowed')
  }
}

export function readScenarioSecret(raw) {
  assert.ok(typeof raw === 'string' && raw.length > 0, 'Set the VPNTE_REAL_SCENARIO GitHub Actions secret first')
  assert.ok(Buffer.byteLength(raw) <= 48 * 1024, 'Scenario secret exceeds 48 KiB; remove unused cached profiles')
  let seed
  try { seed = JSON.parse(raw) } catch { throw new Error('VPNTE_REAL_SCENARIO must contain valid JSON; payload omitted') }
  assert.ok(seed?.schemaVersion === 1, 'Unsupported scenario secret schema')
  assert.ok(seed.settings && !Array.isArray(seed.settings) && seed.settings.connectionMode === 'directVpn'
    && seed.settings.routingMode === 'hard', 'Scenario requires explicit Direct VPN / hard routing settings')
  assert.ok(Array.isArray(seed.profiles) && seed.profiles.length === 2, 'Provide exactly two real connection profiles, A then B')
  for (const profile of seed.profiles) {
    assert.ok(typeof profile?.input === 'string' && profile.input.trim().length > 0,
      'Each profile needs an importable URI or complete JSON in input')
    assert.ok(profile.clientDevice === undefined || ['pc', 'android', 'ios', 'mac'].includes(profile.clientDevice),
      'Unsupported client device')
  }
  return seed
}

export async function seedScenario(invoke, seed) {
  assert.equal((await invoke('serversList')).length, 0, 'Runner profile is not fresh')
  assert.equal((await invoke('getTunStatus')).running, false, 'Runner already has an active tunnel')
  await invoke('saveSettings', { ...await invoke('getSettings'), ...seed.settings })
  const settings = await invoke('getSettings')
  for (const [key, value] of Object.entries(seed.settings)) {
    // Actual/expected settings can contain credentials: never print either.
    assert.ok(JSON.stringify(settings[key]) === JSON.stringify(value), 'Application did not retain the requested settings')
  }
  const profiles = []
  for (const profile of seed.profiles) {
    const added = await invoke('serversAdd', profile.input, profile.clientDevice ? { clientDevice: profile.clientDevice } : undefined)
    assert.ok(Array.isArray(added) && added.length === 1 && added[0]?.id, 'Each input must import exactly one profile')
    profiles.push(added[0])
  }
  assert.ok(profiles[0].id !== profiles[1].id, 'A and B must be different profiles')
  await invoke('serversSelect', profiles[0].id)
  assert.ok((await invoke('serversGetActive')).activeId === profiles[0].id, 'Initial selection was not retained')
  return { original: profiles[0], target: profiles[1], settings }
}
