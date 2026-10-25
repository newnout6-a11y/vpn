// Runner policy and seeding. No Electron, filesystem or network side effects on import.
import assert from 'node:assert/strict'
import { stripVTControlCharacters } from 'node:util'
import { connect as connectTls } from 'node:tls'
import { request } from 'node:http'
import { setTimeout as delay } from 'node:timers/promises'
import { open } from 'node:fs/promises'
import { join } from 'node:path'

export function runtimeFailureKinds(text) {
  const kinds = []
  for (const [kind, pattern] of [
    ['dns-failed', /failed to (?:lookup|resolve|retrieve response)|dns[^\r\n]*(?:fail|timeout)/i],
    ['tls-rejected', /tls[^\r\n]*(?:fail|reject|certificate|first record)|certificate[^\r\n]*(?:fail|invalid|unknown)|handshake[^\r\n]*(?:fail|timeout)/i],
    ['connection-refused', /connection (?:was )?refused/i], ['connection-reset', /connection (?:was )?reset/i],
    ['dial-failed', /failed to (?:dial|connect)|all (?:dial|connection) attempts failed/i],
    ['network-unreachable', /no route to host|network is unreachable/i],
    ['deadline', /deadline exceeded|i\/o timeout|operation timed out/i],
    ['access-denied', /permission denied|access (?:is )?denied/i],
    ['unexpected-eof', /unexpected eof|read: eof/i],
    ['outbound-transfer-failed', /failed to (?:process outbound traffic|transfer request)/i],
    ['response-header-failed', /failed to read response header/i],
    ['closed-pipe', /io: read\/write on closed pipe/i]
  ]) if (pattern.test(String(text))) kinds.push(kind)
  return kinds
}

// Bounded, fixed-file inspection on the disposable hosted runner only. Raw
// runtime logs/configuration are never returned or uploaded.
const runtimeLogFiles = ['xray-a.log', 'xray-b.log', 'xray.log']
export async function snapshotRuntimeLogs(directory) {
  return Promise.all(runtimeLogFiles.map(async file => {
    let handle
    try {
      handle = await open(join(directory, file), 'r')
      const info = await handle.stat()
      if (!info.isFile()) throw new Error('Not a regular log')
      return { file, state: 'present', size: info.size, dev: info.dev, ino: info.ino, birthtimeMs: info.birthtimeMs }
    } catch (error) { return { file, state: error?.code === 'ENOENT' ? 'missing' : 'unavailable' } }
    finally { await handle?.close().catch(() => {}) }
  }))
}

export async function inspectRuntimeFailures(directory, baseline) {
  return Promise.all(runtimeLogFiles.map(async file => {
    let handle
    try {
      handle = await open(join(directory, file), 'r')
      const info = await handle.stat()
      if (!info.isFile()) throw new Error('Not a regular log')
      const before = baseline?.find(entry => entry.file === file)
      if (!before || before.state === 'unavailable') throw new Error('No reliable step boundary')
      if (before.state === 'present' && (info.size < before.size || info.dev !== before.dev ||
        info.ino !== before.ino || info.birthtimeMs !== before.birthtimeMs)) throw new Error('Log rotated during step')
      const offset = before.state === 'present' ? before.size : 0
      const buffer = Buffer.alloc(Math.min(65536, info.size - offset))
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, Math.max(0, info.size - buffer.length))
      return { file, checked: true, bytesRead, kinds: runtimeFailureKinds(buffer.subarray(0, bytesRead).toString('utf8')) }
    } catch { return { file, checked: false, kinds: [] } }
    finally { await handle?.close().catch(() => {}) }
  }))
}

function readControllerJson(api, path, signal) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: api.port, path, method: 'GET', agent: false, signal,
      headers: { Authorization: `Bearer ${api.secret}` } }, response => {
      const chunks = []; let size = 0
      response.on('data', chunk => {
        size += chunk.length
        if (size > 1024 * 1024) response.destroy(new Error('Controller response too large'))
        else chunks.push(chunk)
      })
      response.on('error', reject)
      response.on('end', () => {
        try {
          if (response.statusCode !== 200) throw new Error('Controller read rejected')
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
        } catch (error) { reject(error) }
      })
    })
    req.setTimeout(1000, () => req.destroy(new Error('Controller read deadline')))
    req.on('error', reject); req.end()
  })
}

/** Independent ordinary OS TLS flow, followed by its live sing-box chain. No endpoint packet-capture claim. */
export async function verifySelectorTlsFlow(config, { dial = connectTls, readJson = readControllerJson, pause = delay, timeoutMs = 5000 } = {}) {
  const selectors = config?.outbounds?.filter(outbound => outbound.tag === 'proxy-out' && outbound.type === 'selector') ?? []
  if (!selectors.length) return { applicable: false }
  const abort = new AbortController()
  let socket, timer
  try {
    assert.ok(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 30000)
    const tags = ['vpnte-upstream-a', 'vpnte-upstream-b']
    assert.ok(selectors.length === 1 && JSON.stringify([...selectors[0].outbounds].sort()) === JSON.stringify(tags))
    const controller = config.experimental?.clash_api
    const match = /^127\.0\.0\.1:([0-9]{1,5})$/.exec(controller?.external_controller ?? '')
    assert.ok(match && +match[1] > 0 && +match[1] <= 65535 && /^[a-f0-9]{32}$/i.test(controller.secret))
    const api = { port: +match[1], secret: controller.secret }
    const work = async () => {
      const selected = await readJson(api, '/proxies/proxy-out', abort.signal)
      abort.signal.throwIfAborted()
      assert.ok(selected?.type === 'Selector' && tags.includes(selected.now)
        && Array.isArray(selected.all) && JSON.stringify([...selected.all].sort()) === JSON.stringify(tags))
      await new Promise((resolve, reject) => {
        socket = dial({ host: '1.1.1.1', port: 443, servername: 'cloudflare-dns.com', rejectUnauthorized: true,
          minVersion: 'TLSv1.2', signal: abort.signal }, () => socket.authorized === true ? resolve() : reject(new Error('TLS unverified')))
        socket.on('error', reject)
      })
      abort.signal.throwIfAborted()
      assert.ok(Number.isInteger(socket.localPort) && socket.localPort > 0)
      for (let attempt = 0; attempt < 20; attempt++) {
        const snapshot = await readJson(api, '/connections', abort.signal)
        abort.signal.throwIfAborted()
        assert.ok(Array.isArray(snapshot?.connections) && snapshot.connections.length <= 10000)
        const matches = snapshot.connections.filter(connection => String(connection.metadata?.sourcePort) === String(socket.localPort)
          && connection.metadata?.destinationIP === '1.1.1.1' && String(connection.metadata?.destinationPort) === '443')
        assert.ok(matches.length <= 1)
        if (matches.length) {
          const chains = matches[0].chains
          assert.ok(Array.isArray(chains) && chains.includes('proxy-out') && chains.includes(selected.now)
            && !chains.includes('direct-out'))
          return { applicable: true, tlsVerified: true, proxyOutChainVerified: true }
        }
        await pause(50, undefined, { signal: abort.signal })
      }
      throw new Error('Ordinary TLS flow chain not found')
    }
    return await Promise.race([work(), new Promise((_, reject) => {
      timer = setTimeout(() => { abort.abort(); reject(new Error('Flow deadline')) }, timeoutMs)
    })])
  } catch { throw new Error('Selector ordinary TLS flow was not confirmed; private details omitted') }
  finally {
    clearTimeout(timer); abort.abort()
    if (socket && !socket.closed) {
      await new Promise((resolve, reject) => {
        const closed = () => { clearTimeout(limit); resolve() }
        const limit = setTimeout(() => { socket.removeListener('close', closed); reject(new Error('Selector probe socket close not confirmed')) }, 250)
        socket.once('close', closed); socket.destroy()
      })
    }
  }
}

export function hostedLaunchArgs(port) {
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535, 'Invalid inspector port')
  return [`--inspect=127.0.0.1:${port}`]
}

/** The hosted positive oracle runs after the action timer, on the existing TUN. */
export async function verifyNativeTunOwnership(execute) {
  let evidence
  try {
    const stdout = await execute(['run', '--mode', 'integration', 'src/main/native/ownedTunInterfaceCore.itest.ts', '--reporter=dot'],
      { VPNTE_REQUIRE_TUN_OWNERSHIP_COMPARISON: '1', FORCE_COLOR: '0' })
    for (const line of stdout.split(/\r?\n/)) {
      try {
        const value = JSON.parse(stripVTControlCharacters(line))
        if (value?.fixture === 'owned-tun-read-only') evidence = value
      } catch { /* Vitest status lines are not evidence. */ }
    }
  } catch { throw new Error('Positive native/CIM TUN comparison failed; output omitted') }
  assert.ok(Number.isInteger(evidence?.comparisons) && evidence.comparisons > 0 && evidence.comparisons <= 4096
    && Number.isInteger(evidence?.positive) && evidence.positive > 0 && evidence.positive <= evidence.comparisons,
  'Positive native/CIM TUN comparison was not confirmed')
  return { status: 'PASS', comparisons: evidence.comparisons, positive: evidence.positive }
}

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
// Fixed diagnostic vocabulary only: PowerShell may include private configuration
// in its error output, so neither its message nor arbitrary native codes escape.
export function safeWindowsOracleError(error) {
  const stderr = String(error?.stderr ?? '')
  const tag = stderr.match(/\bVPNTE_ORACLE_(?:RUNTIME_INVENTORY|CONFIG_READ|ADAPTER_INVENTORY|ADDRESS_INVENTORY|PID_IDENTITY|SELECTOR_READ|SELECTOR_IDENTITY|TUN_IDENTITY|SLOT_IDENTITY|ENDPOINT_ROUTE|REPORT_SERIALIZE)\b/)?.[0]
  const native = tag && stderr.match(/\bVPNTE_NATIVE_(?:ADDRESS_NOT_FOUND|ACCESS_DENIED|READ_FAILED)\b/)?.[0]
  const failure = new Error(`Windows oracle/shutdown failed${tag ? ` [${tag}]` : ''}; command output omitted`)
  if (tag) failure.oracleCode = tag
  if (native) failure.oracleNativeCode = native
  return failure
}
