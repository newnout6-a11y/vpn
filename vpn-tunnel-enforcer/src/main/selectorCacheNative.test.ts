// AT-02-002/004: bundled-core selector persistence, confined to loopback.
// No TUN, system routes, firewall changes, credentials, or external connections.
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { request } from 'node:http'
import { createServer } from 'node:net'
import { join, resolve, sep } from 'node:path'
import { expect, it } from 'vitest'

it.runIf(process.platform === 'win32')('starts the configured slot with disabled cache even when the bundled core saved b (AT-02-002)', async () => {
  const tempRoot = resolve('.tmp')
  await mkdir(tempRoot, { recursive: true })
  const directory = await mkdtemp(join(tempRoot, 'selector-cache-native-'))
  const secret = '0123456789abcdef0123456789abcdef'
  let active: ChildProcess | undefined
  async function port(): Promise<number> {
    const listener = createServer()
    listener.listen(0, '127.0.0.1')
    await once(listener, 'listening')
    const chosen = (listener.address() as { port: number }).port
    await new Promise<void>((done, fail) => listener.close(error => error ? fail(error) : done()))
    return chosen
  }
  async function api(apiPort: number, selected?: string): Promise<string | undefined> {
    return new Promise((done, fail) => {
      const req = request({ host: '127.0.0.1', port: apiPort, path: '/proxies/proxy-out',
        method: selected ? 'PUT' : 'GET', headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' } }, res => {
        let content = ''
        res.on('data', chunk => {
          content += chunk
          if (content.length > 16384) req.destroy(new Error('Oversized controller response'))
        })
        res.on('error', fail)
        res.on('end', () => {
          if (res.statusCode !== (selected ? 204 : 200)) { fail(new Error('Controller request refused')); return }
          try { done(content ? JSON.parse(content).now : undefined) } catch (error) { fail(error) }
        })
      })
      req.setTimeout(300, () => req.destroy(new Error('Controller timeout')))
      req.on('error', fail)
      if (selected) req.write(JSON.stringify({ name: selected }))
      req.end()
    })
  }
  async function stop(): Promise<void> {
    if (!active) return
    const child = active
    if (child.exitCode !== null || child.signalCode !== null) { active = undefined; return }
    const closed = once(child, 'close')
    if (!child.kill('SIGTERM')) throw new Error('Owned loopback core could not be stopped')
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([closed, new Promise<never>((_done, fail) => {
        timer = setTimeout(() => fail(new Error('Owned loopback core exit was not confirmed')), 3000)
      })])
      active = undefined
    } finally { clearTimeout(timer) }
  }
  async function start(cacheEnabled: boolean): Promise<{ apiPort: number; selected: string | undefined }> {
    assert.equal(active, undefined)
    const apiPort = await port()
    let inboundPort = await port()
    while (inboundPort === apiPort) inboundPort = await port()
    const config = {
      log: { level: 'error' },
      inbounds: [{ type: 'mixed', tag: 'loopback-only', listen: '127.0.0.1', listen_port: inboundPort }],
      outbounds: [
        { type: 'selector', tag: 'proxy-out', outbounds: ['vpnte-upstream-a', 'vpnte-upstream-b'], default: 'vpnte-upstream-a' },
        { type: 'direct', tag: 'vpnte-upstream-a' }, { type: 'direct', tag: 'vpnte-upstream-b' }
      ],
      route: { final: 'proxy-out' },
      experimental: {
        clash_api: { external_controller: `127.0.0.1:${apiPort}`, secret },
        cache_file: { enabled: cacheEnabled, path: join(directory, 'cache.db') }
      }
    }
    const configPath = join(directory, 'config.json')
    await writeFile(configPath, JSON.stringify(config))
    active = spawn(resolve('resources/sing-box.exe'), ['run', '-c', configPath], {
      cwd: directory, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
    })
    let spawnError = false
    active.stdout?.on('data', () => {})
    active.stderr?.on('data', () => {})
    active.on('error', () => { spawnError = true })
    const deadline = Date.now() + 4000
    while (Date.now() < deadline) {
      if (spawnError || active.exitCode !== null) throw new Error('Owned loopback core did not start')
      try { return { apiPort, selected: await api(apiPort) } } catch { /* Controller may still be binding. */ }
      await new Promise(done => setTimeout(done, 20))
    }
    throw new Error('Loopback controller readiness deadline')
  }
  try {
    const first = await start(true)
    expect(first.selected).toBe('vpnte-upstream-a')
    await api(first.apiPort, 'vpnte-upstream-b')
    expect(await api(first.apiPort)).toBe('vpnte-upstream-b')
    await stop()
    const restored = await start(true)
    expect(restored.selected).toBe('vpnte-upstream-b') // Proves the cold-start hazard.
    await stop()
    const isolated = await start(false)
    expect(isolated.selected).toBe('vpnte-upstream-a')
    await api(isolated.apiPort, 'vpnte-upstream-b')
    expect(await api(isolated.apiPort)).toBe('vpnte-upstream-b')
    await stop()
    const restarted = await start(false)
    expect(restarted.selected).toBe('vpnte-upstream-a')
  } finally {
    await stop()
    const absoluteDirectory = resolve(directory)
    if (!absoluteDirectory.startsWith(tempRoot + sep)) throw new Error('Unexpected temporary directory')
    await rm(absoluteDirectory, { recursive: true, force: true })
  }
}, 15000)
