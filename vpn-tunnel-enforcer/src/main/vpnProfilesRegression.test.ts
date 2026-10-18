import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter, getEventListeners } from 'events'
import { PassThrough } from 'stream'

const execFileMock = vi.hoisted(() => {
  const fn = vi.fn() as any
  fn[Symbol.for('nodejs.util.promisify.custom')] = vi.fn()
  return fn
})
const spawnMock = vi.hoisted(() => vi.fn())
const spawnResult = vi.hoisted(() => ({ stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), exitCode: 0, stdin: '' }))

vi.mock('child_process', () => ({
  default: { execFile: execFileMock, exec: vi.fn(), spawn: spawnMock },
  execFile: execFileMock,
  exec: vi.fn(),
  spawn: spawnMock
}))

function curlStdout(headers: string, body = '') {
  return Buffer.from(`${headers}\r\n\r\n${body}`, 'utf8')
}

describe('vpnProfiles regressions', () => {
  beforeEach(() => {
    vi.resetModules()
    execFileMock.mockReset()
    execFileMock[Symbol.for('nodejs.util.promisify.custom')].mockReset()
    spawnMock.mockReset()
    spawnResult.stdout = Buffer.alloc(0)
    spawnResult.stderr = Buffer.alloc(0)
    spawnResult.exitCode = 0
    spawnResult.stdin = ''
    spawnMock.mockImplementation(() => {
      const child = new EventEmitter() as any
      child.stdin = new PassThrough()
      child.stdin.on('data', (data: Buffer) => { spawnResult.stdin += data.toString('utf8') })
      child.stdout = new PassThrough()
      child.stderr = new PassThrough()
      child.kill = vi.fn()
      queueMicrotask(() => {
        child.stdout.end(spawnResult.stdout)
        child.stderr.end(spawnResult.stderr)
        child.emit('exit', spawnResult.exitCode)
        child.emit('close', spawnResult.exitCode)
      })
      return child
    })
  })

  it('keeps the subscription URL and credentials out of argv (AT-01-009)', async () => {
    spawnResult.stdout = curlStdout('HTTP/1.1 200 OK', 'vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One')
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    await resolveVpnProfiles('https://sub.example.test/SECRET-SUBSCRIPTION-TOKEN?auth=PRIVATE-TOKEN')
    const argv = JSON.stringify(spawnMock.mock.calls[0][1])
    expect(argv).not.toContain('SECRET-SUBSCRIPTION-TOKEN')
    expect(argv).not.toContain('PRIVATE-TOKEN')
    expect(spawnResult.stdin).toContain('url = "https://sub.example.test/SECRET-SUBSCRIPTION-TOKEN?auth=PRIVATE-TOKEN"')
    expect(spawnMock.mock.calls[0][1].slice(0,3)).toEqual(['-q','--config','-'])
  })

  it('unwraps only the first VPN URI from Happ add base64 lists', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const first = 'vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One'
    const second = 'trojan://secret@two.example.com:443?sni=front.example.com#Two'
    const payload = Buffer.from([first, '# comment', second].join('\n'), 'utf8').toString('base64url')

    const resolved = await resolveVpnProfiles(`happ://add/${payload}`)

    expect(resolved.profiles).toHaveLength(1)
    expect(resolved.profiles[0].outbound.server).toBe('one.example.com')
  })

  it('reports HTTP redirects without Location instead of parsing an empty body', async () => {
    spawnResult.stdout = curlStdout('HTTP/1.1 302 Found')

    const { resolveVpnProfiles } = await import('./vpnProfiles')

    await expect(resolveVpnProfiles('https://sub.example.test/list')).rejects.toThrow(/without a Location header/)
  })

  it('dedupes identical in-flight subscription resolution calls', async () => {
    const body = 'vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One'
    spawnResult.stdout = curlStdout('HTTP/1.1 200 OK', body)

    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const [a, b] = await Promise.all([
      resolveVpnProfiles('https://sub.example.test/list'),
      resolveVpnProfiles('https://sub.example.test/list')
    ])

    expect(a.profiles).toHaveLength(1)
    expect(b.profiles).toHaveLength(1)
    expect(spawnMock).toHaveBeenCalledTimes(1)
    const argv = JSON.stringify(spawnMock.mock.calls[0]?.[1] ?? [])
    expect(argv).not.toMatch(/x-hwid|Happ\/3\.22\.1/)
  })

  it('cancels curl without releasing its physical work before close or retrying (AT-00-003)', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true) })
    spawnMock.mockReturnValue(child)
    const controller = new AbortController()
    const run = resolveVpnProfiles('https://sub.example.test/list', { signal: controller.signal })
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    controller.abort()
    await vi.waitFor(() => expect(child.kill).toHaveBeenCalled())
    let settled = false
    void run.then(() => { settled = true }, () => { settled = true })
    await Promise.resolve()
    expect(settled).toBe(false)
    child.stdout.end(curlStdout('HTTP/1.1 200 OK', 'vless://00000000-0000-4000-8000-000000000000@late.example.com:443#Late'))
    child.emit('close', 0)
    await rejected
    expect(spawnMock).toHaveBeenCalledTimes(1)
    expect(execFileMock[Symbol.for('nodejs.util.promisify.custom')]).not.toHaveBeenCalled()
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0)
  })

  it('cancels the DoH fallback and waits for its actual child close (AT-00-003)', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    let dohChild: any
    const children: any[] = []
    spawnMock.mockImplementation((_exe, args) => {
      const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true) })
      children.push(child)
      if (args.includes('cloudflare-dns.com:443:1.1.1.1')) dohChild = child
      else queueMicrotask(() => { child.stdout.end(curlStdout('HTTP/1.1 200 OK')); child.emit('close', 0) })
      return child
    })
    const controller = new AbortController()
    const run = resolveVpnProfiles('https://sub.example.test/list', { signal: controller.signal })
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(dohChild).toBeDefined())
    const count = children.length
    controller.abort()
    expect(dohChild.kill).toHaveBeenCalledOnce()
    let settled = false
    void run.then(() => { settled = true }, () => { settled = true })
    await Promise.resolve()
    expect(settled).toBe(false)
    dohChild.emit('close', null)
    await rejected
    expect(children).toHaveLength(count)
    expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0)
  })

  it('isolates cancellation from independent callers for the same URL (AT-00-003)', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const children: any[] = []
    spawnMock.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true) })
      children.push(child)
      return child
    })
    const controller = new AbortController()
    const cancelled = resolveVpnProfiles('https://sub.example.test/list', { signal: controller.signal })
    const rejected = expect(cancelled).rejects.toMatchObject({ category: 'cancelled' })
    const independent = resolveVpnProfiles('https://sub.example.test/list')
    expect(children).toHaveLength(2)
    controller.abort()
    children[0].emit('close', null)
    await rejected
    const body = 'vless://00000000-0000-4000-8000-000000000000@independent.example.com:443#Independent'
    children[1].stdout.end(curlStdout('HTTP/1.1 200 OK', body))
    children[1].emit('close', 0)
    expect((await independent).profiles[0].outbound.server).toBe('independent.example.com')
    expect(children[1].kill).not.toHaveBeenCalled()
  })

  it('does not spawn for an already cancelled resolution (AT-00-003)', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const controller = new AbortController()
    controller.abort()
    await expect(resolveVpnProfiles('https://sub.example.test/list', { signal: controller.signal })).rejects.toMatchObject({ category: 'cancelled' })
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it('parses spx / spider_x for Reality and passes to xray config generator', async () => {
    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const { toXrayOutbound } = await import('./xrayEngine')
    const uri = 'vless://00000000-0000-4000-8000-000000000000@reality.example.com:443?security=reality&pbk=fake-public-key&sid=1234&spx=%2Ftest-path#Reality'
    const resolved = await resolveVpnProfiles(uri)
    expect(resolved.profiles).toHaveLength(1)
    const profile = resolved.profiles[0]
    expect(profile.outbound.tls?.reality?.spider_x).toBe('/test-path')

    const outbound = toXrayOutbound(profile.outbound)
    expect(outbound.streamSettings?.realitySettings?.spiderX).toBe('/test-path')
  })
})
