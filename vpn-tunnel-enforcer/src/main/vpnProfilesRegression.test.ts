import { beforeEach, describe, expect, it, vi } from 'vitest'

const execFileMock = vi.hoisted(() => {
  const fn = vi.fn() as any
  fn[Symbol.for('nodejs.util.promisify.custom')] = vi.fn()
  return fn
})

vi.mock('child_process', () => ({
  default: { execFile: execFileMock },
  execFile: execFileMock
}))

function curlStdout(headers: string, body = '') {
  return Buffer.from(`${headers}\r\n\r\n${body}`, 'utf8')
}

describe('vpnProfiles regressions', () => {
  beforeEach(() => {
    vi.resetModules()
    execFileMock.mockReset()
    execFileMock[Symbol.for('nodejs.util.promisify.custom')].mockReset()
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
    execFileMock[Symbol.for('nodejs.util.promisify.custom')].mockResolvedValue({
      stdout: curlStdout('HTTP/1.1 302 Found'),
      stderr: Buffer.alloc(0)
    })

    const { resolveVpnProfiles } = await import('./vpnProfiles')

    await expect(resolveVpnProfiles('https://sub.example.test/list')).rejects.toThrow(/without a Location header/)
  })

  it('dedupes identical in-flight subscription resolution calls', async () => {
    const body = 'vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One'
    execFileMock[Symbol.for('nodejs.util.promisify.custom')].mockResolvedValue({
      stdout: curlStdout('HTTP/1.1 200 OK', body),
      stderr: Buffer.alloc(0)
    })

    const { resolveVpnProfiles } = await import('./vpnProfiles')
    const [a, b] = await Promise.all([
      resolveVpnProfiles('https://sub.example.test/list'),
      resolveVpnProfiles('https://sub.example.test/list')
    ])

    expect(a.profiles).toHaveLength(1)
    expect(b.profiles).toHaveLength(1)
    expect(execFileMock[Symbol.for('nodejs.util.promisify.custom')]).toHaveBeenCalledTimes(1)
  })
})
