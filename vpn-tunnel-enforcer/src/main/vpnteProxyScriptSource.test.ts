import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const scriptSource = () => readFileSync(join(process.cwd(), 'resources', 'vpnte-proxy.ps1'), 'utf8')

describe('vpnte-proxy script source regressions', () => {
  it('validates that control URL must be a local loopback endpoint', () => {
    const script = scriptSource()

    expect(script).toContain('Test-IsSafeLocalControlUrl')
    expect(script).toContain("$u.Scheme -ne 'http'")
    expect(script).toContain("127.0.0.1")
    expect(script).toContain("localhost")
    expect(script).toContain("::1")
    expect(script).toContain("$u.Port -le 0 -or $u.Port -gt 65535")
  })

  it('rejects external or non-loopback control URLs from env and endpoint file', () => {
    const script = scriptSource()

    expect(script).toContain('VPNTE_CONTROL_URL is not a valid local loopback address')
    expect(script).toContain('Test-IsSafeLocalControlUrl $raw')
  })

  it('guards Invoke-VpnteProxy against token exfiltration to non-loopback targets', () => {
    const script = scriptSource()

    expect(script).toContain('if (-not (Test-IsSafeLocalControlUrl $path))')
    expect(script).toContain('Invalid control API request target')
    expect(script).toContain('X-VPNTE-Control-Token')
  })
})
