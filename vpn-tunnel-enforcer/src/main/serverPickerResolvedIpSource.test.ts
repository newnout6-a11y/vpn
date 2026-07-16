import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const mainSource = readFileSync(join(process.cwd(), 'src/main/serverPicker.ts'), 'utf8')
const rendererSource = readFileSync(join(process.cwd(), 'src/renderer/pages/Servers.tsx'), 'utf8')

describe('resolved IP display', () => {
  it('resolves in parallel and persists the result without blocking the initial list', () => {
    expect(mainSource).toContain('const CONCURRENCY = 24')
    expect(mainSource).toContain('async function resolveAndPersistProfileIps()')
    expect(mainSource).toContain("handleLogged('servers:resolve-ips'")
    expect(mainSource).toContain("handleLogged('servers:list', async () => {\n    return getProfiles()")
  })

  it('renders the resolved IP and refreshes it in the background', () => {
    expect(rendererSource).toContain('IP: {profile.resolvedIp ?? \'—\'}')
    expect(rendererSource).toContain('serversResolveIps?: () => Promise<ServerProfile[]>')
  })
})
