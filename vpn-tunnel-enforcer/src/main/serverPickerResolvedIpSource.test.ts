import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Normalize line endings before matching. `core.autocrlf=true` (the Windows
 * default) checks these files out with CRLF, so a multi-line needle written
 * with bare `\n` never matches on a Windows worktree even though the code is
 * exactly right.
 */
const readSource = (rel: string): string =>
  readFileSync(join(process.cwd(), rel), 'utf8').replace(/\r\n/g, '\n')

const mainSource = readSource('src/main/serverPicker.ts')
const rendererSource = readSource('src/renderer/pages/Servers.tsx')

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
