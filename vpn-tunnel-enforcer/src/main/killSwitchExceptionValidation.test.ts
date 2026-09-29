import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  BrowserWindow: { getFocusedWindow: vi.fn(() => null), getAllWindows: vi.fn(() => []) },
  dialog: { showOpenDialog: vi.fn() }
}))
vi.mock('./notifications', () => ({ notify: vi.fn() }))
vi.mock('./tunController', () => ({ tunController: { getStatus: vi.fn(() => ({ running: false })) } }))

import { validateKillSwitchException } from './granularKillSwitch'

describe('strict kill-switch exception validation (AT-03-009)', () => {
  let dir = ''
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
    dir = ''
  })

  it.each([
    '192.0.2.1',
    '10.0.0.0/8',
    '0.0.0.0/0',
    '2001:db8::/32',
    '::/0'
  ])('accepts valid IP/CIDR %s', async value => {
    await expect(validateKillSwitchException({ type: 'ip', value, label: 'test' })).resolves.toMatchObject({ value })
  })

  it.each(['999.1.1.1', '10.0.0.1/33', '2001:db8::/129', 'host.example', '10.0.0.0/x'])(
    'rejects invalid IP/CIDR %s',
    async value => {
      await expect(validateKillSwitchException({ type: 'ip', value, label: 'test' })).rejects.toThrow(/IP|CIDR/)
    }
  )

  it('requires an existing readable executable and returns its canonical path', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vpnte-exception-'))
    const executable = join(dir, 'allowed.exe')
    await writeFile(executable, 'fixture')
    await expect(validateKillSwitchException({ type: 'app', value: executable, label: 'Allowed' }))
      .resolves.toMatchObject({ type: 'app', value: executable })
    await expect(validateKillSwitchException({ type: 'app', value: join(dir, 'missing.exe'), label: 'Missing' }))
      .rejects.toThrow()
  })
})