import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, realpath, rm, writeFile } from 'fs/promises'
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
    '2001:db8::/32',
    '2001:db8::1'
  ])('accepts valid IP/CIDR %s', async value => {
    await expect(validateKillSwitchException({ type: 'ip', value, label: 'test' })).resolves.toMatchObject({ value })
  })

  it.each(['0.0.0.0/0', '::/0', '999.1.1.1', '10.0.0.1/33', '2001:db8::/129', 'host.example', '10.0.0.0/x'])(
    'rejects invalid IP/CIDR %s',
    async value => {
      await expect(validateKillSwitchException({ type: 'ip', value, label: 'test' })).rejects.toThrow(/IP|CIDR/)
    }
  )

  it.each(['192.0.2.1/0x10', '192.0.2.1/+24', '2001:db8::1/1e1', '2001:db8::1/64.0'])(
    'does not normalize malformed CIDR %s into a saved exception (AT-03-009)', async value => {
      await expect(validateKillSwitchException({ type: 'ip', value, label: 'test' }))
        .rejects.toThrow('exception.value')
    }
  )

  it('requires an existing readable executable and returns its canonical path', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vpnte-exception-'))
    const executable = join(dir, 'allowed.exe')
    await writeFile(executable, 'fixture')
    await expect(validateKillSwitchException({ type: 'app', value: executable, label: 'Allowed' }))
      // os.tmpdir() may be an 8.3 short path (C:UsersRUNNER~1...); the validator returns the canonical one.
      .resolves.toMatchObject({ type: 'app', value: await realpath(executable) })
    await expect(validateKillSwitchException({ type: 'app', value: join(dir, 'missing.exe'), label: 'Missing' }))
      .rejects.toThrow()
  })
})
