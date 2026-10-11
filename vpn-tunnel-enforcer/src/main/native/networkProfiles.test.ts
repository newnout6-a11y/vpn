// AT-03-005/006: network profile names for the native adapter snapshot come from the warm elevated
// helper, never from in-process COM; any doubt throws so the PowerShell worker path is used.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const helper = vi.hoisted(() => ({ running: vi.fn(), exec: vi.fn() }))
vi.mock('../elevatedPsHelper', () => ({ isElevatedPsHelperRunning: helper.running, execElevatedPs: helper.exec }))
import { fetchNetworkProfiles, parseNetworkProfiles } from './networkProfiles'

beforeEach(() => { helper.running.mockReset().mockReturnValue(true); helper.exec.mockReset() })

describe('parseNetworkProfiles', () => {
  it('groups names by interface index and drops empty names', () => {
    const map = parseNetworkProfiles('﻿[{"ifIndex":17,"name":"Office"},{"ifIndex":17,"name":"Guest"},{"ifIndex":5,"name":""}]')
    expect([...map.entries()]).toEqual([[17, ['Office', 'Guest']]])
  })
  it('accepts an empty list (no connected networks is a normal state)', () => {
    expect(parseNetworkProfiles('[]').size).toBe(0)
  })
  it.each(['{"ifIndex":17,"name":"x"}', '[{"ifIndex":"17","name":"x"}]', '[{"ifIndex":1}]', 'not json'])('refuses unexpected shape %s', text => {
    expect(() => parseNetworkProfiles(text)).toThrow()
  })
})

describe('fetchNetworkProfiles', () => {
  it('runs the read-only script in the physical-adapter-lockdown policy', async () => {
    helper.exec.mockResolvedValue({ stdout: '[{"ifIndex":3,"name":"Home"}]', stderr: '', exitCode: 0 })
    expect((await fetchNetworkProfiles()).get(3)).toEqual(['Home'])
    expect(helper.exec).toHaveBeenCalledWith(expect.stringContaining('Get-NetConnectionProfile'), expect.any(Number), 'physical-adapter-lockdown')
    expect(helper.exec.mock.calls[0][0]).not.toMatch(/\b(Set|New|Remove|Disable|Enable)-/)
  })
  it('fails closed when the helper is not running', async () => {
    helper.running.mockReturnValue(false)
    await expect(fetchNetworkProfiles()).rejects.toThrow(/not running/)
    expect(helper.exec).not.toHaveBeenCalled()
  })
  it('fails closed on a non-zero exit or a helper error', async () => {
    helper.exec.mockResolvedValue({ stdout: '', stderr: 'x', exitCode: 1 })
    await expect(fetchNetworkProfiles()).rejects.toThrow(/exit 1/)
    helper.exec.mockRejectedValue(new Error('timeout'))
    await expect(fetchNetworkProfiles()).rejects.toThrow(/timeout/)
  })
})
