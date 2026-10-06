// AT-11-002 / F-183: shutdown needs strict status, while UI retains its existing contract.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const targets = vi.hoisted(() => {
  const target = (name: string) => ({
    name,
    apply: vi.fn(),
    rollback: vi.fn(),
    isApplied: vi.fn()
  })
  return {
    androidStudio: target('Android Studio'),
    gradle: target('Gradle'),
    env: {
      ...target('Environment Variables'),
      scope: 'user-global' as const,
      warning: 'Environment backup warning',
      backupPath: vi.fn(() => 'mock-env-backup.json')
    },
    git: target('Git')
  }
})

vi.mock('./androidStudio', () => ({ androidStudio: targets.androidStudio }))
vi.mock('./gradle', () => ({ gradle: targets.gradle }))
vi.mock('./env', () => ({ env: targets.env }))
vi.mock('./git', () => ({ git: targets.git }))

import { autoconfig } from './index'

describe('autoconfig strict status', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    for (const target of Object.values(targets)) target.isApplied.mockResolvedValue(false)
  })

  it.each([true, false])('returns the env target result unchanged: %s', async (applied) => {
    targets.env.isApplied.mockResolvedValue(applied)

    expect(await autoconfig.isApplied('env')).toBe(applied)
    expect(targets.env.isApplied).toHaveBeenCalledExactlyOnceWith()
    expect(targets.androidStudio.isApplied).not.toHaveBeenCalled()
    expect(targets.gradle.isApplied).not.toHaveBeenCalled()
    expect(targets.git.isApplied).not.toHaveBeenCalled()
    expect(targets.env.apply).not.toHaveBeenCalled()
    expect(targets.env.rollback).not.toHaveBeenCalled()
  })

  it.each([
    ['android-studio', 'androidStudio'],
    ['gradle', 'gradle'],
    ['git', 'git']
  ] as const)('delegates to the known target %s', async (id, key) => {
    targets[key].isApplied.mockResolvedValue(true)
    expect(await autoconfig.isApplied(id)).toBe(true)
    expect(targets[key].isApplied).toHaveBeenCalledExactlyOnceWith()
    expect(targets.env.isApplied).not.toHaveBeenCalled()
  })

  it('propagates the original status error without blind rollback', async () => {
    const error = new Error('Access denied reading HTTP_PROXY')
    targets.env.isApplied.mockRejectedValue(error)

    await expect(autoconfig.isApplied('env')).rejects.toBe(error)
    expect(targets.env.isApplied).toHaveBeenCalledExactlyOnceWith()
    for (const target of Object.values(targets)) {
      expect(target.apply).not.toHaveBeenCalled()
      expect(target.rollback).not.toHaveBeenCalled()
    }
  })

  it.each(['unknown', 'toString', '__proto__'])('rejects unknown target %s', async (id) => {
    await expect(autoconfig.isApplied(id)).rejects.toThrow(`Unknown autoconfig target: ${id}`)
    for (const target of Object.values(targets)) expect(target.isApplied).not.toHaveBeenCalled()
  })

  it('keeps the UI getStatus contract on status errors, including metadata and other targets', async () => {
    targets.env.isApplied.mockRejectedValue(new Error('reg query timed out'))
    targets.git.isApplied.mockResolvedValue(true)

    const status = await autoconfig.getStatus()
    expect(status.map(({ id }) => id)).toEqual(['android-studio', 'gradle', 'env', 'git'])
    expect(status.find(({ id }) => id === 'env')).toEqual({
      id: 'env',
      name: 'Environment Variables',
      applied: false,
      scope: 'user-global',
      warning: 'Environment backup warning',
      managedPath: undefined,
      backupPath: 'mock-env-backup.json'
    })
    expect(status.find(({ id }) => id === 'git')?.applied).toBe(true)
    for (const target of Object.values(targets)) expect(target.isApplied).toHaveBeenCalledExactlyOnceWith()
  })
})
