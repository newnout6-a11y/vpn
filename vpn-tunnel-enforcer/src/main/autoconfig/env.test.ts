import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { lstat, mkdir, readFile, unlink, writeFile } from 'fs/promises'
import { homedir } from 'os'
import { join } from 'path'

const { mockExecFile, mockFs, mockRegistry } = vi.hoisted(() => ({
  mockExecFile: vi.fn(),
  mockFs: {} as Record<string, string>,
  mockRegistry: {} as Record<string, string>
}))

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  const customExecFile = (...args: any[]) => {
    const callback = args[args.length - 1]
    const result = mockExecFile(...args.slice(0, -1))
    if (result instanceof Error) callback(result)
    else callback(null, result)
  }
  return { ...actual, default: { ...actual, execFile: customExecFile }, execFile: customExecFile }
})

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  const methods = { lstat: vi.fn(), readFile: vi.fn(), writeFile: vi.fn(), mkdir: vi.fn(), unlink: vi.fn() }
  return { ...actual, default: { ...actual, ...methods }, ...methods }
})

const proxyKeys = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'] as const
const backupFile = join(homedir(), '.vpnte', 'env-proxy-backup.json')
const pendingFile = `${backupFile}.pending`
const originalValues = {
  HTTP_PROXY: 'http://corporate:8080',
  HTTPS_PROXY: 'http://secure-corporate:8443',
  ALL_PROXY: 'socks5h://corporate:1080',
  NO_PROXY: 'localhost,internal.corp'
}
const vpnValues = {
  HTTP_PROXY: 'socks5h://127.0.0.1:10808',
  HTTPS_PROXY: 'socks5h://127.0.0.1:10808',
  ALL_PROXY: 'socks5h://127.0.0.1:10808',
  NO_PROXY: 'localhost,127.0.0.1,::1'
}

type ProxyValues = Partial<Record<typeof proxyKeys[number], string>>
let env: typeof import('./env').env

function fileError(code: string): Error {
  return Object.assign(new Error(`${code}: environment backup unavailable`), { code })
}

function missingRegistryValue(message = 'The system was unable to find the specified registry key or value.'): Error {
  return Object.assign(new Error(message), { code: 1, stderr: message })
}

function registryCommand(cmd: string, args: string[]) {
  if (cmd === 'reg' && args[0] === 'query') {
    const name = args[3]
    return mockRegistry[name] === undefined
      ? missingRegistryValue()
      : { stdout: `HKEY_CURRENT_USER\\Environment\r\n    ${name}    REG_SZ    ${mockRegistry[name]}\r\n`, stderr: '' }
  }
  if (cmd === 'setx') mockRegistry[args[0]] = args[1]
  else if (cmd === 'reg' && args[0] === 'delete') delete mockRegistry[args[3]]
  else if (cmd !== 'powershell') throw new Error(`Unexpected mocked command: ${cmd} ${args.join(' ')}`)
  return { stdout: '', stderr: '' }
}

function saveBackup(values: ProxyValues = {}): string {
  const receipt = JSON.stringify({
    createdAt: 1000,
    httpProxy: values.HTTP_PROXY ?? null,
    httpsProxy: values.HTTPS_PROXY ?? null,
    allProxy: values.ALL_PROXY ?? null,
    noProxy: values.NO_PROXY ?? null
  })
  mockFs[backupFile] = receipt
  return receipt
}

function seedRegistry(values: ProxyValues) {
  Object.assign(mockRegistry, values)
  for (const key of proxyKeys) vi.stubEnv(key, values[key])
}

function mutations() {
  return mockExecFile.mock.calls
    .filter(([cmd, args]) => cmd === 'setx' || (cmd === 'reg' && args[0] === 'delete'))
    .map(([cmd, args]) => [cmd, args])
}

function queriedKeys() {
  return mockExecFile.mock.calls
    .filter(([cmd, args]) => cmd === 'reg' && args[0] === 'query')
    .map(([, args]) => args[3])
}

// AT-11-002 / F-183: shutdown must retire app-owned cleanup, not foreign proxies,
// and must retain the obligation whenever restoration or receipt retirement is unknown.
describe('env autoconfig backup and verified rollback', () => {
  beforeEach(async () => {
    vi.resetModules()
    vi.resetAllMocks()
    for (const key of Object.keys(mockFs)) delete mockFs[key]
    for (const key of Object.keys(mockRegistry)) delete mockRegistry[key]
    for (const key of proxyKeys) vi.stubEnv(key, undefined)
    mockExecFile.mockImplementation(registryCommand)
    vi.mocked(readFile).mockImplementation(async (path: any) => {
      if (mockFs[String(path)] !== undefined) return mockFs[String(path)]
      throw fileError('ENOENT')
    })
    vi.mocked(lstat).mockImplementation(async (path: any): Promise<any> => {
      if (mockFs[String(path)] !== undefined) return {}
      throw fileError('ENOENT')
    })
    vi.mocked(writeFile).mockImplementation(async (path: any, content: any, options: any) => {
      if (options?.flag === 'wx' && mockFs[String(path)] !== undefined) throw fileError('EEXIST')
      mockFs[String(path)] = String(content)
    })
    vi.mocked(mkdir).mockResolvedValue(undefined)
    vi.mocked(unlink).mockImplementation(async (path: any) => {
      if (mockFs[String(path)] === undefined) throw fileError('ENOENT')
      delete mockFs[String(path)]
    })
    env = (await import('./env')).env
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('exposes scope, warning, and backupPath matching the autoconfig contract', () => {
    expect(env.name).toBe('Environment Variables')
    expect(env.scope).toBe('user-global')
    expect(env.warning).toContain('pre-existing variables are backed up and restored on rollback')
    expect(env.backupPath()).toBe(backupFile)
  })

  it('backs up all original values before apply and preserves the receipt on repeated apply', async () => {
    seedRegistry(originalValues)
    expect(await env.apply('127.0.0.1:10808')).toBe(true)
    const receipt = mockFs[backupFile]
    expect(mockFs[pendingFile]).toBeDefined()
    expect(JSON.parse(receipt)).toEqual({
      createdAt: expect.any(Number),
      httpProxy: originalValues.HTTP_PROXY,
      httpsProxy: originalValues.HTTPS_PROXY,
      allProxy: originalValues.ALL_PROXY,
      noProxy: originalValues.NO_PROXY
    })
    expect(mockRegistry).toEqual(vpnValues)
    for (const key of proxyKeys) expect(process.env[key]).toBe(vpnValues[key])
    expect(await env.isApplied()).toBe(true)

    mockExecFile.mockClear()
    expect(await env.apply('127.0.0.1:10809', 'http')).toBe(true)
    expect(mockFs[backupFile]).toBe(receipt)
    expect(vi.mocked(writeFile).mock.calls.filter(([path]) => path === backupFile)).toHaveLength(1)
    expect(queriedKeys()).toEqual([])
    expect(mockRegistry.HTTP_PROXY).toBe('http://127.0.0.1:10809')
  })

  it('restores mixed original/unset values, verifies all four, and retires the receipt', async () => {
    const originals = { HTTP_PROXY: originalValues.HTTP_PROXY, NO_PROXY: originalValues.NO_PROXY }
    saveBackup(originals)
    seedRegistry(vpnValues)

    expect(await env.rollback()).toBe(true)
    expect(mutations()).toEqual([
      ['setx', ['HTTP_PROXY', originals.HTTP_PROXY]],
      ['reg', ['delete', 'HKCU\\Environment', '/v', 'HTTPS_PROXY', '/f']],
      ['reg', ['delete', 'HKCU\\Environment', '/v', 'ALL_PROXY', '/f']],
      ['setx', ['NO_PROXY', originals.NO_PROXY]]
    ])
    expect(queriedKeys()).toEqual(proxyKeys.flatMap(key => [key, key]))
    expect(mockRegistry).toEqual(originals)
    for (const key of proxyKeys) expect(process.env[key]).toBe(originals[key as keyof typeof originals])
    expect(mockFs[backupFile]).toBeUndefined()
    expect(unlink).toHaveBeenCalledWith(backupFile)
    expect(mockFs[pendingFile]).toBeUndefined()
    expect(await env.isApplied()).toBe(false)
    vi.resetModules()
    env = (await import('./env')).env
    expect(await env.isApplied()).toBe(false)
  })

  it.each([
    {},
    { HTTP_PROXY: originalValues.HTTP_PROXY },
    { HTTPS_PROXY: originalValues.HTTPS_PROXY },
    { ALL_PROXY: originalValues.ALL_PROXY },
    { NO_PROXY: originalValues.NO_PROXY },
    originalValues
  ])('leaves pre-existing proxies untouched without a receipt: %j', async (values) => {
    seedRegistry(values)
    expect(await env.isApplied()).toBe(false)
    expect(await env.rollback()).toBe(false)
    expect(await env.isApplied()).toBe(false)
    expect(mockRegistry).toEqual(values)
    for (const key of proxyKeys) expect(process.env[key]).toBe(values[key as keyof typeof values])
    expect(mockExecFile).not.toHaveBeenCalled()
    expect(writeFile).not.toHaveBeenCalled()
    expect(unlink).not.toHaveBeenCalled()
  })

  it('reports a valid receipt even when HTTP_PROXY is missing', async () => {
    const receipt = saveBackup()
    seedRegistry({ HTTPS_PROXY: vpnValues.HTTPS_PROXY, ALL_PROXY: vpnValues.ALL_PROXY, NO_PROXY: vpnValues.NO_PROXY })
    expect(await env.isApplied()).toBe(true)
    expect(await env.isApplied()).toBe(true)
    expect(mockExecFile).not.toHaveBeenCalled()
    expect(mockFs[backupFile]).toBe(receipt)

    expect(await env.rollback()).toBe(true)
    expect(mutations()).toHaveLength(3)
    expect(mutations().some(([, args]) => args.includes('HTTP_PROXY'))).toBe(false)
    expect(mockRegistry).toEqual({})
    expect(await env.isApplied()).toBe(false)
  })

  it.each([{}, originalValues])('keeps already-restored values pending until verified receipt retirement: %j', async (values) => {
    const receipt = saveBackup(values)
    seedRegistry(values)
    expect(await env.isApplied()).toBe(true)
    expect(mockFs[backupFile]).toBe(receipt)
    expect(mockExecFile).not.toHaveBeenCalled()

    expect(await env.rollback()).toBe(true)
    expect(queriedKeys()).toEqual([...proxyKeys])
    expect(mutations()).toEqual([])
    expect(mockRegistry).toEqual(values)
    expect(await env.isApplied()).toBe(false)
  })

  it.each(['status', 'apply', 'failed first setx', 'failed first setx with existing backup', 'rollback'])(
    'does not forget a vanished receipt after %s and a process restart, including repeated retries', async (source) => {
      seedRegistry(originalValues)
      if (source !== 'apply' && source !== 'failed first setx') saveBackup(originalValues)
      if (source === 'status') expect(await env.isApplied()).toBe(true)
      else if (source === 'rollback') {
        mockExecFile.mockImplementation((cmd: string, args: string[]) => (
          cmd === 'reg' && args[0] === 'query' && args[3] === 'HTTP_PROXY'
            ? new Error('Access denied') : registryCommand(cmd, args)
        ))
        expect(await env.rollback()).toBe(false)
      } else {
        if (source.startsWith('failed first setx')) {
          mockExecFile.mockImplementation((cmd: string, args: string[]) => (
            cmd === 'setx' ? new Error('Access denied') : registryCommand(cmd, args)
          ))
        }
        expect(await env.apply('127.0.0.1:10808')).toBe(source === 'apply')
      }
      expect(mockFs[backupFile]).toBeDefined()
      delete mockFs[backupFile]
      vi.resetModules()
      env = (await import('./env')).env
      const values = { ...mockRegistry }
      mockExecFile.mockClear()
      vi.mocked(writeFile).mockClear()
      vi.mocked(unlink).mockClear()

      for (let retry = 0; retry < 2; retry++) {
        await expect(env.isApplied()).rejects.toMatchObject({ code: 'ENOENT' })
        expect(await env.rollback()).toBe(false)
        expect(await env.apply('127.0.0.1:10809')).toBe(false)
      }
      expect(mockRegistry).toEqual(values)
      expect(mockExecFile).not.toHaveBeenCalled()
      expect(writeFile).not.toHaveBeenCalled()
      expect(unlink).not.toHaveBeenCalled()
    }
  )

  it.each(['EACCES', 'EIO'])('does not change proxies when persisting the cleanup marker fails: %s (AT-11-002)', async code => {
    seedRegistry(originalValues)
    const write = vi.mocked(writeFile).getMockImplementation()!
    vi.mocked(writeFile).mockImplementation(async (...args: any[]) => {
      if (args[0] === pendingFile) throw fileError(code)
      return write(...args as Parameters<typeof writeFile>)
    })
    expect(await env.apply('127.0.0.1:10808')).toBe(false)
    expect(mutations()).toEqual([])
    expect(mockRegistry).toEqual(originalValues)
    expect(mockFs[backupFile]).toBeDefined()
    await expect(env.isApplied()).rejects.toMatchObject({ code })
  })

  it.each(['EACCES', 'EPERM', 'EIO'])('treats an unreadable marker as unknown, preserving foreign settings: %s', async code => {
    seedRegistry(originalValues)
    vi.mocked(lstat).mockRejectedValue(fileError(code))
    await expect(env.isApplied()).rejects.toMatchObject({ code })
    expect(await env.apply('127.0.0.1:10808')).toBe(false)
    expect(await env.rollback()).toBe(false)
    expect(mutations()).toEqual([])
    expect(mockRegistry).toEqual(originalValues)
    expect(writeFile).not.toHaveBeenCalled()
  })

  it.each(proxyKeys)('retains cleanup after partial %s restoration, receipt loss and restart (AT-03-007)', async key => {
    seedRegistry(originalValues)
    expect(await env.apply('127.0.0.1:10808')).toBe(true)
    mockExecFile.mockImplementation((cmd: string, args: string[]) => (
      cmd === 'reg' && args[0] === 'query' && args[3] === key
        ? new Error('Readback denied') : registryCommand(cmd, args)
    ))
    expect(await env.rollback()).toBe(false)
    expect(mockRegistry[key]).toBe(vpnValues[key])
    expect(mockFs[pendingFile]).toBeDefined()
    delete mockFs[backupFile]
    vi.resetModules()
    env = (await import('./env')).env
    mockExecFile.mockClear()
    await expect(env.isApplied()).rejects.toMatchObject({ code: 'ENOENT' })
    expect(await env.apply('127.0.0.1:10809')).toBe(false)
    expect(await env.rollback()).toBe(false)
    expect(mockExecFile).not.toHaveBeenCalled()
  })

  it('keeps an empty marker pending after receipt loss and restart', async () => {
    seedRegistry(originalValues)
    expect(await env.apply('127.0.0.1:10808')).toBe(true)
    mockFs[pendingFile] = ''
    delete mockFs[backupFile]
    vi.resetModules()
    env = (await import('./env')).env
    await expect(env.isApplied()).rejects.toMatchObject({ code: 'ENOENT' })
    expect(mockRegistry).toEqual(vpnValues)
  })

  it('retains pending cleanup across restart when marker retirement fails after verified restoration', async () => {
    seedRegistry(originalValues)
    expect(await env.apply('127.0.0.1:10808')).toBe(true)
    const remove = vi.mocked(unlink).getMockImplementation()!
    vi.mocked(unlink).mockImplementation(async path => {
      if (path === pendingFile) throw fileError('EACCES')
      return remove(path)
    })
    expect(await env.rollback()).toBe(false)
    expect(mockRegistry).toEqual(originalValues)
    expect(mockFs[pendingFile]).toBeDefined()
    vi.resetModules()
    env = (await import('./env')).env
    await expect(env.isApplied()).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it.each(['EACCES', 'EPERM', 'EIO'])('fails closed on backup read error %s without registry access', async (code) => {
    const receipt = saveBackup(originalValues)
    seedRegistry(originalValues)
    const error = fileError(code)
    vi.mocked(readFile).mockRejectedValue(error)
    await expect(env.isApplied()).rejects.toBe(error)
    expect(await env.apply('127.0.0.1:10808')).toBe(false)
    expect(await env.rollback()).toBe(false)
    expect(mockFs[backupFile]).toBe(receipt)
    expect(mockRegistry).toEqual(originalValues)
    expect(mockExecFile).not.toHaveBeenCalled()
    expect(writeFile).not.toHaveBeenCalled()
    expect(unlink).not.toHaveBeenCalled()
  })

  it.each(['not json', '{}', '{"httpProxy":null,"httpsProxy":null,"allProxy":null}',
    '{"httpProxy":null,"httpsProxy":null,"allProxy":42,"noProxy":null}'])(
    'rejects malformed/partial backup without changing foreign values: %s', async (receipt) => {
      mockFs[backupFile] = receipt
      seedRegistry(originalValues)
      await expect(env.isApplied()).rejects.toThrow()
      expect(await env.apply('127.0.0.1:10808')).toBe(false)
      expect(await env.rollback()).toBe(false)
      expect(mockFs[backupFile]).toBe(receipt)
      expect(mockRegistry).toEqual(originalValues)
      expect(mockExecFile).not.toHaveBeenCalled()
      expect(writeFile).not.toHaveBeenCalled()
      expect(unlink).not.toHaveBeenCalled()
    }
  )

  it.each(['mkdir', 'writeFile'] as const)('does not mutate foreign proxies if backup %s fails', async (operation) => {
    seedRegistry(originalValues)
    if (operation === 'mkdir') vi.mocked(mkdir).mockRejectedValueOnce(fileError('EACCES'))
    else vi.mocked(writeFile).mockRejectedValueOnce(fileError('EACCES'))
    expect(await env.apply('127.0.0.1:10808')).toBe(false)
    expect(mutations()).toEqual([])
    expect(mockRegistry).toEqual(originalValues)
    expect(mockFs[backupFile]).toBeUndefined()
    expect(unlink).not.toHaveBeenCalled()
    expect(await env.isApplied()).toBe(false)
  })

  it('compensates a midway apply failure with verified rollback', async () => {
    seedRegistry(originalValues)
    mockExecFile.mockImplementation((cmd: string, args: string[]) => (
      cmd === 'setx' && args[0] === 'ALL_PROXY' && args[1] === vpnValues.ALL_PROXY
        ? new Error('setx failed') : registryCommand(cmd, args)
    ))
    expect(await env.apply('127.0.0.1:10808')).toBe(false)
    expect(mockRegistry).toEqual(originalValues)
    for (const key of proxyKeys) expect(process.env[key]).toBe(originalValues[key])
    expect(mockFs[backupFile]).toBeUndefined()
    expect(await env.isApplied()).toBe(false)
  })

  describe.each(['set', 'delete'] as const)('verified %s rollback', (operation) => {
    it.each(proxyKeys.flatMap(key => ['command error', 'readback mismatch', 'readback error'].map(failure => ({ key, failure })) ))(
      'preserves and retries $key after $failure while restoring independent entries', async ({ key, failure }) => {
        const originals: ProxyValues = operation === 'set' ? originalValues : {}
        const receipt = saveBackup(originals)
        seedRegistry(vpnValues)
        let attemptedMutation = false
        mockExecFile.mockImplementation((cmd: string, args: string[]) => {
          if (cmd === 'reg' && args[0] === 'query' && args[3] === key && attemptedMutation && failure === 'readback error') {
            return new Error('Readback denied')
          }
          if ((cmd === 'setx' && args[0] === key) || (cmd === 'reg' && args[0] === 'delete' && args[3] === key)) {
            attemptedMutation = true
            if (failure === 'command error') return new Error('Restore denied')
            if (failure === 'readback mismatch') return { stdout: '', stderr: '' }
          }
          return registryCommand(cmd, args)
        })

        expect(await env.rollback()).toBe(false)
        expect(queriedKeys()).toEqual(expect.arrayContaining([...proxyKeys]))
        expect(mockFs[backupFile]).toBe(receipt)
        expect(unlink).not.toHaveBeenCalled()
        expect(await env.isApplied()).toBe(true)
        expect(mockRegistry[key]).toBe(failure === 'readback error' ? originals[key] : vpnValues[key])
        expect(process.env[key]).toBe(vpnValues[key])
        for (const other of proxyKeys.filter(other => other !== key)) {
          expect(mockRegistry[other]).toBe(originals[other])
          expect(process.env[other]).toBe(originals[other])
        }

        mockExecFile.mockClear()
        mockExecFile.mockImplementation(registryCommand)
        expect(await env.rollback()).toBe(true)
        expect(queriedKeys()).toEqual(expect.arrayContaining([...proxyKeys]))
        expect(mutations()).toEqual(failure === 'readback error' ? [] : [operation === 'set'
          ? ['setx', [key, originals[key]]]
          : ['reg', ['delete', 'HKCU\\Environment', '/v', key, '/f']]])
        expect(mockRegistry).toEqual(originals)
        for (const name of proxyKeys) expect(process.env[name]).toBe(originals[name])
        expect(mockFs[backupFile]).toBeUndefined()
        expect(unlink).toHaveBeenCalledWith(backupFile)
        expect(await env.isApplied()).toBe(false)
      }
    )
  })

  it.each(proxyKeys)('does not mutate %s on an unknown current read; restores the other three and retries', async (key) => {
    const receipt = saveBackup()
    seedRegistry(vpnValues)
    mockExecFile.mockImplementation((cmd: string, args: string[]) => (
      cmd === 'reg' && args[0] === 'query' && args[3] === key
        ? new Error('Access denied') : registryCommand(cmd, args)
    ))
    expect(await env.rollback()).toBe(false)
    expect(mockRegistry).toEqual({ [key]: vpnValues[key] })
    expect(process.env[key]).toBe(vpnValues[key])
    expect(mutations()).toHaveLength(3)
    expect(mutations().some(([, args]) => args.includes(key))).toBe(false)
    expect(mockFs[backupFile]).toBe(receipt)
    expect(await env.isApplied()).toBe(true)
    expect(unlink).not.toHaveBeenCalled()

    mockExecFile.mockClear()
    mockExecFile.mockImplementation(registryCommand)
    expect(await env.rollback()).toBe(true)
    expect(mutations()).toEqual([['reg', ['delete', 'HKCU\\Environment', '/v', key, '/f']]])
    expect(mockRegistry).toEqual({})
    expect(await env.isApplied()).toBe(false)
  })

  it.each(['denied', 'vanished'])('retains the obligation when receipt unlink is %s', async (failure) => {
    const receipt = saveBackup(originalValues)
    seedRegistry(vpnValues)
    vi.mocked(unlink).mockImplementationOnce(async () => {
      if (failure === 'vanished') delete mockFs[backupFile]
      throw fileError(failure === 'denied' ? 'EACCES' : 'ENOENT')
    })
    expect(await env.rollback()).toBe(false)
    expect(mockRegistry).toEqual(originalValues)
    if (failure === 'denied') {
      expect(mockFs[backupFile]).toBe(receipt)
      expect(await env.isApplied()).toBe(true)
    } else {
      for (let retry = 0; retry < 2; retry++) await expect(env.isApplied()).rejects.toMatchObject({ code: 'ENOENT' })
      expect(await env.rollback()).toBe(false)
      mockFs[backupFile] = receipt
    }
    mockExecFile.mockClear()
    expect(await env.rollback()).toBe(true)
    expect(queriedKeys()).toEqual([...proxyKeys])
    expect(mutations()).toEqual([])
    expect(mockFs[backupFile]).toBeUndefined()
    expect(await env.isApplied()).toBe(false)
  })

  describe('strict registry parsing through backup and rollback', () => {
    it.each([
      { name: 'HTTP_PROXY', type: 'REG_SZ', value: 'http://corporate:8080' },
      { name: 'HTTP_PROXY', type: 'REG_EXPAND_SZ', value: 'http://%PROXY_HOST%:8080' },
      { name: 'http_proxy', type: 'REG_SZ', value: 'http://corporate:8080' },
      { name: 'HTTP_PROXY', type: 'REG_SZ', value: '' }
    ])('backs up and verifies $name $type "$value"', async ({ name, type, value }) => {
      seedRegistry({ HTTP_PROXY: value })
      mockExecFile.mockImplementation((cmd: string, args: string[]) => (
        cmd === 'reg' && args[0] === 'query' && args[3] === 'HTTP_PROXY' && mockRegistry.HTTP_PROXY !== undefined
          ? { stdout: `HKEY_CURRENT_USER\\Environment\r\n    ${name}    ${type}    ${mockRegistry.HTTP_PROXY}\r\n`, stderr: '' }
          : registryCommand(cmd, args)
      ))
      expect(await env.apply('127.0.0.1:10808')).toBe(true)
      expect(JSON.parse(mockFs[backupFile]).httpProxy).toBe(value)
      expect(await env.rollback()).toBe(true)
      expect(mockRegistry).toEqual({ HTTP_PROXY: value })
      expect(process.env.HTTP_PROXY).toBe(value)
      expect(await env.isApplied()).toBe(false)
    })

    it.each([
      'The system was unable to find the specified registry key or value.',
      'Не удается найти указанный раздел или параметр реестра.',
      'Не удалось найти указанный раздел или параметр реестра.'
    ])('accepts only confirmed missing registry values during backup and deletion readback: %s', async (message) => {
      mockExecFile.mockImplementation((cmd: string, args: string[]) => (
        cmd === 'reg' && args[0] === 'query' && mockRegistry[args[3]] === undefined
          ? missingRegistryValue(message) : registryCommand(cmd, args)
      ))
      expect(await env.apply('127.0.0.1:10808')).toBe(true)
      const saved = JSON.parse(mockFs[backupFile])
      for (const field of ['httpProxy', 'httpsProxy', 'allProxy', 'noProxy']) expect(saved[field]).toBeNull()
      expect(await env.rollback()).toBe(true)
      expect(mockRegistry).toEqual({})
      expect(await env.isApplied()).toBe(false)
    })

    it.each([
      { label: 'access denied', result: Object.assign(new Error('Access denied'), { code: 1, stderr: 'ERROR: Access is denied.' }) },
      { label: 'timeout', result: Object.assign(new Error('reg query timed out'), { code: 'ETIMEDOUT', killed: true, signal: 'SIGTERM' }) },
      { label: 'killed missing-value response', result: Object.assign(missingRegistryValue(), { killed: true, signal: 'SIGTERM' }) },
      { label: 'missing executable', result: Object.assign(missingRegistryValue(), { code: 'ENOENT' }) },
      ...['', 'HKEY_CURRENT_USER\\Environment\r\n',
        '    HTTP_PROXY_OTHER    REG_SZ    http://corporate:8080',
        '    HTTP_PROXY    REG_DWORD    0x1',
        '    HTTP_PROXY    unexpected output'].map(stdout => ({ label: `unparseable output ${JSON.stringify(stdout)}`, result: { stdout, stderr: '' } }))
    ])('fails closed on $label without overwriting the unknown value', async ({ result }) => {
      seedRegistry(originalValues)
      mockExecFile.mockImplementation((cmd: string, args: string[]) => (
        cmd === 'reg' && args[0] === 'query' && args[3] === 'HTTP_PROXY'
          ? result : registryCommand(cmd, args)
      ))
      expect(await env.apply('127.0.0.1:10808')).toBe(false)
      expect(mockFs[backupFile]).toBeUndefined()
      expect(mutations()).toEqual([])
      expect(writeFile).not.toHaveBeenCalled()

      const receipt = saveBackup(originalValues)
      expect(await env.rollback()).toBe(false)
      expect(mockRegistry).toEqual(originalValues)
      expect(process.env.HTTP_PROXY).toBe(originalValues.HTTP_PROXY)
      expect(mutations()).toEqual([])
      expect(mockFs[backupFile]).toBe(receipt)
      expect(unlink).not.toHaveBeenCalled()
      expect(await env.isApplied()).toBe(true)
    })

    it.each(proxyKeys)('aborts apply before any mutation when original %s is unparseable', async (key) => {
      seedRegistry(originalValues)
      mockExecFile.mockImplementation((cmd: string, args: string[]) => (
        cmd === 'reg' && args[0] === 'query' && args[3] === key
          ? { stdout: '', stderr: '' } : registryCommand(cmd, args)
      ))
      expect(await env.apply('127.0.0.1:10808')).toBe(false)
      expect(mockRegistry).toEqual(originalValues)
      expect(mutations()).toEqual([])
      expect(mockFs[backupFile]).toBeUndefined()
      expect(writeFile).not.toHaveBeenCalled()
      expect(unlink).not.toHaveBeenCalled()
    })
  })
})
