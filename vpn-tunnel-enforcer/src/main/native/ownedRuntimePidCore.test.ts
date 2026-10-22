// AT-00-002 / AT-02-002/009: Win32 enumeration, exact ownership, incomplete reads and handle lifetime.
import { win32 } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { readOwnedRuntimePidInProcess, readOwnedRuntimeStateInProcess, type ProcessReadApi } from './ownedRuntimePidCore'

const executable = 'C:\\VPNTE\\runtime\\vpnte-sing-box.exe'
type Row = { pid: number; path: string | null; name?: string }
function fixture(rows: Row[], endError = 18) {
  let index = 0
  const closed: Array<number | bigint> = []
  const write = (entry: Buffer) => {
    const row = rows[index]
    if (!row) return false
    entry.fill(0); entry.writeUInt32LE(568); entry.writeUInt32LE(row.pid, 8)
    entry.write(row.name ?? 'vpnte-sing-box.exe', 44, 'utf16le')
    return true
  }
  const api = {
    snapshot: vi.fn(() => 42n),
    first: vi.fn((_handle, entry: Buffer) => { index = 0; return write(entry) }),
    next: vi.fn((_handle, entry: Buffer) => { index++; return write(entry) }),
    open: vi.fn((_access, _inherit, pid: number) => 10000 + pid),
    image: vi.fn((handle, _flags, buffer: Buffer, length: number[]) => {
      const path = rows.find(row => row.pid === Number(handle) - 10000)?.path
      if (path == null) return false
      buffer.write(path, 'utf16le'); length[0] = path.length; return true
    }),
    compare: vi.fn((a: string, _alen, b: string): number => a.toUpperCase() === b.toUpperCase() ? 2 : 1),
    close: vi.fn(handle => { closed.push(handle); return true }),
    error: vi.fn(() => endError)
  } satisfies ProcessReadApi
  return { api, closed, read: () => readOwnedRuntimePidInProcess(executable, api),
    state: () => readOwnedRuntimeStateInProcess(win32.dirname(executable), api) }
}

describe('native fresh runtime presence (AT-02-001/005, AT-03-007/012)', () => {
  it('proves absence only after a complete empty enumeration and closes its snapshot', () => {
    const f = fixture([])
    expect(f.state()).toBe(false)
    expect(f.api.error).toHaveBeenCalledOnce()
    expect(f.closed).toEqual([42n])
  })
  it.each(['vpnte-sing-box.exe', 'vpnte-etw-sidecar.exe', 'vpnte-xray.exe'])('observes %s by ordinal-insensitive path within the strict runtime directory', name => {
    const f = fixture([{ pid: 731, name: name.toUpperCase(), path: `c:\\vpnte\\RUNTIME\\subdir\\${name}` }])
    expect(f.state()).toBe(true)
    expect(f.closed).toEqual([10731, 42n])
  })
  it('does not confuse siblings, lookalike prefixes or unrelated image names with ownership', () => {
    const f = fixture([{ pid: 731, path: 'C:\\VPNTE\\runtime-evil\\vpnte-sing-box.exe' },
      { pid: 732, path: 'C:\\Foreign\\vpnte-sing-box.exe' },
      { pid: 733, path: null, name: 'arbitrary.exe' }])
    expect(f.state()).toBe(false)
    expect(f.api.next).toHaveBeenCalledTimes(3)
    expect(f.closed).toEqual([10731, 10732, 42n])
  })
  it('does not cache absence or require a singular PID for a presence observation', () => {
    const rows: Row[] = [], f = fixture(rows)
    expect(f.state()).toBe(false)
    rows.push({ pid: 731, path: executable }, { pid: 732, path: executable })
    expect(f.state()).toBe(true)
    expect(f.read).toThrow(/exactly one owned process/)
    rows.length = 0
    expect(f.state()).toBe(false)
    expect(f.api.snapshot).toHaveBeenCalledTimes(4)
  })
  it.each([false, true])('rejects incomplete enumeration after observed presence=%s', present => {
    const f = fixture(present ? [{ pid: 731, path: executable }] : [], 5)
    expect(f.state).toThrow(/incomplete process enumeration/)
    expect(f.closed.at(-1)).toBe(42n)
  })
  it('keeps unreadable candidate paths unknown even after seeing an owned process', () => {
    const f = fixture([{ pid: 731, path: executable }, { pid: 732, name: 'vpnte-xray.exe', path: null }])
    expect(f.state).toThrow(/executable path unavailable/)
    expect(f.api.snapshot).toHaveBeenCalledTimes(2)
    expect(f.closed).toEqual([10731, 10732, 42n, 10731, 10732, 42n])
  })
  it.each(['open', 'image'] as const)('uses a fresh complete observation after a candidate disappears during %s', failure => {
    for (const after of [[], [{ pid: 732, path: executable }], [{ pid: 732, path: 'C:\\Foreign\\vpnte-sing-box.exe' }]]) {
      const rows: Row[] = [{ pid: 731, path: null }], f = fixture(rows)
      if (failure === 'open') f.api.open.mockReturnValueOnce(0)
      f.api.snapshot.mockImplementation(() => {
        if (f.api.snapshot.mock.calls.length === 2) {
          expect(f.closed).toEqual(failure === 'open' ? [42n] : [10731, 42n])
          rows.splice(0, rows.length, ...after)
          return 43n
        }
        return 42n
      })
      expect(f.state()).toBe(after[0]?.path === executable)
      expect(f.api.snapshot).toHaveBeenCalledTimes(2)
      expect(f.api.first.mock.calls.map(call => call[0])).toEqual([42n, 43n])
      expect(f.api.error).toHaveBeenCalledTimes(2) // failed path read, then complete fresh enumeration
      expect(f.closed.at(-1)).toBe(43n)
    }
  })
  it('keeps a fresh rescan incomplete even if its readable owned process was observed', () => {
    const rows: Row[] = [{ pid: 731, path: null }], f = fixture(rows, 5)
    f.api.snapshot.mockImplementation(() => {
      if (f.api.snapshot.mock.calls.length === 2) rows.splice(0, 1, { pid: 732, path: executable })
      return 42n
    })
    expect(f.state).toThrow(/incomplete process enumeration/)
    expect(f.api.snapshot).toHaveBeenCalledTimes(2)
    expect(f.closed).toEqual([10731, 42n, 10732, 42n])
  })
  it('does not retry a failed handle closure after an unreadable candidate', () => {
    const f = fixture([{ pid: 731, path: null }]); f.api.close.mockReturnValue(false)
    expect(f.state).toThrow(/handle close failed/)
    expect(f.api.snapshot).toHaveBeenCalledOnce()
  })
  it('does not retry malformed image evidence or arbitrary reader exceptions', () => {
    for (const failure of ['length', 'exception']) {
      const f = fixture([{ pid: 731, path: executable }])
      f.api.image.mockImplementation((_handle, _flags, _buffer, length) => {
        if (failure === 'exception') throw new Error('runtime PID: executable path unavailable')
        length[0] = 0; return true
      })
      expect(f.state).toThrow(/executable path unavailable/)
      expect(f.api.snapshot).toHaveBeenCalledOnce()
    }
  })
  it('keeps startup PID proof strict when the candidate path disappears', () => {
    const f = fixture([{ pid: 731, path: null }])
    expect(f.read).toThrow(/executable path unavailable/)
    expect(f.api.snapshot).toHaveBeenCalledOnce()
  })
  it('refuses duplicate/zero process identities and failed handle closure as exit evidence', () => {
    for (const rows of [[{ pid: 0, path: executable }], [{ pid: 731, path: executable }, { pid: 731, path: executable }]]) {
      const f = fixture(rows)
      expect(f.state).toThrow(/process identity/)
      expect(f.closed.at(-1)).toBe(42n)
    }
    const f = fixture([]); f.api.close.mockReturnValue(false)
    expect(f.state).toThrow(/handle close failed/)
  })
  it.each(['', 'relative', '\\\\server\\share', 'C:/runtime', 'C:\\..\\runtime', 'C:\\.\\runtime',
    'C:\\runtime:stream', 'C:\\runtime\n', 'C:\\"runtime', 'C:\\' + 'x'.repeat(2048)])('rejects an unsafe runtime directory before reading processes: %j', path => {
    const f = fixture([])
    expect(() => readOwnedRuntimeStateInProcess(path, f.api)).toThrow(/invalid runtime directory/)
    expect(f.api.snapshot).not.toHaveBeenCalled()
  })
})

describe('native owned runtime PID (AT-00-002, AT-02-002/009)', () => {
  it.each(['open', 'image'] as const)('captures the %s Win32 failure before handle cleanup overwrites it (AT-00-005)', failure => {
    const f = fixture([{ pid: 731, path: executable }])
    let lastError = failure === 'open' ? 5 : 31
    if (failure === 'open') f.api.open.mockReturnValue(0)
    else f.api.image.mockReturnValue(false)
    f.api.error.mockImplementation(() => lastError)
    f.api.close.mockImplementation(handle => { f.closed.push(handle); lastError = 6; return true })
    expect(f.read).toThrow(`runtime PID: executable path unavailable (${failure === 'open' ? 'OpenProcess' : 'QueryFullProcessImageNameW'}; win32=${failure === 'open' ? 5 : 31})`)
    expect(f.api.error).toHaveBeenCalledOnce()
    expect(f.closed).toEqual(failure === 'open' ? [42n] : [10731, 42n])
  })
  it('reports the fresh scan failure while preserving the bounded retry (AT-00-005)', () => {
    const f = fixture([{ pid: 731, path: executable }])
    f.api.open.mockReturnValue(0)
    f.api.error.mockReturnValueOnce(87).mockReturnValueOnce(5)
    expect(f.state).toThrow('runtime PID: executable path unavailable (OpenProcess; win32=5)')
    expect(f.api.error).toHaveBeenCalledTimes(2)
    expect(f.api.snapshot).toHaveBeenCalledTimes(2)
    expect(f.closed).toEqual([42n, 42n])
  })
  it('finishes enumeration and distinguishes exact case-insensitive paths from siblings/prefix collisions', () => {
    const f = fixture([{ pid: 731, path: executable.toLowerCase() },
      { pid: 732, path: 'C:\\Foreign\\vpnte-sing-box.exe' },
      { pid: 733, path: 'C:\\VPNTE\\runtime-evil\\vpnte-sing-box.exe' },
      { pid: 734, path: null, name: 'foreign.exe' }])
    expect(f.read()).toBe(731)
    expect(f.api.next).toHaveBeenCalledTimes(4)
    expect(f.api.open.mock.calls).toEqual([[0x1000, false, 731], [0x1000, false, 732], [0x1000, false, 733]])
    expect(f.closed).toEqual([10731, 10732, 10733, 42n])
  })
  it.each([
    [], [{ pid: 731, path: 'C:\\Foreign\\vpnte-sing-box.exe' }],
    [{ pid: 731, path: executable }, { pid: 732, path: executable }],
    [{ pid: 731, path: executable }, { pid: 732, path: null }]
  ])('never returns an owned PID from missing, ambiguous or unreadable evidence: %j', (...rows) => {
    // it.each treats each row array as arguments; rebuild the process list.
    const f = fixture(rows as Row[])
    expect(f.read).toThrow()
    expect(f.closed.at(-1)).toBe(42n)
  })
  it('rejects an incomplete enumeration even after seeing one correct process', () => {
    const f = fixture([{ pid: 731, path: executable }], 5)
    expect(f.read).toThrow(/incomplete process enumeration/)
    expect(f.closed).toEqual([10731, 42n])
  })
  it('refuses a duplicate process identity without opening it a second time', () => {
    const f = fixture([{ pid: 731, path: executable }, { pid: 731, path: executable }])
    expect(f.read).toThrow(/duplicate process identity/)
    expect(f.api.open).toHaveBeenCalledOnce()
    expect(f.closed).toEqual([10731, 42n])
  })
  it.each([0, -1, 32768, 1.5])('rejects invalid image length %s and closes both handles', length => {
    const f = fixture([{ pid: 731, path: executable }])
    f.api.image.mockImplementation((_handle, _flags, _path, size) => { size[0] = length; return true })
    expect(f.read).toThrow(/executable path unavailable/)
    expect(f.closed).toEqual([10731, 42n])
  })
  it('refuses a failed OpenProcess without closing a null process handle', () => {
    const f = fixture([{ pid: 731, path: executable }]); f.api.open.mockReturnValue(0)
    expect(f.read).toThrow(/executable path unavailable/)
    expect(f.closed).toEqual([42n])
  })
  it('rejects malformed process layouts/names and failed ordinal comparison', () => {
    for (const kind of ['layout', 'name', 'compare']) {
      const f = fixture([{ pid: 731, path: executable }])
      if (kind === 'compare') f.api.compare.mockReturnValue(0)
      else f.api.first.mockImplementation((_handle, entry) => {
        entry.writeUInt32LE(kind === 'layout' ? 0 : 568)
        if (kind === 'name') entry.fill(0x41, 44)
        return true
      })
      expect(f.read).toThrow()
      expect(f.closed).toEqual([42n])
    }
  })
  it('does not claim success if a handle close fails; still closes the outer snapshot', () => {
    const f = fixture([{ pid: 731, path: executable }])
    f.api.close.mockImplementation(handle => { f.closed.push(handle); return handle === 42n })
    expect(f.read).toThrow(/handle close failed/)
    expect(f.closed).toEqual([10731, 42n])
  })
  it('rejects invalid snapshot handles without calling Process32First or CloseHandle', () => {
    const f = fixture([]); f.api.snapshot.mockReturnValue(-1n)
    expect(f.read).toThrow(/snapshot unavailable/)
    expect(f.api.first).not.toHaveBeenCalled()
    expect(f.closed).toEqual([])
  })
  it.each(['', 'relative.exe', 'C:\\runtime\\core.dll', 'C:\\bad\0name.exe', 'C:\\' + 'x'.repeat(32768) + '.exe'])('rejects malformed expected paths before native calls', path => {
    const f = fixture([])
    expect(() => readOwnedRuntimePidInProcess(path, f.api)).toThrow(/invalid executable path/)
    expect(f.api.snapshot).not.toHaveBeenCalled()
  })
  it('refuses FFI in the Electron main process even with a valid executable', () => {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'type')
    Object.defineProperty(process, 'type', { configurable: true, value: 'browser' })
    try {
      expect(() => readOwnedRuntimePidInProcess(win32.resolve(executable))).toThrow(/must not run in the Electron main/)
      expect(() => readOwnedRuntimeStateInProcess(win32.dirname(executable))).toThrow(/must not run in the Electron main/)
    }
    finally {
      if (descriptor) Object.defineProperty(process, 'type', descriptor)
      else Reflect.deleteProperty(process, 'type')
    }
  })
})
