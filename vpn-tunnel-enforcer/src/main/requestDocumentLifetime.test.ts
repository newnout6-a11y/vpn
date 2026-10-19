// AT-00-003/005: main-only document ownership, no renderer-controlled signals.
import { EventEmitter } from 'node:events'
import type { WebContents } from 'electron'
import { describe, expect, it } from 'vitest'
import { requestDocumentLifetime } from './requestDocumentLifetime'

function sender(destroyed = false) {
  return Object.assign(new EventEmitter(), { isDestroyed: () => destroyed }) as EventEmitter & WebContents
}

describe('requesting document lifetime', () => {
  it.each(['destroyed', 'render-process-gone', 'did-start-navigation'])('aborts only its requester on %s and disposes listeners', event => {
    const first = sender(), second = sender()
    const own = requestDocumentLifetime(first), other = requestDocumentLifetime(second)
    first.emit(event, { isMainFrame: true, isSameDocument: false })
    expect(own.signal.aborted).toBe(true)
    expect(other.signal.aborted).toBe(false)
    own.dispose(); own.dispose(); other.dispose()
    expect(first.eventNames()).toEqual([]); expect(second.eventNames()).toEqual([])
  })

  it.each([{ isMainFrame: false, isSameDocument: false }, { isMainFrame: true, isSameDocument: true }])
  ('retains the document for navigation $isMainFrame / $isSameDocument', details => {
    const owner = sender(), lifetime = requestDocumentLifetime(owner)
    owner.emit('did-start-navigation', details)
    expect(lifetime.signal.aborted).toBe(false)
    lifetime.dispose()
    owner.emit('destroyed')
    expect(lifetime.signal.aborted).toBe(false)
    expect(owner.eventNames()).toEqual([])
  })

  it('combines internal cancellation without aborting the caller signal on navigation', () => {
    const owner = sender(), controller = new AbortController()
    const lifetime = requestDocumentLifetime(owner, controller.signal)
    owner.emit('render-process-gone')
    expect(lifetime.signal.aborted).toBe(true); expect(controller.signal.aborted).toBe(false)
    lifetime.dispose()
    const next = requestDocumentLifetime(owner, controller.signal)
    controller.abort()
    expect(next.signal.aborted).toBe(true)
    next.dispose(); expect(owner.eventNames()).toEqual([])
  })

  it('refuses an unavailable requester or already-cancelled action before registering listeners', () => {
    const destroyed = sender(true), active = sender(), controller = new AbortController()
    controller.abort()
    expect(() => requestDocumentLifetime(destroyed)).toThrow(expect.objectContaining({ category: 'cancelled' }))
    expect(() => requestDocumentLifetime(active, controller.signal)).toThrow(expect.objectContaining({ category: 'cancelled' }))
    expect(destroyed.eventNames()).toEqual([]); expect(active.eventNames()).toEqual([])
  })

  it('preserves main-only work without an IPC sender', () => {
    const controller = new AbortController(), lifetime = requestDocumentLifetime(undefined, controller.signal)
    expect(lifetime.signal.aborted).toBe(false)
    controller.abort(); expect(lifetime.signal.aborted).toBe(true)
    lifetime.dispose()
  })
})
