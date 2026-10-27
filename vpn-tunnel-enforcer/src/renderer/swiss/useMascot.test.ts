// «Пломбик» state machine: phase reactions, idle sleep, nags, slow link, petting.
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))

import { useMascot, type MascotInput } from './useMascot'

const input = (over: Partial<MascotInput> = {}): MascotInput => ({ phase: 'on', startedAt: null, downMbps: 0, ...over })
const mount = (first: MascotInput) => renderHook((p: MascotInput) => useMascot(p), { initialProps: first })
const advance = (ms: number) => act(() => { vi.advanceTimersByTime(ms) })

beforeEach(() => {
  vi.useFakeTimers()
  // Deterministic line picks; pushes the 25–45 s wander timer to its far end (~45 s)
  vi.spyOn(Math, 'random').mockReturnValue(0.99)
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('useMascot', () => {
  it('announces the build, then celebrates when the tunnel comes up', () => {
    const view = mount(input({ phase: 'off' }))
    view.rerender(input({ phase: 'connecting' }))
    expect(view.result.current.view.speech?.text).toBe('mascot.building')
    expect(view.result.current.view.mood).toBe('scan')
    view.rerender(input({ phase: 'on' }))
    expect(view.result.current.view.speech?.text).toMatch(/^mascot\.connected[0-2]$/)
    expect(view.result.current.view.mood).toBe('happy')
    expect(view.result.current.view.fx).toBe('confetti')
  })

  it('warns in the alert phase but never sends the user to the power button', () => {
    const view = mount(input({ phase: 'on' }))
    view.rerender(input({ phase: 'alert' }))
    expect(view.result.current.view.speech?.text).toBe('mascot.alert')
    advance(25000)
    expect(view.result.current.perch).toBe('home')
    expect(view.result.current.view.speech?.text).not.toBe('mascot.exposedNag')
  })

  it('when genuinely exposed, hops onto the power button after 20 s', () => {
    const view = mount(input({ phase: 'on' }))
    view.rerender(input({ phase: 'off' }))
    expect(view.result.current.view.speech?.text).toBe('mascot.exposed')
    advance(20000)
    expect(view.result.current.perch).toBe('toggle')
    expect(view.result.current.view.speech?.text).toBe('mascot.exposedNag')
  })

  it('falls asleep after 30 s without input and startles awake', () => {
    const view = mount(input({ phase: 'connecting' }))
    advance(30000)
    expect(view.result.current.view.mood).toBe('sleep')
    expect(view.result.current.view.fx).toBe('zzz')
    act(() => { window.dispatchEvent(new MouseEvent('mousemove')) })
    expect(view.result.current.view.mood).toBe('scared')
    expect(view.result.current.view.speech?.text).toMatch(/^mascot\.startle[0-2]$/)
  })

  it('comments on a link that stays in the slow band for 30 s', () => {
    const view = mount(input({ phase: 'on', downMbps: 1.5 }))
    advance(29000)
    expect(view.result.current.view.speech?.text).not.toBe('mascot.slow')
    advance(1000)
    expect(view.result.current.view.speech?.text).toBe('mascot.slow')
  })

  it('stays quiet about speed while idle (0 = nothing to say)', () => {
    const view = mount(input({ phase: 'on', downMbps: 0 }))
    advance(31000)
    expect(view.result.current.view.speech?.text).not.toBe('mascot.slow')
  })

  it('purrs while petted and asks to stop after 6 s of strokes', () => {
    const view = mount(input({ phase: 'on' }))
    act(() => view.result.current.pet())
    expect(view.result.current.view.mood).toBe('petted')
    expect(view.result.current.view.fx).toBe('hearts')
    expect(view.result.current.view.speech?.text).toMatch(/^mascot\.pet[0-3]$/)
    for (let i = 0; i < 13; i++) {
      act(() => {
        vi.advanceTimersByTime(500)
        view.result.current.pet()
      })
    }
    expect(view.result.current.view.speech?.text).toBe('mascot.petEnough')
    expect(view.result.current.view.mood).toBe('squint')
  })

  it('stops looking petted shortly after the strokes stop', () => {
    const view = mount(input({ phase: 'on' }))
    act(() => view.result.current.pet())
    expect(view.result.current.view.mood).toBe('petted')
    advance(900)
    expect(view.result.current.view.mood).toBe('calm')
  })
})
