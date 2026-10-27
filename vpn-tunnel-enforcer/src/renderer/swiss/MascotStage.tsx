import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Mascot } from './Mascot'
import type { MascotApi, MascotPhase, Speech } from './useMascot'

// Mascot box (body + feet); the seal tag sticks out ~24px above it.
const W = 96
const H = 89
const TAG = 24

interface Pt { x: number; y: number; scale: number }

/**
 * Any element with data-perch="name" is a spot the mascot can sit on.
 *   data-perch-x     0..1 horizontal anchor (default 0.5)
 *   data-perch-y     "top" (sits on the top edge, default) | "bottom"
 *   data-perch-scale size multiplier (default 1)
 */
function measure(name: string): Pt | null {
  const el = document.querySelector<HTMLElement>('[data-perch="' + name + '"]')
  if (!el) return null
  const r = el.getBoundingClientRect()
  if (r.width === 0 && r.height === 0) return null
  const ax = Number(el.dataset.perchX ?? 0.5)
  const y = el.dataset.perchY === 'bottom' ? r.bottom : r.top
  const scale = Number(el.dataset.perchScale ?? 1)
  return { x: r.left + r.width * ax, y, scale }
}

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** Fixed overlay that draws the mascot on its current perch and hops between perches. */
export function MascotStage({ phase, mascot }: { phase: MascotPhase; mascot: MascotApi }) {
  const { view, perch } = mascot
  const [pos, setPos] = useState<Pt | null>(null)
  const [dir, setDir] = useState<number | null>(null) // non-null while airborne
  const [landId, setLandId] = useState(0)
  const posRef = useRef<Pt | null>(null)
  const perchRef = useRef(perch)
  const flying = useRef(false)
  const raf = useRef(0)

  useLayoutEffect(() => {
    posRef.current = pos
  }, [pos])

  // Stick to the current perch while it moves (scroll, resize, layout changes)
  const glue = useCallback(() => {
    if (flying.current) return
    const t = measure(perchRef.current) ?? measure('home')
    if (!t) return
    setPos(p => (p && Math.abs(p.x - t.x) < 0.5 && Math.abs(p.y - t.y) < 0.5 && p.scale === t.scale ? p : t))
  }, [])

  useLayoutEffect(() => {
    glue()
  })

  useEffect(() => {
    window.addEventListener('scroll', glue, true)
    window.addEventListener('resize', glue)
    // Layout can shift without scroll/resize (banners appear, cards expand)
    const id = window.setInterval(glue, 500)
    return () => {
      window.removeEventListener('scroll', glue, true)
      window.removeEventListener('resize', glue)
      window.clearInterval(id)
      window.cancelAnimationFrame(raf.current)
    }
  }, [glue])

  // Hop along a parabola whenever the perch changes
  useEffect(() => {
    if (perchRef.current === perch) return
    perchRef.current = perch
    const from = posRef.current
    const to = measure(perch)
    if (!from || !to || prefersReducedMotion()) {
      glue()
      return
    }
    const dist = Math.hypot(to.x - from.x, to.y - from.y)
    const dur = Math.min(950, 420 + dist * 0.5)
    const lift = Math.min(170, 60 + dist * 0.22)
    const start = performance.now()
    flying.current = true
    setDir(to.x >= from.x ? 1 : -1)
    window.cancelAnimationFrame(raf.current)

    const step = (now: number) => {
      const t = Math.min(1, (now - start) / dur)
      const e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2
      const tgt = measure(perch) ?? to
      setPos({
        x: from.x + (tgt.x - from.x) * e,
        y: from.y + (tgt.y - from.y) * e - lift * 4 * t * (1 - t),
        scale: from.scale + (tgt.scale - from.scale) * e
      })
      if (t < 1) {
        raf.current = window.requestAnimationFrame(step)
      } else {
        flying.current = false
        setDir(null)
        setLandId(i => i + 1)
      }
    }
    raf.current = window.requestAnimationFrame(step)
  }, [perch, glue])

  if (!pos) return null
  const airborne = dir !== null
  const onSignal = perch === 'home' && !airborne && phase === 'on'

  return (
    <div className="c-swiss pointer-events-none fixed inset-0 z-40" aria-hidden="true">
      <div
        className="pointer-events-auto absolute"
        style={{
          left: pos.x - W / 2,
          top: pos.y - H,
          width: W,
          height: H,
          transform: 'scale(' + pos.scale + ') rotate(' + (airborne ? (dir as number) * 12 : 0) + 'deg)',
          transformOrigin: 'bottom center'
        }}
      >
        <div key={'land-' + landId} className={landId ? 'm-land' : ''}>
          <Mascot phase={phase} view={airborne ? { ...view, mood: 'excited' } : view} onPoke={mascot.poke} onSignal={onSignal} />
        </div>
      </div>
      {view.speech && <Bubble speech={view.speech} pos={pos} />}
    </div>
  )
}

function Bubble({ speech, pos }: { speech: NonNullable<Speech>; pos: Pt }) {
  const head = pos.y - (H + TAG) * pos.scale
  const below = head < 80 // no room above: talk from underneath
  const k = pos.x < 280 ? 14 : 86 // which point of the bubble sits over the mascot
  return (
    <div
      key={'speech-' + speech.id}
      className="absolute"
      style={{ left: pos.x, top: below ? pos.y + 12 : head - 14, transform: 'translate(-' + k + '%, ' + (below ? '0' : '-100%') + ')' }}
    >
      <div className="bubble-in swiss-mono relative w-max max-w-[230px] border-2 border-[var(--ink)] bg-[var(--paper)] px-2.5 py-1.5 text-[11px] leading-snug text-[var(--ink)]">
        {speech.text}
        <span
          className={'absolute h-3 w-3 -translate-x-1/2 rotate-45 border-[var(--ink)] bg-[var(--paper)] ' + (below ? '-top-[7px] border-l-2 border-t-2' : '-bottom-[7px] border-b-2 border-r-2')}
          style={{ left: k + '%' }}
        />
      </div>
    </div>
  )
}
