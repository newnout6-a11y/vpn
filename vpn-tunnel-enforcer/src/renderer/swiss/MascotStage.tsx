import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { cn } from '../design-system/utils'
import { Mascot } from './Mascot'
import type { MascotApi, MascotPhase, Speech } from './useMascot'

// Mascot box (body + feet); the seal tag sticks out ~24px above it.
const W = 96
const H = 89
const TAG = 24

interface Pt { x: number; y: number; scale: number }

/**
 * Any element with data-perch="name" is a spot the mascot can sit on.
 *   data-perch-x     0..1 preferred horizontal anchor (default 0.5)
 *   data-perch-y     "top" (sits on the top edge, default) | "bottom" (stands inside, on the bottom edge)
 *   data-perch-scale size multiplier (default 1)
 *   data-perch-fit   "gap": only land in a horizontal gap free of text/icons; no gap = not available
 */
function measure(name: string): Pt | null {
  const el = document.querySelector<HTMLElement>('[data-perch="' + name + '"]')
  if (!el) return null
  const r = el.getBoundingClientRect()
  if (r.width === 0 && r.height === 0) return null
  const ax = Number(el.dataset.perchX ?? 0.5)
  const y = el.dataset.perchY === 'bottom' ? r.bottom : r.top
  const scale = Number(el.dataset.perchScale ?? 1)
  const prefer = r.left + r.width * ax
  if (el.dataset.perchFit !== 'gap') return { x: prefer, y, scale }
  const x = freeSpotX(el, r, W * scale + 4, prefer)
  return x === null ? null : { x, y, scale }
}

/** x-centre of the free horizontal slot (no glyphs, no icons) closest to prefer. */
function freeSpotX(el: HTMLElement, r: DOMRect, need: number, prefer: number): number | null {
  const taken: Array<[number, number]> = []
  const range = document.createRange()
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT)
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent || !n.textContent.trim()) continue
    range.selectNodeContents(n)
    for (const box of Array.from(range.getClientRects())) if (box.width > 0) taken.push([box.left, box.right])
  }
  // Text-less leaves: icons, status squares (but not full-width background layers)
  el.querySelectorAll('*').forEach(c => {
    if (c.children.length > 0 || (c.textContent && c.textContent.trim())) return
    const box = c.getBoundingClientRect()
    if (box.width > 0 && box.height > 0 && box.width < r.width * 0.6) taken.push([box.left, box.right])
  })
  taken.sort((a, b) => a[0] - b[0])
  const pad = 6
  const gaps: Array<[number, number]> = []
  let cursor = r.left + pad
  for (const [a, b] of taken) {
    if (a - pad > cursor) gaps.push([cursor, a - pad])
    cursor = Math.max(cursor, b + pad)
  }
  if (r.right - pad > cursor) gaps.push([cursor, r.right - pad])
  let best: number | null = null
  for (const [a, b] of gaps) {
    if (b - a < need) continue
    const x = Math.min(Math.max(prefer, a + need / 2), b - need / 2)
    if (best === null || Math.abs(x - prefer) < Math.abs(best - prefer)) best = x
  }
  return best
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

  const goHomeRef = useRef(mascot.goHome)
  useEffect(() => {
    posRef.current = pos
    goHomeRef.current = mascot.goHome
  })

  // Stick to the current perch while it moves (scroll, resize, layout changes).
  // If the spot disappears (text grew into it), hop home: never snap.
  const glue = useCallback(() => {
    if (flying.current) return
    const t = measure(perchRef.current)
    if (!t) {
      if (perchRef.current !== 'home') goHomeRef.current()
      return
    }
    setPos(p => (p && Math.abs(p.x - t.x) < 0.5 && Math.abs(p.y - t.y) < 0.5 && p.scale === t.scale ? p : t))
  }, [])

  // Re-glue only when the target or the tunnel phase changes (layout may shift);
  // traffic-driven re-renders don't force layout reads. Scroll/resize/interval cover the rest.
  useLayoutEffect(() => {
    glue()
  }, [glue, perch, phase])

  useEffect(() => {
    // One measure per frame at most, however many scroll events fire
    let frame = 0
    const onScrollOrResize = () => {
      if (frame) return
      frame = window.requestAnimationFrame(() => {
        frame = 0
        glue()
      })
    }
    window.addEventListener('scroll', onScrollOrResize, true)
    window.addEventListener('resize', onScrollOrResize)
    return () => {
      window.removeEventListener('scroll', onScrollOrResize, true)
      window.removeEventListener('resize', onScrollOrResize)
      if (frame) window.cancelAnimationFrame(frame)
      window.cancelAnimationFrame(raf.current)
    }
  }, [glue])

  // Layout and text can change without scroll/resize (banners, ticking values).
  // At home the check is one cheap rect read; the text-gap scan only runs
  // while he sits on a fit=gap perch, and stops when the window is hidden.
  useEffect(() => {
    const id = window.setInterval(() => {
      if (!document.hidden) glue()
    }, perch === 'home' ? 1500 : 500)
    return () => window.clearInterval(id)
  }, [glue, perch])

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
    <div className="c-swiss pointer-events-none fixed inset-0 z-40">
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
        <Mascot
          phase={phase}
          view={airborne ? { ...view, mood: 'excited' } : view}
          onPoke={mascot.poke}
          label={mascot.name}
          landId={landId}
          onSignal={onSignal}
        />
      </div>
      {view.speech && <Bubble speech={view.speech} pos={pos} />}
      {/* Replies the user asked for (pokes) are read out; ambient chatter is not */}
      <span className="sr-only" aria-live="polite">
        {view.speech && view.speech.announce ? view.speech.text : ''}
      </span>
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
      aria-hidden="true"
      style={{ left: pos.x, top: below ? pos.y + 12 : head - 14, transform: 'translate(-' + k + '%, ' + (below ? '0' : '-100%') + ')' }}
    >
      <div className="bubble-in swiss-mono relative w-max max-w-[230px] border-2 border-[var(--ink)] bg-[var(--paper)] px-2.5 py-1.5 text-[11px] leading-snug text-[var(--ink)]">
        {speech.text}
        <span
          className={cn(
            'absolute h-3 w-3 -translate-x-1/2 rotate-45 border-[var(--ink)] bg-[var(--paper)]',
            below ? '-top-[7px] border-l-2 border-t-2' : '-bottom-[7px] border-b-2 border-r-2'
          )}
          style={{ left: k + '%' }}
        />
      </div>
    </div>
  )
}
