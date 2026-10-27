import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { cn } from '../design-system/utils'
import type { Fx, MascotPhase, MascotView, Mood } from './useMascot'

/** «Пломбик» — the seal-mascot, built from plain squares. */

interface Props {
  phase: MascotPhase
  view: MascotView
  onPoke: () => void
  /** Translated accessible name. */
  label: string
  /** Bumps on every landing to replay the squash. */
  landId: number
  /** True while sitting on the orange slab: black body + orange eyes. */
  onSignal: boolean
}

interface Eye {
  w: number
  h: number
  pupil: number // 0 = no pupil
  shape?: 'diamond'
  dy?: number
  anim?: 'm-orbit' | 'm-tremble' | 'm-scan'
  fixed?: [number, number]
  blink?: boolean
}
interface Face {
  left: Eye
  right?: Eye
  mouth: (eye: string) => CSSProperties
}

const open = (o: Partial<Eye> = {}): Eye => ({ w: 18, h: 18, pupil: 8, blink: true, ...o })
const bar = (h: number, dy = 0): Eye => ({ w: 18, h, pupil: 0, dy })
const rect = (w: number, h: number, extra: CSSProperties = {}) => (eye: string): CSSProperties => ({ width: w, height: h, background: eye, ...extra })
const ring = (s: number) => (eye: string): CSSProperties => ({ width: s, height: s, border: '2px solid ' + eye })

const FACES: Record<Mood, Face> = {
  calm: { left: open(), mouth: rect(26, 4) },
  worried: { left: open({ w: 22, h: 24, pupil: 6, anim: 'm-tremble' }), mouth: ring(10) },
  scared: { left: open({ w: 22, h: 24, pupil: 5, anim: 'm-tremble' }), mouth: ring(13) },
  scan: { left: open({ anim: 'm-scan' }), mouth: rect(14, 3) },
  happy: { left: bar(5, -3), mouth: rect(24, 9) },
  love: { left: { w: 18, h: 18, pupil: 0, shape: 'diamond' }, mouth: rect(22, 8) },
  squint: { left: open({ h: 6, pupil: 4, blink: false }), mouth: rect(10, 3, { transform: 'translateX(8px)' }) },
  think: { left: open({ fixed: [-4, -4] }), mouth: rect(6, 6, { transform: 'translateX(10px)' }) },
  dizzy: { left: open({ pupil: 6, anim: 'm-orbit', blink: false }), mouth: rect(18, 3, { transform: 'rotate(-14deg)' }) },
  wink: { left: open(), right: bar(3, 4), mouth: rect(18, 4, { transform: 'rotate(-8deg)' }) },
  excited: { left: open({ w: 20, h: 20, pupil: 10 }), mouth: rect(22, 11) },
  sleep: { left: bar(3, 5), mouth: rect(8, 4) }
}

const LOOP: Partial<Record<Mood, string>> = { calm: 'm-breathe', sleep: 'm-breathe-slow', excited: 'm-bounce' }

export function Mascot({ phase, view, onPoke, label, landId, onSignal }: Props) {
  const bodyRef = useRef<HTMLDivElement>(null)
  const [look, setLook] = useState({ x: 0, y: 0 })

  // Pupils follow the cursor (rAF-throttled)
  useEffect(() => {
    let frame = 0
    const onMove = (e: MouseEvent) => {
      if (frame) return
      frame = window.requestAnimationFrame(() => {
        frame = 0
        const r = bodyRef.current?.getBoundingClientRect()
        if (!r) return
        const dx = e.clientX - (r.left + r.width / 2)
        const dy = e.clientY - (r.top + r.height / 2)
        setLook({ x: Math.max(-4, Math.min(4, dx / 45)), y: Math.max(-4, Math.min(4, dy / 45)) })
      })
    }
    window.addEventListener('mousemove', onMove)
    return () => {
      window.removeEventListener('mousemove', onMove)
      if (frame) window.cancelAnimationFrame(frame)
    }
  }, [])

  const on = phase === 'on'
  const body = onSignal ? 'var(--on-signal)' : 'var(--ink)'
  const eye = onSignal || on ? 'var(--signal)' : 'var(--paper)'
  const tagFill = on ? (onSignal ? 'var(--paper)' : 'var(--signal)') : 'transparent'
  const face = FACES[view.mood]
  const eyes = [face.left, face.right ?? face.left]

  return (
    <div className="relative w-[96px] select-none">
      {/* The button never remounts (keyboard focus survives); only the keyed
          inner layers do, to replay landing squash and one-shot body moves. */}
      <button
        type="button"
        onClick={onPoke}
        aria-label={label}
        title={label}
        className="relative mx-auto block focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--signal)]"
      >
        <span key={'land-' + landId} className={cn('block', landId > 0 && 'm-land')}>
        <span key={'body-' + view.bodyId} className={cn('block', view.body)}>
        <span className={cn('relative block', LOOP[view.mood])}>
          <Effects fx={view.fx} fxId={view.fxId} body={body} eye={eye} onSignal={onSignal} />

          {/* Seal tag */}
          <span className="m-tag absolute -top-[22px] left-1/2 flex -translate-x-1/2 flex-col items-center">
            <span className="h-3 w-3 border-2" style={{ borderColor: body, background: tagFill }} />
            <span className="h-3 w-[2px]" style={{ background: body }} />
          </span>

          <div ref={bodyRef} className="relative h-[80px] w-[80px] transition-[background-color] duration-300" style={{ background: body }}>
            <div className="absolute left-0 right-0 top-[22px] flex h-6 items-center justify-center gap-3">
              {eyes.map((e, i) => (
                <EyeView key={i} spec={e} eye={eye} body={body} look={look} side={i === 0 ? 'left' : 'right'} />
              ))}
            </div>
            <span className="absolute bottom-[14px] left-1/2 -ml-[13px] flex w-[26px] justify-center" aria-hidden="true">
              <span className="block transition-[width,height,background-color,transform] duration-200" style={face.mouth(eye)} />
            </span>
          </div>

          <div className="mt-[3px] flex justify-between px-3">
            <span className="h-1.5 w-4" style={{ background: body }} />
            <span className="h-1.5 w-4" style={{ background: body }} />
          </div>
        </span>
        </span>
        </span>
      </button>
    </div>
  )
}

function EyeView({ spec, eye, body, look, side }: { spec: Eye; eye: string; body: string; look: { x: number; y: number }; side: string }) {
  if (spec.shape === 'diamond') {
    return (
      <span className="flex h-[18px] w-[18px] items-center justify-center">
        <span className="block h-[13px] w-[13px] rotate-45" style={{ background: eye }} />
      </span>
    )
  }
  const free = !spec.fixed && spec.anim !== 'm-scan' && spec.anim !== 'm-orbit'
  const pupilPos = spec.fixed
    ? 'translate(' + spec.fixed[0] + 'px, ' + spec.fixed[1] + 'px)'
    : free ? 'translate(' + look.x + 'px, ' + look.y + 'px)' : undefined
  return (
    <span
      className={cn(spec.blink && 'm-eye ' + side, 'flex items-center justify-center overflow-hidden transition-[width,height,background-color,transform] duration-200')}
      style={{ background: eye, width: spec.w, height: spec.h, transform: spec.dy ? 'translateY(' + spec.dy + 'px)' : undefined }}
    >
      {spec.pupil > 0 && (
        <span className={spec.anim ?? ''}>
          <span className="block transition-transform duration-100" style={{ background: body, width: spec.pupil, height: spec.pupil, transform: pupilPos }} />
        </span>
      )}
    </span>
  )
}

const CONFETTI = Array.from({ length: 14 }, (_, i) => {
  const a = (i / 14) * Math.PI * 2 + (i % 2 ? 0.2 : -0.1)
  const d = 56 + (i % 3) * 16
  return { dx: Math.cos(a) * d, dy: Math.sin(a) * d - 20, rot: (i % 2 ? 1 : -1) * (180 + i * 30), size: i % 3 === 0 ? 8 : 6 }
})

function Effects({ fx, fxId, body, eye, onSignal }: { fx: Fx; fxId: number; body: string; eye: string; onSignal: boolean }) {
  if (!fx) return null
  if (fx === 'confetti') {
    const colors = onSignal ? [body, 'var(--paper)'] : ['var(--signal)', body, 'var(--mute)']
    return (
      <span key={fxId} className="pointer-events-none absolute left-1/2 top-[40px] z-10" aria-hidden="true">
        {CONFETTI.map((c, i) => (
          <span
            key={i}
            className="m-confetti absolute"
            style={{
              width: c.size,
              height: c.size,
              background: colors[i % colors.length],
              animationDelay: (i % 4) * 20 + 'ms',
              ['--dx' as string]: c.dx + 'px',
              ['--dy' as string]: c.dy + 'px',
              ['--rot' as string]: c.rot + 'deg'
            } as CSSProperties}
          />
        ))}
      </span>
    )
  }
  if (fx === 'zzz') {
    return (
      <span className="swiss-mono pointer-events-none absolute -right-3 -top-1 font-bold" style={{ color: body }} aria-hidden="true">
        {[0, 1, 2].map(i => (
          <span key={i} className="m-zzz absolute" style={{ animationDelay: i * 0.8 + 's', fontSize: 11 + i * 3 }}>
            z
          </span>
        ))}
      </span>
    )
  }
  if (fx === 'dots') {
    return (
      <span className="pointer-events-none absolute -top-[40px] left-1/2 flex -translate-x-1/2 gap-1" aria-hidden="true">
        {[0, 1, 2].map(i => (
          <span key={i} className="m-dot h-2 w-2" style={{ background: body, animationDelay: i * 0.33 + 's' }} />
        ))}
      </span>
    )
  }
  if (fx === 'sweat') {
    return <span className="m-drop pointer-events-none absolute -left-1 top-1 z-10 h-[10px] w-[6px] border-2" style={{ borderColor: body, background: eye }} aria-hidden="true" />
  }
  return (
    <span className="pointer-events-none absolute -left-8 top-[24px] flex flex-col gap-2.5" aria-hidden="true">
      {[18, 26, 14].map((w, i) => (
        <span key={i} className="m-speed block h-[3px]" style={{ width: w, background: body, animationDelay: i * 0.12 + 's' }} />
      ))}
    </span>
  )
}
