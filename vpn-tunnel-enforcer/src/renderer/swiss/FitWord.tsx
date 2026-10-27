import { useLayoutEffect, useRef, useState } from 'react'
import { Stagger } from './motion'

const MAX = 150
const MIN = 40

/**
 * Big status word that fills its column: measures the word's real width in the
 * display face at 100px (letter-spacing is in em, so width scales linearly) and
 * sets the font-size so every word (SECURE, LINKING, EXPOSED…) is equally wide.
 * Decorative: the live status text lives in the role="status" caption.
 */
export function FitWord({ text, busyDot = false }: { text: string; busyDot?: boolean }) {
  const boxRef = useRef<HTMLDivElement>(null)
  const probeRef = useRef<HTMLSpanElement>(null)
  const [size, setSize] = useState<number | null>(null)

  useLayoutEffect(() => {
    const box = boxRef.current
    const probe = probeRef.current
    if (!box || !probe) return
    const fit = () => {
      const at100 = probe.getBoundingClientRect().width
      if (!at100) return // not laid out (hidden page, jsdom)
      const next = Math.max(MIN, Math.min(MAX, (box.clientWidth / at100) * 100 * 0.98))
      setSize(s => (s !== null && Math.abs(s - next) < 0.5 ? s : next))
    }
    fit()
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(fit) : null
    if (ro) ro.observe(box)
    // Re-fit once the bundled font has loaded (fallback metrics differ)
    if (document.fonts) void document.fonts.ready.then(fit)
    return () => {
      if (ro) ro.disconnect()
    }
  }, [text, busyDot])

  return (
    <div ref={boxRef} className="swiss-word-wrap relative" aria-hidden="true">
      <span ref={probeRef} className="swiss-word pointer-events-none invisible absolute left-0 top-0" style={{ fontSize: 100 }}>
        {text}
        {busyDot ? '.' : ''}
      </span>
      <div className="swiss-word" style={{ fontSize: size ?? 96 }}>
        <Stagger text={text} />
        {busyDot && <span className="blink">.</span>}
      </div>
    </div>
  )
}
