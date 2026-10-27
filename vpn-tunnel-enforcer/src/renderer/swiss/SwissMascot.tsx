import { useAppStore } from '../store'
import { MascotStage } from './MascotStage'
import { useMascot, type MascotPhase } from './useMascot'

export type SwissPhase = MascotPhase

/**
 * Owns the mascot's timers so the Dashboard itself never re-renders on a
 * timer. It stays mounted while the window is hidden (the overlay lives
 * inside the dashboard page, so it is not painted when another page is
 * shown) and renders nothing where it can't animate (jsdom in tests).
 */
export function SwissMascot({ phase }: { phase: SwissPhase }) {
  const canAnimate = typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && typeof window.requestAnimationFrame === 'function'
  if (!canAnimate) return null
  return <MascotRuntime phase={phase} />
}

function MascotRuntime({ phase }: { phase: SwissPhase }) {
  const startedAt = useAppStore(s => s.tunStartedAt)
  // The mascot only reacts to two bands, so it only re-renders when they change:
  //   fast  ≥ 75 Mbit/s → 10 Mbit/s buckets ("Летим!")
  //   slow  0.3–3 Mbit/s → 0.5 Mbit/s buckets ("Тащимся…")
  //   anything else → 0 (idle or ordinary: nothing to say)
  const bandMbps = useAppStore(s => {
    const mbps = (Math.max(0, s.traffic.smoothedDownloadBps || s.traffic.downloadBps) * 8) / 1000000
    if (mbps >= 75) return Math.round(mbps / 10) * 10
    if (mbps >= 0.3 && mbps < 3) return Math.max(0.5, Math.floor(mbps * 2) / 2)
    return 0
  })
  const mascot = useMascot({ phase, startedAt, downMbps: bandMbps })
  return <MascotStage phase={phase} mascot={mascot} />
}
