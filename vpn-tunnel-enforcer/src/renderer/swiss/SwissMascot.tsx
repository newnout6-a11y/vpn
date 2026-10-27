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
  // Only the 75 Mbit/s spike matters to the mascot: 0 below it, 10 Mbit/s buckets above,
  // so ordinary traffic samples don't re-render the overlay.
  const fastMbps = useAppStore(s => {
    const mbps = (Math.max(0, s.traffic.smoothedDownloadBps || s.traffic.downloadBps) * 8) / 1000000
    return mbps >= 75 ? Math.round(mbps / 10) * 10 : 0
  })
  const mascot = useMascot({ phase, startedAt, downMbps: fastMbps })
  return <MascotStage phase={phase} mascot={mascot} />
}
