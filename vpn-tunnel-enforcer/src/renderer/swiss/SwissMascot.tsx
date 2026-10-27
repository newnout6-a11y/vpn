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
  const downBps = useAppStore(s => s.traffic.smoothedDownloadBps || s.traffic.downloadBps)
  const mascot = useMascot({ phase, startedAt, downMbps: (Math.max(0, downBps) * 8) / 1000000 })
  return <MascotStage phase={phase} mascot={mascot} />
}
