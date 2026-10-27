import { useAppStore } from '../store'
import { usePageActive } from '../hooks/usePageActive'
import { MascotStage } from './MascotStage'
import { useMascot, type MascotPhase } from './useMascot'

export type SwissPhase = MascotPhase

/**
 * Owns the mascot's per-second state so the Dashboard itself never re-renders
 * on a timer. Renders nothing when the page is hidden or the environment
 * can't animate (jsdom in tests has no matchMedia / layout).
 */
export function SwissMascot({ phase }: { phase: SwissPhase }) {
  const active = usePageActive()
  const canAnimate = typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && typeof window.requestAnimationFrame === 'function'
  if (!active || !canAnimate) return null
  return <MascotRuntime phase={phase} />
}

function MascotRuntime({ phase }: { phase: SwissPhase }) {
  const startedAt = useAppStore(s => s.tunStartedAt)
  const downBps = useAppStore(s => s.traffic.smoothedDownloadBps || s.traffic.downloadBps)
  const mascot = useMascot({ phase, startedAt, downMbps: (Math.max(0, downBps) * 8) / 1000000 })
  return <MascotStage phase={phase} mascot={mascot} />
}
