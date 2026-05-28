/**
 * Runtime watchdog that catches a foreign VPN/TUN adapter (Happ-TUN, WireGuard,
 * OpenVPN, Hiddify, …) appearing AFTER our tunnel is already up.
 *
 * Why this exists. The pre-flight check inside `tunController.start()` already
 * refuses to bring our TUN up next to a live foreign tunnel. But the user can
 * still flip Happ from "Proxy" to "TUN" mode (or launch a separate VPN client)
 * while our TUN keeps running. With two `auto_route` adapters on the box the
 * default route flaps, DNS goes into a loop, and the user sees "intermittent
 * internet" with no idea where to look. The diagnostic dump from 2026-05-28
 * shows exactly this: our TUN running normally, then a `happ-tun` (sing-tun,
 * 172.18.0.2) appears mid-session and starts fighting for the route.
 *
 * What we do. While our TUN is running we poll `detectForeignTun()` every
 * 15s. The detector uses `os.networkInterfaces()` (locale-independent, no PS
 * spawn, ~1ms) so polling is cheap. On a transition empty→present we emit:
 *   - a `warn` log with the foreign tunnel name + IP so it shows up in the
 *     diagnostic ZIP for support,
 *   - a `notify('warn', ...)` toast,
 *   - a structured `tun-status-changed` event (`competing-tun:<name>`) so
 *     the renderer can show a banner without polling on its own.
 *
 * On the reverse transition (foreign tunnel disappears while ours is still
 * up) we log info and emit a `running` status event so the banner clears.
 *
 * We deliberately do NOT auto-stop our tunnel on detection. Tearing the user's
 * TUN out from under them while they actively troubleshoot would be more
 * disruptive than the route conflict — they should see the warning and decide.
 */
import { detectForeignTun } from './tunController'
import { logEvent } from './appLogger'
import { notify } from './notifications'

type StatusEmitter = (status: string) => void

const POLL_INTERVAL_MS = 15_000

let timer: ReturnType<typeof setInterval> | null = null
let lastForeign: string | null = null
let emitStatus: StatusEmitter | null = null

function check(): void {
  const foreign = detectForeignTun()
  if (foreign && !lastForeign) {
    lastForeign = foreign
    logEvent('warn', 'competing-tun', 'foreign VPN/TUN appeared while our TUN is running', {
      foreign
    })
    notify(
      'warn',
      'Обнаружен второй VPN',
      `Запущен ещё один туннель: ${foreign}. Двойной маршрут ломает DNS — оставьте только один VPN.`
    )
    emitStatus?.(`competing-tun:${foreign}`)
  } else if (!foreign && lastForeign) {
    logEvent('info', 'competing-tun', 'foreign VPN/TUN disappeared', { previous: lastForeign })
    lastForeign = null
    // Clear the banner. We let the caller re-emit whatever the actual TUN
    // status is on the next status callback (we don't want to fight with
    // proxy-down / killswitch-active / running).
    emitStatus?.('running')
  } else if (foreign && lastForeign && foreign !== lastForeign) {
    // Same situation, different foreign adapter — log it but keep banner up.
    logEvent('warn', 'competing-tun', 'foreign VPN/TUN changed identity', {
      from: lastForeign,
      to: foreign
    })
    lastForeign = foreign
    emitStatus?.(`competing-tun:${foreign}`)
  }
}

export function startCompetingTunWatch(onStatus: StatusEmitter): void {
  stopCompetingTunWatch()
  emitStatus = onStatus
  // Run once immediately so a foreign TUN that exists at start time shows up
  // in the very first beat instead of waiting POLL_INTERVAL_MS.
  check()
  timer = setInterval(check, POLL_INTERVAL_MS)
}

export function stopCompetingTunWatch(): void {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
  emitStatus = null
  lastForeign = null
}

/**
 * Test-only — read the watchdog's current view of the foreign TUN. Returns
 * null when nothing is detected.
 */
export function getCurrentForeignTun(): string | null {
  return lastForeign
}
