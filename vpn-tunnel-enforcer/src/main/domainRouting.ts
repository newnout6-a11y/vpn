/**
 * Domain Routing Service — main process module for per-domain traffic routing.
 *
 * Responsibilities:
 * - Rule CRUD operations (stored in electron-store)
 * - Domain matching with wildcard support (*.example.com matches subdomains only)
 * - Priority-ordered rule evaluation (first match wins)
 * - Hit count tracking per session
 * - Import domain lists from text files
 * - Reorder rules by providing new ID order
 * - Register IPC handlers for all DomainRoutingChannels
 *
 * Pure functions exported for property testing:
 * - matchDomain(rules, domain)
 * - parseDomainList(text)
 */

import { ipcMain, dialog } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'crypto'
import { readFileSync } from 'fs'
import type { DomainRule, DomainAction } from '../shared/ipc-types'

// ─── Store ───────────────────────────────────────────────────────────────────

interface DomainRoutingStoreSchema {
  domainRules: DomainRule[]
}

const domainRoutingStore = new Store<DomainRoutingStoreSchema>({
  name: 'domain-routing',
  defaults: {
    domainRules: []
  }
})

// ─── Session Hit Counts ──────────────────────────────────────────────────────

/** In-memory hit counts for the current session, keyed by rule ID */
const sessionHitCounts = new Map<string, number>()

// ─── Pure Functions (exported for property testing) ──────────────────────────

/**
 * Matches a domain against a list of rules sorted by priority.
 * Returns the first matching rule, or null if no rule matches.
 *
 * Matching logic:
 * - Wildcard pattern `*.x.com` matches any subdomain of x.com
 *   (e.g., sub.x.com, a.b.x.com) but NOT x.com itself
 * - Exact pattern `x.com` matches only `x.com`
 * - Rules are evaluated in priority order (sorted ascending by priority number)
 * - First match wins
 */
export function matchDomain(rules: DomainRule[], domain: string): DomainRule | null {
  if (!domain || typeof domain !== 'string') return null

  const normalizedDomain = domain.toLowerCase().trim()
  if (!normalizedDomain) return null

  // Sort rules by priority (lower number = higher priority)
  const sorted = [...rules].sort((a, b) => a.priority - b.priority)

  for (const rule of sorted) {
    if (!rule.pattern || typeof rule.pattern !== 'string') continue

    const pattern = rule.pattern.toLowerCase().trim()
    if (!pattern) continue

    if (pattern.startsWith('*.')) {
      // Wildcard pattern: *.x.com matches subdomains of x.com but not x.com itself
      const baseDomain = pattern.slice(2) // Remove "*."
      if (!baseDomain) continue

      // Domain must end with .baseDomain and be longer than baseDomain
      // (i.e., there must be at least one subdomain segment)
      if (
        normalizedDomain.endsWith('.' + baseDomain) &&
        normalizedDomain.length > baseDomain.length + 1
      ) {
        return rule
      }
    } else {
      // Exact match
      if (normalizedDomain === pattern) {
        return rule
      }
    }
  }

  return null
}

/**
 * Parses a text string containing domain patterns (one per line) into DomainRule objects.
 *
 * - Trims whitespace from each line
 * - Skips empty lines and whitespace-only lines
 * - Assigns sequential priorities starting from 0
 * - Default action is 'direct'
 * - Each rule gets a unique ID and hitCount of 0
 */
export function parseDomainList(text: string): DomainRule[] {
  if (!text || typeof text !== 'string') return []

  const lines = text.split(/\r?\n/)
  const rules: DomainRule[] = []

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue

    rules.push({
      id: randomUUID(),
      pattern: trimmed,
      action: 'direct',
      priority: rules.length,
      hitCount: 0
    })
  }

  return rules
}

// ─── CRUD Operations ─────────────────────────────────────────────────────────

function getRules(): DomainRule[] {
  const stored = domainRoutingStore.get('domainRules')
  if (!Array.isArray(stored)) return []
  // Merge session hit counts into stored rules
  return stored.map((rule) => ({
    ...rule,
    hitCount: sessionHitCounts.get(rule.id) ?? rule.hitCount
  }))
}

function addRule(input: Omit<DomainRule, 'id' | 'hitCount'>): DomainRule {
  const newRule: DomainRule = {
    ...input,
    id: randomUUID(),
    hitCount: 0
  }
  const rules = domainRoutingStore.get('domainRules') ?? []
  rules.push(newRule)
  domainRoutingStore.set('domainRules', rules)
  return newRule
}

function updateRule(id: string, patch: Partial<DomainRule>): DomainRule {
  const rules = domainRoutingStore.get('domainRules') ?? []
  const index = rules.findIndex((r) => r.id === id)
  if (index === -1) {
    throw new Error(`Domain rule not found: ${id}`)
  }

  const updated: DomainRule = {
    ...rules[index],
    ...patch,
    id, // id cannot be changed
    hitCount: sessionHitCounts.get(id) ?? rules[index].hitCount
  }
  rules[index] = updated
  domainRoutingStore.set('domainRules', rules)
  return updated
}

function deleteRule(id: string): void {
  const rules = domainRoutingStore.get('domainRules') ?? []
  const filtered = rules.filter((r) => r.id !== id)
  domainRoutingStore.set('domainRules', filtered)
  sessionHitCounts.delete(id)
}

function reorderRules(ids: string[]): DomainRule[] {
  const rules = domainRoutingStore.get('domainRules') ?? []
  const ruleMap = new Map(rules.map((r) => [r.id, r]))

  // Reorder based on provided ID order, assigning new priorities
  const reordered: DomainRule[] = []
  for (let i = 0; i < ids.length; i++) {
    const rule = ruleMap.get(ids[i])
    if (rule) {
      reordered.push({ ...rule, priority: i })
    }
  }

  // Append any rules not in the provided list at the end
  for (const rule of rules) {
    if (!ids.includes(rule.id)) {
      reordered.push({ ...rule, priority: reordered.length })
    }
  }

  domainRoutingStore.set('domainRules', reordered)

  // Return with session hit counts merged
  return reordered.map((rule) => ({
    ...rule,
    hitCount: sessionHitCounts.get(rule.id) ?? rule.hitCount
  }))
}

function importFromFile(filePath: string): DomainRule[] {
  const text = readFileSync(filePath, 'utf-8')
  const parsed = parseDomainList(text)

  // Get existing rules to determine starting priority
  const existing = domainRoutingStore.get('domainRules') ?? []
  const startPriority = existing.length

  // Adjust priorities for imported rules
  const imported = parsed.map((rule, index) => ({
    ...rule,
    priority: startPriority + index
  }))

  const combined = [...existing, ...imported]
  domainRoutingStore.set('domainRules', combined)

  // Return with session hit counts merged
  return combined.map((rule) => ({
    ...rule,
    hitCount: sessionHitCounts.get(rule.id) ?? rule.hitCount
  }))
}

function resetHitCounts(): void {
  sessionHitCounts.clear()
}

// ─── Hit Count Tracking ──────────────────────────────────────────────────────

/**
 * Increments the hit count for a matched rule during the current session.
 * Called externally when a domain match occurs during traffic routing.
 */
export function recordHit(ruleId: string): void {
  const current = sessionHitCounts.get(ruleId) ?? 0
  sessionHitCounts.set(ruleId, current + 1)
}

// ─── Sing-box route rule generation ──────────────────────────────────────────

/**
 * Translate the user's domain rules into sing-box 1.13 route rules, ready to
 * be spliced into the `route.rules` array of the generated config.
 *
 * Mapping:
 *   - action 'direct' → outbound 'direct-out' (bypass VPN)
 *   - action 'vpn'    → outbound 'proxy-out'  (force through VPN)
 *   - action 'block'  → outbound 'block-out'  (drop)
 *
 * Pattern → sing-box matcher:
 *   - "*.example.com"  → domain_suffix ".example.com"  (subdomains only — the
 *     leading dot makes sing-box NOT match the bare apex, matching our
 *     matchDomain() wildcard semantics)
 *   - "example.com"    → domain "example.com"          (exact)
 *   - "keyword"        → (no dot, no wildcard) domain_keyword "keyword"
 *
 * Rules are grouped by (action) and emitted in priority order. Because
 * sing-box evaluates route rules top-to-bottom and first-match-wins, and we
 * inject these BEFORE the catch-all final, the lowest-priority-number rule
 * must come first — so we sort ascending by priority and emit one rule object
 * per DomainRule (sing-box dedups internally; correctness over compactness).
 *
 * Returns [] when there are no rules, so callers can spread unconditionally.
 */
export function generateDomainRouteRules(): Array<Record<string, any>> {
  return domainRulesToSingboxRules(getRules())
}

/**
 * Pure translation of DomainRule[] → sing-box route rule objects. Exported
 * separately so it can be unit-tested without touching the electron-store.
 */
export function domainRulesToSingboxRules(input: DomainRule[]): Array<Record<string, any>> {
  const rules = input
    .filter((r) => r && typeof r.pattern === 'string' && r.pattern.trim())
    .sort((a, b) => a.priority - b.priority)

  const outboundFor = (action: DomainAction): string =>
    action === 'direct' ? 'direct-out' : action === 'block' ? 'block-out' : 'proxy-out'

  const result: Array<Record<string, any>> = []
  for (const rule of rules) {
    const pattern = rule.pattern.trim().toLowerCase()
    const rb: Record<string, any> = rule.action === 'block'
      ? { action: 'reject', method: 'default', no_drop: true }
      : { outbound: outboundFor(rule.action) }

    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2)
      if (!base) continue
      rb.domain_suffix = [`.${base}`]
    } else if (pattern.includes('.')) {
      rb.domain = [pattern]
    } else {
      // No dot, no wildcard — treat as a keyword match (e.g. "telegram").
      rb.domain_keyword = [pattern]
    }
    result.push(rb)
  }
  return result
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const domainRoutingService = {
  getRules,
  addRule,
  updateRule,
  deleteRule,
  reorderRules,
  importFromFile,
  resetHitCounts,
  recordHit,

  /**
   * Match a domain against the current rule set and record a hit if matched.
   * Returns the matching rule or null.
   */
  matchAndRecord(domain: string): DomainRule | null {
    const rules = getRules()
    const matched = matchDomain(rules, domain)
    if (matched) {
      recordHit(matched.id)
    }
    return matched
  }
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerDomainRoutingIpcHandlers(): void {
  ipcMain.handle('domain-routing:list', () => {
    return domainRoutingService.getRules()
  })

  ipcMain.handle(
    'domain-routing:add',
    (_event, rule: Omit<DomainRule, 'id' | 'hitCount'>) => {
      return domainRoutingService.addRule(rule)
    }
  )

  ipcMain.handle(
    'domain-routing:update',
    (_event, id: string, patch: Partial<DomainRule>) => {
      return domainRoutingService.updateRule(id, patch)
    }
  )

  ipcMain.handle('domain-routing:delete', (_event, id: string) => {
    domainRoutingService.deleteRule(id)
  })

  ipcMain.handle('domain-routing:reorder', (_event, ids: string[]) => {
    return domainRoutingService.reorderRules(ids)
  })

  ipcMain.handle('domain-routing:import', (_event, filePath: string) => {
    return domainRoutingService.importFromFile(filePath)
  })

  ipcMain.handle('domain-routing:reset-hits', () => {
    domainRoutingService.resetHitCounts()
  })

  ipcMain.handle('domain-routing:browse-file', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [
        { name: 'Text Files', extensions: ['txt', 'csv', 'list'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    return result.filePaths[0]
  })
}
