/**
 * Snapshot the deep-research workflow mid-flight.
 *
 * WHY THIS EXISTS. The first run of this research died on an exhausted API
 * balance during the verify phase, and the synthesis step never ran — so the
 * tool returned almost nothing even though 105 agents had already done ~30
 * minutes of work. That work was not lost: every workflow subagent streams its
 * transcript to disk as it goes, and the run directory also carries a
 * journal.jsonl of cached results keyed by prompt hash. This script recovers a
 * usable report out of those artifacts WITHOUT re-running or resuming anything.
 *
 * Run it any time — mid-run, after a crash, or after a normal completion:
 *
 *   node .research/snapshot.mjs
 *
 * It reads the verify-phase transcripts, pairs each claim with its votes, and
 * writes .research/live-snapshot.{json,md}. Claims are grouped exactly the way
 * the workflow itself grades them: 2 refutations out of 3 kill a claim, and a
 * claim whose voters all abstained (agents died) counts as UNADJUDICATED — not
 * as refuted. That distinction is the whole point: the first run reported 20
 * claims as "killed" when several had simply lost all three voters to HTTP 403.
 */

import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const RUN_DIR = process.argv[2] || join(
  process.env.USERPROFILE || process.env.HOME,
  '.claude/projects/c--Users-Redmi-CascadeProjects-vpn',
  'dd9263dc-872d-4e9e-9a6e-1f8fbffcd5d7/subagents/workflows/wf_edca1387-f97'
)
const OUT_DIR = new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')

const VOTES_PER_CLAIM = 3
const REFUTATIONS_REQUIRED = 2

/** Pull the claim/source/quote triple back out of a VERIFY_PROMPT body. */
function parseVerifyPrompt(text) {
  const claim = /## Claim under review\s*\n"([\s\S]*?)"\s*\n\s*\n\*\*Source:\*\*/.exec(text)
  if (!claim) return null
  const source = /\*\*Source:\*\*\s*(\S+)\s*\(([^)]*)\)/.exec(text)
  const quote = /\*\*Supporting quote:\*\*\s*"([\s\S]*?)"\s*\n\s*\n## Checklist/.exec(text)
  const voter = /voter (\d+)\/(\d+)/.exec(text)
  return {
    claim: claim[1].trim(),
    sourceUrl: source?.[1] ?? '',
    sourceQuality: source?.[2] ?? '',
    quote: quote?.[1]?.trim() ?? '',
    voter: voter ? Number(voter[1]) : null
  }
}

/** First user message of a transcript = the agent's prompt. */
function promptOf(lines) {
  for (const ln of lines) {
    let ev
    try { ev = JSON.parse(ln) } catch { continue }
    if (ev?.message?.role !== 'user') continue
    const c = ev.message.content
    return typeof c === 'string' ? c : Array.isArray(c) ? c.map(x => x.text || '').join('') : ''
  }
  return ''
}

/** Last structured-output tool call in a transcript = the agent's return value. */
function structuredOf(lines) {
  let last = null
  for (const ln of lines) {
    let ev
    try { ev = JSON.parse(ln) } catch { continue }
    const content = ev?.message?.content
    if (!Array.isArray(content)) continue
    for (const c of content) {
      if (c.type === 'tool_use' && c.input && typeof c.input === 'object') {
        if ('refuted' in c.input || Array.isArray(c.input.claims) || Array.isArray(c.input.findings)) last = c.input
      }
    }
  }
  return last
}

const files = readdirSync(RUN_DIR).filter(f => f.endsWith('.jsonl') && f !== 'journal.jsonl')

const byClaim = new Map()
const extracted = []

for (const f of files) {
  const lines = readFileSync(join(RUN_DIR, f), 'utf8').split('\n').filter(Boolean)
  const prompt = promptOf(lines)
  const out = structuredOf(lines)

  // Fetch-phase agent: carries the extracted claim corpus.
  if (out && Array.isArray(out.claims)) {
    const url = /https?:\/\/[^\s"'<>)\]]+/.exec(prompt)?.[0] ?? ''
    for (const c of out.claims) {
      if (c?.claim) extracted.push({ claim: c.claim, quote: c.quote ?? '', source: c.source || url, importance: c.importance, quality: out.sourceQuality })
    }
    continue
  }

  // Verify-phase agent: one adversarial vote on one claim.
  const parsed = parseVerifyPrompt(prompt)
  if (!parsed) continue
  const key = parsed.claim.slice(0, 120)
  if (!byClaim.has(key)) byClaim.set(key, { ...parsed, votes: [] })
  if (out && 'refuted' in out) {
    byClaim.get(key).votes.push({ refuted: !!out.refuted, confidence: out.confidence, evidence: out.evidence })
  }
}

// ─── Grade, using the workflow's own rule ───
const confirmed = [], refuted = [], unadjudicated = []
for (const c of byClaim.values()) {
  const refutes = c.votes.filter(v => v.refuted).length
  const supports = c.votes.length - refutes
  const row = { ...c, supports, refutes, abstained: VOTES_PER_CLAIM - c.votes.length }
  if (c.votes.length < REFUTATIONS_REQUIRED) unadjudicated.push(row)
  else if (refutes >= REFUTATIONS_REQUIRED) refuted.push(row)
  else confirmed.push(row)
}

const stats = {
  generatedAt: new Date().toISOString(),
  transcripts: files.length,
  claimsExtracted: extracted.length,
  claimsWithVotes: byClaim.size,
  confirmed: confirmed.length,
  refuted: refuted.length,
  unadjudicated: unadjudicated.length
}

writeFileSync(join(OUT_DIR, 'live-snapshot.json'),
  JSON.stringify({ stats, confirmed, refuted, unadjudicated, extracted }, null, 2))

// ─── Markdown for reading ───
const esc = s => String(s ?? '').replace(/\r?\n/g, ' ').trim()
const section = (title, rows, withEvidence) => [
  `## ${title} (${rows.length})`,
  '',
  ...rows.flatMap(r => {
    const best = withEvidence ? r.votes.find(v => !v.refuted) || r.votes[0] : null
    return [
      `### ${esc(r.claim)}`,
      `**Голоса:** ${r.supports}-${r.refutes}${r.abstained ? ` (воздержалось ${r.abstained})` : ''} · **Источник:** ${r.sourceUrl || '—'} (${r.sourceQuality || '?'})`,
      r.quote ? `> ${esc(r.quote)}` : '',
      best?.evidence ? `**Разбор верификатора:** ${esc(best.evidence).slice(0, 700)}` : '',
      ''
    ].filter(Boolean)
  })
].join('\n')

writeFileSync(join(OUT_DIR, 'live-snapshot.md'), [
  '# Срез deep-research (снят с транскриптов, без повторного прогона)',
  '',
  `Снято: ${stats.generatedAt}`,
  `Транскриптов: ${stats.transcripts} · извлечённых утверждений: ${stats.claimsExtracted} · получивших голоса: ${stats.claimsWithVotes}`,
  `Подтверждено: ${stats.confirmed} · опровергнуто: ${stats.refuted} · **не рассмотрено: ${stats.unadjudicated}**`,
  '',
  '> Не рассмотренные — это НЕ опровергнутые. У них все голосующие агенты не вернули вердикт',
  '> (упали, либо ещё считают). Читать как «неизвестно», а не как «ложно».',
  '',
  section('Подтверждено', confirmed, true),
  section('Опровергнуто', refuted, true),
  section('Не рассмотрено', unadjudicated, false)
].join('\n'))

console.log(JSON.stringify(stats, null, 2))
console.log('\nwrote live-snapshot.json / live-snapshot.md to', OUT_DIR)


