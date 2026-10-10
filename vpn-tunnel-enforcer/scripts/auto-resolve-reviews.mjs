#!/usr/bin/env node
/**
 * Autonomous Reviewer Feedback Triage & Resolver
 *
 * Interacts with GitHub PRs, parses reviews and comments from configured reviewers,
 * generates structured tasks for the Antigravity agent, and verifies Definition of Done.
 *
 * Usage:
 *   node scripts/auto-resolve-reviews.mjs [--status]
 *   node scripts/auto-resolve-reviews.mjs --check-dod
 */

import { execFileSync } from 'child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'

function runCommand(cmd, args, opts = {}) {
  try {
    const stdout = execFileSync(cmd, args, {
      encoding: 'utf8',
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...opts
    })
    return { ok: true, stdout: stdout.trim(), stderr: '' }
  } catch (err) {
    return {
      ok: false,
      stdout: err.stdout ? String(err.stdout).trim() : '',
      stderr: err.stderr ? String(err.stderr).trim() : String(err.message)
    }
  }
}

function loadConfig() {
  const possiblePaths = [
    join(process.cwd(), 'reviewer-automation.config.json'),
    join(process.cwd(), '..', 'reviewer-automation.config.json')
  ]
  for (const p of possiblePaths) {
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, 'utf8'))
      } catch {}
    }
  }
  return {
    reviewers: {
      recognizedBots: [
        { id: 'coderabbitai[bot]', name: 'CodeRabbit AI', enabled: true },
        { id: 'revixappdev[bot]', name: 'Revix AI', enabled: true },
        { id: 'greptile-apps[bot]', name: 'Greptile AI', enabled: true }
      ]
    }
  }
}

const config = loadConfig()

function getPrNumber() {
  const res = runCommand('gh', ['pr', 'view', '--json', 'number'])
  if (!res.ok) throw new Error(`Failed to get PR number: ${res.stderr}`)
  return JSON.parse(res.stdout).number
}

function getRepo() {
  const res = runCommand('gh', ['repo', 'view', '--json', 'nameWithOwner'])
  if (!res.ok) throw new Error(`Failed to get repo: ${res.stderr}`)
  return JSON.parse(res.stdout).nameWithOwner
}

export function fetchActionableItems() {
  const repo = getRepo()
  const prNumber = getPrNumber()

  const reviewsRes = runCommand('gh', ['api', `repos/${repo}/pulls/${prNumber}/reviews`, '--paginate', '--slurp'])
  const reviews = reviewsRes.ok ? JSON.parse(reviewsRes.stdout).flat() : []

  const commentsRes = runCommand('gh', ['api', `repos/${repo}/pulls/${prNumber}/comments`, '--paginate', '--slurp'])
  const comments = commentsRes.ok ? JSON.parse(commentsRes.stdout).flat() : []

  const actionable = []

  for (const c of comments) {
    const author = c.user?.login || ''
    if (config.reviewers?.ignoredLogins?.includes(author)) continue

    const botEntry = config.reviewers?.recognizedBots?.find(b => b.id.toLowerCase() === author.toLowerCase())
    let isAct = false
    if (botEntry && botEntry.actionableKeywords) {
      isAct = botEntry.actionableKeywords.some(kw => (c.body || '').toLowerCase().includes(kw.toLowerCase()))
    } else {
      isAct = /\b(fix|bug|issue|todo|suggest|broken|fails)\b/i.test(c.body || '')
    }

    if (isAct) {
      actionable.push({
        id: c.id,
        author,
        path: c.path,
        line: c.line || c.original_line,
        url: c.html_url,
        body: c.body
      })
    }
  }

  return { repo, prNumber, reviews, actionable }
}

export function runDodVerification() {
  console.log('Running Definition of Done checks...')

  console.log('1. Typecheck: tsc --noEmit...')
  const tc = runCommand('npm', ['run', 'typecheck'])
  if (!tc.ok) {
    console.error('Typecheck failed:', tc.stderr || tc.stdout)
    return false
  }

  console.log('2. Unit Tests: vitest...')
  const tests = runCommand('npm', ['test'])
  if (!tests.ok) {
    console.error('Tests failed:', tests.stderr || tests.stdout)
    return false
  }

  console.log('3. Traceability Coverage...')
  const cov = runCommand('python', ['../docs/04-приёмочные-тесты/traceability/check-coverage.py'])
  if (!cov.ok) {
    console.error('Traceability failed:', cov.stderr || cov.stdout)
    return false
  }

  console.log('All DoD checks passed (100% green)!')
  return true
}

async function main() {
  const args = process.argv.slice(2)

  if (args.includes('--check-dod')) {
    const passed = runDodVerification()
    process.exit(passed ? 0 : 1)
  }

  try {
    const items = fetchActionableItems()
    console.log(`PR #${items.prNumber} on ${items.repo}: ${items.actionable.length} actionable items found.`)

    const outDir = join(process.cwd(), '.automation')
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true })
    writeFileSync(join(outDir, 'pending-fixes.json'), JSON.stringify(items, null, 2), 'utf8')
    console.log(`Saved tasks to .automation/pending-fixes.json`)
  } catch (err) {
    console.error(`Error: ${err.message}`)
    process.exit(1)
  }
}

if (process.argv[1]?.endsWith('auto-resolve-reviews.mjs')) {
  main()
}
