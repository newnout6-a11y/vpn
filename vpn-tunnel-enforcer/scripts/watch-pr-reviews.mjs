#!/usr/bin/env node
/**
 * Reviewer Comment & PR Feedback Watcher
 *
 * Automatically inspects and watches GitHub PR reviews and reviewer comments
 * across all configured reviewers (CodeRabbit, Revix, Greptile, human reviewers, etc.).
 *
 * Configured via reviewer-automation.config.json.
 *
 * Usage:
 *   node scripts/watch-pr-reviews.mjs [--once] [--pr <num>]
 *   node scripts/watch-pr-reviews.mjs --watch [--interval <seconds>]
 *   node scripts/watch-pr-reviews.mjs --json
 */

import { execFileSync } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'

const args = process.argv.slice(2)
const isWatch = args.includes('--watch')
const isJson = args.includes('--json')
const prIndex = args.indexOf('--pr')
const explicitPr = prIndex !== -1 && args[prIndex + 1] ? args[prIndex + 1] : null
const intervalIndex = args.indexOf('--interval')
const parsedInterval = intervalIndex !== -1 ? parseInt(args[intervalIndex + 1], 10) : NaN
const intervalSec = Number.isFinite(parsedInterval) && parsedInterval >= 5 ? parsedInterval : 30

// Load reviewer automation config if present
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
      ],
      humans: { enabled: true, allowAll: true },
      ignoredLogins: ['github-actions[bot]', 'dependabot[bot]']
    }
  }
}

const config = loadConfig()

function runGh(ghArgs) {
  try {
    const stdout = execFileSync('gh', ghArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
    return stdout.trim()
  } catch (err) {
    if (err.stderr) {
      throw new Error(`gh error: ${err.stderr.trim()}`)
    }
    throw err
  }
}

function getRepoInfo() {
  const repoJson = runGh(['repo', 'view', '--json', 'nameWithOwner'])
  return JSON.parse(repoJson).nameWithOwner
}

function getCurrentPrNumber() {
  if (explicitPr) return explicitPr
  const prJson = runGh(['pr', 'view', '--json', 'number,title,url,headRefName'])
  const pr = JSON.parse(prJson)
  return pr.number
}

function fetchPrData(repo, prNumber) {
  // Use --paginate and --slurp to retrieve all paginated pages and flatten them
  const reviewsRaw = runGh(['api', `repos/${repo}/pulls/${prNumber}/reviews`, '--paginate', '--slurp'])
  const rawReviews = JSON.parse(reviewsRaw)
  const reviews = Array.isArray(rawReviews) ? rawReviews.flat() : []

  const inlineCommentsRaw = runGh(['api', `repos/${repo}/pulls/${prNumber}/comments`, '--paginate', '--slurp'])
  const rawInline = JSON.parse(inlineCommentsRaw)
  const inlineComments = Array.isArray(rawInline) ? rawInline.flat() : []

  const issueCommentsRaw = runGh(['api', `repos/${repo}/issues/${prNumber}/comments`, '--paginate', '--slurp'])
  const rawIssue = JSON.parse(issueCommentsRaw)
  const issueComments = Array.isArray(rawIssue) ? rawIssue.flat() : []

  return { reviews, inlineComments, issueComments }
}

function isActionableComment(comment) {
  const body = comment.body || ''
  const login = comment.user?.login || ''

  const ignored = config.reviewers?.ignoredLogins || []
  if (ignored.includes(login)) return false

  const botConfig = config.reviewers?.recognizedBots?.find(b => b.id === login)
  if (botConfig && botConfig.actionableKeywords) {
    return botConfig.actionableKeywords.some(kw => body.toLowerCase().includes(kw.toLowerCase()))
  }

  // Generic actionable indicators for human or other bot reviewers
  return /fix|issue|bug|problem|todo|warning|please update|should be|suggest/i.test(body)
}

function printSummary(repo, prNumber, data) {
  const { reviews, inlineComments, issueComments } = data

  const actionableComments = inlineComments.filter(isActionableComment)

  if (isJson) {
    console.log(JSON.stringify({
      repo,
      prNumber,
      totalReviews: reviews.length,
      totalInlineComments: inlineComments.length,
      actionableCount: actionableComments.length,
      actionableComments: actionableComments.map(c => ({
        id: c.id,
        author: c.user?.login,
        path: c.path,
        line: c.line || c.original_line,
        url: c.html_url,
        body: c.body
      })),
      reviews,
      inlineComments,
      issueComments
    }, null, 2))
    return
  }

  console.log(`\n======================================================================`)
  console.log(`🔍 Review Feedback for ${repo} PR #${prNumber}`)
  console.log(`Configured Reviewers: ${config.reviewers?.recognizedBots?.map(b => b.name).join(', ') || 'Default'}`)
  console.log(`======================================================================`)

  // Reviews summary
  console.log(`\n📋 Reviews Submitted (${reviews.length}):`)
  if (reviews.length === 0) {
    console.log('   (No formal reviews submitted yet)')
  } else {
    for (const r of reviews) {
      const stateBadge = r.state === 'APPROVED' ? '✅ APPROVED' : r.state === 'CHANGES_REQUESTED' ? '❌ CHANGES REQUESTED' : `💬 ${r.state}`
      console.log(`   • @${r.user?.login} [${stateBadge}] - ${r.submitted_at || r.created_at}`)
      if (r.body) {
        const bodyLines = r.body.split('\n').filter(Boolean)
        const preview = bodyLines.slice(0, 3).join('\n     ')
        console.log(`     ${preview}`)
      }
    }
  }

  // Actionable inline comments
  console.log(`\n💬 Actionable Code Comments (${actionableComments.length} of ${inlineComments.length}):`)
  if (actionableComments.length === 0) {
    console.log('   (No pending actionable comments detected)')
  } else {
    for (const c of actionableComments) {
      console.log(`   ------------------------------------------------------------------`)
      console.log(`   📍 ${c.path}:${c.line || c.original_line} by @${c.user?.login}`)
      console.log(`   🔗 ${c.html_url}`)
      const lines = c.body.split('\n').filter(Boolean)
      const firstLines = lines.slice(0, 4).join('\n      ')
      console.log(`      ${firstLines}`)
    }
  }

  // General Issue Comments
  const reviewerIssueComments = issueComments.filter(c => !config.reviewers?.ignoredLogins?.includes(c.user?.login))
  console.log(`\n💬 Discussion Comments (${reviewerIssueComments.length}):`)
  for (const c of reviewerIssueComments.slice(-3)) {
    console.log(`   • @${c.user?.login}: ${c.body.split('\n')[0].slice(0, 80)}`)
  }

  console.log(`\n======================================================================\n`)
}

async function main() {
  try {
    const repo = getRepoInfo()
    const prNumber = getCurrentPrNumber()

    if (!isWatch) {
      const data = fetchPrData(repo, prNumber)
      printSummary(repo, prNumber, data)
      return
    }

    console.log(`👀 Watching for reviewer comments on ${repo} PR #${prNumber} (interval: ${intervalSec}s)...`)
    let seenCommentIds = new Set()
    let seenReviewIds = new Set()

    // Prime initial
    const initial = fetchPrData(repo, prNumber)
    initial.reviews.forEach(r => seenReviewIds.add(r.id))
    initial.inlineComments.forEach(c => seenCommentIds.add(c.id))
    printSummary(repo, prNumber, initial)

    while (true) {
      await new Promise(res => setTimeout(res, intervalSec * 1000))
      try {
        const current = fetchPrData(repo, prNumber)
        const newReviews = current.reviews.filter(r => !seenReviewIds.has(r.id))
        const newComments = current.inlineComments.filter(c => !seenCommentIds.has(c.id))

        if (newReviews.length > 0 || newComments.length > 0) {
          console.log(`\n🔔 [${new Date().toLocaleTimeString()}] NEW REVIEW FEEDBACK RECEIVED!`)
          newReviews.forEach(r => {
            seenReviewIds.add(r.id)
            console.log(`   📢 New review from @${r.user?.login}: ${r.state}`)
          })
          newComments.forEach(c => {
            seenCommentIds.add(c.id)
            const actionable = isActionableComment(c) ? ' [ACTIONABLE]' : ''
            console.log(`   💬 New inline comment${actionable} on ${c.path}:${c.line || c.original_line} by @${c.user?.login}`)
            console.log(`      ${c.body.slice(0, 150)}...`)
          })
        }
      } catch (pollErr) {
        console.error(`Poll error: ${pollErr.message}`)
      }
    }
  } catch (err) {
    console.error(`Error: ${err.message}`)
    process.exit(1)
  }
}

main()
