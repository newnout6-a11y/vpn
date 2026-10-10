#!/usr/bin/env node
/**
 * Reviewer Comment & PR Feedback Watcher
 *
 * Automatically inspects and watches GitHub PR reviews and reviewer comments
 * (including CodeRabbit AI reviews, human reviews, and inline diff comments).
 *
 * Usage:
 *   node scripts/watch-pr-reviews.mjs [--once] [--pr <num>]
 *   node scripts/watch-pr-reviews.mjs --watch [--interval <seconds>]
 *   node scripts/watch-pr-reviews.mjs --json
 */

import { execFileSync } from 'child_process'

const args = process.argv.slice(2)
const isWatch = args.includes('--watch')
const isJson = args.includes('--json')
const prIndex = args.indexOf('--pr')
const explicitPr = prIndex !== -1 && args[prIndex + 1] ? args[prIndex + 1] : null
const intervalIndex = args.indexOf('--interval')
const intervalSec = intervalIndex !== -1 && args[intervalIndex + 1] ? parseInt(args[intervalIndex + 1], 10) : 30

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
  const reviewsRaw = runGh(['api', `repos/${repo}/pulls/${prNumber}/reviews`])
  const reviews = JSON.parse(reviewsRaw)

  const inlineCommentsRaw = runGh(['api', `repos/${repo}/pulls/${prNumber}/comments`])
  const inlineComments = JSON.parse(inlineCommentsRaw)

  const issueCommentsRaw = runGh(['api', `repos/${repo}/issues/${prNumber}/comments`])
  const issueComments = JSON.parse(issueCommentsRaw)

  return { reviews, inlineComments, issueComments }
}

function formatComment(comment) {
  const author = comment.user?.login || 'unknown'
  const isBot = author.includes('[bot]') || author.toLowerCase().includes('coderabbit')
  const path = comment.path || null
  const line = comment.line || comment.original_line || null
  const body = comment.body || ''
  const url = comment.html_url || ''
  const createdAt = comment.created_at || ''

  return {
    id: comment.id,
    author,
    isBot,
    path,
    line,
    body,
    url,
    createdAt
  }
}

function printSummary(repo, prNumber, data) {
  const { reviews, inlineComments, issueComments } = data

  if (isJson) {
    console.log(JSON.stringify({ repo, prNumber, reviews, inlineComments, issueComments }, null, 2))
    return
  }

  console.log(`\n======================================================================`)
  console.log(`🔍 Review Feedback for ${repo} PR #${prNumber}`)
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
        const preview = r.body.split('\n')[0].slice(0, 100)
        console.log(`     "${preview}..."`)
      }
    }
  }

  // Inline comments
  console.log(`\n💬 Inline Code Comments (${inlineComments.length}):`)
  if (inlineComments.length === 0) {
    console.log('   (No inline diff comments)')
  } else {
    for (const c of inlineComments) {
      console.log(`   ------------------------------------------------------------------`)
      console.log(`   📍 ${c.path}:${c.line || c.original_line} by @${c.user?.login}`)
      console.log(`   🔗 ${c.html_url}`)
      // Extract brief excerpt or AI prompt if available
      const lines = c.body.split('\n').filter(Boolean)
      const firstLines = lines.slice(0, 4).join('\n      ')
      console.log(`      ${firstLines}`)
    }
  }

  // General Issue Comments
  const reviewerIssueComments = issueComments.filter(c => c.user?.login !== 'github-actions[bot]')
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
            console.log(`   💬 New inline comment on ${c.path}:${c.line || c.original_line} by @${c.user?.login}`)
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
