import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

describe('watch-pr-reviews automation script', () => {
  it('exists and has executable structure', () => {
    const scriptPath = join(process.cwd(), 'scripts', 'watch-pr-reviews.mjs')
    expect(existsSync(scriptPath)).toBe(true)

    const content = readFileSync(scriptPath, 'utf8')
    expect(content).toContain('#!/usr/bin/env node')
    expect(content).toContain('getCurrentPrNumber')
    expect(content).toContain('fetchPrData')
    expect(content).toContain('printSummary')
    expect(content).toContain('--paginate')
    expect(content).toContain('--slurp')
    expect(content).toContain('loadConfig')
    expect(content).toContain('isActionableComment')
  })

  it('reviewer automation config exists and defines recognized bots and antigravity agent', () => {
    const configPath = join(process.cwd(), '..', 'reviewer-automation.config.json')
    expect(existsSync(configPath)).toBe(true)

    const cfg = JSON.parse(readFileSync(configPath, 'utf8'))
    expect(cfg.agent.engine).toBe('antigravity')
    expect(cfg.agent.model).toBe('gemini-3.8-flash-high')
    expect(cfg.agent.reasoningEffort).toBe('high')
    expect(cfg.reviewers.recognizedBots.some((b: any) => b.id === 'coderabbitai[bot]')).toBe(true)
    expect(cfg.reviewers.recognizedBots.some((b: any) => b.id === 'revixappdev[bot]')).toBe(true)
    expect(cfg.reviewers.recognizedBots.some((b: any) => b.id === 'greptile-apps[bot]')).toBe(true)
  })

  it('workflow for reviewer comments exists and specifies correct trigger events', () => {
    const workflowPath = join(process.cwd(), '..', '.github', 'workflows', 'on-reviewer-comment.yml')
    expect(existsSync(workflowPath)).toBe(true)

    const workflowContent = readFileSync(workflowPath, 'utf8')
    expect(workflowContent).toContain('pull_request_review:')
    expect(workflowContent).toContain('pull_request_review_comment:')
    expect(workflowContent).toContain('issue_comment:')
    expect(workflowContent).toContain('types: [submitted, edited]')
    expect(workflowContent).toContain('types: [created, edited]')
    expect(workflowContent).toContain("github.actor != 'github-actions[bot]'")
    expect(workflowContent).toContain('actions/github-script@v7')
    expect(workflowContent).toContain('NOTIFICATION_WEBHOOK_URL: ${{ secrets.NOTIFICATION_WEBHOOK_URL }}')
  })
})

