/**
 * Tests for classifyNavigation — the single source of truth for what the main
 * window is allowed to navigate to / open. Regression guard for S1 (a hostile
 * subscription supplying a malicious `webPageUrl` / link target).
 */

import { describe, it, expect } from 'vitest'
import { classifyNavigation } from './navigationPolicy'

describe('classifyNavigation — production (file:// renderer)', () => {
  const dev = undefined

  it('allows our own file:// origin (in-app routing/assets)', () => {
    expect(classifyNavigation('file:///C:/app/renderer/index.html', dev)).toBe('allow-internal')
    expect(classifyNavigation('file:///C:/app/renderer/assets/x.js', dev)).toBe('allow-internal')
  })

  it('sends external https to the OS browser', () => {
    expect(classifyNavigation('https://panel.example.com/sub', dev)).toBe('open-external')
    expect(classifyNavigation('http://example.com', dev)).toBe('open-external')
  })

  it('blocks dangerous schemes a hostile webPageUrl could smuggle', () => {
    expect(classifyNavigation('javascript:alert(1)', dev)).toBe('block')
    expect(classifyNavigation('data:text/html,<script>alert(1)</script>', dev)).toBe('block')
    expect(classifyNavigation('vbscript:msgbox(1)', dev)).toBe('block')
    expect(classifyNavigation('ms-settings:notifications', dev)).toBe('block')
    expect(classifyNavigation('happ://add/whatever', dev)).toBe('block')
    expect(classifyNavigation('file://other-host/share/evil.exe', dev)).toBe('block')
    // ^ file:// WITH a remote host is a UNC/remote path — never internal.
  })

  it('blocks malformed input', () => {
    expect(classifyNavigation('', dev)).toBe('block')
    expect(classifyNavigation('not a url', dev)).toBe('block')
    expect(classifyNavigation('://missing-scheme', dev)).toBe('block')
  })
})

describe('classifyNavigation — dev (HMR server)', () => {
  const dev = 'http://localhost:5173'

  it('allows same-origin dev navigation', () => {
    expect(classifyNavigation('http://localhost:5173/index.html', dev)).toBe('allow-internal')
    expect(classifyNavigation('http://localhost:5173/@vite/client', dev)).toBe('allow-internal')
  })

  it('treats a different http origin as external', () => {
    expect(classifyNavigation('http://localhost:9999/', dev)).toBe('open-external')
    expect(classifyNavigation('https://evil.example.com/', dev)).toBe('open-external')
  })

  it('still blocks dangerous schemes in dev', () => {
    expect(classifyNavigation('javascript:alert(1)', dev)).toBe('block')
    expect(classifyNavigation('data:text/html,x', dev)).toBe('block')
  })

  it('tolerates a malformed dev URL by falling back to scheme rules', () => {
    expect(classifyNavigation('https://example.com', 'not-a-url')).toBe('open-external')
    expect(classifyNavigation('javascript:alert(1)', 'not-a-url')).toBe('block')
  })
})
