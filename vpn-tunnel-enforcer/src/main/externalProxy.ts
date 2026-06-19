import { app } from 'electron'
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http'
import { access, copyFile, mkdir, stat, writeFile } from 'fs/promises'
import { join } from 'path'
import { randomBytes, timingSafeEqual } from 'crypto'
import { serverPicker } from './serverPicker'
import { logEvent } from './appLogger'
import type { ServerProfile } from '../shared/ipc-types'

const CONTROL_HOST = '127.0.0.1'
export const EXTERNAL_PROXY_CONTROL_PORT = 17873
const DEFAULT_PROXY_PORT = 17990
const RUNTIME_EXE_NAME = 'vpnte-external-proxy.exe'
export const EXTERNAL_PROXY_CONTROL_TOKEN_HEADER = 'x-vpnte-control-token'
const CONTROL_TOKEN_FILE = 'external-proxy-control-token'

type ExternalProxyAction = 'start' | 'rotate' | 'connect' | 'trigger'

export interface ExternalProxyStatus {
  running: boolean
  host: string
  port: number | null
  proxyUrl: string | null
  profileId: string | null
  profileName: string | null
  country: string | null
  pid: number | null
  startedAt: number | null
}

export interface ExternalProxyProfileRow {
  id: string
  name: string
  country: string | null
  protocol: string
  server: string
  port: number
  groupId: string | null
  active: boolean
}

interface StartExternalProxyOptions {
  country?: string | null
  profileId?: string | null
  port?: number | null
  action?: ExternalProxyAction
}

interface ExternalProxyState {
  process: ChildProcessWithoutNullStreams | null
  port: number | null
  profileId: string | null
  profileName: string | null
  country: string | null
  startedAt: number | null
  lastCountryQuery: string | null
}

const state: ExternalProxyState = {
  process: null,
  port: null,
  profileId: null,
  profileName: null,
  country: null,
  startedAt: null,
  lastCountryQuery: null
}

let controlServer: Server | null = null
let controlToken: string | null = null
let operationLock: Promise<void> = Promise.resolve()
let controlServerStarting = false

function externalRuntimeDir(): string {
  return join(app.getPath('userData'), 'external-proxy-runtime')
}

function controlTokenPath(): string {
  return join(app.getPath('userData'), CONTROL_TOKEN_FILE)
}

async function ensureControlToken(): Promise<string> {
  if (controlToken) return controlToken
  controlToken = randomBytes(32).toString('hex')
  await mkdir(app.getPath('userData'), { recursive: true })
  await writeFile(controlTokenPath(), controlToken + '\n', { encoding: 'utf8', mode: 0o600 })
  return controlToken
}

function bundledResource(name: string): string {
  if (app.isPackaged) return join(process.resourcesPath, name)
  return join(app.getAppPath(), 'resources', name)
}

async function copyIfStale(src: string, dst: string): Promise<void> {
  try {
    const [srcStat, dstStat] = await Promise.all([stat(src), stat(dst)])
    if (srcStat.size === dstStat.size && srcStat.mtimeMs === dstStat.mtimeMs) return
  } catch {
    // Missing destination or stat failure: copy below.
  }
  await copyFile(src, dst)
}

function normalizeText(value: string | null | undefined): string {
  return String(value ?? '').trim().toLowerCase()
}

const COUNTRY_ALIASES: Record<string, string[]> = {
  ru: ['ru', 'rus', 'russia', 'россия', 'рф'],
  de: ['de', 'deu', 'germany', 'германия', 'немец'],
  nl: ['nl', 'nld', 'netherlands', 'holland', 'нидерланды', 'голланд'],
  gb: ['gb', 'uk', 'united kingdom', 'great britain', 'britain', 'англия', 'британия', 'великобритания'],
  us: ['us', 'usa', 'united states', 'america', 'сша', 'америка'],
  se: ['se', 'swe', 'sweden', 'швеция'],
  fi: ['fi', 'fin', 'finland', 'финляндия'],
  fr: ['fr', 'fra', 'france', 'франция'],
  tr: ['tr', 'turkey', 'турция'],
  jp: ['jp', 'jpn', 'japan', 'япония'],
  sg: ['sg', 'singapore', 'сингапур'],
  kz: ['kz', 'kazakhstan', 'казахстан']
}

function countryNeedles(query: string | null | undefined): string[] {
  const q = normalizeText(query)
  if (!q) return []
  const fromAlias = Object.values(COUNTRY_ALIASES).find((aliases) => aliases.includes(q))
  return fromAlias ?? [q]
}

function profileMatchesCountry(profile: ServerProfile, countryQuery: string | null | undefined): boolean {
  const needles = countryNeedles(countryQuery)
  if (!needles.length) return true
  const haystack = normalizeText(`${profile.country ?? ''} ${profile.name ?? ''}`)
  return needles.some((needle) => haystack.includes(needle))
}

function usableProfiles(countryQuery?: string | null): ServerProfile[] {
  return serverPicker
    .getProfiles()
    .filter((profile) => profile.enabled !== false && profile.outbound && typeof profile.outbound === 'object')
    .filter((profile) => profileMatchesCountry(profile, countryQuery))
}

function listExternalProxyProfiles(countryQuery?: string | null): ExternalProxyProfileRow[] {
  const activeId = serverPicker.getActiveProfileId()
  return usableProfiles(countryQuery).map((profile) => ({
    id: profile.id,
    name: profile.name,
    country: profile.country ?? null,
    protocol: profile.protocol,
    server: profile.server,
    port: profile.port,
    groupId: profile.groupId ?? null,
    active: profile.id === activeId
  }))
}

export function pickExternalProxyProfile(
  profiles: ServerProfile[],
  opts: { profileId?: string | null; country?: string | null; currentProfileId?: string | null; action?: ExternalProxyAction } = {}
): ServerProfile | null {
  const usable = profiles
    .filter((profile) => profile.enabled !== false && profile.outbound && typeof profile.outbound === 'object')
    .filter((profile) => profileMatchesCountry(profile, opts.country))
  if (!usable.length) return null

  const explicit = String(opts.profileId ?? '').trim()
  if (explicit) {
    return usable.find((profile) => profile.id === explicit) ?? null
  }

  if (opts.action === 'connect' || opts.action === 'trigger') return null

  if (opts.action === 'rotate' && opts.currentProfileId) {
    const currentIndex = usable.findIndex((profile) => profile.id === opts.currentProfileId)
    return usable[(currentIndex >= 0 ? currentIndex + 1 : 0) % usable.length] ?? usable[0]
  }

  const active = serverPicker.getActiveProfile()
  if (active && usable.some((profile) => profile.id === active.id)) return active
  return usable[0]
}

export function buildExternalProxyConfig(profile: ServerProfile, port: number): Record<string, unknown> {
  const outbound = {
    ...(profile.outbound as Record<string, unknown>),
    tag: 'proxy-out'
  }

  return {
    log: { level: 'warn' },
    inbounds: [
      {
        type: 'mixed',
        tag: 'external-mixed-in',
        listen: CONTROL_HOST,
        listen_port: port
      }
    ],
    outbounds: [
      outbound,
      { type: 'direct', tag: 'direct-out' },
      { type: 'block', tag: 'block-out' }
    ],
    route: {
      rules: [
        { action: 'sniff' },
        { protocol: 'dns', outbound: 'proxy-out' }
      ],
      final: 'proxy-out',
      auto_detect_interface: false
    }
  }
}

async function stageRuntime(profile: ServerProfile, port: number): Promise<{ exe: string; config: string; cwd: string }> {
  const runtimeDir = externalRuntimeDir()
  await mkdir(runtimeDir, { recursive: true })

  const src = bundledResource('sing-box.exe')
  const exe = join(runtimeDir, RUNTIME_EXE_NAME)
  const config = join(runtimeDir, 'external-proxy.json')

  await access(src)
  await copyIfStale(src, exe)
  await writeFile(config, JSON.stringify(buildExternalProxyConfig(profile, port), null, 2), 'utf8')

  return { exe, config, cwd: runtimeDir }
}

function parsePort(raw: unknown): number {
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return DEFAULT_PROXY_PORT
  return n
}

async function withExternalProxyOperation<T>(fn: () => Promise<T>): Promise<T> {
  const previous = operationLock
  let release!: () => void
  operationLock = new Promise<void>((resolve) => {
    release = resolve
  })
  await previous.catch(() => undefined)
  try {
    return await fn()
  } finally {
    release()
  }
}

async function stopExternalProxyUnlocked(reason = 'requested'): Promise<ExternalProxyStatus> {
  const proc = state.process
  state.process = null
  if (proc && !proc.killed) {
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 1500)
      proc.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
      try {
        proc.kill()
      } catch (err) {
        clearTimeout(timer)
        logEvent('warn', 'external-proxy', 'failed to kill external proxy process', err)
        resolve()
      }
    })
  }
  logEvent('info', 'external-proxy', 'stopped', { reason })
  state.port = null
  state.profileId = null
  state.profileName = null
  state.country = null
  state.startedAt = null
  return getExternalProxyStatus()
}

async function stopExternalProxy(reason = 'requested'): Promise<ExternalProxyStatus> {
  return withExternalProxyOperation(() => stopExternalProxyUnlocked(reason))
}

async function startExternalProxyUnlocked(options: StartExternalProxyOptions = {}): Promise<ExternalProxyStatus> {
  const port = parsePort(options.port ?? state.port ?? DEFAULT_PROXY_PORT)
  const country = options.country ?? state.lastCountryQuery
  const profiles = usableProfiles(country)
  const profile = pickExternalProxyProfile(profiles, {
    profileId: options.profileId,
    country,
    currentProfileId: state.profileId,
    action: options.action ?? 'start'
  })
  if ((options.action === 'connect' || options.action === 'trigger') && options.profileId && !profile) {
    throw new Error(`VPN profile not found or unusable: ${options.profileId}`)
  }
  if (!profile) {
    throw new Error(country ? `No VPN profiles found for country: ${country}` : 'No VPN profiles with outbound config found')
  }

  const runtime = await stageRuntime(profile, port)
  await new Promise<void>((resolve, reject) => {
    const check = spawn(runtime.exe, ['check', '-c', runtime.config], { cwd: runtime.cwd, windowsHide: true })
    let stderr = ''
    check.stderr.on('data', (chunk) => { stderr += String(chunk) })
    check.once('error', reject)
    check.once('exit', (code) => {
      if (code === 0) resolve()
      else reject(new Error(stderr.trim() || `sing-box check failed with exit code ${code}`))
    })
  })

  if (state.process) {
    await stopExternalProxyUnlocked(options.action === 'rotate' ? 'rotate' : options.action === 'connect' || options.action === 'trigger' ? 'trigger' : 'restart')
  }

  const proc = spawn(runtime.exe, ['run', '-c', runtime.config], { cwd: runtime.cwd, windowsHide: true })
  state.process = proc
  state.port = port
  state.profileId = profile.id
  state.profileName = profile.name
  state.country = profile.country ?? null
  state.startedAt = Date.now()
  state.lastCountryQuery = country ?? null

  proc.stdout.on('data', (chunk) => logEvent('debug', 'external-proxy', String(chunk).trim()))
  proc.stderr.on('data', (chunk) => logEvent('warn', 'external-proxy', String(chunk).trim()))
  proc.once('exit', (code, signal) => {
    if (state.process === proc) {
      logEvent('warn', 'external-proxy', 'process exited', { code, signal })
      state.process = null
      state.port = null
      state.profileId = null
      state.profileName = null
      state.country = null
      state.startedAt = null
    }
  })

  try {
    serverPicker.selectProfile(profile.id)
  } catch {
    // Selection is a UI convenience only; the proxy already has its config.
  }

  logEvent('info', 'external-proxy', 'started', {
    port,
    profileId: profile.id,
    profileName: profile.name,
    country: profile.country ?? null,
    pid: proc.pid
  })

  return getExternalProxyStatus()
}

async function startExternalProxy(options: StartExternalProxyOptions = {}): Promise<ExternalProxyStatus> {
  return withExternalProxyOperation(() => startExternalProxyUnlocked(options))
}

function getExternalProxyStatus(): ExternalProxyStatus {
  const running = Boolean(state.process && !state.process.killed)
  return {
    running,
    host: CONTROL_HOST,
    port: running ? state.port : null,
    proxyUrl: running && state.port ? `http://${CONTROL_HOST}:${state.port}` : null,
    profileId: running ? state.profileId : null,
    profileName: running ? state.profileName : null,
    country: running ? state.country : null,
    pid: running ? state.process?.pid ?? null : null,
    startedAt: running ? state.startedAt : null
  }
}

function formatProfileListText(rows: ExternalProxyProfileRow[]): string {
  return rows
    .map((row) => [
      row.id,
      row.country ?? '',
      row.protocol,
      `${row.server}:${row.port}`,
      row.active ? 'active' : '',
      row.name
    ].join('\t'))
    .join('\n')
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let raw = ''
    req.on('data', (chunk: Buffer) => {
      raw += String(chunk)
      if (raw.length > 64 * 1024) req.destroy()
    })
    req.on('end', () => {
      if (!raw.trim()) return resolve({})
      try {
        resolve(JSON.parse(raw))
      } catch {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

function send(res: ServerResponse, status: number, payload: unknown, text = false): void {
  const body = text ? String(payload) : JSON.stringify(payload, null, 2)
  res.writeHead(status, {
    'Content-Type': text ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': 'http://127.0.0.1',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': `Content-Type, ${EXTERNAL_PROXY_CONTROL_TOKEN_HEADER}, Authorization`,
    'Vary': 'Origin'
  })
  res.end(body + (text ? '\n' : ''))
}

export function isExternalProxyMutationPath(path: string): boolean {
  return path === '/start' || path === '/rotate' || path === '/connect' || path === '/trigger' || path === '/stop'
}

export function isValidExternalProxyControlToken(expected: string | null, provided: string | null | undefined): boolean {
  if (!expected || !provided) return false
  const expectedBuffer = Buffer.from(expected)
  const providedBuffer = Buffer.from(provided)
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer)
}

function requestControlToken(req: IncomingMessage): string | null {
  const header = req.headers[EXTERNAL_PROXY_CONTROL_TOKEN_HEADER]
  if (Array.isArray(header)) return header[0] ?? null
  if (typeof header === 'string' && header.trim()) return header.trim()
  const auth = req.headers.authorization
  if (typeof auth === 'string') {
    const match = auth.match(/^Bearer\s+(.+)$/i)
    if (match) return match[1].trim()
  }
  return null
}

async function handleControlRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') return send(res, 204, '', true)
  const url = new URL(req.url ?? '/', `http://${CONTROL_HOST}:${EXTERNAL_PROXY_CONTROL_PORT}`)
  const path = url.pathname.replace(/^\/api\/external-proxy/, '')
  const wantsText = url.searchParams.get('format') === 'text' || url.searchParams.get('text') === '1'

  if (isExternalProxyMutationPath(path)) {
    if (req.method !== 'POST') {
      return send(res, 405, wantsText ? 'method-not-allowed' : { ok: false, error: 'method-not-allowed' }, wantsText)
    }
    if (!isValidExternalProxyControlToken(controlToken, requestControlToken(req))) {
      return send(res, 401, wantsText ? 'unauthorized' : { ok: false, error: 'unauthorized' }, wantsText)
    }
  } else if (req.method !== 'GET') {
    return send(res, 405, wantsText ? 'method-not-allowed' : { ok: false, error: 'method-not-allowed' }, wantsText)
  }

  const body = req.method === 'POST' ? await readBody(req) : {}
  const param = (name: string): string | null => {
    const fromQuery = url.searchParams.get(name)
    if (fromQuery !== null) return fromQuery
    const fromBody = body[name]
    return typeof fromBody === 'string' || typeof fromBody === 'number' ? String(fromBody) : null
  }

  try {
    if (path === '/status' || path === '/') {
      const status = getExternalProxyStatus()
      return send(res, 200, wantsText ? (status.proxyUrl ?? 'stopped') : status, wantsText)
    }
    if (path === '/list') {
      const rows = listExternalProxyProfiles(param('country'))
      return send(res, 200, wantsText ? formatProfileListText(rows) : { profiles: rows }, wantsText)
    }
    if (path === '/start' || path === '/rotate' || path === '/connect' || path === '/trigger') {
      const status = await startExternalProxy({
        action: path === '/rotate' ? 'rotate' : path === '/connect' ? 'connect' : path === '/trigger' ? 'trigger' : 'start',
        country: param('country'),
        profileId: param('profileId') ?? param('id'),
        port: param('port') ? parsePort(param('port')) : null
      })
      return send(res, 200, wantsText ? status.proxyUrl ?? '' : status, wantsText)
    }
    if (path === '/stop') {
      const status = await stopExternalProxy('api')
      return send(res, 200, wantsText ? 'stopped' : status, wantsText)
    }
    return send(res, 404, { ok: false, error: 'not-found' })
  } catch (err: any) {
    logEvent('warn', 'external-proxy', 'control request failed', { path, error: err?.message || String(err) })
    return send(res, 500, wantsText ? (err?.message || String(err)) : { ok: false, error: err?.message || String(err) }, wantsText)
  }
}

export function registerExternalProxyControlServer(): void {
  if (controlServer || controlServerStarting) return
  controlServerStarting = true
  const port = Number(process.env.VPNTE_CONTROL_PORT || EXTERNAL_PROXY_CONTROL_PORT)
  ensureControlToken().then(() => {
    controlServer = createServer((req, res) => {
      handleControlRequest(req, res).catch((err) => {
        send(res, 500, { ok: false, error: err?.message || String(err) })
      })
    })
    controlServer.listen(port, CONTROL_HOST, () => {
      controlServerStarting = false
      logEvent('info', 'external-proxy', 'control server listening', { host: CONTROL_HOST, port, tokenFile: controlTokenPath() })
    })
    controlServer.on('error', (err) => {
      controlServerStarting = false
      logEvent('warn', 'external-proxy', 'control server failed', err)
      controlServer = null
    })
  }).catch((err) => {
    controlServerStarting = false
    logEvent('warn', 'external-proxy', 'failed to initialize control token', { error: (err as Error).message })
  })
}

export const externalProxy = {
  start: startExternalProxy,
  stop: stopExternalProxy,
  status: getExternalProxyStatus,
  list: listExternalProxyProfiles,
  registerControlServer: registerExternalProxyControlServer
}
