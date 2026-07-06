import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const appSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'App.tsx'), 'utf8')
const dashboardSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Dashboard.tsx'), 'utf8')
const serversSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Servers.tsx'), 'utf8')
const splitTunnelSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'SplitTunnel.tsx'), 'utf8')
const maintenanceSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Maintenance.tsx'), 'utf8')
const settingsSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Settings.tsx'), 'utf8')
const storeSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'store.ts'), 'utf8')
const serverDetailSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'components', 'ServerDetailModal.tsx'), 'utf8')
const browserIpCardSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'components', 'BrowserIpCard.tsx'), 'utf8')
const preloadSource = () => readFileSync(join(process.cwd(), 'src', 'preload', 'index.ts'), 'utf8')
const macSelectSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'design-system', 'MacSelect.tsx'), 'utf8')

describe('App source regressions', () => {
  it('marks restarting before clearing the busy flag on terminal statuses', () => {
    const source = appSource()
    const handlerStart = source.indexOf('onTunStatusChanged')
    const setRestarting = source.indexOf('store.setRestarting', handlerStart)
    const clearBusy = source.indexOf('store.setConnectionBusy(null)', handlerStart)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(setRestarting).toBeGreaterThan(handlerStart)
    expect(setRestarting).toBeLessThan(clearBusy)
  })

  it('backs off periodic Happ detection failures', () => {
    const source = appSource()

    expect(source).toContain('detectHappFailureCountRef')
    expect(source).toContain('detectHappNextAllowedAtRef')
    expect(source).toContain('Date.now() < detectHappNextAllowedAtRef.current')
    expect(source).toContain('90_000 * (2 ** failures)')
  })

  it('keeps server-switch stop/start transitions from surfacing leak and disconnect UI', () => {
    const source = appSource()

    expect(source).toContain('store.serverSwitchingName && isLeak')
    expect(source).toContain("isServerSwitching && status === 'stopped'")
    expect(source).toContain("status === 'stopped' && !isServerSwitching")
    expect(source).toContain('stoppingNowRef.current || useAppStore.getState().serverSwitchingName')
  })

  it('suppresses transient firewall banners during TUN status handoffs', () => {
    const app = appSource()
    const dashboard = dashboardSource()

    expect(app).toContain('suppressFirewallBannerBriefly')
    expect(app).toContain('suppressFirewallBannerUntil={firewallBannerSuppressUntil}')
    expect(app).toContain('setFirewallBannerSuppressUntil(current => current === until ? 0 : current)')
    expect(dashboard).toContain('suppressFirewallBannerUntil?: number')
    expect(dashboard).toContain('Date.now() >= suppressFirewallBannerUntil')
  })

  it('keeps large server/app lists off expensive layout animations', () => {
    const servers = serversSource()
    const splitTunnel = splitTunnelSource()

    expect(servers).not.toContain('<AnimatePresence initial={false}>')
    expect(servers).not.toContain('<motion.div\n      layout')
    expect(servers).not.toContain("animate={{ height: 'auto'")
    expect(splitTunnel).not.toContain('framer-motion')
    expect(splitTunnel).not.toContain('<motion.div\n      layout')
    expect(servers).toContain('initial={{ opacity: 0 }}')
  })

  it('does not block the Servers page first paint on group metadata', () => {
    const servers = serversSource()
    const effectStart = servers.indexOf('void fetchProfiles().finally')
    const groupsStart = servers.indexOf('void fetchGroups()', effectStart)

    expect(effectStart).toBeGreaterThanOrEqual(0)
    expect(groupsStart).toBeGreaterThan(effectStart)
    expect(servers).not.toContain('await refreshAll()\n      } finally {\n        if (mounted) setLoading(false)')
  })

  it('exposes a separate proxy-list export action on the Servers page', () => {
    const servers = serversSource()
    const preload = preloadSource()

    expect(servers).toContain('handleExportProxyList')
    expect(servers).toContain('serversExportAllProxiesToFile')
    expect(servers).toContain("t('servers.exportProxyList', 'Proxy list')")
    expect(preload).toContain("serversExportAllProxiesToFile: () => ipcRenderer.invoke('servers:export-all-proxies-file')")
  })

  it('keeps server add selects above the server list and shows key-loading feedback', () => {
    const servers = serversSource()
    const select = macSelectSource()
    const splitTunnel = splitTunnelSource()

    expect(select).not.toContain('createPortal')
    expect(select).toContain("open && 'z-[120]'")
    expect(select).toContain("'absolute z-[130] w-full mt-1 py-1'")
    expect(servers).toContain('<MacCard className="relative z-30 overflow-visible">')
    expect(servers).toContain("t('servers.add.loadingKeys', 'Загружаем и проверяем ключи...')")
    expect(servers).toContain('<MacProgress indeterminate size="sm"')
    expect(servers).toContain('disabled={adding || (!groupsAvailable && groupOptions.length === 1)}')
    expect(servers).toContain('bulkNotice')
    expect(servers).toContain('servers.exportKeysWorking')
    expect(servers).toContain('servers.exportProxyListWorking')
    expect(servers).not.toContain('hoverable={!isSwitching}')
    expect(splitTunnel).toContain('transition-colors duration-100')
  })

  it('cleans corrupt split-tunnel display paths without mutating route paths', () => {
    const splitTunnel = splitTunnelSource()

    expect(splitTunnel).toContain('displaySplitTunnelPath')
    expect(splitTunnel).toContain('hasCorruptPathText')
    expect(splitTunnel).toContain("return `${nextStem}${ext || (isLeaf ? '.exe' : '')}`")
    expect(splitTunnel).toContain('const displayPath = isProcess ?')
    expect(splitTunnel).toContain('title={displayPath}')
    expect(splitTunnel).toContain('{displayPath}')
    expect(splitTunnel).not.toContain("title={isProcess ? t('splitTunneling.commandSubtitle') : app.path}")
  })

  it('labels active firewall block-default as protection, not stale stuck state', () => {
    const maintenance = maintenanceSource()

    expect(maintenance).toContain('protectedTunnelActive?: boolean')
    expect(maintenance).toContain('firewallBlockDefaultLabel')
    expect(maintenance).toContain("'активная защита'")
    expect(maintenance).toContain('block default: {firewallBlockDefaultLabel(firewallHealth)}')
    expect(maintenance).not.toContain('stuck block:')
  })

  it('keeps the geo privacy setting honest for server detail lookups', () => {
    const detail = serverDetailSource()
    const settings = settingsSource()
    const browserIp = browserIpCardSource()

    expect(settings).toContain('Не делать онлайн-гео lookup в приложении')
    expect(settings).toContain('ipapi.co, ip-api.com, ipwho.is, ipinfo или iplocation')
    expect(settings).toContain('Это не меняет сайты вроде 2ip.ru')
    expect(detail).toContain('const disableGeoLookup = useAppStore(s => s.settings.disableGeoLookup)')
    expect(detail).toContain('setLoading(!disableGeoLookup)')
    expect(detail).toContain('if (!disableGeoLookup) {')
    expect(detail).toContain('fetch(`https://ipapi.co/${host}/json/`')
    expect(detail).toContain('}, [open, profile, disableGeoLookup])')
    expect(detail).toContain('(ipInfo || (!disableGeoLookup && fallbackCountry))')
    expect(browserIp).not.toContain('https://ipinfo.io/json')
  })

  it('keeps settings descriptions aligned with implemented settings behavior', () => {
    const settings = settingsSource()
    const store = storeSource()

    expect(settings).toContain('Оставляет DHCP/DNS физического адаптера как есть')
    expect(settings).toContain('узкие списки гос/карт')
    expect(settings).toContain('использует маршрут служебных загрузок')
    expect(settings).toContain('Открывает Починку и расширенные параметры')
    expect(settings).not.toContain('Открывает страницы Приложения и Починка')
    expect(settings).not.toContain('через выбранный proxy')
    expect(store).toContain('deepTrafficInspectionEnabled: false')
  })
})
