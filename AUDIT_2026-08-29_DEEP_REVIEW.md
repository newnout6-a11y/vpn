# Глубокое ревью VPN Tunnel Enforcer

**Дата:** 2026-08-29
**Ревизия:** ветка `main`, коммит `62bfe8c` (`docs: add architecture navigation`)
**Метод:** статическое чтение кода + граф знаний (`codebase-memory-mcp`, проект `C-Users-Redmi-CascadeProjects-vpn`, 4851 узлов / 10 866 связей). Приложение **не запускалось**, реальное поведение firewall / Wintun / маршрутов на живой Windows не проверялось.
**Статус выводов:** всё, что ниже, выведено из исходников с указанием `файл:строка`. Там, где вывод требует runtime-подтверждения, это помечено явно.

> **Находки 1-5 исправлены** в коммите `7132b51` (2026-08-29), в рекомендованном порядке 3 → 2 → 4 → 1 → 5. Разбор правок и оставшихся пробелов — в разделе [ЧТО ИСПРАВЛЕНО](#что-исправлено). Находки 6-9 и технический долг открыты.
>
> Текст ревью намеренно оставлен в состоянии на `62bfe8c` — ссылки `файл:строка` ниже указывают на код **до** исправлений. Ценность документа в рассуждении, которое привело к правкам, а оно читается только против того кода.

---

## 1. Что это за проект

Windows-приложение на Electron, которое загоняет весь трафик машины в контролируемый VPN-путь. Не обёртка над сторонним клиентом, а полноценный контроллер: сам генерирует конфиг sing-box, поднимает Wintun-адаптер, правит маршруты / DNS / firewall Windows и умеет всё это откатывать.

Три режима работы:

| Режим | Что делает |
|---|---|
| **Hard (TUN)** | свой `sing-box` + Wintun-адаптер, `auto_route` + `strict_route`, DNS-хайджек, опциональный firewall kill-switch |
| **local-proxy** | обёртка над локальным SOCKS5/HTTP-прокси, который поднял Happ или другой клиент |
| **Soft (Autoconfig)** | правка прокси-настроек Android Studio, Gradle, Git и переменных `HTTP_PROXY`/`HTTPS_PROXY` с откатом |

Целевая модель угроз — обход DPI/цензуры (RU-контекст): анти-DPI отпечатки TLS, smart-RU split routing, защита от отравления пингов, отказ от паттернов, которые сами триггерят фильтрацию.

---

## 2. Масштаб

| Слой | Строк | Файлов |
|---|---|---|
| `src/main` | 34 888 | 68 |
| `src/renderer` | 15 837 | 49 |
| `src/shared` | 776 | 2 |
| `src/preload` | 621 | 1 |
| Тесты | 10 674 | 78 |
| Rust ETW sidecar | 871 | 2 |
| PowerShell в `resources/` | 509 | 4 |

Итого ~52 тыс. строк продакшн-кода, ~10,7 тыс. строк тестов.

**Стек:** Electron 42, React 18, electron-vite, TypeScript 5.4, Zustand 4, TailwindCSS 3, i18next, Vitest 4, `sing-box` + Wintun, `electron-store`, `sudo-prompt`, `axios`, `socks`, `tldts`.

**IPC:** 159 каналов — 146 `ipcRenderer.invoke` + 13 push-событий main→renderer.

---

## 3. Архитектура

```
renderer (React)  →  preload (валидирующий bridge)  →  main (Electron)
                                                        ├── sing-box + Wintun
                                                        ├── Windows firewall / DNS / routes
                                                        ├── electron-store
                                                        └── PowerShell + Rust ETW sidecar
```

Семь доменов в `src/main`:

| Домен | Ключевые файлы |
|---|---|
| Tunnel runtime | `tunController.ts`, `tunAdapter.ts`, `connectionPlanner.ts`, `managedChildProcess.ts` |
| Network safety | `systemNetwork.ts`, `firewallKillSwitch.ts`, `granularKillSwitch.ts`, `physicalAdapterLockdown.ts`, `browserHardening.ts` |
| Profiles | `vpnProfiles.ts`, `serverPicker.ts`, `serverGroups.ts`, `serverProbe.ts`, `keyHealthChecker.ts` |
| Routing | `smartRoute.ts`, `ruleSetManager.ts`, `domainRouting.ts`, `dnsProfiles.ts`, `splitTunneling.ts` |
| Observability | `appLogger.ts`, `systemDiagnostics.ts`, `leakDiagnostics.ts`, `leakSelfTest.ts`, `trafficForensics.ts`, `systemSnapshot.ts`, `diagnosticsExport.ts` |
| Automation | `scheduler.ts`, `profileRotation.ts`, `autoPilot.ts`, `adaptiveBypass.ts` |
| UI support | `notifications.ts`, `themeManager.ts`, `i18n.ts`, `configManager.ts` |

Документация архитектуры лежит в `vpn-tunnel-enforcer/docs/architecture/` (README, `module-map.md`, `review-guide.md`) — для проекта такого размера сделана необычно хорошо: описаны runtime-границы, IPC-домены, правила размещения новых файлов и Definition of Done для структурных правок. Плюс 8 фазовых документов по censorship-resilience и RFC (`traffic-observability-rfc.md`, `multi-account-isolation-plan.md`, `vless-quic-fallback-investigation.md`).

### Заявленные инварианты (docs/architecture/README.md:26-33)

1. Renderer не вызывает Windows API, shell-команды и ФС напрямую.
2. Любой новый IPC-метод проходит через preload с валидацией аргументов.
3. Изменения состояния туннеля учитывают старт, стоп, crash recovery и stale-process recovery.
4. Изменения firewall / DNS / IPv6 / маршрутов имеют симметричный rollback и проверку результата.
5. Секреты и VPN-ключи не попадают в UI-логи, диагностические ZIP и сообщения об ошибках.
6. Feature-модуль владеет своими IPC-каналами; `index.ts` только связывает модули.

**Инварианты 4 и 5 в текущем коде нарушены** — см. находки 1, 3 и 5.

---

## 4. Tunnel runtime и network safety

### Поток запуска

`startProtection` (`index.ts:630-807`) — тонкий оркестратор, тяжёлая работа в `tunController.start()`:

1. Подавление leak self-test на 20 с + `captureSnapshot('tun-pre-start')` (`:631-634`).
2. `combinedPreStartProbe()` — один проход PowerShell собирает количество firewall-правил, активные туннели и слушающие прокси (`:640-644`, реализация `connectionPlanner.ts:222-320`).
3. Если найден stale kill-switch — `disableKillSwitchIfActive('restart preflight')`, при неудаче жёсткий abort (`:648-661`).
4. `getRoutingPlan()`; abort если `!plan.canStartHard` (`:665-674`).
5. `applyTunNetworkBaseline()` запускается **параллельно**, не дожидаясь (`:680-692`).
6. `beginAdaptiveConnection()` (`:694-706`).
7. `await tunController.start({...})` (`:707-715`).
8. При провале: очистка adaptive-контекста, `markAdaptiveFailure`, **дождаться baseline-промис и откатить** `rollbackTunNetworkBaselineIfApplied`, снапшот `tun-start-failed` (`:716-727`).
9. При успехе: `scheduleAdaptiveVerification`, старт traffic forensics, поллинг VPN IP (8×500 мс, `ipMonitor.recheck` только когда IP отличается от `preVpnIp`) (`:731-778`).
10. Обновление tray, открытие записи в connection-history, `captureSnapshot('tun-post-start')`, периодические снапшоты (60 с) + leak test (30 с) + watcher смены сети (`:780-800`).

`stopProtection` (`index.ts:1003-1077`) — зеркально: закрытие записи истории, остановка таймеров и форензики, `externalProxy.stopAll('vpn-stop')` **до** остановки туннеля, `tunController.stop()`, `ipMonitor.clearVpnIp()`, `trafficMonitor.stop()`, `repairOrphanedPhysicalAdapterDns` как страховка, авто-откат location-privacy, tray→off, `captureSnapshot('tun-post-stop')`.

### Лестница откатов в start()

Гварды: отказ при `running` / `startInProgress` / `stopInProgress` (`tunController.ts:2027-2035`). Каждый ранний выход вызывает `rollbackEarlyAdapterLockdown()` (`:2227-2236`):

| Точка отказа | Строки | Действие |
|---|---|---|
| foreign-TUN preflight | `:2144-2152` | return, откат не нужен |
| парсинг прокси / недоступен / full-tunnel-check | `:2256-2312` | откат lockdown + return |
| очистка owned-runtime | `:2340-2350` | откат + return |
| подготовка runtime / проверка singbox | `:2412-2418` | откат + return |
| lockdown упал после запуска sing-box | `:2819-2829` | `killOwnedRuntimeProcesses()` + откат + fail |
| sing-box вышел до старта (`onExit`) | `:2458-2583` | снос kill-switch + lockdown, **кроме** случая запланированного retry по WSAEACCES |
| таймаут старта (30×250 мс = 7,5 с) | `:3037-3065` | disable kill-switch + откат lockdown |

Lockdown, валидация прокси и kill-switch намеренно перекрываются по времени: lockdown стартует на `:2188` параллельной IIFE, kill-switch идёт одновременно с `waitForTunInterface` (`:2851-2933`).

### Генерация конфига sing-box

`generateSingboxConfig()` — `tunController.ts:719-1056`, 337 строк, синхронная и чистая. `prepareRuntime()` (`:1715-1852`) стейджит бинари, пре-резолвит порты, вызывает генератор и пишет `sing-box.json`.

- **Inbounds** (`:933-979`): `tun` (тег `tun-in`, `interface_name: 'Ethernet 5'` из `tunAdapter.ts:32`, только IPv4 `192.168.250.253/30`, `auto_route:true`, `strict_route:true`, `route_address:['0.0.0.0/1','128.0.0.0/1']`, MTU из `selectTunMtu`, `stack:'mixed'`, `udp_timeout:'30s'`) плюс `mixed` inbound `mixed-direct-in` на `127.0.0.1:dPort`. IPv6 намеренно опущен, причина в комментарии `:940-951`.
- **Outbounds** (`:980-984`): `proxy-out` (socks/http для localProxy либо outbound профиля для directVpn), `direct-out`, `block-out`.
- **DNS** (`:899-932`): bootstrap UDP 1.1.1.1 / 8.8.8.8 (`buildDnsBootstrapServers:552-557`) + remote-резолверы (`buildRemoteDnsServers:501-550`, каждый с `detour:'proxy-out'`, по умолчанию DoH Cloudflare/Google, с учётом DNS-профиля как tcp/doh/dot) + опциональный smart-RU direct DNS. `final: dns-remote`, `strategy: 'ipv4_only'`.
- **DNS-хайджек**: правило `{ protocol:'dns', action:'hijack-dns' }` на `:1007`, порядок — после `sniff`, но до любого блокирующего UDP-правила (`:1002-1011`).
- **Route rules** (`:985-1036`): `mixed-direct-in→direct-out`; имена процессов прокси-ядер→direct для предотвращения петли (`PROXY_CORE_PROCESS_NAMES:251-298`); опциональный reject QUIC UDP/443; `sniff`; hijack-dns; опциональный reject всего UDP для TCP-only outbound; пользовательские domain-правила; smart-RU split; `final:'proxy-out'`, `auto_detect_interface:true`, `default_domain_resolver:'dns-remote'`.
- **Анти-DPI**: всем TLS-outbound принудительно ставится uTLS `chrome` + ALPN. Stealth-режим добавляет `record_fragment` и детерминированную ротацию отпечатка на сервер, пропуская Reality (`:797-839`). `sanitizeProxyOutbound` (`:584-663`) вырезает `domain_strategy` и multiplex.
- **experimental** (`:1041-1054`): `clash_api` на `127.0.0.1:clashPort` со случайным секретом, `cache_file` включён.

### Crash recovery

`performCrashRecovery()` — `index.ts:1130-1160+`, на старте:

1. `recoverStaleBaseline()` (`index.ts:540-560`) — если манифест baseline есть, а `tasklist` не показывает `vpnte-sing-box.exe`, откатить.
2. `recoverStaleKillSwitch()` (`firewallKillSwitch.ts:701-738`) — проверяет манифест ИЛИ прямую проверку firewall ИЛИ «залипший» `DefaultOutboundAction=Block` без правил; если sing-box не запущен — `disableKillSwitch` и возврат Allow.
3. `isPhysicalAdapterLockdownApplied()` + sing-box не запущен → откат lockdown (`index.ts:1137-1146`).
4. `repairOrphanedPhysicalAdapterDns` (`physicalAdapterLockdown.ts:644-704`) — сбрасывает DNS у физадаптеров, всё ещё привязанных к резолверу VPNTE.
5. Откат env-autoconfig (`setx HTTP_PROXY`).

Подмеханизмы:

- **Stale owned runtime**: `killOwnedTunRuntimeProcesses` (`:1104-1142`) убивает только `vpnte-sing-box.exe` / `vpnte-etw-sidecar.exe`, **у которых `ExecutablePath` внутри runtime-каталога** — никогда не трогает сторонний sing-box.
- **Stale TUN-адаптер**: `removeStaleTunInterface` (`:1258-1326`) чистит все известные алиасы (текущий + legacy `VPNTE-TUN`), Remove→Disable→Rename как фолбэк.
- **Авто-restart при падении**: `RESTART_BACKOFF_MS=[2000,5000,10000]` (`:226`); прогон, продержавшийся `STABLE_RESET_MS=30000`, сбрасывает счётчик (`:3013-3022`). Отдельный retry с новым портом на WSAEACCES (`:2484-2578`). Пока retry запланирован, **kill-switch намеренно держится поднятым** (`:2600-2761`).
- **Post-trial failover** (`:1871-2023`): после исчерпания retry, если группа активного ключа `expired`, пробуются соседние ключи через `keyHealthChecker`.
- **Baseline** (`systemNetwork.ts`): наличие файла-манифеста = источник истины (`:21-23`); `applyTunNetworkBaseline` прерывается, если экспорт бэкапа HKCU не удался (`:193-200`); откат идемпотентен и сериализован через `withBaselineOpLock` (`:49-61`).
- **Crash-safety lockdown**: PENDING-манифест пишется **до** первого касания адаптера (`physicalAdapterLockdown.ts:454-466`); при ошибке batch-PS манифест сохраняется, а не перезатирается «ничего не изменено» (`:528-535`).
- Внешний boot-recovery: `resources/vpnte-recover.ps1`, покрыт `bootRecoveryScriptSource.test.ts`.

### Kill-switch

Механизм — **Windows Defender Firewall через elevated PowerShell** (командлеты NetSecurity), не raw WFP и не `netsh` в нормальном пути (`netsh` только для nuclear reset). `enableKillSwitch` — `firewallKillSwitch.ts:334-589`:

- Стратегия: `Set-NetFirewallProfile -DefaultOutboundAction Block` для Domain/Private/Public, при этом allow-исключения создаются **первыми** (`:396-525`).
- Allow-правила: программа sing-box, программы владельца прокси, InterfaceAlias TUN (с ожиданием до 15 с внутри PS, `:437-455`), LAN CIDR (`LAN_BYPASS_CIDRS:28-39`, только IPv4), подсеть TUN, DHCP 67/68, валидированные пользовательские IP/CIDR-исключения.
- **Fail-safe гейт** (`:497-510`): если отсутствует хоть одно обязательное allow-правило, все правила удаляются и бросается исключение **до** переключения на Block. Пользователя не запирают без интернета.
- `disableKillSwitch`→`restoreAndCleanup` (`:595-638`) сначала восстанавливает дефолты профилей, потом удаляет правила `VPNTE-killswitch*`. `nuclearFirewallReset` (`:908-930`) — `netsh advfirewall export/reset` как последнее средство.

`granularKillSwitch.ts` (403 строки) — не отдельный механизм, а **слой политики** над `firewallKillSwitch`: три уровня (`off`/`standard`/`strict`, `:146-180`) плюс персистентный список исключений, владеет IPC-обработчиками (`registerKillSwitchIpc:362-403`). `standard` = блокировать только при падении VPN, `strict` = блокировать всегда, когда трафик вне VPN.

### Внешние процессы

| Процесс | Как запускается | Как контролируется |
|---|---|---|
| `vpnte-sing-box.exe` | `tunController.start` `:2777-2794`: если приложение уже elevated — `execFileCb`, иначе `sudo.exec` (UAC) | НЕ через `managedChildProcess`; убивается `killOwnedTunRuntimeProcesses` по CIM-запросу с фильтром по `ExecutablePath` |
| Elevated PowerShell | `execElevated` (`admin.ts`) либо персистентный `elevatedPsHelper` | — |
| `curl.exe` | `curlText:1498-1506` | валидация IP при full-tunnel |
| `netsh` / unelevated `powershell` | метрика интерфейса, пробы присутствия, пробы планировщика | — |
| `vpnte-external-proxy.exe`, `vpnte-etw-sidecar.exe` | сайдкары | `managedChildProcess` |

`managedChildProcess.ts` (136 строк) используется **только** `externalProxy.ts` и `keyHealthChecker.ts`. Дизайн: JSON pid-файл (`owner/pid/exePath/configPath/createdAt`, mode `0o600`); `cleanupManagedChildPidFile` (`:98-119`) проверяет совпадение owner, затем `stopWindowsProcessIfMatches` (`:41-70`) через CIM подтверждает, что живой PID имеет тот же `ExecutablePath`/`CommandLine`, и только потом `Stop-Process -Force` — защита от переиспользования PID.

**В кодовой базе две расходящиеся стратегии контроля внешних процессов**: CIM-по-пути для основного runtime и pid-файл-с-верификацией для сайдкаров.

---

## 5. Профили и роутинг

### Парсинг ключей

Всё в `vpnProfiles.ts` (2759 строк). Единая модель `VpnProfile { name, protocol, outbound, clientDevice?, clientFingerprint? }` (`:24-30`). Протоколы (`:11-22`): vless, trojan, shadowsocks, vmess, hysteria2, naive, anytls, shadowtls, tuic, wireguard, sing-box.

**URI-схемы** — диспетчер `parseLine` (`:1631-1647`), regex на `:137`:

| Парсер | Строка | Особенности |
|---|---|---|
| `parseVless` | `:609` | Reality требует `pbk` (`:464`) |
| `parseTrojan` | `:630` | |
| `parseShadowsocks` | `:659` | base64 userinfo; SIP003-плагин отклоняется (`:684`) |
| `parseVmess` | `:700` | base64 JSON формата v2rayN |
| `parseHysteria2` | `:730` | плюс `hy2://`, obfs, mport-диапазоны |
| `parseNaive` / `parseAnyTls` / `parseShadowTls` / `parseTuic` / `parseWireGuard` | `:759` / `:775` / `:799` / `:817` / `:839` | |

**JSON-форматы**: sing-box outbounds (`jsonOutboundCandidatesToProfiles:1070`), Xray/v2ray (`xrayOutboundToProfiles:972`), Clash YAML через **самописный YAML-парсер** (`parseYamlObject:1385`, `clashProxyToProfile:1547`). Рекурсивное извлечение вложенных JSON до глубины 6 (`parseJsonValueProfiles:1210`, `findJsonDocumentEnd:1089`).

**Подписки**: `resolveVpnProfiles:2309` (с in-flight lock), `fetchAndParseSubscription:2153` тянет через `curl.exe` (`:1993`, ручной follow редиректов до 6 хопов). Декодирование `decodeSubscriptionBody:259` (gzip/deflate/brotli/utf16le). `parseVpnProfiles:1649` перебирает варианты `collectTextVariants:1152` (рекурсивный base64 до глубины 3) → JSON → Clash → URI. Заголовки подписки → `SubscriptionUserInfo` (`:2056`).

**Deep links**: `unwrapHappAddLink:2201` (`crypt3/4/5` и `routing` отклоняются с понятным сообщением), `unwrapMantarayLink:2254`.

Всё сходится в `finishOutbound:555` → outbound sing-box с тегом `proxy-out`. Обратная сериализация в URI — `exportOutboundToUri:2700`.

### Хранение и миграции

`electron-store`, несколько именованных сторов. Централизованные в `sharedStores.ts`: `serverPickerStore` (`profiles[]`, `activeProfileId`), `serverGroupsStore` (`groups[]`), `granularKillSwitchStore`. Свои сторы у `splitTunneling.ts:42`, `domainRouting.ts:32`, `dnsProfiles.ts:196`, `ruleSetManager.ts:59`.

**Формальной версионной схемы нет.** Вместо неё — пять идемпотентных миграций, запускаемых на старте в строгом порядке (`index.ts:1778-1807`): `migrateLegacyDirectVpnProfiles` → `backfillMissingOutbounds` → `migrateProfilesIntoGroups` (`serverPicker.ts:1435`) → `consolidateBogusSniGroups:1618` (чинит установки, испорченные удалённым ошибочным Tier2 SNI-splitting) → `backfillProfileSourceUris:1668` → `clearStaleStoredPings:1723`.

**Группы** (`serverGroups.ts`, 837 строк): `source: 'subscription'|'manual'`, поля `sourceUrl/status/expiresAt/traffic*/refreshIntervalSeconds`. Дедуп по каноническому URL (`canonicalizeSubscriptionUrl:166`). Авто-refresh (`refreshDueServerGroups:636`, sweep раз в 60 с, дефолт 30 мин, clamp 5 мин – 24 ч). Merge по **connection-tuple** `server|port|protocol` (`profileTupleKey:279` — намеренно не по `sourceUri`, чтобы не плодить дубли); исчезнувшие ключи архивируются (`enabled:false`, `removedFromSubscriptionAt`), ID сохраняются. Пустой ответ панели → статус `expired` с формулировкой «триал истёк, ключи могут работать».

### Health check, probe, ping

Четыре независимых механизма, все работают с реальной сетью (моки только в тестах):

**(а) Ping в UI** — `serverPicker.ts` `pingServer:197`→`smartEndpointPing:328`. Лестница проб: SOCKS-TCP через direct-proxy при активном туннеле; TCP+ICMP с привязкой к физадаптеру; `reliableTcpPing:688`; `stealthTcpProbe:728` (curl `--resolve yandex.ru:port:ip`, читает `%{time_connect}` — измеряет RTT без утечки реального SNI); `icmpPing:542` (`ping.exe` + декодер CP866 `:622`). Таймауты: ICMP 1500 мс, TCP 1800 мс × 3 попытки, медиана.

**Защита от отравления пингов** (три слоя):
1. Отсечка `≤3 мс` для non-loopback (`:373-375`, `:382-384`, `parseIcmpReply:598`) — против прозрачных перехватчиков 443, спуфящих локальный SYN-ACK.
2. `pingAll:796` — **no-op пока туннель поднят** (`:814-816`), иначе tunnel-RTT (~2 мс до CDN через Reality) запишется в `profile.ping`.
3. `clearStaleStoredPings:1723` — на старте стирает отравленные значения.

Плюс `tunnelHttpProbe:236` — гонка RU-friendly (`yandex.ru`, `gosuslugi.ru`) против глобальных URL, кэш с session-key и асимметричным TTL (успех 3500 мс / провал 1500 мс). Всё это покрыто `serverPickerPingPoisoning.test.ts`.

**(б) Key health** — `keyHealthChecker.ts` (488 строк). Поднимает **изолированный `sing-box.exe`** с полным outbound профиля (`buildKeyProbeConfig:263`), делает реальный TCP+TLS+HTTP GET к `yandex.ru` / `1.1.1.1` / `gstatic.com` (`KEY_PROBE_DESTINATIONS:32`). Таймаут 8000 мс, concurrency 5. Классификация ошибок `classifyOutboundProbeFailure:218` (auth-failed / tls-failed / timeout / config-failed, отдельная ветка для hy2 `:200`). Reality SNI считается безопасным для утечки (`tlsLeaksSni:101`), plain-TLS — нет. Пишет `status`/`healthStatus`, но НЕ `ping` (`:461`).

**(в) Диагностика сервера** — `serverProbe.ts` (262 строки): DNS resolve, reverse DNS, ASN через `ipapi.co`, latency TCP-connect. `getTlsCert:201` и `getHttpBanner:212` **намеренно всегда возвращают null** — запрос сертификата утекает SNI в TSPU. `scanPorts:175` ограничен одним известным портом: сам паттерн сканирования триггерит DPI.

**(г)** `socksPing.ts` (97 строк) — чистый SOCKS5-handshake на сырых байтах протокола (`:21`), медиана попыток.

### Smart RU split routing

`smartRoute.ts` (374 строки) — чистый модуль без electron и store. Три генератора: `smartRouteRules:303`, `smartRouteDnsRules:344`, `smartRouteRuleSets:265`.

Порядок правил: IP-чекеры→`proxy-out` (первыми, `IP_CHECKER_SUFFIXES:189`) → VPN-pinned медиа (YouTube/googlevideo, `:165`)→`proxy-out` → RU-gov geosite→`direct-out` → карты (`:141`, direct/proxy по тумблеру) → `geoip-ru`→`direct-out`. `suffixListToMatcher:236` эмитит apex как `domain` плюс субдомены как `domain_suffix` (чтобы `.2ip.ru` не матчил голый apex).

**Только два rule-set** (`:84-90`): `geoip-ru` и `geosite-category-gov-ru`. `category-ru` намеренно не используется — он утащил бы YouTube на direct через TSPU.

Источник `.srs` — SagerNet GitHub raw (`:87-90`), но при заданном `ruleSetDir` используется `type:'local'` с диска. **Причина**: упавшая первичная загрузка `remote` rule-set — это ФАТАЛЬНАЯ ошибка старта sing-box, туннель не поднимается, kill-switch не встаёт, реальный IP утекает (`:58-72`). Стейджинг в runtime-каталог с безопасным фолбэком: если хоть один файл не застейджился, `ruleSetDir` сбрасывается и `rule_set` не эмитится вообще — туннель поднимается без split (`tunController.ts:1805-1819`).

DNS-корректность: отдельный сервер `dns-direct` с реальными RU-upstream с физадаптера (не `type:local`, иначе петля в TUN-резолвер). RU-домены резолвятся direct → получают реальные RU-IP → матчатся `geoip-ru`.

Обновление — `ruleSetManager.ts` (343 строки): стор с метаданными (sha256, size, lastUpdatedAt, lastError), `downloadRuleSet:194` через curl по bootstrap-маршруту, атомарный `rename` из `.tmp`. `chooseSmartRouteRuleSetSource:81` берёт managed только если файл полностью скачан, иначе bundled.

### Split tunneling — по имени процесса

`splitTunneling.ts` (601 строка). Реализация целиком внутри route-rules sing-box: `{ process_name: [...], outbound: 'direct-out' }` (`generateSplitTunnelRouteRules:402`, `getDirectProcessNames:428`). Правило создаётся только для `rule==='direct'`; `vpn`/`none` идут дефолтом в `proxy-out`. Потребляется в `tunController.ts:2165`. Это **не** route-table и не WFP-split.

Два вида записей (`SplitTunnelApp.kind`): `'app'` (найденный путь к exe) и `'process'` (голое имя команды). Обнаружение приложений — `discoverInstalledApps:127`, PowerShell-скан реестра Uninstall (HKLM, WOW6432Node, HKCU; `queryRegistryApps:163`). Извлечение иконок отложено (`icon:null`). `normalizeProcessName:323` — путь→leaf, добавляет `.exe`, lowercase; известное ограничение: `node.js` ошибочно распознаётся как имя с расширением (задокументировано).

Hot-reload (`hotReloadIfActive:461`): sing-box не умеет live-reload, поэтому `tunController.restartWithLastOptions` — полный stop+start с уведомлением в UI.

### Device identity / HWID

Это **не** OS-level спуфинг HWID или MAC. Только эмуляция клиента для получения ключей от панелей (совместимость с Happ), всё в `vpnProfiles.ts`:

- `buildSubscriptionHwid:1671`→`buildHappSubscriptionHwid:168`→`buildMobileSubscriptionHwid:149`: sha256 от сида `['happ-compatible-mobile-hwid', device, hostname(), username, USERDOMAIN, arch, platform]`, срез 16 hex для mobile / 32 для generic. Стабилен для машины. Override через env `VPNTE_SUBSCRIPTION_HWID`.
- User-Agent: `Happ/3.22.1/<OS>/<hwid>` плюс sing-box / v2RayTun / v2rayN (`getSubscriptionUserAgents:184`).
- Заголовки: `x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model` (`subscriptionCommonCurlArgs:1697`, `DEVICE_HEADER_PROFILES:126`).
- `ClientDevice` — pc/android/ios/mac; `DEVICE_FINGERPRINTS:119` → uTLS-отпечаток (chrome/android/ios/safari), `applyClientDeviceToOutbound:172`.

---

## 6. IPC и renderer

### IPC-каналы

Источник истины — `src/preload/index.ts` (621 строка), а не `ipc-types.ts`. Ровно **146 `invoke`** + **13 `on`**.

| Префикс | Кол-во | | Префикс | Кол-во |
|---|---|---|---|---|
| *(корневые, kebab-case)* | 39 | | `scheduler:` | 5 |
| `servers:` | 16 | | `notifications:` | 5 |
| `domain-routing:` | 7 | | `theme:` | 5 |
| `external-proxy:` | 7 | | `config:` | 4 |
| `split-tunnel:` | 6 | | `firewall:` | 3 |
| `groups:` | 6 | | `adaptive-bypass:` | 3 |
| `kill-switch:` | 6 | | `url-availability:` | 3 |
| `dns:` | 6 | | `rotation:` | 3 |
| `connection-history:` | 6 | | `i18n:` | 3 |
| | | | `smart-route:`, `network:`, `traffic-history:`, `ip-monitor:`, `speed-test:` | по 2 |
| | | | `tun:`, `system:`, `server:` | по 1 |

Push-события: `ip-changed`, `tun-status-changed`, `traffic-stats`, `leak-detected`, `main-error`, `app:shutting-down`, `inapp-notification`, `theme-changed`, `server-active-changed`, `kill-switch:traffic-blocked`, `i18n:locale-changed`, `speed-test:progress`, `traffic-history:enrichment-updated`.

**Расхождение контракта**: типизированные интерфейсы в `ipc-types.ts` (`ServerChannels`, `SchedulerChannels`, `WidgetChannels`) **нигде не используются как типы** — только упоминаются в комментариях. Реальный мост типизирован собственным `ElectronAPI` с возвратами преимущественно `Promise<any>`. `WidgetChannels` (`ipc-types.ts:651-654`) — мёртвый контракт: ни в preload, ни в `ipcMain.handle` его нет, хотя `widgetLayout` в `ExtendedSettings` присутствует.

### Валидация в preload

Guard есть у **всех** каналов, принимающих аргументы — ни одного канала с сырым аргументом рендерера. Набор ассертов (`preload/index.ts:265-366`): `assertString` (+лимит символов), `assertEnum`, `assertPort`/`assertRequiredPort` (1-65535), `assertBoolean`, `assertStringArray` (лимит 500 элементов), `assertPlainObject` (объект + JSON ≤ 256 KiB), `assertExternalProxySlot`/`StartOptions`. Лимиты: `MAX_TEXT_ARG_CHARS=4096`, `MAX_VPN_INPUT_CHARS=256 KiB`. Контракт-тест — `preload/preloadValidation.test.ts`.

Но глубина неоднородна:

- **Поверхностно для объектов**: 12 каналов используют `assertPlainObject`, который проверяет только «это объект и JSON не больше 256 KiB», **без проверки полей**: `save-settings` (383), `scheduler:create` (464), `scheduler:update` (465), `kill-switch:add-exception` (472), `rotation:set-config` (477), `dns:create` (481), `dns:update` (482), `domain-routing:add` (488), `domain-routing:update` (489), `connection-history:filter` (496), `notifications:set-prefs` (521), `theme:create` (549).
- **Недо-валидированный enum**: `i18n:set-locale` (`:543`) использует `assertString` вместо `assertEnum(['en','ru'])`, хотя тип `Locale` и хелпер есть.
- Возвращаемые значения не валидируются.

### Безопасность Electron

Главное окно — `main/index.ts:352-366`:

| Параметр | Значение |
|---|---|
| `contextIsolation` | `true` (`:363`) |
| `nodeIntegration` | `false` (`:364`) |
| `sandbox` | **не задан явно** для главного окна (полагается на дефолт Electron ≥20). Явно `true` только у offscreen-проб (`domainEnrichment.ts:156`, `urlAvailability.ts:804`) |
| `webSecurity` | не переопределён (дефолт `true`) |
| Мост | ровно один `contextBridge.exposeInMainWorld('electronAPI', …)` (`preload:368`), сырой `ipcRenderer` наружу не идёт |

**CSP** (`main/index.ts:1189-1210`) — применяется **только при `app.isPackaged`** (в dev CSP нет), через `onHeadersReceived`: `default-src 'self'`; `script-src 'self'` (без `unsafe-inline` — хорошо); `style-src 'self' 'unsafe-inline'`; `connect-src 'self' https: wss:` (широко, но оправдано обращениями к ipify/ip-api); `object-src 'none'`; `base-uri 'self'`; `frame-ancestors 'none'`; `form-action 'none'`.

**Navigation policy** — чистая функция `classifyNavigation` (`navigationPolicy.ts`, покрыта тестами) + `hardenWebContents` (`index.ts:477-503`): `setWindowOpenHandler` отправляет http(s) в системный браузер и запрещает всё остальное (дочерние окна не создаются никогда); `will-navigate` отменяет всё не same-origin; `will-attach-webview` всегда `preventDefault`. Мотивация в комментарии: `webPageUrl` может прийти из заголовка подписки провайдера, то есть контролируется не пользователем.

**Lifecycle**: single-instance lock + фокус по `second-instance` (`:330-335`); `setAppUserModelId` до `whenReady` (`:312`); диалог подтверждения закрытия с graceful-очисткой (`:374-434`); `before-quit`→`performShutdownCleanup` (`:2022-2031`).

### Структура renderer

10 страниц (`nav.ts:24-34`), роутинг императивный — `useState<Page>` + `switch` в `App.tsx:553-567`, роутера нет, все страницы `lazy` (`:9-18`): `dashboard`, `apps` (SplitTunnel), `servers`, `speedtest`, `availability`, `trafficHistory`, `schedule`, `maintenance` (только при `advancedMode`), `settings`, `logs`.

Навигация: сайдбар `components/Sidebar.tsx` → примитив `MacSidebar`. Глубокая навигация из любых компонентов — через шину CustomEvent (`nav.ts`, `navigateTo`→`vpnte:navigate`), которую `App.tsx:519-526` транслирует в `setPage`. Оптимизация: посещённые страницы кэшируются (`visitedPages`), тяжёлые (`trafficHistory`, `logs`) монтируются только когда активны (`:33, 547-551`).

`store.ts` (Zustand, 483 строки) — осознанно **один глобальный стор** вместо слайсов, обоснование в шапке файла (`:3-31`). Паттерн IPC-first: фичевое состояние (splitTunnel, servers, schedule, dns, routing, widgets, notifications, speedTest, rotation, killSwitch) живёт локально в компонентах, тема — в `ThemeProvider`, i18n — в react-i18next. Глобально только то, что переживает смену вкладок: состояние соединения (`mode`, `tunRunning`, `publicIp`, `isLeak`, `vpnIp`, `proxyDown`, `connectionBusy`, `firewallKillSwitchActive`, `competingTun`), диагностика (`routingHealth`, `leakChecks`, `traffic`, `browserIpCheck`, `lastMainError`), `settings` (~40 полей, `:69-117`), `logs` (кольцевой буфер 500), блок `maintenance*`, `globalToasts`.

Design system — 12 примитивов + утилита `cn`, стиль macOS, темизация через CSS-переменные, `class-variance-authority`: `MacButton`, `MacCard`, `MacModal`, `MacInput`, `MacSelect`, `MacSwitch`, `MacBadge`, `MacProgress`, `MacSegmentedControl`, `MacToast`, `MacDragList`, `MacSidebar`. Переиспользование высокое: 506 упоминаний в 41 файле; все примитивы ≤ 181 строки.

---

## 7. Observability

### Rust ETW sidecar

`native/vpnte-etw-sidecar` — 606 строк `main.rs` + 265 `classify.rs`. Зависимости: `ferrisetw 1.2` (feature `time_rs`), `time 0.3`, `serde_json`. Релиз: `opt-level="z"`, LTO, `codegen-units=1`, `panic="abort"`, strip.

Слушает пять ETW-провайдеров: **TCPIP, DNS-Client, WFP, Winsock-AFD, WebIO** (`main.rs:5-6`). GUID резолвится по имени через `Provider::by_name`, фолбэк на встроенную таблицу `classify::known_guid` (`:161-165`). Имя трейс-сессии `VPNTE-ETW` (`:32`), требует прав администратора.

**Транспорт до main — файл, не stdout.** Сайдкар пишет NDJSON по строке на событие в путь из `--events` (`:53`); main читает `events.ndjson` (`trafficForensics.ts:378`). Stdout/stderr сливаются в `sidecar-stdout.log` / `sidecar-stderr.log` (`:671-678`). Лимиты: `DATA_EVENT_CAP = 250 000` событий (`:34`), heartbeat 30 с (`:33`). Остановка — через `spawn_stdin_watcher` (`:427`), закрытие stdin = сигнал завершения. Падение фиксируется в манифесте через `once('error')` (`:679`), форензика продолжается на pktmon/netsh.

Запуск (`startSidecar:629-680`): `findSidecarExecutable` ищет `vpnte-etw-sidecar.exe`, `.cmd`, `.ps1` в `resourcesPath` и рядом с `execPath`; override через env `VPNTE_TRAFFIC_FORENSICS_SIDECAR` (`0` = отключить). Если найден `.ps1`/`.cmd` — запускается через `powershell.exe -File` / `cmd.exe /c call`.

`classify.rs` — чистая классификация без I/O: `provider_category`, `canonical_provider`, `known_guid`, `derive_event_and_reason` (из task+opcode делает нормализованное имя события и причину), `is_significant` для фильтрации шума.

`extract_fields` (`main.rs:255`) — цикломатика 23 / когнитивная 81, четвёртая по сложности функция в проекте. Разбирает поля ETW-событий, включая ручной парсинг `sockaddr` (`parse_sockaddr:349`).

### Traffic forensics

`trafficForensics.ts` (1288 строк) + `trafficForensicsSummary.ts` (1269 строк) — вместе больше, чем весь renderer-слой страниц.

Корень артефактов — `%APPDATA%\VPN Tunnel Enforcer\traffic-forensics` (`:185`), сессия в подкаталоге по `sessionId` (`:992`). Манифест сессии `session-manifest.json` (`:310`) — источник истины для stale-состояния; `pruneOldSessions(settings.retainSessions)` (`:1254`).

Два движка: **pktmon** и **netsh trace**. Скрипты сборки артефактов генерируются в TS и пишутся на диск как `.ps1`, затем исполняются elevated (`buildPktmonStopScript:814`, `buildPktmonLiveSnapshotScript:838`, вызовы на `:911, 1018, 1101, 1108`). `telemetrySnapshotCommands:133` собирает 18 текстовых срезов: `nettcp`, `netudp`, `ipconfig`, `routes`, `route-print`, `arp`, `dns-cache`, `netstat`, `adapters`, `adapter-stats`, `interfaces`, `dns-client-servers`, `dns-client`, `firewall-rules`, `firewall-profiles`, `dnsclient-events`, `tcpip-events`, `chromium-policy`.

`maxSizeMb` зажат `Math.min(2048, Math.max(128, ...))` (`:179`) — числовой инъекции нет.

`generateTrafficForensicsSummary` — цикломатика 47 / когнитивная 135, **третья по сложности функция проекта**. Строит evidence-linked выводы (TUN path, WFP/firewall block, DNS-корреляция) из всех NDJSON-потоков сразу; сложность от количества источников и матрицы противоречивых состояний.

`trafficMonitor.ts` (320 строк) — счётчики трафика берутся из `Get-NetAdapterStatistics -Name <adapter>` через PowerShell (`:186`), то есть байты на уровне адаптера, а не разбивка по outbound sing-box. Имя адаптера экранируется (`:181`). На не-Windows есть fallback-заглушка (`:66, 207`).

`domainEnrichment.ts` (335 строк) — обогащение доменов в истории трафика делается **реальными скрытыми `BrowserWindow`**, которые ходят на `https://<domain>` и скрейпят метаданные страницы (`inspectWebsite:144-178`, окна с `sandbox: true` на `:156`). Домен извлекается через `tldts`. Практическое следствие: открытие экрана истории трафика заставляет приложение фактически посетить сайты, которые посещал пользователь.

### Leak-тесты

`leakSelfTest.ts` (490 строк) проверяет одну вещь, но честно: привязывает `curl.exe --interface <ip-физадаптера>` к каждому физическому адаптеру с IPv4 и пробует достать `https://1.1.1.1` (`:8-17, 232-255`). Если достаёт — физический адаптер не заблокирован, значит kill-switch/lockdown не работают. Дополнительно: сверка публичного IP через TUN против каждого физадаптера (`publicIpMismatch`), расхождение Cloudflare-trace против default-route IP как признак DNS-утечки (`:266-272`). Запускается каждые 30 с при поднятом туннеле. От ложных срабатываний при stop/restart защищает генерация сессии (`mySession`) плюс `ipMonitor.suspend()` в начале `tunController.stop()` (`:3125`). WebRTC здесь не проверяется.

`browserHardening.ts` (445 строк) — пишет политику Chromium `WebRtcIPHandling` в `HKLM`/`HKCU\Software\Policies\<browser>` для Yandex Browser, Chrome, Edge, Brave, Chromium, Vivaldi, Opera (`:80-115`). Есть backup-манифест (`ensureManifest:164`), read-back верификация записи (`:236`) и откат. Отдельно логируется случай, когда подтвердилась только HKCU-политика без HKLM (`:244-247`) — автор понимал, что HKCU-политику может перезаписать пользовательский процесс.

### Логирование

`appLogger.ts`: формат — построчный текст (`formatLine:159`), уровни debug/info/warn/error, scope. Ротация: при превышении `MAX_LOG_BYTES = 5 MiB` (`:54`) файл переименовывается в `app.prev.log`, вытесняя предыдущее поколение (`rotateIfNeeded:80-90`). `MAX_DETAIL_CHARS = 4000` на поле details (`:17`), чтение хвоста ограничено `MAX_READ_BYTES = 1 MiB` (`:18`).

Редакция при записи (`logEvent:170-173`): три скруббера подряд к message и details — `redactSensitiveText`, `redactTopologyText` (IP/MAC/IPv6, `:105`), `redactSensitiveConfig`. IPC-логи прогоняются через `compactForIpcLog` (`ipcLogging.ts`), который применяет `redactSensitiveConfig`. Покрыто `appLoggerRedaction.test.ts`.

### Внешние сервисы

| Категория | Хосты | Где |
|---|---|---|
| Публичный IP | `api.ipify.org`, `api6.ipify.org`, `api.myip.com`, `ifconfig.me`, `ifconfig.co`, `icanhazip.com` (+ ipv4/ipv6), `v6.ident.me`, `1.1.1.1/cdn-cgi/trace`, `one.one.one.one`, `cloudflare.com/cdn-cgi/trace` | `ipMonitor.ts:5-6`, `leakDiagnostics.ts:68-70,150-162`, `leakSelfTest.ts:82-87`, `externalProxyHealth.ts:3-5`, `tunController.ts:1468-1469,1511`, `autoPilot.ts:56`, `happDetector.ts:39` |
| Гео / ASN | `ipapi.co`, `ipinfo.io`, `ipwho.is`, `api.iplocation.net`, `ipinfo.is`, **`ip-api.com` (HTTP!)** | `serverPicker.ts:1043-1113`, `serverProbe.ts:154`, `urlAvailability.ts:295` |
| Connectivity | `google.com/generate_204`, `gstatic.com`, `detectportal.firefox.com`, `msftconnecttest.com` (HTTP, стандартный NCSI), `storeedgefd.dsx.mp.microsoft.com` | `systemDiagnostics.ts:524-528`, `speedTest.ts:41-44` |
| Speedtest | `speed.cloudflare.com`, `proof.ovh.net`, `speedtest.tele2.net` | `speedTest.ts:51-63,180` |
| RU-проверки маршрутизации | `yandex.ru`, `gosuslugi.ru`, `internet.yandex.ru` | `serverPicker.ts:128-133,754`, `routingSelfTest.ts:63-64` |
| DoH | `cloudflare-dns.com`, `dns.google` | `vpnProfiles.ts:1761,1767` |
| Rule-sets | `raw.githubusercontent.com/SagerNet/...` | `smartRoute.ts:88-89` |
| Доступность | `www.youtube.com` | `urlAvailability.ts:125` |

Отключается частично — настройка `disableGeoLookup` глушит только гео-часть.

### Диагностический ZIP

`diagnosticsExport.ts` (307 строк), `exportDiagnosticsZip` — цикломатика 26 / когнитивная 99. ZIP собирается через PowerShell `Compress-Archive` из временного stage-каталога (`:95, 289`), без npm-зависимостей.

Содержимое: `settings.json` (через `redactSettingsForDiagnostics`, `:101`), `app-log.json` (`:105, 209`), runtime-каталог (JSON парсится и редактируется `redactSensitiveConfig`, текст — `redactSensitiveText`, иначе заглушка `<redacted: runtime log>`, `:132-140`), манифесты baseline / killswitch / adapter-lockdown (`:152-154`), снапшоты за последнее окно с лимитом `DIAGNOSTICS_SNAPSHOT_MAX_FILES` (`:159-195`, тоже редактируются), README с описанием содержимого (`:215+`), и `traffic-forensics/` (`:202`).

---

## 8. Automation и external proxy

### Кто может менять состояние туннеля

Девять точек вызова, и большинство **обходит** оркестратор `startProtection`/`stopProtection`:

| Вызов | Файл:строка | Через оркестратор? |
|---|---|---|
| `startProtection` → `tunController.start` | `index.ts:707` | да |
| `startDirectVpnProtection` → `start` | `index.ts:919` | да |
| `stopProtection` → `stop` | `index.ts:1047` | да |
| `autoPilot` → `stop` / `start` | `autoPilot.ts:126, 209` | **нет** |
| `profileRotation` → `stop` / `start` | `profileRotation.ts:294, 297` | **нет** |
| `serverPicker` (переключение сервера) → `stop` / `start` | `serverPicker.ts:1827, 1832` | **нет** |
| `restartWithLastOptions` (split-tunnel, domain-routing, настройки, client device) | `splitTunneling.ts:475`, `domainRouting.ts:344`, `index.ts:1410`, `serverPicker.ts:2366` | **нет** |
| Self-restart: post-trial failover / WSAEACCES retry / crash restart | `tunController.ts:1994, 2570, 2667` | **нет** |

Гварды уровня контроллера (`running` / `startInProgress` / `stopInProgress`) предотвращают гонки самого `start`, но побочные эффекты оркестратора при обходе теряются.

### Модули автоматизации

- `scheduler.ts` — планировщик по расписанию.
- `profileRotation.ts` — периодическая ротация профилей, `scheduleNextRotation` (`:319`).
- `autoPilot.ts` — автоматический recovery/выбор.
- `adaptiveBypass.ts` — обучаемый подбор режима обхода; единственный, кто корректно использует `restartForAdaptiveChange` с сохранением защиты сети.

### External proxy control API

`externalProxy.ts`. HTTP-сервер на `node:http` (`createServer:2058`), слушает `127.0.0.1:17873` (`CONTROL_HOST:20`, `EXTERNAL_PROXY_CONTROL_PORT:21`), с фолбэком на порт 0 при занятости (`:2084-2093`). Десять слотов прокси: слот 1 — legacy `127.0.0.1:17990`, слоты 2-10 — `17991`-`17999`, выбор через `?slot=N`.

Аутентификация:

- Токен — `randomBytes(32).toString('hex')` (`ensureControlToken:610-615`), генерируется раз за сессию приложения.
- Пишется в `%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token` плюс branded-каталог совместимости, `mode: 0o600` (`writeControlTokenFiles:592-608`).
- Endpoint-дескриптор с портом и путём к токену — `control-endpoint.json` (`writeControlEndpoint:617`).
- Сравнение через `timingSafeEqual` с предварительной проверкой длины (`isValidExternalProxyControlToken:1895-1900`).
- Принимается заголовок `X-VPNTE-Control-Token` либо `Authorization: Bearer` (`requestControlToken:1902-1912`).
- Мутирующие пути перечислены явно (`isExternalProxyMutationPath:1891`) и требуют `POST` + токен (`:1920-1929`). `GET /status`, `/list`, `/instances` — без токена.
- CORS: `Access-Control-Allow-Origin: http://127.0.0.1` (`send:1879`).
- Тело запроса ограничено 64 KiB с `req.destroy()` при превышении (`readBody:1861`).

Оценка: CSRF и DNS-rebinding практически закрыты комбинацией «кастомный заголовок + POST + ACAO только для `http://127.0.0.1`» — сторонняя страница не сможет пройти preflight и прочитать ответ. Замечания уровня defense-in-depth: нет валидации заголовка `Host` (`:1916` строит URL из константы, игнорируя присланный Host), а `mode: 0o600` под Windows Node фактически не применяет ACL — защита сводится к дефолтному ACL `%APPDATA%`, то есть любой процесс того же пользователя токен прочитает.

Скрипт-обёртка `resources/vpnte-proxy.ps1` (136 строк) читает токен через `Get-VpnteControlToken:61` и подставляет в заголовок (`:80`), запросы через `Invoke-WebRequest -UseBasicParsing` (`:83`).

---

# НАХОДКИ

Порядок — по убыванию серьёзности.

## 1. Локальное повышение привилегий через runtime-каталог

**Серьёзность:** высокая. **Эксплуатируемость:** реальная при наличии локального кода от имени пользователя.

`electron-builder.yml:18` — `requestedExecutionLevel: requireAdministrator`, то есть приложение **всегда** работает с правами администратора. При этом:

- `getTunRuntimeDir()` = `%APPDATA%\VPN Tunnel Enforcer\tun-runtime` (`tunController.ts:303-305`) — каталог в профиле пользователя, где у пользователя Full Control по умолчанию.
- Туда копируются `vpnte-sing-box.exe`, `wintun.dll`, `libcronet.dll` (`:1734-1736`) и оттуда же запускаются elevated (`:2456` через `cmd /c cd /d "<runtimeDir>" && "<singbox>" run -c ...`, и `:2777-2794`).
- **Во всём `src/main` нет ни одного `icacls`, `Set-Acl` или иной работы с ACL** — проверено grep'ом, ноль вхождений.
- `copyResourceIfStale` (`:321-338`) сравнивает только mtime и size, поэтому подменённый бинарь совпадающего размера и времени не будет перезатёрт никогда.

**Вектор:** непривилегированный процесс от того же пользователя подменяет `vpnte-sing-box.exe` или подкладывает `wintun.dll` рядом с ним → выполнение кода с правами администратора при следующем подключении. DLL-planting через `wintun.dll` проще подмены exe, потому что не требует обходить staleness-проверку. Это ровно тот класс, от которого UAC должен защищать (CWE-379 / CWE-732).

Тот же класс, отдельный путь: `trafficForensics.ts:903-914` пишет `live-snapshot.ps1` в `%APPDATA%\...\traffic-forensics\<session>\` и сразу выполняет его elevated через `-File`. Между записью и запуском TOCTOU-окно (CWE-367). Аналогично `:1018, 1101, 1108`.

**Что сделано правильно и не является проблемой:** boot-recovery регистрируется как `/RU SYSTEM /SC ONSTART` и указывает на `<resourcesPath>\vpnte-recover.ps1` (`settings.ts:240-247`), а `perMachine: true` ставит приложение в `%ProgramFiles%` — путь админ-only, подмены нет. То есть про этот риск автор думал, просто runtime-каталог не закрыл.

**Починка:** `icacls` на runtime-каталог со снятием прав записи у non-admin, либо стейджинг в `%ProgramData%` с ужесточённым ACL; плюс проверка Authenticode-подписи или хеша перед запуском; для форензики — писать `.ps1` в админ-only каталог.

## 2. Kill-switch снимается при каждом рестарте «на месте»

**Серьёзность:** высокая. **Эффект:** окно реальной утечки трафика.

В `stop()` есть флаг `preserveNetworkProtection`, который пропускает откат baseline / firewall / lockdown (`tunController.ts:3072, 3174, 3219, 3231`). Используется он **ровно в одном месте** — `restartForAdaptiveChange` (`:3307-3310`).

Все остальные пути рестарта вызывают `stop()` без опций → защита полностью разбирается и собирается заново:

| Путь | Строка | Когда срабатывает |
|---|---|---|
| `restartWithLastOptions` | `:3279` | смена правил split-tunnel, domain-routing, настроек, client device |
| `serverPicker.restartDirectVpnForSelectedProfile` | `serverPicker.ts:1827` | **каждое переключение сервера** |
| `profileRotation` | `profileRotation.ts:294` | каждая плановая ротация |

Между `stop()` и успешным `start()` — 500 мс явной паузы (`:3285`) плюс вся стартовая последовательность с PowerShell-пробами, то есть секунды, в течение которых трафик идёт через физический адаптер без kill-switch.

Это прямо противоречит заявленному в README принципу «failures are surfaced as blocked/proxy-down instead of silently leaking through the physical adapter» и инварианту 4 из `docs/architecture/README.md:31`.

**Починка почти механическая** — механизм уже написан и работает в адаптивном пути: передать `preserveNetworkProtection: true` (и `preserveLastStartOptions: true` где нужно) в остальных путях рестарта.

## 3. Список VPN-серверов уходит по открытому HTTP

**Серьёзность:** высокая для целевой модели угроз. **Починка:** один символ.

`serverPicker.ts:1113` — batch-геолокация делает запрос на `http://ip-api.com/batch?fields=status,country,countryCode,query`, передавая туда IP-адреса серверов пользователя. **Без TLS.**

Для приложения, построенного вокруг обхода DPI, это инвертирует всю модель угроз: любой наблюдатель на пути, включая ту самую систему фильтрации, получает в открытом виде точный перечень эндпоинтов, которыми пользуется владелец. Остальные гео-сервисы в коде идут по HTTPS — выбивается только этот.

Отключается через `disableGeoLookup`, но по умолчанию включено.

## 4. Провал ротации оставляет систему без туннеля и без kill-switch молча

**Серьёзность:** высокая. **Эффект:** утечка без уведомления.

`profileRotation.ts:297-307` — `tunController.start()` обёрнут в `.catch(err => logEvent('warn', ...))`. Если ротированный ключ не поднялся:

1. `stop()` уже выполнен (`:294`), значит kill-switch снят (см. находку 2).
2. Туннель лежит.
3. Пользователю не сказано ничего — одна строка `warn` в лог.

Сравнить с `serverPicker.ts:1828-1844`, где обе операции проверяются и бросают осмысленную ошибку — там сделано правильно.

## 5. Диагностический ZIP не редактирует форензику, хотя утверждает обратное

**Серьёзность:** средняя-высокая (приватность). **Смягчение:** форензика opt-in.

`stageTrafficForensicsArtifacts` (`trafficForensics.ts:1248-1288`) заканчивается `copyDirBestEffort(manifest.sessionDir, ...)` (`:1280`) — рекурсивное копирование каталога сессии **без какой-либо редакции**. В архив попадают:

- `events.ndjson` — события ETW DNS-Client, то есть **каждый домен, который пользователь резолвил**, плюс TCPIP-события с каждым удалённым IP и портом;
- `*.etl` / `*.pcapng` — сырые захваты пакетов;
- `netstat-*.txt`, `nettcp-*.txt`, `dns-cache-*.txt` — полные таблицы соединений и DNS-кеш;
- `dns.ndjson`, `flows.ndjson`, `timeline.ndjson`, `summary.json`.

Редакция (`redactSensitiveConfig` / `redactSensitiveText`) применяется только к runtime-каталогу и снапшотам (`diagnosticsExport.ts:132-140, 191-193`), **не** к `traffic-forensics/`.

При этом README внутри архива заявляет (`diagnosticsExport.ts:275-278`):

```
redaction: {
  settings: 'subscriptions, profile links and known secrets are redacted',
  runtimeJson: 'runtime JSON is parsed and sensitive values are redacted',
  logs: 'text logs are redacted with the same sensitive-pattern scrubber'
}
```

Про сырую форензику не сказано — пользователь резонно решит, что весь бандл вычищен.

**Отдельно: сам скруббер слабее, чем кажется.** `redactSensitiveText` (`vpnProfiles.ts`) закрывает только:

```js
.replace(/\b(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\/\S+/gi, '<redacted-vpn-uri>')
.replace(/\bhttps?:\/\/[^\s"'<>]{8,}/gi, '<redacted-url>')
.replace(/\b(Could not resolve host|No such host is known|resolve host):\s*[^\s"'<>]+/gi, '$1: <redacted-host>')
.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, '<redacted-uuid>')
```

**Голые доменные имена и IP он не трогает вообще.** Маскировка IP/MAC живёт в `redactTopologyText`, а тот применяется только в `appLogger.logEvent` при записи, не при экспорте.

**Смягчающее обстоятельство:** при выключенном `deepTrafficInspection` и отсутствии живой сессии `stageTrafficForensicsArtifacts` возвращает `false` и ничего не кладёт (`:1255-1257`).

## 6. Побочные эффекты оркестратора теряются при обходных рестартах

**Серьёзность:** средняя. **Эффект:** искажение данных, рассинхрон состояния.

`startProtection` делает существенно больше, чем `tunController.start`: baseline, запись в connection-history, периодические снапшоты, leak self-test, traffic forensics, tray. `serverPicker.restartDirectVpnForSelectedProfile` и `profileRotation` дублируют только часть (адаптивный контекст, иногда IP-поллинг).

Практические следствия:

- запись в connection-history не закрывается и не переоткрывается при смене сервера → трафик двух разных серверов склеивается в одну запись и атрибутируется неверно;
- `trafficMonitor` не перезапускается (возможно намеренно, для непрерывности графика, но нигде не задокументировано);
- `profileRotation` не делает `ipMonitor.resume()` и не верифицирует новый IP, в отличие от `serverPicker.ts:1846-1849`.

## 7. `Invoke-Expression` в elevated-хелпере за regex-денилистом

**Серьёзность:** низкая как самостоятельная уязвимость, средняя как ложное чувство защиты. **Эксплуатируемость:** не эксплуатируется напрямую.

`elevatedPsHelper.ts` держит постоянный elevated PowerShell, который читает JSON построчно со stdin и выполняет `Invoke-Expression $cmd.script` (`:113`).

Защита — регэкспный денилист `BLOCKED_SCRIPT_TOKENS` (`:33-57`) плюс per-policy allow/deny наборы для двух домены (`POLICY_REQUIRED_TOKENS:59-77`, `POLICY_FORBIDDEN_TOKENS:79-99`). Компартментализация сделана грамотно: скрипту `firewall-killswitch` запрещены `netsh`, `Set-DnsClientServerAddress`, `route add`; скрипту `physical-adapter-lockdown` — командлеты firewall. Также есть лимиты `MAX_SCRIPT_CHARS = 64 KiB`, `MAX_PENDING_COMMANDS = 8`, `MAX_RESTARTS = 3`.

Но денилист на PowerShell — заведомо слабая граница. Заблокированы `Invoke-Expression`, `iex`, `Start-Process`, `cmd`, `powershell`, `Add-Type`, `Remove-Item`, `&`, `&&`, `||`. **Не заблокированы**: `[System.Diagnostics.Process]::Start`, `[scriptblock]::Create`, `$ExecutionContext.InvokeCommand.InvokeScript`, `New-Service`, `Set-Service`, `schtasks`, `wmic`, `Invoke-CimMethod`, dot-sourcing `. { }`, `Set-Content`, `Out-File`, `New-Item`, `Copy-Item`.

Канал управления — stdin дочернего процесса, посторонний процесс туда не пишет. То есть это защита от инъекции в собственный код приложения, а не от внешнего атакующего. Оценка как «второй рубеж»: даёт ложное чувство надёжности.

**Побочный дефект того же денилиста (баг доступности, не безопасности):** `/\brm\b/i`, `/\bdel\b/i`, `/\bcmd(?:\.exe)?\b/i` — широкие word-boundary регэкспы, которые матчатся по **данным** внутри скрипта. Путь к exe вида `C:\...\cmd\app.exe`, выбранный пользователем через `kill-switch:browse-app` и попавший в текст firewall-скрипта, отклонит всю операцию → **kill-switch молча не встанет**.

## 8. Двойное состояние kill-switch

`granularKillSwitch` хранит `killSwitchLevel`, но `tunController.start()` читает легаси-булеан `settings.firewallKillSwitch`. Синхронизируются вручную в двух местах (`granularKillSwitch.ts:196-211, 252-273`). Заготовка для расхождения: изменение одного без другого даёт состояние, где UI показывает одно, а туннель поднимается с другим.

## 9. Инъекции в PowerShell — не найдено

Проверены все точки, где данные попадают в текст скрипта. Экранирование `'` → `''` (корректный способ для одинарных кавычек PowerShell) применяется последовательно в 12 местах: `admin.ts:17`, `firewallKillSwitch.ts:213`, `physicalAdapterLockdown.ts:148`, `connectionPlanner.ts:115, 233-234`, `splitTunneling.ts:170`, `trafficForensics.ts:96`, `tunController.ts:1101, 1646`, `trafficMonitor.ts:181`, `systemDiagnostics.ts:564`, `diagnosticsExport.ts:35`.

Скрипты передаются через `-EncodedCommand` в base64/UTF-16LE (`admin.ts:13-15`), не через командную строку. `maxSizeMb` из настроек зажат числовым clamp (`trafficForensics.ts:179`).

Долг здесь только в дублировании: двенадцать независимых копий трёхстрочного `psQuote`.

---

# ТЕХНИЧЕСКИЙ ДОЛГ

## Сложность

Топ функций по когнитивной сложности (из графа знаний):

| Функция | Файл | Цикломатическая | Когнитивная |
|---|---|---|---|
| `start` | `tunController.ts:2026-3069` (1043 строки) | **91** | **224** |
| `Servers` | `renderer/pages/Servers.tsx` | 105 | 184 |
| `generateTrafficForensicsSummary` | `trafficForensicsSummary.ts` | 47 | 135 |
| `App` | `renderer/App.tsx` | 71 | 127 |
| `Dashboard` | `renderer/pages/Dashboard.tsx` | 61 | 120 |
| `onExit` (замыкание внутри `start`) | `tunController.ts:2458-2773` (315 строк) | 31 | 103 |
| `exportDiagnosticsZip` | `diagnosticsExport.ts` | 26 | 99 |
| `extract_fields` | `native/.../main.rs:255` | 23 | 81 |
| `xrayOutboundToProfiles` | `vpnProfiles.ts:972` | 26 | 79 |
| `attemptPostTrialFailover` | `tunController.ts:1871-2023` | 23 | 63 |
| `stop` | `tunController.ts:3071-3243` | 22 | 60 |
| `handleControlRequest` | `externalProxy.ts:1914` | 26 | 54 |

`tunController.start` — самая рискованная точка кодовой базы: промис + интервальный поллер + вложенные замыкания + fire-and-forget откаты в одной функции. Изолированно не тестируется; тесты на неё — это `*Source.test.ts`, которые грепают исходник по подстрокам (`tunControllerRecoverySource.test.ts:109, 145`, `mainIpcRegression.test.ts:111, 153-154`, `serverPickerSource.test.ts:11`).

## God-файлы

| Файл | Строк |
|---|---|
| `tunController.ts` | 3336 |
| `vpnProfiles.ts` | 2759 |
| `serverPicker.ts` | 2623 |
| `renderer/pages/Servers.tsx` | 2203 |
| `trafficForensics.ts` | 1288 |
| `trafficForensicsSummary.ts` | 1269 |
| `firewallKillSwitch.ts` | 930 |
| `urlAvailability.ts` | 883 |
| `renderer/pages/Settings.tsx` | 879 |
| `systemDiagnostics.ts` | 846 |
| `serverGroups.ts` | 837 |
| `renderer/components/ServerDetailModal.tsx` | 865 |
| `renderer/pages/Dashboard.tsx` | 816 |
| `physicalAdapterLockdown.ts` | 731 |
| `renderer/pages/Logs.tsx` | 713 |
| `renderer/components/DashboardSide.tsx` | 692 |
| `renderer/components/FirstRunWizard.tsx` | 679 |
| `shared/ipc-types.ts` | 654 |
| `renderer/App.tsx` | 637 |
| `preload/index.ts` | 621 |
| `splitTunneling.ts` | 601 |

В `docs/architecture/README.md:37` крупные файлы (`index.ts`, `tunController.ts`, `Servers.tsx`) признаны осознанно отложенными — честно, но долг накапливается.

## Дублирование

- **Четыре почти идентичных `ps()`-хелпера** с base64/UTF-16LE и одинаковыми преамбулами: `firewallKillSwitch.ts:113-180`, `systemNetwork.ts:91-107`, `physicalAdapterLockdown.ts:151-180`, `connectionPlanner.ts:53-72`.
- **Двенадцать копий `psQuote`** (перечислены в находке 9).
- **Три реализации atomic-manifest** (tmp+rename): `firewallKillSwitch.ts:98-103`, `systemNetwork.ts`, `physicalAdapterLockdown.ts`.
- **PS-скрипты проб скопированы**: `getActiveTunnels` / `getProxyListeners` (`connectionPlanner.ts:106-194`) продублированы в `combinedPreStartProbe` (`:240-276`) — тот же regex туннелей, тот же regex листенеров, и длинный хардкод-список портов встречается дважды.
- **Списки приватных CIDR в двух местах**: `LAN_BYPASS_CIDRS` (`firewallKillSwitch.ts:28-39`) и `route_exclude_address` в TUN-конфиге (`tunController.ts:957-965`).
- **`vpnProfileToServerProfile` продублирован**: `serverGroups.ts:295` и `serverPicker.ts:1932`.
- **Стор `server-picker` инстанцируется дважды**: `sharedStores.ts:18` и локально `serverPicker.ts:88` — один файл, два инстанса.
- **Две расходящиеся стратегии контроля внешних процессов**: CIM-по-пути для основного runtime, pid-файл-с-верификацией для сайдкаров.

## Проглоченные ошибки и непроверенные результаты

- Массовые `.catch(() => undefined)` на откатах и снапшотах: `index.ts:634, 725, 794`, `settings.ts:236, 246`, `profileRotation.ts:294-307`.
- `applyLowTunInterfaceMetric` не верифицирует, что метрика применилась — только фоновый readback с предупреждением (`tunController.ts:2891-2908`).
- `notifyWinInetSettingsChanged` — fire-and-forget (`systemNetwork.ts:168-175`).
- Ошибки reg-команд baseline понижаются до warning, и прогон продолжается (`systemNetwork.ts:220-235`).
- Парсинг результатов регэкспами по маркерам в stdout (`A${i}_ipv6:off`, `__VPNTE_DONE__`, `RULES:`, `SAVED:`) — хрупкая связка между JS и встроенным текстом PS.
- `copyResourceIfStale` сравнивает только mtime+size (`tunController.ts:321-338`) — см. находку 1.

## Мёртвый и паразитный код

- `WidgetChannels` (`ipc-types.ts:651-654`) — контракт без реализации.
- Типизированные интерфейсы каналов в `ipc-types.ts` нигде не используются как типы.
- `dnsProfiles.ts:184 isValidIPv6Group` — не используется.
- `subscriptionFallbackCurlArgs` (`vpnProfiles.ts:1724`) — всегда возвращает `[]`.
- `hitCount` в `domainRouting.ts` — инкремент удалён (`:326-330`), поле навсегда 0.
- Пять идемпотентных стартовых миграций — накопленный churn схемы.

## i18n

Словари `ru.json` (553 строки) и `en.json` (551) синхронны: 21 секция, паритет ключей. Единственная легитимная разница — русские плюральные формы `servers.groups.serverCount_few` / `_many` (`ru.json:186-187`).

**Но внедрение частичное.** Кириллица найдена в 21 `.tsx`, `useTranslation` используют 20 файлов, и списки пересекаются лишь частично. Целиком хардкод-русские, без i18n:

| Файл | Кириллических строк |
|---|---|
| `pages/Availability.tsx` | 61 |
| `App.tsx` (все `addLog` + оверлей) | 41 |
| `pages/Maintenance.tsx` | 41 |
| `components/BrowserIpCard.tsx` | 40 |
| `components/DiagnosticsCard.tsx` | 39 |
| `components/ExternalProxyCard.tsx` | 37 |

Плюс `store.ts:334, 410-414` содержит русские литералы в `routingHealth.message`. Ключи `sidebar.availability` и `sidebar.maintenance` отсутствуют в обеих локалях и замаскированы inline-фолбэком (`Sidebar.tsx:32, 38`). Для англоязычного пользователя эти экраны останутся русскими.

Отдельно: README внутри диагностического ZIP содержит **сломанную кодировку** (`diagnosticsExport.ts:215-234` — mojibake вида `Р”РёР°РіРЅРѕСЃС‚РёРєР°`), при том что рядом на `:253-261` лежит корректный русский текст. В `appLogger.ts:31` есть `repairMojibake` — видимо, известная проблема.

## Прочие расхождения

- README заявляет «Electron 30», в `package.json` — `electron: ^42.0.0`.
- README заявляет installer `VPN-Tunnel-Enforcer-Setup-1.1.0.exe`, версия пакета — `1.1.8`.
- В UI протокол статусов TUN — «магические» строки, парсящиеся в рендере (`App.tsx:142-220`: `restarting:N/M`, `competing-tun:<name>`, `proxy-down`, `killswitch-active`). Хрупкая связка renderer↔main через строки.
- Обширная защитная логика от stale/out-of-order IPC-событий в `App.tsx` (`stoppingNowRef`, `tunEventSeqRef`, ignore-ветки) — признак того, что порядок событий из main не гарантирован.
- Best-effort вызовы через `as unknown as Record<...>` в обход типов моста (`App.tsx:169-174`).

---

# ЧТО СДЕЛАНО СИЛЬНО

Чтобы список находок не создавал ложного впечатления — вот то, что в этом проекте заметно выше среднего:

1. **Дисциплина откатов.** Лестница early-exit в `start()`, где каждая ветка чистит за собой. Манифесты пишутся атомарно и служат источником истины для recovery. PENDING-манифест lockdown пишется до первого касания адаптера, чтобы после краша было что откатывать.
2. **Fail-safe в kill-switch.** Проверка наличия всех обязательных allow-правил **до** переключения на `Block` (`firewallKillSwitch.ts:497-510`). Пользователя не запирают без интернета — это именно тот сценарий, который обычно ломают.
3. **Осознанный анти-DPI.** Принудительный uTLS chrome + ALPN на всех TLS-outbound. Локальные rule-sets вместо remote с явно задокументированной причиной (упавшая загрузка = фатальный старт sing-box = утечка). Отказ от port-scan и TLS-cert probe, потому что сам паттерн триггерит DPI. Stealth-режим с `record_fragment` и ротацией отпечатков.
4. **Защита от отравления пингов.** Три независимых слоя плюс регрессионный тест. Это тонкая проблема, которую в большинстве VPN-клиентов не решают вообще.
5. **Многослойная редакция секретов** в логах и IPC-логах, с тестом.
6. **Валидация IPC** — ни одного канала с сырым аргументом рендерера, плюс контракт-тест.
7. **Navigation policy как чистая тестируемая функция** с внятной мотивацией в комментарии (`webPageUrl` из заголовка подписки не доверенный).
8. **Комментарии объясняют «почему», а не «что»** — например, почему IPv6 опущен в TUN, почему `category-ru` не используется, почему `profileTupleKey` не включает `sourceUri`, почему Tier2 SNI-splitting удалён. Это редкость.
9. **Документация архитектуры** (`docs/architecture/`) с инвариантами, маршрутом ревью и Definition of Done.

---

# ПРИОРИТЕТЫ

| № | Находка | Объём правки | Статус |
|---|---|---|---|
| 1 | Runtime-каталог в `%APPDATA%` + всегда-админ = EoP | средний (ACL + верификация подписи) | ACL сделан, подписи нет |
| 2 | Kill-switch снимается при смене сервера и ротации | **малый** — механизм уже есть | исправлено |
| 3 | `http://ip-api.com` со списком серверов | **тривиальный** — один символ | исправлено |
| 4 | Провал ротации оставляет систему без защиты молча | малый | исправлено |
| 5 | Форензика в ZIP без редакции при заявленной редакции | средний | исправлено для форензики |
| 6 | Потеря побочных эффектов оркестратора | средний (рефакторинг) | открыто |
| 7-9 | Денилист PS, двойное состояние kill-switch, дублирование | по обстоятельствам | открыто |

Находки 2, 3 и 4 — дешёвые и с наибольшим эффектом на безопасность пользователя. Разумная последовательность: 3 → 2 → 4 → 1 → 5.

---

# ЧТО ИСПРАВЛЕНО

**Коммит:** `7132b51` (2026-08-29), 23 файла, +2256 / −170. Порядок — тот, что рекомендован выше: 3 → 2 → 4 → 1 → 5. Каждая правка с регрессионными тестами; после — `tsc --noEmit` чисто, 711 passed / 2 skipped.

Ниже — что именно сделано, **и что осталось незакрытым**. Второе важнее первого.

## #3 — плейнтекстовая геолокация → закрыто

`http://ip-api.com/batch` заменён на `https://get.geojs.io/v1/ip/country.json`. Одной смены схемы мало, поэтому добавлено два барьера:

- `isHttpsGeoUrl()` (`serverPicker.ts`) — гард в начале `fetchGeoJson`, то есть любой будущий гео-эндпоинт не-HTTPS отвергается до сетевого вызова, а не полагается на внимательность автора правки;
- `curl --proto =https --proto-redir =https` — иначе редирект `301 → http://` сводит гард на нет.

Тесты (`serverPickerGeoTransport.test.ts`, 10 шт.) сканируют исходник на `http://`-литералы в сетевых путях. Комментарий, называющий исторический `http://ip-api.com`, специально оставлен читаемым — тест снимает комментарии перед проверкой (`stripComments()`).

**Осталось:** сам факт запроса раскрывает список серверов третьей стороне, теперь по TLS. Это свойство любой внешней геолокации, а не дефект; `disableGeoLookup` по-прежнему единственный способ не раскрывать вообще.

## #2 — kill-switch при рестарте → закрыто

Добавлен `TunController.restartProtected(reason, nextOptions, { settleMs })` (`tunController.ts:3297`). Все три пути переведены на него: `restartWithLastOptions`, `restartForAdaptiveChange`, `serverPicker.restartDirectVpnForSelectedProfile`, `profileRotation`.

Существенная часть — **не** сохранение защиты (это уже умел флаг), а поведение при провале. Сохранённый stop оставляет firewall блокирующим без туннеля: утечки нет, но интернета тоже нет, и вернуться в это состояние молча нельзя. Поэтому `start()` обёрнут в try/catch, и **оба** пути отказа (провал stop, провал start) выполняют полный `stop()` без сохранения.

Побочно нашлось в рендерере: статус `adapting` не обрабатывался и падал в ветку неизвестного статуса — UI показывал разрыв там, где защита не снималась. Оба переходных статуса теперь `isTransitioning` (`App.tsx`).

## #4 — молчаливый провал ротации → закрыто

`.catch(err => logEvent('warn', ...))` вокруг реконнекта проглатывал отказ, и ротация возвращала успех при лежащем туннеле. Теперь ошибка отслеживается, `rotateToNextProfile` возвращает `success: false` и пользователь получает явное уведомление, что защита выключена и трафик идёт обычным маршрутом. `scheduleNextRotation` вызывается по-прежнему безусловно — следующий тик должен повторить попытку, а не заглохнуть.

## #1 — EoP через runtime-каталог → закрыто частично

Новый `runtimeDirSecurity.ts` (`ensureElevatedRuntimeDirHardened`, `verifyDirectoryHardened`). Каталог приводится к DACL «только SYSTEM + Administrators» **до** того, как в него что-либо копируется — вызов стоит перед `copyResourceIfStale` в `prepareRuntime` (`tunController.ts:1744`). Два неочевидных момента, оба намеренные:

- `SetAccessRuleProtection($true, $false)` — второй аргумент `$false` означает «не копировать унаследованные правила внутрь». Без этого унаследованный от `%APPDATA%` Full Control для пользователя materialize'ится как явное правило и всё насмарку;
- `SetOwner($admins)` — владелец неявно держит `WRITE_DAC` и может отменить всё вышеперечисленное. Без смены владельца ужесточение декоративно.

Форензический TOCTOU (`.ps1` write→exec) закрыт тем же механизмом: `ensureLayout()` ужесточает `traffic-forensics/`, сессионные каталоги наследуют DACL (`trafficForensics.ts:281`).

Ужесточение **не фатально** by design: туннель, отказывающийся стартовать, для пользователя хуже, чем туннель из слабо защищённого каталога. Отказ логируется на уровне `error` и выводится как диагностический пункт `runtime-acl` (`systemDiagnostics.ts:265`), то есть состояние видно, а не подразумевается.

**Осталось незакрытым — читать обязательно:**

1. **Верификации подписи нет.** Рекомендация ревью включала Authenticode/хеш-проверку перед запуском; сделан только ACL. Grep по `tunController.ts` на `Get-AuthenticodeSignature` — ноль. Пока ACL держится, подменить бинарь без прав админа нельзя, поэтому это не дыра, а отсутствующий второй слой. Если ужесточение не сработало (старый каталог с уже испорченным DACL, нестандартная политика, кастомный `userData`), ловить подмену нечем.
2. **`copyResourceIfStale` по-прежнему сравнивает только mtime+size** (`tunController.ts:322`). Внутри модели «каталог админ-only» этого достаточно; как защита от подмены — нет.
3. **Реальное поведение на живой Windows не проверено.** Тесты (`runtimeDirSecurity.test.ts`, 16 шт.) мокают `child_process` и проверяют форму PowerShell-скрипта и разбор вывода. Что `Set-Acl` + `icacls /reset /T` дают ожидаемый DACL на настоящей машине — не подтверждено ни здесь, ни ранее.

## #5 — форензика в ZIP → закрыто, с сознательным компромиссом

Новый `forensicsRedaction.ts`. **Маскировка была отвергнута осознанно:** ценность packet-форензики — в связке DNS → соединение → reset → drop, а связка живёт в адресах. Заменив всё на `<redacted-ip>`, мы получаем архив, по которому нельзя ничего диагностировать, и пользователи возвращаются к отправке сырых захватов — приватность становится хуже, а не лучше.

Вместо этого — согласованная псевдонимизация: один редактор на весь экспорт, поэтому токен означает один и тот же адрес во всех файлах архива. Сохраняются два свойства, потому что они и есть предмет анализа: **класс адреса** (public/private — это буквально вопрос «была ли утечка») и **публичный суффикс** (`<domain-4>.ru` — иначе не разобрать smart-RU split). Таблица соответствия в архив не пишется, живёт только в памяти во время экспорта.

Сырые захваты (`*.etl`, `*.pcapng`, `pktmon-trace.txt`) исключены целиком: payload не редактируется. Путь к ним есть в логе, если поддержка попросит осознанно.

Отдельно про `copyDirRedacted`: **ветки байтового копирования в нём нет**. Всё идёт `readFile('utf-8')` → redact → `writeFile`, поэтому незнакомый тип артефакта скрабится по умолчанию. Старый `cp()`-fallback позволял ровно обратное — новый артефакт утекал сырым, и никто бы не заметил.

Манифест переписан: по строке на класс артефактов, включая `notRedacted:` (имя машины, состав адаптеров, структура маршрутов остаются — без них сетевые проблемы не разбираются, и честнее это сказать).

**Осталось незакрытым:**

1. **Слабость `redactSensitiveText` из находки #5 не устранена.** Голые домены и IP он по-прежнему не трогает, а `redactTopologyText` по-прежнему живёт только в `appLogger` (grep: ноль вхождений вне него). То есть `settings.json`, `runtime-*.log`, `snapshots/` и `app-log.json` в архиве чистятся **старым** скруббером, а новая псевдонимизация применяется только к `traffic-forensics/`. Для снапшотов это заметно: они содержат таблицы маршрутов и адреса адаптеров.
2. **Смягчение осталось смягчением:** при выключенном `deepTrafficInspection` форензики в архиве нет вообще, и тогда весь механизм неактивен.

## Побочные дефекты, найденные по пути

- `diagnosticsExport.ts` писал **два README**, первый — с mojibake-русским после UTF-8/1251 round-trip (`Р”РёР°РіРЅРѕСЃС‚РёРєР°…`), и только перезапись вторым спасала пользователя от кракозябр. Заголовок диалога сохранения был испорчен так же и **был виден в UI**. Оставлен один README; добавлены тесты на количество и на mojibake-подпись.
- `serverPickerResolvedIpSource.test.ts` проверял многострочный текст исходника и падал на любом свежем чекауте при `core.autocrlf=true` (HEAD-блоб LF, рабочая копия CRLF). Добавлена нормализация переводов строк.

## Что это меняет в приоритетах

Открыто: находки **6-9** и весь раздел технического долга. Плюс три новых пункта из списков «осталось» выше, которых в исходном ревью не было как отдельных задач:

| Пункт | Откуда | Объём |
|---|---|---|
| Authenticode/хеш-проверка бинарей перед запуском | второй слой к #1 | средний |
| Псевдонимизация для снапшотов и логов в ZIP, не только для форензики | остаток #5 | малый — механизм готов |
| Runtime-подтверждение DACL на живой Windows | граница #1 | ручная проверка |

Отдельно стоит отметить находку **#7**: у regex-денилиста вокруг `Invoke-Expression` есть баг доступности — `/\bcmd(?:\.exe)?\b/i` совпадает с выбранным пользователем путём к exe и молча отменяет kill-switch. Это не только security-вопрос, но и «защита тихо не включилась», то есть по эффекту ближе к находкам 2 и 4, чем её позиция в списке подразумевает.

---

# ЧТО НЕ ПРОВЕРЕНО

Честные границы этого ревью:

- **Приложение не запускалось.** Реальное поведение firewall, Wintun, маршрутов, DNS на живой Windows не подтверждено. Все выводы — из чтения кода. Это остаётся верным и после исправлений: правки к находкам 1-5 проверены типизацией и юнит-тестами, но не запуском на живой машине.
- **Тесты не запускались** (`npm test`, `npm run typecheck`) — на момент самого ревью. При исправлениях запускались: `tsc --noEmit` чисто, 711 passed / 2 skipped на коммите `7132b51`.
- **Эксплойты не писались.** Находка 1 обоснована из кода и конфигурации сборки, но PoC не строился.
- **Не разбирались**: `autoconfig/` (Soft-режим целиком), `scheduler.ts` в деталях, `notifications.ts`, `themeManager.ts`, `configManager.ts`, `speedTest.ts`, `urlAvailability.ts` (883 строки), `happDetector.ts`, `geoBlockDetect.ts`, `locationPrivacy.ts`, `snapshotBootstrap.ts` и V8-снапшоты, `build/installer.nsh`, содержимое `resources/vpnte-eos-compat.ps1`.
- **Не проверялась** актуальность зависимостей на известные CVE.
- **Сабагенты были недоступны** большую часть сессии (403 от провайдера), поэтому разделы 7-8 и весь security-ревью PowerShell сделаны прямым чтением, без параллельной перекрёстной проверки. Разделы 4-6 частично опираются на отчёты сабагентов, полученные в начале сессии; их выводы я выборочно верифицировал (в частности, находку 2 — чтением `tunController.ts:3071-3310` целиком).

