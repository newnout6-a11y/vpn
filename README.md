# VPN Tunnel Enforcer

[![Electron](https://img.shields.io/badge/Electron-42_LTS-47848F?logo=electron&logoColor=white)](https://www.electronjs.org/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Windows-клиент (10/11 x64, версия 1.1.22) для изоляции сетевого трафика и обхода блокировок: системный TUN через Wintun + sing-box, fail-closed WFP kill-switch, перехват DNS, Smart RU маршрутизация, форензика трафика на Rust ETW-сайдкаре, планировщик и ротация серверов.

> **Честная оговорка:** в `docs/` и `docs-factory8090/` лежит ТЗ — это план развития, а не описание текущего состояния. Раздел [«Что пока не реализовано»](#что-пока-не-реализовано-план) ниже перечисляет фичи из ТЗ/старого README, которых в коде нет.

---

## Режимы работы

**Hard Mode (directVpn)** — требует прав администратора:
- Wintun-адаптер (алиас маскируется под `Ethernet 5..12`, подсеть `192.168.250.252/30`, адрес `.253`, резолвер `.254`, метрика 5, IPv4-only).
- Ядро `sing-box` (основное), сателлит `xray-core` для VLESS-REALITY (SOCKS на `127.0.0.1`, случайный порт).
- Поднятие туннеля — ~10 шагов: pre-flight (чужой TUN → отказ с объяснением), lockdown физических адаптеров (IPv6 off, DNS → `.254`, `DisableSmartNameResolution`), копирование бинарей в рантайм (только если устарели — по size+mtime), генерация конфига + `sing-box check -c`, запуск, ожидание `Status=Up` у TUN, и **только потом** kill-switch (иначе правило по `-InterfaceAlias` молча не создастся).
- Watchdog: directVpn — проверка egress-IP каждые 15 с; localProxy — TCP-проба прокси каждые 5 с, 3 промаха → `proxy-down` без роняния TUN. Авторестарт с бэкоффом 2/5/10 с, затем post-trial failover по соседним ключам группы.

**Soft Mode (localProxy)** — без админ-прав: прямое локальное SOCKS5/HTTP-проксирование. TCP-проба upstream + `validateProxyFullTunnel` (curl-гонка через прокси vs прямой IP — проверка, что прокси не отдаёт мой же IP). Автоконфиг окружения разработчика: Android Studio, Git, Gradle, переменные `HTTP_PROXY`/`HTTPS_PROXY` в `HKCU\Environment` (для SOCKS5 пишется `socks5h://`, чтобы DNS тоже шёл через прокси).

**Connection Planner** — pre-start зонд одним комбинированным PowerShell-скриптом (TUN + loopback + правила VPNTE), вердикт `ready/protected/blocked/broken` с рекомендацией режима.

## Протоколы

Реально поддерживаются парсером `vpnProfiles.ts` (подписки, ключи, экспорт URI): **VLESS** (XTLS-Reality через xray; Vision/gRPC/WebSocket через sing-box), **WireGuard**, **Hysteria2**, **TUIC**, **Shadowsocks** (в т.ч. 2022 AEAD, SIP002), **VMess** (AEAD, `alterId: 0`), **Trojan**, **Naive**, **AnyTLS**, **ShadowTLS**. uTLS-отпечаток `chrome`, `record_fragment` в stealth для non-Reality.

## DNS

- Перехват: правило `{ protocol: 'dns', action: 'hijack-dns' }` — весь DNS из TUN идёт в резолвер sing-box. Стратегия `ipv4_only`; TUN IPv4-only, IPv6-утечки закрываются kill-switch + lockdown.
- DoH через туннель (`1.1.1.1` cloudflare-dns.com, `8.8.8.8` dns.google), plain-DNS — TCP/53 через туннель, DoT — через туннель.
- Bootstrap: UDP напрямую к DNS физических адаптеров или `1.1.1.1`/`8.8.8.8` для резолва имени VPN-сервера до поднятия туннеля — **имя сервера при этом видно провайдеру** (известное ограничение).
- Smart RU: `dns-direct` к pre-lockdown DNS для `.ru/.su/.рф` и gov-ru (чтобы geoip-ru видел реальные RU IP).

## Kill-switch (WFP)

- `DefaultOutboundAction=Block` на трёх профилях (Domain/Private/Public) — вместо Block-правил по интерфейсу (старый подход блокировал сам sing-box, т.к. Block всегда побеждает Allow).
- Allow-правила `VPNTE-killswitch-*`: exe sing-box, exe приложения, владельцы upstream-прокси (Happ `xray.exe` и т.п.), TUN по `-InterfaceAlias`, loopback v4/v6, LAN, DHCP (UDP 67/68), NTP (UDP 123 — часы для REALITY/TLS), пользовательские IP/CIDR.
- Манифест отката — атомарная запись temp+rename, crash-recovery при старте приложения. Манифест и промежуточные скрипты хранятся в `%ProgramData%\VPNTE\manifests\` с защищённым DACL (только SYSTEM и Администраторы) и проверкой от symlink/junction abuse (WP-3).
- Granular: `off` / `standard` (блок при обрыве VPN) / `strict` (блок всегда вне VPN). При strictMode аварийное восстановление сохраняет блокировку (fail-closed) до явного действия пользователя. Ядерный `nuclearFirewallReset` (бэкап `.wfw` + `netsh advfirewall reset`).
- Fail-closed: при падении туннеля kill-switch **намеренно остаётся** до авторестарта/failover.

## Маршрутизация

Порядок правил sing-box (упрощённо): `mixed-direct-in` (127.0.0.1) → direct (диагностика) → `live-check-in` → proxy-out (health-пробы) → процессы прокси-ядер (Happ.exe, xray.exe…) → direct (анти-петля) → UDP/443 → reject (TCP-only outbound) → `hijack-dns` → `ip_is_private` → direct (**строго после** hijack, чтобы DNS на шлюз перехватывался) → весь UDP → reject (directVpn + TCP-only) → STUN 19302/3478 → proxy-out (анти-WebRTC) → пользовательские доменные правила → Smart RU (IP-чекеры/Google/медиа → proxy-out; gov-ru/geosite/geoip-ru → direct-out по локальным `geoip-ru.srs`, `geosite-category-gov-ru.srs`) → final → proxy-out.

Split tunneling — по **имени процесса** (direct/vpn/none), hot-reload через рестарт без снятия защиты. Честная оговорка: ТЗ требует абсолютный путь процесса (имя подвержено подмене) — пока расхождение.

## Форензика трафика

- Сессии: elevated `pktmon` (провайдеры TCPIP/WFP/Winsock-AFD/WebIO, circular capture 128–2048 MiB, default 512), fallback — `netsh trace`. Хранилище `<userData>/traffic-forensics/sessions/<timestamp>`, retention 1–10 сессий (default 3).
- **Rust ETW-сайдкар** (`native/vpnte-etw-sidecar/`, `ferrisetw`): 5 провайдеров (TCPIP, DNS-Client, WFP, Winsock-AFD, WebIO), heartbeat каждые 30 с, лимит 250 000 data-событий с backpressure, только метаданные (5-tuple, DNS-имена — не пейлоады), стабильная kernel-сессия `VPNTE-ETW` с reclaim осиротевшей. Честная оговорка: PowerShell-фолбэк (`vpnte-etw-sidecar.ps1`) — это поллинг Event Log, а не настоящий ETW, и на части систем теряет события.
- Summary: `summary.json`, `timeline.ndjson`, `flows.ndjson`, `dns.ndjson`, `drops.ndjson`, `tcp-health.ndjson`, вердикты (`leak`, `TUN path`, `kill-switch block`, `reset`, `timeout/loss`, `MTU`, `sing-box failure`, `insufficient evidence`).
- Zombie recovery протухших `running: true`, 30-секундный warmup без варнингов, stop-артефакты переопределяют stale-статусы.
- Экспорт — с redaction: IPv4/IPv6/MAC/домены → стабильные токены, raw ETL/PCAPNG не экспортируются, маппинг токенов не сохраняется.

## Диагностика и UI

10 страниц: Dashboard, Servers, SpeedTest, Availability, TrafficHistory, Schedule, Settings, Logs, Maintenance, SplitTunnel. React 18 + Zustand (IPC-first стор, без кешей), i18n ru/en (~615 ключей).

- **DiagnosticsCard**: активный leak self-test (`curl.exe --interface <IPv4 физ. адаптера>` к api.ipify.org — leak, если физ. адаптер вышел в интернет или его IP ≠ TUN IP), routing self-test (VPN-путь vs direct-путь через `mixed-direct-in`), статус ETW-сайдкара (движок, категории, топ-домены, heartbeat), экспорт диагностики в ZIP, рестарт форензики.
- `runSystemDiagnostics()`: runtime, TUN, DNS, адаптеры, маршруты, процессы/листенеры, endpoints, службы Windows, логи, forensics status.
- Browser hardening (реестр WebRTC-policy Chromium + `user_pref` Firefox) — это **не** Browser Boxes, их нет (см. ниже).

## Автоматизация

- **Scheduler**: окна `[start, end)`, overnight-привязка к предыдущему дню, горизонт 7 дней.
- **AutoPilot**: трогает только собственный VPNTE TUN, требует рабочий прокси перед стартом TUN, при failure восстанавливает baseline.
- **Rotation**: интервал 5–1440 мин, sequential/random, reconnect через `restartProtected`. Честная оговорка: commit профиля происходит **до** успешного reconnect — атомарного health-before-commit пока нет.
- **keyHealthChecker**: изолированный sing-box/xray во временной директории, HTTPS через профиль к Cloudflare/Yandex/Gstatic, timeout 8 с, concurrency 5.
- **ipMonitor**: racing по Cloudflare trace / ipify / icanhazip / myip.com, poll 30 с, колбэк только при смене IP.
- **liveServerProbe**: глубокие DNS/TCP/TLS/HTTP-пробы, traceroute, throughput — ручная диагностика из UI, **не** гейт выбора сервера.

## External Proxy Control API

Локальный REST на `127.0.0.1:17873`:
- `GET /status`, `/instances`, `/list`
- `POST /start`, `/rotate`, `/connect`, `/connect-profiles`, `/trigger`, `/healthcheck`, `/profiles/healthcheck`, `/stop`, `/instances/prewarm|status-batch|reserve|renew|release`
- Слоты 1..47546: порт слота = `17990 + slot - 1` (слот 100 → `18089`). Мутирующие запросы — заголовок `X-VPNTE-Control-Token` (файл `%APPDATA%\VPN Tunnel Enforcer\external-proxy-control-token`).

## Безопасность: что есть и чего нет
 
**Есть (реализовано в WP-1 и WP-3):**
- **Шифрование секретов:** ключи VPN, токены, UUID и ссылки подписок шифруются через Electron `safeStorage` (Windows DPAPI); хранилища групп серверов и бэкапы миграции защищены.
- **Доверенная IPC-граница:** строгая проверка `senderFrame` (только mainFrame), точного origin/file entry point, валидация structured-clone (лимиты глубины, размера строк/бинарников, запрет `__proto__`, NaN/Infinity); действенный `<meta>` CSP для `file://`.
- **Безопасный экспорт и импорт:** экспорт ключей требует нативного системного диалога подтверждения в main-процессе; очистка буфера обмена через 60 с по SHA-256 таймеру; импорт конфигов и правил доменов привязан к одноразовым capability-токенам нативного диалога.
- **Транзакционный Firewall и Boot Recovery:** манифесты хранятся в `%ProgramData%\VPNTE\manifests\` с защитой ACL (SYSTEM/Admins only) и защитой от symlinks; регистрация задачи `BootRecoveryTask` в packaged-сборках проверена (UTF-16LE EncodedCommand); независимый покомпонентный откат (DNS, IPv6, Firewall, WinINet); fail-closed блокировка при strictMode; защита от удаления физических сетевых адаптеров.
- Скрытие приватных данных устройства (HWID, заголовки) из командной строки `curl` (передаются через stdin).

**Открыто (плановые задачи):**
- Подпись кода (ожидает решения владельца по сертификату, раздел 10.8 ТЗ-06);
- Миграция Electron 42 → 44 (дедлайн 20.10.2026, WP-11).

## Что пока не реализовано (план)

Из старого README и ТЗ в коде **отсутствуют** (проверено поиском по `src/`, `scripts/`, `resources/`, `native/`): **AmneziaWG**, **FakeIP**, **DoQ**, **Chromium Browser Boxes** (изолированные инстансы с SOCKS `10801..10850`), ядро **mihomo** (в коде упоминается только как детект конкурирующих клиентов). Это план пакета WP-12 — см. `docs-factory8090/06-ТЗ-исправление-и-развитие.md`. Полное ТЗ — в `docs/` (3 тома).

---

## Структура репозитория

```
vpn/
├── docs/                                 # ТЗ (3 тома: сетевое ядро / безопасность / жизненный цикл) — план, не факт
├── docs-factory8090/                     # База знаний: аудит (210 находок F-001…F-210), 44 фичи (88 документов), компоненты, открытые вопросы, план WP-0..WP-12
├── vpn-tunnel-enforcer/                  # Исходный код приложения (Electron + React)
│   ├── src/
│   │   ├── main/                         # Главный процесс: сеть, IPC, безопасность, форензика (~270 файлов)
│   │   ├── preload/                      # contextBridge-мост, валидация аргументов
│   │   ├── renderer/                     # UI: 10 страниц, компоненты, i18n ru/en
│   │   └── shared/                       # Общие типы (75 типов IPC), схемы
│   ├── native/vpnte-etw-sidecar/          # Rust ETW-сайдкар (ferrisetw)
│   ├── resources/                        # .srs-правила, .ps1/.cmd скрипты, иконки
│   ├── scripts/                          # build-sidecar.mjs и др.
│   └── package.json                      # Версия приложения 1.1.22
├── progress.md                           # Журнал выполненных задач
└── README.md                             # Этот документ
```

## Требования

- **ОС:** Windows 10 (сборка 19041+) или Windows 11 x64.
- **Среда:** Node.js 18+ (рекомендуется 20/22 LTS), npm 9+.
- **Права:** Hard Mode (Wintun, WFP, адаптеры) требует администратора — UAC-элевация реализована внутри приложения.

## Быстрый старт

```bash
cd vpn-tunnel-enforcer
npm install
npm run dev        # из корня репозитория тоже работает
```

> `npm run dev` запускает приложение через `electron-vite`. Открывайте окно Electron, а не браузерный URL Vite — интерфейс использует типизированный IPC-мост `contextBridge`.

## Тесты

134 тест-файла на Vitest (1164 теста). Последний прогон в Linux-песочнице (28.09.2026): 1109 passed, 43 failed (преимущественно Windows-специфика: пути/PowerShell), 12 skipped; на Windows набор зелёный. Актуальные итоги — вывод `npm test`.

```bash
npm test                                            # полный набор
npm --prefix vpn-tunnel-enforcer run test:watch     # watch-режим
npm --prefix vpn-tunnel-enforcer run test:coverage  # покрытие
npm run typecheck                                   # tsc --noEmit
```

## Сборка

```bash
npm run dist:win       # NSIS-инсталлятор
npm run dist:portable  # портативная версия
```

Артефакты — в `vpn-tunnel-enforcer/dist/`, например `VPN-Tunnel-Enforcer-Setup-1.1.22.exe`.

> **Важно для сборки:** в `resources/` репозитория **нет** `sing-box.exe`, `xray.exe`, `wintun.dll`, `libcronet.dll`, `vpnte-etw-sidecar.exe` — их нужно положить вручную до `dist`. `npm run build:sidecar` требует Rust/cargo на Windows; без него сборка молча пропускается и в установщик попадёт только PowerShell-фолбэк сайдкара.

## Лицензия

MIT.
