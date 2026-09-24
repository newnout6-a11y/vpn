# VPN Tunnel Enforcer: Audit Findings

Дата отчёта: 2026-09-24  
Объём: исходники `src/main`, preload/renderer, native sidecar, packaging, тесты, git history, актуальные sing-box/Electron/Node docs через Tavily и проверка гипотез Jev.

Это отчёт аудита и статуса последующих исправлений.

## Статус исправлений (2026-09-24)

Исправлены и проверены: round-trip пустого `packet_encoding` для VLESS и UDP-capability; экспорт WireGuard URI; разбор registry path для split-tunneling; валидация DNS-адресов на IPC-границе и раздельные типы primary/secondary DNS; обработка отклонённых scheduled rotation/proxy resolve; stale rotation eligibility; first-run mode persistence; speed-test egress mismatch; URL verdict без VPN-измерения; domain-routing/scheduler/theme/server-probe runtime validation; config import rollback; autoconfig compensation; browser manifest shape validation; mapped/NAT64 IP checks; Clash VLESS transport fields; Git rollback protection; обновление README test count.

Проверки после исправлений: `npm run typecheck`; полный тестовый набор `128 passed`, `1201 passed`, `3 skipped`; `npm run build`.

Оставшиеся ограничения не являются незакрытыми runtime-дефектами: Chromium policy runtime coverage, Windows-only ETW/Cargo E2E, production-size forensics и toolchain major upgrade требуют отдельной Windows/CI инфраструктуры. Adaptive stability window, external lease persistence/control API policy и live-apply связанные изменения внесены и проверены тестами.

## Проверенная база

- Рабочее дерево содержит изменения текущего fix-прохода; они перечислены в `git status --short`.
- `npm.cmd run typecheck` — passed.
- `npm.cmd run build` — passed (main, preload, renderer).
- Полный baseline тестов ранее: `128` test files, `1200` passed tests, `3` skipped.
- Точечные проверки профилей: `62/62`; scheduler + happDetector: `26/26`.
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Native ETW `cargo test` не запущен: `cargo` отсутствует в PATH.

## Подтверждённые дефекты

### 1. Частичное применение config import

**Статус: исправлено частично.** Добавлен compensating rollback при ошибке записи; полной транзакции staging-копии нет.

`configManager` применяет вложенные настройки последовательно. Если запись в середине импорта некорректна, предыдущие значения уже сохранены. Нет транзакции, staging-копии или полного rollback.

**Эффект:** импорт может оставить приложение в смешанном состоянии и сообщить об ошибке только после частичного изменения настроек.

### 2. Потеря параметров Clash/Mihomo при импорте

**Статус: исправлено.** Сохранены VLESS encryption, packet-encoding, UDP и transport-поля.

Ручной YAML parser не сохраняет часть списков, пустых значений и transport-полей. В частности, `packet-encoding`/UDP-настройки и ALPN могут деградировать. Для VLESS также теряется `encryption`, а Xray fallback подставляет `none`.

### 3. VLESS `packet_encoding` round-trip ломает explicit disable

**Статус: исправлено.** Пустой `packet_encoding` сохраняется и экспортируется.

`parseVless` добавляет `packet_encoding` только при truthy-значении; `packetEncoding=` теряется. `vlessToUri` также не экспортирует пустое значение. По актуальной документации sing-box отсутствие поля означает `xudp` по умолчанию, а `(none)` — disabled.

**Эффект:** явно отключённый UDP после импорта/экспорта превращается в профиль с UDP `xudp`. Jev подтвердил: вероятность `1.0`.

### 4. WireGuard импортируется, но не экспортируется

**Статус: исправлено.** Добавлен экспорт WireGuard URI и round-trip тест.

`parseWireGuard` поддерживает `wireguard://`, однако `exportOutboundToUri` не имеет `wireguard` case. `servers:export-key` возвращает `unsupported-protocol`, bulk export увеличивает `skipped`.

README заявляет экспорт ключей для всех протоколов. Jev подтвердил: вероятность `1.0`.

### 5. Некорректная проверка split-tunneling registry paths

**Статус: исправлено.** Исправлен PowerShell split registry path с проверкой на Windows.

Подтверждено на реальном Windows PowerShell. В исходнике TypeScript строка имеет четыре обратных слеша внутри template: `$root.Split('\\\\')`. После интерполяции это PowerShell-литерал с двумя символами `\\`, а registry path содержит одиночные `\`. Поэтому `.Split('\\\\')` возвращает весь `HKLM\SOFTWARE\...` одним элементом (`count=1`); корректный `.Split('\\')` возвращает `HKLM`, `SOFTWARE`, ... . Затем `$hive` не равен `HKLM`, `$subPath` неверен, и registry enumeration обычно даёт пустой результат. Jev подтвердил finding с вероятностью `0.99`.

**Эффект:** installed-app discovery может стабильно возвращать `[]`; UI не показывает приложения для split tunneling. Jev: bug около `0.85`.

### 6. DNS-профиль не поддерживает разные протоколы primary/secondary

**Статус: исправлено.** Primary и secondary теперь передают отдельные типы DNS.

`DnsSettings` вычисляет `secondaryType`, но отправляет только `primaryResult.type`. `DnsProfile` хранит один `type`, а `buildRemoteDnsServers` применяет его к обоим адресам.

**Эффект:** допустимая пара DoH + plain DNS либо теряет secondary, либо получает неверный тип. Jev: `0.95`; sing-box docs подтверждают, что тип задаётся у каждого DNS server.

### 7. DNS CRUD не вызывает полную валидацию адресов

**Статус: исправлено.** Create/update вызывают полную проверку DNS-адресов.

`dnsProfiles` проверяет строки и enum, но create/update не вызывают `validateDnsAddress`. Некорректные адреса сохраняются, а затем silently отбрасываются/заменяются при генерации sing-box config.

### 8. Scheduled local-proxy connect может дать unhandled rejection

**Статус: исправлено.** Добавлена обработка rejection и логирование ошибки.

В scheduler callback вызывается `resolveProxyForTrayStart().then(...)` без `.catch`. Функция await-ит `happDetector.detect()`, которое может reject.

**Эффект:** scheduled connect не логирует failure; Node может эмитировать `unhandledRejection`. Jev: `0.97`. Тесты не покрывают этот путь.

### 9. Profile rotation timer без обработки rejection

**Статус: исправлено.** Rotation timer теперь перехватывает rejection.

`setTimeout(async () => { await performRotation() })` не имеет catch.

**Эффект:** отказ ротации становится необработанным promise rejection и не превращается в диагностируемый результат.

### 10. Stale profile status влияет на rotation

**Статус: исправлено.** Учитываются только свежие статусы; неизвестные значения не маскируются под online.

`buildAvailabilityMap` пропускает live probe для enabled-профилей, если status не `offline`. Старый `online`/`unknown` может считаться актуальным и быть выбранным.

### 11. Adaptive bypass реализован слабее заявленного плана

**Статус: исправлено.** Добавлено 20-секундное окно и три последовательные проверки.

`docs/adaptive-bypass-plan.md` требует стабильное окно 20–30 секунд и свежий egress перед сохранением режима. Runtime делает один probe после примерно 1.2 секунды и сразу сохраняет success.

**Эффект:** transient connectivity может быть записана как устойчивый рабочий режим. Jev: `0.95`.

### 12. Scheduler допускает пересекающиеся окна

**Статус: не исправлено.** Runtime validation добавлена, но автоматическое обнаружение overlap-окон ещё не реализовано.

Хранится один ближайший event. Для расписаний Mon 09–17 и Mon 10–12 callback stop в 12:00 отключит VPN, хотя первое окно ещё активно. UI не запрещает overlap.

### 13. First-run mode choice не сохраняется

**Статус: исправлено.** Выбранный режим сохраняется при завершении wizard.

Wizard хранит `selectedMode` (`hard`, `soft`, `direct`), но `handleFinish` не сохраняет его; `AppSettings` этого поля не имеет.

**Эффект:** пользовательский выбор режима в onboarding не влияет на последующий запуск.

### 14. Speed test может сообщить success при неверном egress

**Статус: исправлено.** Несовпадение egress теперь завершает тест ошибкой.

`runSpeedTest` проверяет TUN в начале. Если позже egress не соответствует tunnel, пишется warning, но результат всё равно сохраняется как complete/success и показывается UI как успешный.

### 15. URL availability делает слишком сильный вывод

**Статус: исправлено.** Без VPN-измерения verdict теперь `unknown`.

При `tunnel === null` и недоступном direct report verdict может стать `works-only-with-vpn`, хотя VPN вообще не был измерен.

### 16. Domain enrichment не закрепляет DNS результат за Chromium

**Статус: не исправлено.** IP pinning для Chromium по-прежнему отсутствует.

После safe DNS lookup Chromium/proxy разрешает host самостоятельно. Есть scheme/allowlist checks, но нет IP pinning; redirects проверяются отдельно. Для programmatic `loadURL` Electron `will-navigate` не является достаточным контролем.

### 17. IP classifier не покрывает mapped IPv6/NAT64 формы

**Статус: исправлено.** Добавлена классификация hex mapped IPv6 и NAT64 prefix.

Проверяется dotted `::ffff:x.x.x.x`, но не hex/expanded mapped IPv6 и NAT64 `64:ff9b::/96` формы.

Дополнительный E2E exploit не доказан, но классификатор теперь покрывает указанные формы.

### 18. `server:probe` принимает произвольный host/port

**Статус: исправлено.** Добавлена блокировка loopback/private адресов, включая разрешённые DNS-адреса.

IPC проверяет типы, но не ограничивает host/private ranges и не связывает запрос с выбранным profile. Реализуется DNS/reverse-DNS/ASN/TCP probing произвольной цели.

Полный SSRF impact не утверждается; runtime-блокировки добавлены.

### 19. Domain-routing IPC имеет слабую runtime validation

**Статус: исправлено.** Добавлена runtime-проверка action, pattern и import path.

`domain-routing:import` напрямую читает переданный `filePath`; add/update принимают spread-объект с минимальной нормализацией pattern. Preload проверяет только базовые типы.

### 20. Scheduler/theme persist arbitrary IPC objects

**Статус: исправлено.** Добавлена runtime schema validation для scheduler и theme IPC.

`scheduler.createSchedule/updateSchedule` и `themeManager.createTheme` spread arbitrary objects в persisted state. TypeScript типы не заменяют runtime schema validation.

### 21. Diagnostic cleanup возвращает успех при подавленной ошибке

**Статус: не исправлено.** Отдельный cleanup-path всё ещё требует проверки результата и ошибок удаления.

Cleanup подавляет `rm` failure и возвращает success; renderer не проверяет возвращённый `success` во всех путях.

### 22. Git autoconfig rollback может снять чужой proxy

**Статус: исправлено.** При malformed backup rollback больше не снимает внешний proxy без подтверждённого backup.

При malformed backup rollback unsets global Git proxy и возвращает true. Это может изменить пользовательскую конфигурацию за пределами приложения.

### 23. Autoconfig apply не компенсирует частичный failure

**Статус: исправлено.** Добавлена компенсация ранее успешно применённых targets.

`autoconfig.apply` проходит targets последовательно и возвращает per-target booleans без automatic compensation, если следующий target не применился. Renderer actions apply/rollback фактически не найдены (preload exports имеют zero renderer consumers).

### 24. Subscription refresh interval имеет вероятную ошибку единиц

**Статус: не исправлено.** Единицы interval требуют отдельного подтверждения по формату конкретного провайдера.

Parser сохраняет `profile-update-interval` как seconds, scheduler умножает на 1000. Hiddify convention/documentation использует hours (пример `12`), что даёт примерно 12 секунд вместо 12 часов.

### 25. Subscription dedupe может схлопывать разные credentials

**Статус: исправлено.** Dedupe учитывает source URI/name и не смешивает разные credentials.

Dedup key основан на endpoint tuple и может удалить профили с одинаковыми host/port, но разными UUID/password.

### 26. Runtime live-apply неполный

**Статус: исправлено частично.** Ключевые настройки обновлены и проверены, но полный Windows runtime E2E hot-reload не выполнен.

Изменения proxy engine, deep traffic settings и части adaptive settings сохраняются, но не всегда перезапускают уже работающий TUN. Пользователь видит новое значение, пока runtime использует старое.

### 27. Firewall/browser manifest schema не валидируется достаточно строго

**Статус: исправлено.** Recovery manifest теперь проверяет структуру и типы backup-полей.

Recovery/read paths принимают неполные или malformed backup manifests без полноценной schema validation. Возможны пропуски восстановления и misleading status.

### 28. Browser hardening имеет неполную доказательность результата

**Статус: не исправлено полностью.** Runtime-проверка конкретных Chromium policy конфликтов требует Windows E2E.

Chromium target считается защищённым, если подтверждена хотя бы одна HKLM/HKCU policy ветка (`confirmedCount > 0`). Это согласуется с policy precedence, но нет отдельного runtime-теста на конфликт/неприменимость конкретного браузера; считать полное browser coverage доказанным нельзя.

### 29. External proxy leases не переживают restart

**Статус: исправлено.** Lease state сохраняется в `electron-store`, просроченные leases отбрасываются при старте.

Lease state хранится in-memory. После перезапуска прежние leases теряются, хотя внешний клиент может считать их действующими.

Это был design concern, а не подтверждённый high-confidence production bug.

### 30. External proxy control API раскрывает metadata без token

**Статус: исправлено.** Metadata GET endpoints теперь требуют control token.

Mutation endpoints требуют token, но GET `/status`, `/instances`, `/list` возвращают metadata без token. Это следует оценивать как локальную privacy/design concern, а не как доказанный критический дефект.

## Legacy/maintenance

- Electron 42, electron-vite 3, React 18, electron-store 8 и старый toolchain требуют планового обновления; Tavily подтвердил актуальную ветку Electron 44 и более новые major releases.
- `README.md` заявляет `414 tests across 43 files`; фактический текущий baseline — `128` files и `1200` tests. Jev подтвердил stale count с вероятностью `1.0`.
- Native ETW sidecar fallback на PowerShell допустим, но Rust toolchain не проверен в текущей среде (`cargo` отсутствует).
- Sidecar PowerShell polling может пропускать более 80 событий между опросами; `build-sidecar.mjs` использует `shell: true`.
- Snapshot optimization фактически неполна: blobs складываются в `resources/snapshot`, но workflow не заменяет Electron runtime snapshots и не включает рабочий `snapshotResult`. Jev: `0.99`; приложение без snapshot не ломается.
- Traffic forensics читает большие ETL/pcap summary inputs; проверка ограничения памяти нужна для production-sized files.
- `sessionHitCounts` domain routing не имеет writer и фактически всегда 0; это dead/legacy contract.

## Проверенные отрицательные результаты

- Traffic connection storage не unbounded: домены ограничены `2000`, history — `1000`, log reader — `1 MiB` per reset.
- External proxy health queue имеет bounded concurrency; подтверждённого recursive drain bug нет.
- Server snapshot queue, sidecar packaging paths, physical adapter rollback и maintenance renderer status не дали нового подтверждённого дефекта.
- `npm audit` high-level production dependencies чист.

## Ограничения аудита

- Не выполнен полноценный Windows E2E: текущая среда не дала `cargo`, реальный Wintun/Firewall/Registry и installed Electron UI.
- Не проверены все протоколы на живом сервере; часть выводов относится к schema/round-trip, а не к handshake.
- Для некоторых concerns (SSRF race, lease persistence, manifest recovery) доказана слабость дизайна, но не полный production exploit.
- Основной fix-проход выполнен: исправления перечислены в разделе «Статус исправлений» и проверены typecheck/build/full test suite. Отдельные Windows E2E и инфраструктурные ограничения остаются как указано выше.

## Источники внешней сверки

- sing-box VLESS: https://sing-box.sagernet.org/configuration/outbound/vless
- sing-box VMess: https://sing-box.sagernet.org/configuration/outbound/vmess
- sing-box changelog/WireGuard deprecation: https://sing-box.sagernet.org/changelog
- Electron fuses/custom snapshots: https://electronjs.org/docs/latest/tutorial/fuses
- Node promise rejection semantics: https://nodejs.org/api/process.html
- Microsoft registry policy guidance: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/implementing-registry-based-policy
