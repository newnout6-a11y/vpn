# Исследование и ускорение включения/выключения VPN

Начало: 2026-10-01. Рабочие пакеты: WP-0 (замеры), WP-2 (lifecycle), WP-3 (firewall/recovery).
Это журнал исследования и изменений, а не нормативное ТЗ.

## Задача владельца

Подробно изучить весь процесс включения и выключения, использовать внешнюю документацию, найти и реализовать ускорения без потери качества, продолжать исследование после первых улучшений. Сначала сохранить исходное состояние, вести журнал правок.

## Исходная точка

- HEAD до исследования: `11014ba` (`fix(tun): settle startup failures and verify native Windows identities`). Рабочее дерево чистое. Существующие изменения уже закоммичены; первый коммит исследования сохраняет этот журнал без изменения исходников.
- Electron 44.4.3, приложение 1.1.22; Win32 PowerShell 5.1 используется системными операциями.
- Перед первым коммитом: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=dot --maxWorkers=4` — 154 файла passed, 2 skipped, 1477 тестов passed, 10 skipped, 0 failures (56.81 s); `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — exit 0, AC 927/927, F 210/210.

## Фактические измерения исходной версии

Источник: `%APPDATA%/vpn-tunnel-enforcer/logs/app.log`, сессия 2026-10-01 00:25–00:26 MSK (в файле UTC 2026-09-30 21:25–21:26). Времена ниже получены из событий, а не из ощущения скорости UI.

| Этап | Время | Примечание |
| --- | ---: | --- |
| Полный IPC start-direct-vpn | 22 755 ms | 21:25:52.483 → 21:26:15.238 UTC |
| Подготовка до tunController.start | ~3 076 ms | Проверка старого firewall, профиль, подготовка |
| tunController.start | 19 015 ms | Есть подробные start timing |
| Xray / proxy validation | ~3 071 ms | Локальная готовность процесса, не доказательство удалённого egress |
| Physical adapter lockdown | 3 797 ms | Параллельно с подготовкой ядра |
| Ожидание sing-box процесса | 441 ms | Один probe |
| Ожидание TUN-интерфейса | 11 ms | Интерфейс уже появился |
| Снимок владельца TUN | 2 383 ms | Запрос native identity + durable journal |
| Полная установка firewall | 15 208 ms | Параллельная фаза; основной критический путь |
| Ожидание firewall после готовности TUN | 12 704 ms | Часть предыдущей строки, не прибавлять повторно |
| Полный IPC stop-tun | 10 993 ms | 21:26:28.084 → 21:26:39.077 UTC |
| Остановка VPN-процессов | 1 129 ms | До события TUN stopped |
| Baseline rollback + первая проверка firewall | 2 652 ms | До auto-disable; отдельные внутренние времена пока не выделены |
| Снятие firewall | 3 961 ms | auto-disable → disengaged |
| Physical adapter rollback | ~980 ms | До transition adapters restored |
| Первая orphaned-DNS проверка | ~1 395 ms | После штатного adapter rollback |
| Повторная orphaned-DNS проверка | ~768 ms | stopProtection после tunController.stop |

Три read-only запуска `powershell.exe -NoProfile -NonInteractive -Command "[Console]::Write('ok')"`: 220/200/193 ms, exit 0. Это только цена простого процесса; ACL, импорт NetSecurity и CIM-операции добавляют время.

## Карта процесса и подтверждённые кандидаты

1. UI → IPC → `startDirectVpnProtection`: soft rollback, проверка stale firewall, выбор профиля, network baseline параллельно, `tunController.start`, IP-monitor/history/diagnostics, фоновые egress и adaptive probes.
2. `tunController.start`: competing-TUN preflight, split rules, Xray, runtime/config/process ownership cleanup, adapter lockdown, spawn, process/TUN readiness, durable TUN-owner journal, interface metric, firewall completion, status.
3. `enableKillSwitchUnlocked`: trusted manifest read, original profiles snapshot, prepared durable journal, native core rules + Block, active durable journal, отдельная live exceptions transaction, status.
4. `stopProtection` → `tunController.stop`: остановка внешних proxy, Xray/sing-box, baseline rollback, firewall rollback, adapter rollback, orphaned-DNS проверка; затем повторная DNS проверка и location privacy.
5. Shutdown после штатного stop повторно проверяет baseline/firewall/adapters. Уже неактивный firewall также требует дорогой trusted read + native rule probe.

| Кандидат | Доказательство | Ограничение |
| --- | --- | --- |
| Лениво сохранять fallback firewall script | `ps()` пишет ACL-protected файл до проверки persistent helper; writeRecoveryArtifact запускает 2 PS-процесса | Fallback всё равно должен получать доверенный файл до исполнения |
| Совместить bootstrap/ACL/read проверки storage | ensure + read повторно проверяют root/directories в разных PS-процессах | Нельзя кэшировать доверие к ACL/пути или доверять отсутствию без проверки |
| Использовать постоянный helper для storage | Каждое read/write/remove стартует отдельные PS-процессы | Нельзя расширять произвольную административную политику; нужен отдельный ограниченный интерфейс |
| Убрать лишнюю стартовую live transaction | Arrays передаются всегда, даже пустые; initial core transaction уже чистит stale VPNTE rules | Нельзя пропускать native read-back; учитывать strictMode и pending recovery journal |
| Разделить ожидание адаптера и firewall | Firewall-скрипт содержит Get-NetAdapter, запрещённый helper policy; попадает в fallback | Проверка адаптера и необходимое allow rule обязаны остаться, отмена должна завершать pending transaction |
| Дедуплицировать DNS/stop/shutdown cleanup | Одинаковые repair вызваны tunController, index, shutdown | Ошибка первого шага не должна отменять независимые последующие шаги; не скрывать частичный rollback |
| Добавить внутренние timings | Сейчас firewall измеряется одной большой фазой; stop не имеет phase timing | Только длительности/счётчики, без секретов/топологии |

## Инварианты качества

- Durable baseline до любых системных изменений; atomic rename/fsync и ACL/reparse/known-folder проверки сохраняются.
- Никакого кэширования доверия к манифесту; каждый authoritative read проверяется.
- Чужие firewall/adapters/processes не изменяются. Baseline исходного Block сохраняется.
- Rollback шаги независимы, failed verification не становится success; cancel/quit дожидаются своих транзакций.
- Фоновые adaptive/egress probes не подменяют готовность; предупреждение о непроверенном egress не подавляется ради быстрого UI.
- Не уменьшать deadlines/grace/retry и не отключать CRL/Defender/ACL для получения красивых цифр.
- Проверки реальной сети и L3 chaos пока не проводились. Native тесты с фиктивными cmdlets не выдаются за реальное измерение подключения.

## Внешняя документация

- [Microsoft: диагностика startup PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/startup-performance?view=powershell-7.5): отдельно измерять процесс, engine и profile; использовать NoProfile/NonInteractive. Описанный CRL timeout относится к PS7 interactive startup; считать его причиной этого случая без замеров нельзя.
- [Microsoft: Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps): persistent policy и effective ActiveStore различаются; ускорение не должно подменять проверку фактической политики наличием записи.
- [Node 24: fs](https://nodejs.org/docs/latest-v24.x/api/fs.html): запись/fsync и rename рассматриваются отдельно; durable snapshot нельзя заменить простой записью ради скорости.

## Журнал изменений

### 2026-10-01 — исходная фиксация

Прочитаны AGENTS, WP-2/WP-3 acceptance, разделы 2.1–2.3 security ТЗ и lifecycle ТЗ. Проверена чистая исходная версия. Разложены реальные start/stop логи, найден критический firewall путь и повторные операции. Исходники ещё не изменены.

## Следующие доказательства

- Подробные timing и число OS boundaries в firewall/storage/stop.
- Regression/fault-injection для новых fast paths и fallback, затем полные DoD проверки.
- Read-only native benchmark холодных/повторных probes; сравнение до/после по одинаковому сценарию.
- Дополнительный разбор Xray, DNS/bootstrap, concurrent диагностики, UI, cancel, restart, shutdown.
- Отдельный разбор предупреждения `TUN routes are not active after direct probe timeout`: start returned success, VPN IP/routes не подтверждены. Недостаточно доказательств, чтобы обвинить конкретный сервер или Happ.

### 2026-10-01 — этап 1: firewall fast path и native benchmark

Изменения:

- `firewallKillSwitch.ps`: сначала постоянный помощник (включая read-only запросы), fallback-файл создаётся только если он нужен. ACL-проверка fallback-файла сохранена.
- После timeout/exit/неизвестного отказа helper нет слепого повторного исполнения. Fallback допустим лишь для typed unavailable/script-rejected, то есть до начала эффектов. Ответ с ненулевым exitCode считается отказом, а не успешной командой.
- Initial core policy и initial exceptions теперь одна native transaction под одним prepared journal. `pendingExceptionPolicy` записывается ДО эффектов; Block/rules/filter/set read-back выполняется в том же скрипте, включая пустой набор. Active commit содержит проверенную policy и удаляет pending. При script/marker/commit failure выполняется компенсация всей initial transaction; неудачная компенсация сохраняет prepared journal.
- Live updates уже работающей защиты остаются отдельными сериализованными транзакциями с прежним baseline.
- Новые phase timing: read manifest, snapshot profiles, prepared journal, native apply, active commit, live phases, restore policy, clear journal. Command timing различает helper/file/elevated-file, стоимость записи fallback и выполнения. Логи не содержат текст команд/секреты.
- Добавлен повторяемый read-only `scripts/benchmark-windows-probes.mjs`. Он не подключает VPN и не меняет network/firewall/registry/ACL. Сырые времена в `.tmp/windows-probe-benchmark.json`; таблица ниже сохранена в Git.

| Read-only probe (5 cold + 5 warm) | Cold median | Warm first | Warm median |
| --- | ---: | ---: | ---: |
| No-op | 138 ms | 72 ms | 1 ms |
| Firewall profiles | 684 ms | 534 ms | 15 ms |
| Owned firewall rule count | 937 ms | 261 ms | 248 ms |
| Adapter count | 752 ms | 607 ms | 23 ms |
| Default/split-route count | 532 ms | 560 ms | 13 ms |

Все 50 probes успешны. Вывод: повторное использование процесса особенно полезно для NetSecurity/NetAdapter/NetTCPIP после первого импорта; wildcard firewall query остаётся заметной операцией и в тёплом процессе. Это не измерение end-to-end подключения после изменений.

Проверки до финального DoD этого этапа:

- `npm.cmd run typecheck` — exit 0.
- `$env:VPNTE_PWSH='powershell.exe'; npm.cmd test -- src/main/firewallTransactions.test.ts src/main/elevatedPsHelper.test.ts src/main/tunControllerStartup.test.ts --reporter=dot --maxWorkers=4` — 3 файла, 54 теста passed, 0 skipped/failures (3.15 s).
- Native initial policy: empty/one/multiple CIDRs; native live policy: empty/one/multiple CIDRs; compensation, absent helper, helper rejection/unavailable/timeout/exit, exitCode failure; preservation of original Block; no fallback artifacts on fast path.
- Промежуточная full suite до последнего read-only fast path: 154 passed / 2 skipped files, 1494 passed / 10 skipped tests, 0 failures (48.92 s). Итоговый прогон будет записан отдельно.
- `python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py` — exit 0, AC 927/927, F 210/210.
- Native harness сначала обнаружил ограничения Windows command-line длины и две ошибки фикстуры (имя hash-map конфликтовало с production `$rules`, затем streaming enumeration менялась при Remove). Harness перенесён в собственный `.tmp/firewall-initial-*/harness.ps1`, фикстура выдаёт снимок коллекции; собственные файлы/каталог удаляются в finally. Эти неуспешные прогоны не считаются доказательством успешной проверки.

Не считать цель завершённой: остаются storage cold launches, main firewall adapter wait/fallback, повторный stop/shutdown cleanup, Xray/DNS/preflight/diagnostics и маршрутный warning. Тайминги реального пользовательского start/stop после изменений ещё не получены.

Дополнительный контроль: первый итоговый full run (50.45 s) дал 1495 passed, 10 skipped, 1 timeout в существующем `twitchHlsProbe.test.ts` (5 s). Отдельный повтор этого файла — 14/14 passed (2.94 s). Тест реально вызывает media probe без HTTP fixture; поэтому этот результат не объявлен успешным полным DoD. Выполняется повтор всего набора без параллельного native benchmark. Production-код media probe и timeout теста не менялись.

Итоговый DoD этапа 1: повтор `npm.cmd test -- --reporter=dot --maxWorkers=4` — exit 0, 154 passed / 2 skipped files, 1496 passed / 10 skipped tests, 0 failures (48.80 s). `npm.cmd run typecheck`, coverage (AC 927/927, F 210/210), `node --check scripts/benchmark-windows-probes.mjs`, `git diff --check` — exit 0. Все изменения этого этапа готовы к атомарному коммиту; наблюдённый media-probe timeout оставлен в журнале как ограничение существующего теста.
