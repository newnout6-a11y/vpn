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

### 2026-10-01 — этап 2: объединённая trusted storage boundary

Этап 1 сохранён в `f029600`, исходная фиксация в `a8c5575`.

`recoveryManifest.ts`: authoritative manifest read, binary artifact read и removal на существующем storage выполняются одним native процессом. Внутри одного запроса каждый раз проверяются Windows known folder, тип/reparse родительского ProgramData, оба защищённых каталога, owner/protected DACL/allow ACE, тип/reparse/owner/DACL самого файла и лимит размера до чтения. Доверие не кэшируется. Bootstrap/elevation запускается только по явному маркеру действительно отсутствующего проверенного каталога; после bootstrap весь запрос повторяется с новыми проверками. Ошибки ACL/permissions/path не превращаются в отсутствие и не запускают «исправление» чужих ACL. Повторное исчезновение после bootstrap даёт ошибку, а не бесконечный retry.

Durable write path (unique wx + fsync + ACL + rename) не изменён. Known-folder prelude выделен в общую функцию для bootstrap и read, чтобы их правила не расходились.

Целевые проверки: `$env:VPNTE_PWSH='powershell.exe'; npm.cmd test -- src/main/recoveryManifestStorage.test.ts --reporter=dot --maxWorkers=4` — 36/36 passed (7.55 s). В том числе native fixture matrix: trusted/file absent, неправильный root/file owner, посторонний directory ACE, parent/file reparse, неверный file type, unprotected DACL, oversize. Файловые cmdlets фиктивные; настоящие ProgramData/ACL не менялись. Bootstrap, повторное исчезновение, смена trust после первого read, binary/remove boundary, fsync/write failures также проверены.

Ожидаемый эффект определяется числом границ: каждый обычный read/remove исключает один cold PowerShell launch и повторные directory ACL checks. Миллисекунды настоящего start/stop после этой правки ещё не измерены.

Дополнительно native matrix расширена: посторонний file ACE, leaf unprotected DACL, directory reparse, несовпадающий ProgramData env. Последний целевой прогон — 40/40 passed (9.79 s). Совместный native прогон recovery storage/boot behavior/boot execution/firewall/systemNetwork до этих четырёх новых сценариев — 5 файлов, 122/122 passed (9.59 s).

Итоговый DoD этапа 2: `npm.cmd test -- --reporter=dot --maxWorkers=4` — exit 0, 154 passed / 2 skipped files, 1515 passed / 10 skipped tests, 0 failures (50.57 s). `npm.cmd run typecheck`, coverage AC 927/927 и F 210/210, `git diff --check` — exit 0. Цель по-прежнему активна; дальнейший приоритет — убрать дублирующий native TUN wait из firewall без расширения helper policy, затем stop/shutdown и Xray/preflight.

### 2026-10-01 — этап 3: единое ожидание принадлежащего VPNTE TUN

- Подготовка firewall snapshot/journal по-прежнему идёт параллельно с ожиданием TUN. Перед native effects добавлен internal Promise barrier: true только после успешного `recordOwnedTunAdapter` (GUID/driver/PnP/address + durable ownership journal). JS deadline 5 s не сокращён. При false/rejection выполняется прежняя компенсация prepared transaction, отказ не превращается в успех.
- Startup script больше не содержит Get-NetAdapter/poll/Start-Sleep, поэтому проходит настоящую неизменённую helper firewall policy. Legacy callers без barrier сохраняют bounded native wait. Политика physical adapters не получила firewall права и наоборот.
- При cancel во время interface/ownership wait, unready TUN или exception barrier закрывается false и pending firewall transaction завершается ДО cleanup. Это исключает запоздалое применение правил после начала rollback.
- Удалено лишнее создание legacy extra-IP rules: initial exceptions теперь сразу создаются в ранее объединённой transaction с hashed names и полным read-back. Очистка старых legacy rules при migration/live update сохранена.
- Целевой native прогон `VPNTE_PWSH=powershell.exe; npm.cmd test -- src/main/firewallTransactions.test.ts src/main/tunControllerStartup.test.ts src/main/elevatedPsHelper.test.ts --reporter=dot --maxWorkers=4`: 64/64 passed (4.69 s). Native empty/one/multiple CIDR matrix выполнена и с barrier, и без; actual helper validator принимает fast script и отклоняет legacy mixed script. OS cmdlets — fixtures, реальная Windows policy не менялась.
- Первый целевой прогон: 63 passed / 1 assertion failure — тест запрещал даже необходимое удаление старого legacy rule. Исправлен oracle, который проверяет отсутствие его создания. Первый full run: 1531 passed / 3 skipped / 1 failure — существующий source assertion ожидал старую интерполяцию alias вместо `psSingleQuote`. Oracle обновлён на безопасное quoting; выполняется повтор полного DoD.
- `npm.cmd run typecheck`, coverage AC 927/927 и F 210/210, `git diff --check`: exit 0. Пользовательские end-to-end времена после этих изменений ещё не получены.

Итоговый DoD этапа 3: `VPNTE_PWSH=powershell.exe; npm.cmd test -- --reporter=dot --maxWorkers=4` — exit 0, 155 passed / 1 skipped files, 1532 passed / 3 skipped tests (51.03 s). Дополнительные семь native cases теперь включены переменной окружения и в полном прогоне. Typecheck и coverage ранее этого этапа — exit 0; `git diff --check` повторяется перед коммитом.

### 2026-10-01 — этап 4: исключение повторных подтверждённых rollback

- `tunController.stop` выдаёт внутренний receipt текущей операции отдельно по baseline, firewall и adapters. Receipt не кэшируется между stop/session и не выходит в обычный stopProtection IPC outcome. Неподтверждённые этапы остаются false; independent retries остаются для каждого из них.
- `rollbackPhysicalAdapterLockdownIfApplied` различает отсутствие trusted manifest (`skipped:true`) и incomplete rollback (`rolledBack:false` без skipped). Trust read errors по-прежнему выбрасываются; отсутствие ownership не превращает чужой DNS в наш и не запускает его сброс.
- DNS safety repair в контроллере и index пропускаются только после подтверждённого rollback/verified no-op в этой остановке. После incomplete/error резервный repair сохраняется; повторный неподтверждённый результат теперь входит в warning вместо ложного чистого выключения.
- Shutdown не повторяет подтверждённые network stages своего только что завершённого `stop()`. Если stop выбросил исключение, metadata отсутствует либо отдельный stage false, соответствующие backstops выполняются. Process backstops (Xray/owned sing-box/external proxies) сохранены: `stopXray` пока не даёт доказательства завершения процесса, поэтому его повтор не удалён ради скорости.
- Новые `stop timing`: stop-xray, stop-runtime, wait-runtime-exit, rollback-baseline, disable-firewall, rollback-adapters, repair-dns, total. Deadline/grace и порядок этапов не сокращены/не переставлены.
- Целевой прогон `npm.cmd test -- src/main/lifecycleCleanup.test.ts src/main/tunControllerRecoverySource.test.ts src/main/mainIpcRegression.test.ts src/main/physicalAdapterLockdownSource.test.ts --reporter=dot --maxWorkers=4`: 4 files, 64/64 passed (2.27 s). Новые тесты исполняют production AST bodies с fake OS boundaries: positive/no-op, partial/recovered retry, runtime/baseline/firewall/adapter/DNS failure matrix, later ACL change, adaptive preservation, shutdown per-stage retries, IPC stripping. Первый прогон нашёл старый source oracle для return shape; обновлён под receipt, поведенческий stopped/warning contract проверяется также новым исполнением.
- `npm.cmd run typecheck`, coverage AC 927/927 F 210/210 — exit 0. Полный native suite выполняется; trailing whitespace замечен diff-check и удалён, повтор проверки обязателен.

#### Зафиксированные расхождения, не исправленные молча

`docs/02-…md`, §2.1 требует firewall policy → rules → DNS → protocols → registry → Wintun. Текущий обычный stop завершает runtime/TUN, затем registry baseline, firewall и adapter rollback; внутри physical rollback IPv6 идёт перед DNS. Это существующее расхождение, ускорение его не меняет. Предложение: отдельный согласованный WP-2/WP-3 lifecycle coordinator с independent staged rollback и native chaos proof; требуется решение владельца согласно AGENTS перед перестановкой.

`stopXray` делает `child.kill()` и сброс active state/PID-файла без ожидания exit; при ошибке kill пишет warn, но не возвращает typed failure. Xray preflight `run -test` не имеет явного deadline и собирает stdout/stderr без bounded buffer; runtime stderr listener прикрепляется после firewall probe. Эти факты не доказывают причину измеренных 23 s, но требуют отдельной проверки lifecycle contract и предельных случаев. Process backstops сохранены до получения stronger proof.

[Microsoft Set-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress?view=windowsserver2025-ps): static addresses заменяют DHCP-derived DNS, ResetServerAddresses возвращает DHCP. Поэтому оптимизация не заменяет read-back безусловным reset и не трогает DNS без owned baseline.

Итоговый DoD этапа 4: `VPNTE_PWSH=powershell.exe; npm.cmd test -- --reporter=dot --maxWorkers=4` — exit 0, 156 passed / 1 skipped files, 1551 passed / 3 skipped tests (56.74 s). Typecheck, traceability AC 927/927 F 210/210 и финальный `git diff --check` — exit 0. Реальные пользовательские stop/quit после изменений пока не измерены.

### 2026-10-01 — этап 5: Xray timing и повторная проверка readiness

- После устранения duplicate native adapter wait перепроверено равенство гарантий: в `recordOwnedTunAdapter` добавлена явная native `Status=Up` проверка до GUID/driver/PnP/IP ownership commit. Native negative fixture с правильными driver/PnP/IP и Disconnected запрещает commit. JS helper comment исправлен: он ищет candidate address, а не выполняет Get-NetAdapter.
- Xray start получил длительности stop-previous, prepare-runtime, cleanup-pid, rotate-log, resolve-server, pick-port, write-config, config-preflight, write-pid, allow-firewall, wait-local-socks и total/success. Ошибки сохраняют partial timings и исходное исключение. Timing event не содержит endpoint/config/credentials. Сам алгоритм и deadlines не сокращены.
- `npm.cmd test -- src/main/lifecycleCleanup.test.ts --reporter=dot --maxWorkers=4`: 22/22 passed (1.88 s). Production Xray body исполняется с fake child events/clock/OS: phase deltas, skipped endpoint/port overrides, propagated failure и отсутствие текста исключения в timing. Native storage/startup целевой прогон: 52/52 passed (10.12 s).
- Первый typecheck нашёл tuple typing у zero-argument log mock; mock сделан variadic, повтор typecheck — exit 0. Full native suite: 156 passed / 1 skipped files, 1555 passed / 3 skipped tests (62.25 s), exit 0. Coverage AC 927/927 F 210/210 и diff-check — exit 0.
- Bundled `resources/sing-box.exe version`: 1.13.13, Go1.25.10 windows/amd64, revision 78b2e12fbdd85e6ec956647d6f79cf0bba85c6ba. Это read-only запуск version, TUN/network не запускались.

#### Дополнительные кандидаты и ограничения

| Участок | Что установлено | Следующее доказательство / решение |
| --- | --- | --- |
| Main после успешного TUN start | Обе ветки ждут `ipMonitor.getCurrentIp()` до возврата IPC. Он делает HTTP, одновременно startMonitoring уже запускает другой IP probe | Измерить post-start IP отдельно. Перенести в существующий background poll с generation fence, сохранив проверки/обработку ошибок |
| IP provider race | Четыре endpoints через Promise.any, axios timeout=10 s; параллельная гонка, не последовательные 40 s | Global single-flight/cache без generation небезопасен: результат старой сети может попасть в новую baseline |
| Pre-VPN IP naming | preVpnIp/preVpnIpDirect получают ПОСЛЕ запуска TUN. Если уже получен exit IP, poll не увидит смены и пойдёт в route fallback | Разделить prior-session evidence и post-start sample, согласовать status/egress контракт |
| Route fallback | Current probe ищет /0 либо 0/1 по ALL_KNOWN_ALIASES, не проверяет оба /1, GUID или effective selected route; exception и absence оба false | Typed диагностика + exact owned identity + оба маршрута и end-to-end egress; не расширять success oracle до «любой route» |
| Source config | auto_route=true, strict_route=true, IPv4 route_address=[0/1,128/1], IPv6 не захватывается | Сопоставить real route dump/child log после воспроизведения; protected runtime logs недоступны этому shell |
| DNS bootstrap | Xray resolve4 → lookup IPv4 до adapter lockdown; нет явного cancellation/deadline на resolver sequence | Сохранить bootstrap до lockdown. Abort/deadline + operation fencing требуют отдельных tests |
| Runtime preparation | OS port picks, параллельные stale-only binary copies, ACL до staging; rule-sets local, failure безопасно отключает split | Отказ от ACL/hash/port preflight ради скорости отклонён. First/warm staging уже различаются |
| Cancel/stop start wait | Stop выставляет stopRequested, ждёт startInProgress не более 2 s, затем cleanup; poll/native calls могут ещё идти | Проверить весь lifecycle mutex/fencing, а не только poll callback; WP-0 deadline/cancel coordinator |
| UI feedback | Cancel сразу ставит connectionCancelling и invalidates transition seq; purple circle/busy button/warning outcome | UI tests зелёные. Animation не создаёт измеренную 23 s задержку |
| Adaptive stability | Stable20s + probes фоновые, scheduleAdaptiveVerification не awaited | Не убирать stability ради сокращения IPC: она уже вне critical path |
| Restart/foreign VPN | Generation/restart timers и independent owned cleanup обязательны; Happ warning появился после stop | Нет доказательств обвинять Happ/сервер в измеренном firewall времени |

[sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/): strict_route на Windows защищает multihomed DNS, route_address заменяет default routes. Проверка должна учитывать config и actual runtime version; присутствие адаптера не доказывает egress.

[Node child_process](https://nodejs.org/api/child_process.html#subprocesskilled): killed означает отправку сигнала, а не exit. Process backstops сохраняются до подтверждения завершения.

Следующий приоритет: post-start HTTP вне critical path с generation fence, полный cancel/restart coordinator, сборка/проверка installer и реальные before/after повторения. Цель активна; L2/native fixtures не заменяют L3 сеть/chaos и фактические пользовательские времена.

### 2026-10-01 — контрольная сборка после этапа 5

- Source commit: `8d8a557`; этап 4: `7197938`, этап 3: `3fcad89`. Working tree перед сборкой чистый.
- `npm.cmd run dist:win` — exit 0. Electron 44.4.3 x64, NSIS 1.1.22. Build включает typecheck. Snapshot generation пропущена из-за отсутствующего mksnapshot; это записано как ограничение сборки, не как созданный snapshot. DeprecationWarning DEP0190 относится к shell args build path; production lifecycle не менялся этой сборкой.
- Installer: `vpn-tunnel-enforcer/dist/VPN-Tunnel-Enforcer-Setup-1.1.22.exe`, 139146729 bytes, modified 2026-10-01T09:17:28.8267569+03:00.
- SHA256: `AEC816E3E5E2214728A71C02F1946F41F2E93D5E091CF32C4EBA25D3D90B5C2F`.
- Authenticode status: `NotSigned`; решение о signing не принято и не изменялось.
- Actual ASAR main содержит все пять markers: verified-adapter-wait, stop timing, tunAdapterReady, native adapter Up rejection, Xray allow-firewall timing. SHA256 пяти unpacked runtime resources (sing-box, Xray, Wintun, Cronet, vpnte-recover.ps1) совпали с workspace sources. Verifier exit 0.
- Сборка — контрольный артефакт текущих изменений, не подтверждение end-to-end ускорения. Installer ещё не запущен, настоящий VPN/network/firewall smoke этой версией не проведён. Из shell protected runtime/ProgramData недоступны; ACL не обходились.
- Дальнейшая работа не закончена: background IP/generation fence, cancel/start coordinator и реальные cold/warm before/after измерения остаются в scope исходной цели. Если следующие этапы меняют исходники, installer необходимо снова пересобрать и записать новый hash.

### 2026-10-01 — этап 6: post-start HTTP вне критического пути

- Обе main startup ветки больше не ждут HTTP `getCurrentIp()` перед возвратом native результата. Запрос перенесён внутрь существующего background poll: четыре endpoints, Promise.any, timeout 10 s, 16 повторов с интервалом 500 ms и route fallback сохранены. Native startup и baseline по-прежнему awaited; их failure/warning не скрываются. Это устраняет зависимость IPC completion от внешнего провайдера, но ещё не является измерением реального ускорения Windows.
- Startup IP-запросы получили owner predicate по generation/running. Проверка выполняется до HTTP, после каждого await и перед изменением cached IP, VPN baseline, health timestamp, recovery callback, UI/tray. Разные owners не разделяют rebaseline sample; новый owner ждёт завершения старого и запрашивает свежий. Same-owner и legacy single-flight сохранены, detached method тоже работает.
- Stop invalidates generation до медленного soft rollback; cancel IPC и shutdown invalidates до cleanup. Отмена во время provider HTTP либо native route probe не запускает дальнейший rebaseline. Ошибка первого background provider запроса логируется, не превращая уже подтверждённый native результат в rejected IPC.
- Новые delayed-boundary tests: отмена до/во время read/probe/rebaseline, old/new owner, отмена queued owner, coalescing, detached invocation; обе startup ветки возвращают результат при held HTTP, сохраняют ожидание baseline/warning/failure и прекращают поздний polling. Это L2 fake boundaries, не полный AT-00-003/AT-02-005 и не native network proof.
- `npm.cmd test -- src/main/tunControllerRecoverySource.test.ts src/main/lifecycleCleanup.test.ts src/main/ipMonitorSession.test.ts src/main/ipMonitor.test.ts src/main/mainIpcRegression.test.ts --reporter=dot --maxWorkers=4`: 5 files, 93/93 passed (2.52 s). Ранний fixture прогон обнаружил отсутствующую injected constant, она добавлена. Первый full suite: 1 failed / 1576 passed — старый shutdown oracle обрезал функцию на 1000 символах. Oracle заменён на полный AST function node, дополнительные executable shutdown tests сохранены.
- Финальный `VPNTE_PWSH=powershell.exe; npm.cmd test -- --reporter=dot --maxWorkers=4`: exit 0, 157 passed / 1 skipped files, 1577 passed / 3 skipped tests (60.11 s). `npm.cmd run typecheck`, `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` (AC 927/927, F 210/210), `git diff --check` — exit 0.
- Область ограничения: периодический unscoped `checkIp` пока не имеет lifecycle generation; stage 6 не обещает fencing всех HTTP в приложении. Незавершённые HTTP не abortятся физически и могут жить до прежнего timeout; новая scoped rebaseline не использует их sample, но может ждать. Geolocation после dynamic import, preflight, native effects и глобальный lifecycle требуют отдельного coordinator.
- Исправлен вводящий в заблуждение source comment «8 s max»: 8 s — сумма интервалов, HTTP может продлевать background проверку. Существующий preVpnIp, взятый после TUN start, и route/status oracle не изменены; нормативное расхождение уже записано в этапе 5.
- [Axios cancellation](https://axios.rest/pages/advanced/cancellation): AbortController/signal поддерживается, CancelToken deprecated. Возможный следующий шаг — operation-owned AbortSignal; отменять весь global HTTP/resolver нельзя, чтобы не затронуть чужую операцию.
- Последний доступный app.log по-прежнему modified 2026-10-01T00:26:57.8703357+03:00, 328207 bytes. Новых живых start/stop после оптимизации нет. Контрольный installer этапа 5 устарел относительно stage 6 и требует пересборки.

### 2026-10-01 — этап 7: воспроизводимый анализ логов и проект coordinator

- Добавлен read-only `scripts/analyze-lifecycle-log.mjs`: file/stdin JSONL → JSON с IPC duration, отдельными TUN/Xray timing events и sample counts/min/median/p95/max. Экспорт не содержит args/result/errors/endpoint/config/IP/path. Учитываются только allowlisted channels/phases; parallel/background не складываются в якобы total.
- Pairing без operation id допускается только для единственного same-channel окна. Overlap, отсутствие start/terminal, reversed timestamps, malformed/truncated records помечаются явно. Summary включает разные исходы (в том числе отменённые/ошибочные), поэтому нельзя объявлять его «временем успешного подключения». IPC finished само по себе не доказывает защищённость.
- `npm.cmd test -- src/main/lifecycleTimingAnalysis.test.ts --reporter=dot --maxWorkers=4`: 6/6 passed (1.50 s). Первый прогон выявил ошибку чтения stdin через promises.readFile(0); stdin заменён на чтение async iterable, повтор зелёный. Реальный file input также исполнен: `node scripts/analyze-lifecycle-log.mjs "$env:APPDATA\vpn-tunnel-enforcer\logs\app.log" > .tmp/lifecycle-before.json`, exit 0, invalidLines=0, outOfOrderRecords=0, unfinished=0, native timing events=1.
- Подтверждённые исходные IPC samples: start-direct-vpn 8209 ms (отмена) и 22755 ms (native successful start); stop-tun 11155/10993 ms; cancel-tun 6873 ms. Для successful start только один sample, статистическую оценку улучшения строить рано.

#### Конкретное предложение отдельного WP-0/WP-2/WP-3 coordinator

Это записанные существующие расхождения, а не доказанная причина каждого измеренного торможения. По AGENTS их исправление требует согласования владельца; этапы 1–7 не меняли rollback order/status oracle.

| Граница production | Установленный факт | Изменение, предлагаемое для согласования |
| --- | --- | --- |
| Main baseline + native start | baselinePromise живёт вне tunController; main ждёт его даже после native result. После этого выполняет schedule/history/tray без нового owner check | Единый operation owner охватывает main baseline и controller; после каждого await проверяет generation; late success не открывает историю и не возвращает успех проигравшей команды |
| stop во время preflight | startInProgress ожидание — 20 × 100 ms, затем cleanup идёт при ещё выполняющемся start. stopInProgress ставится только после ожидания | Serialized lifecycle lane и active operation promise; cancel ack немедленно, cleanup владеет активными effects до их settle/compensation. Повторные stop соединяются с тем же cleanup, не начинают независимый rollback |
| Xray resolveServerAddress | resolve4 → lookup IPv4; сигнала/deadline нет | Dedicated operation Resolver с cancellation; lookup имеет отдельное fencing/deadline, так как Resolver.cancel не отменяет getaddrinfo. Не отменять global resolver чужих callers |
| Xray config test | `spawn(run -test)` без explicit timeout, unlimited stdout/stderr; child не зарегистрирован в activeXrayState | Operation-owned preflight child; AbortSignal/deadline, bounded tails, listeners сразу после spawn, доказанный exit перед release ownership |
| Xray runtime start/stop | activeXrayState выставляется после firewall/SOCKS; stopXray kill()+remove pid/reset не ждёт exit, ошибки kill только warn | Track spawning/ready/stopping process identity по PID/path/start time; typed stop proof, grace/escalation из согласованного контракта, retained manifest при failure |
| Sing-box onExit | callback замыкает start и может писать global state/history/restart | Generation/owned child identity проверяются перед глобальными effects; собственные cleanup/logging старого child допускаются, смена новой session запрещена |
| Network cleanup | Обычный порядок отличается от нормативного §2.1; duplicate stage proof уже оптимизирован | После отдельного согласования привести порядок к ТЗ, independent failure collection сохранить; не запускать потенциально конфликтующие firewall/DNS/adapter mutations параллельно |
| Protected status / route fallback | Presence/alias route не является exact effective route + egress proof; preVpnIp получен после TUN | Отдельное согласование статуса verification/connected и exact owned GUID + 0/1/128/1 + egress; не объявлять provider IP evidence безопасностью всех пакетов |

Минимальные проверки coordinator до merge: AT-00-002/003/007/008, AT-02-002/004/005/006/009/011, AT-03-001/003/004/007. Held boundaries на DNS, preflight, PID write, firewall native transaction, adapter ownership, baseline completion; cancel/quit на 10/50/90%, late callback после нового start; no resurrection/no stale history/no orphan child; повтор shutdown не снимает чужую защиту. L3 — Windows 10/11, cold/warm, packet capture двумя оракулами, baseline byte/read-back equality.

[Node DNS](https://nodejs.org/docs/latest-v24.x/api/dns.html): Resolver.cancel отменяет queries своего экземпляра; lookup использует getaddrinfo/libuv threadpool, resolve использует асинхронный DNS. Их нельзя считать одинаковой отменяемой границей. [Node child_process](https://nodejs.org/api/child_process.html): spawn поддерживает signal/timeout; kill/killed не являются подтверждением exit. Эти возможности — основа предложения, не выполненный coordinator.

#### Реальный before/after smoke после установки контрольного артефакта

1. Зафиксировать installer/source hash, OS, cold/warm, профиль и режим/настройки. Не публиковать ключи. Сохранить current baseline snapshot через существующую диагностику; чужой VPN не включать/выключать посреди парного сравнения.
2. По 5 cold и 5 warm connect/disconnect, cancel во время старта, quit после stop; записать click-to-terminal IPC и native phase durations. Сопоставлять успешные подключения отдельно от cancel/fail; медленный/недоступный IP provider также проверять отдельно. На одинаковом сервере проверить доступность/egress и утечки.
3. После каждого stop сверить owned processes, Wintun/routes, firewall profile/rules/filters, DNS/IPv6/registry baseline. Warning или неполный proof считается отдельным исходом, не «быстрым успешным отключением».
4. Сохранить новые JSONL и выполнить analyser для before/after. Сравнить distributions и critical path, не сумму overlapping stages. При новых timings проверить Xray resolve/preflight/firewall и stop rollback по этапам.
5. Настоящий native smoke пока не исполнен: текущий shell unelevated, protected runtime недоступен, пользователь ушёл спать. UAC/ACL не обходились. Это внешнее ограничение проверки, не причина объявить цель достигнутой.

Итоговый DoD этапа 7: `VPNTE_PWSH=powershell.exe; npm.cmd test -- --reporter=dot --maxWorkers=4` — exit 0, 158 passed / 1 skipped files, 1583 passed / 3 skipped tests (56.61 s). `npm.cmd run typecheck`, coverage AC 927/927 F 210/210 и `git diff --check` — exit 0. Предложение coordinator отправлено владельцу на согласование через async question; до ответа его реализация и изменение нормативного rollback/status контракта не начинаются. Независимая работа над контрольным артефактом продолжается.
