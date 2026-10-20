# WP-0: контракты и наблюдаемость — 18.10.2026

Статус: **в работе**. Основание: том 3 §1.1–1.2, ТЗ-06 WP-0
и решения владельца §10, AT-00-001…010. WP-3 завершён в PR #46;
его L3 `SKIPPED_BY_OWNER` не распространяется на WP-0.
Qodo и Revix работают совместно по уточнению владельца 19.10: пока у Revix
есть квота, учитывать оба ревью на окончательном SHA. Qodo ранее назначен
главным; завершённый Qodo не заменяет разбор Needs changes от Revix.
CodeRabbit исключён из ожидания; окончание trial Greptile не блокирует работу.
CI и review обязательны.
18.10 владелец разрешил продолжать WP-0 при открытом PR #54, сохраняя запрет
его слияния до отдельного решения. Полного Revix для #54 не было из-за квоты.
Позднее 18.10 владелец разрешил сливать PR после пройденных проверок.
#54/#55/#56/#57/#58/#59/#60/#61/#62/#63/#64/#65/#66/#67/#68/#69/#70/#71/#72/#73 слиты в main после exact-head CI success и completed Qodo,
без открытых Qodo findings; прежний запрет слияния отменён. Revix #70 сохранил
Needs changes: владелец отдельно указал это 19.10. Follow-up #74 слит
(`9761514`): synchronous commit и secret export исправлены; окончательный head
`2728df1` получил CI success, completed Qodo 1544399 без открытых findings
и Revix 117906370434 completed/neutral с suggestion и nitpick. Замечания #70
закрыты отдельными исправлениями и проверками, а не прежним merge или Qodo.
#75 также слит (`07a77cb`): final head `1e57482` получил CI 39209022143 success
и completed Qodo 1544667 без открытых findings. Revix сообщил об исчерпанной
квоте до 20.10 00:00 UTC; полного ревью #75 нет, это не approval.
#76 слит (`fa1bd9f`): final head `e232e8f`, Qodo 1544820 completed без
открытых findings, CI 39211150906 success. Revix сообщил free-quota-reached;
полного ревью #76 нет. Его отсутствие при квоте не называется approval.
#77 слит (`1752bda`): final head `84f0d87`, Qodo 1545221 completed без открытых
findings, CI 39216740383 success (Windows/Rust/site). Revix full review недоступен
из-за квоты; отсутствие ревью не approval. Fixes четырёх Qodo findings включены.
#78 слит (`f35c1f8`): final head `72cd14c`, Qodo 1545611 completed без открытых
findings, CI 39220632906 success (Windows/Rust/site). Старый CI 4ae7ab9 имел
один test timeout; он сохранён в журнале. Revix full review по квоте отсутствует.
#79 слит (`d7a4378`): final head `589490b`, Qodo 1546296 completed без открытых
findings, CI 39227466851 success. Оба замечания первого Qodo воспроизведены и
исправлены. Revix full review по квоте отсутствует; это не approval.

## Полная область и первоначальная инвентаризация

| AT | Найденная реализация / доказательства | Остаток до приёмки |
| --- | --- | --- |
| 00-001 | AST-проверка 164 main/preload/shared request channels, общий реестр входов и versioned transport envelope; object contracts проверяют поля/массивы, save-settings покрывает все 39 общих полей AppSettings; TypeScript checker проверяет results всех 164 listeners, public results с `any` больше нет; native contextBridge сохраняет JSON профиля и nullable active result, feature list/cancel, speed-test/config request cancel, planned-feature admission | Завершить проверку текущего PR; отдельная semantic matrix ошибок остаётся в 00-004 |
| 00-002 | Production TunnelStateMachine интегрирована в main lane/IPC/Soft/tray/UI; 4096 stable tours и 117649 tours семи событий глубиной 6, включая timeout/cancel и native completion, с fake PID/TUN ledger и балансом operation events; sticky faults и generation fencing | Общая durable operation history/counters; все blocked/unknown/background paths; native Windows resources; общий admission фоновых restart |
| 00-003 | Main connection lane: UUIDv4, owner, deadline запуска и остановки (#73), priority admission; ручные Hard/Direct и Soft из tray, scheduled startup вместе с proxy detection; общий feature registry с prompt cancellation/deadline и physical drain, speed test, refresh подписок и импорт профилей, включая curl/DoH и commit queue; config browse/validate/apply/export, async file I/O и terminal commit приняты в PR #70/#74; key renderer/clipboard/file exports в PR #71; rotation IPC/timer с native drain и retained evidence в PR #72; document loss #78, config unmount в текущем участке | Review/CI текущего участка; прочие UI/background entrypoints и полная матрица поздних эффектов |
| 00-004 | Общая классификация transport; 157 каналов × 7 категорий через guard; native contextBridge сохраняет code/category/correlation в en/ru; typed local validation; 4 настоящих config handlers × 7 категорий, canonical domain failures | Миграция legacy domain-result `{success:false,error}` и semantic matrix настоящих feature handlers; transport fixtures не доказывают её |
| 00-005 | Один action correlation id в guarded IPC response/error, lifecycle connect/stop и JSONL logger; async isolation, native wait/drain, diagnostic read-back с повторной redaction; ID исходного connect и source/owner/route/confidence в session history/JSON/CSV; JSONL clockId/monotonicMs отдельно от календарных дат и durationMs; реальные owned/legacy/tray/recovery Soft sessions | Все native/background entrypoints и полная матрица событий/истории автоматизаций, live-check и recovery |
| 00-006 | Общий version admission для 20 electron-store файлов / 28 constructors; future-version SHA-256 invariance до defaults/repair и при записи через открытый handle; центральный registry safeStorage трёх stores, real Conf historical fixtures, exact encrypted backups, checksums/history, actual Electron DPAPI/restart/JSONL; #77 принят после Qodo/CI | Startup миграции/классификация между stores, остальные persisted JSON, полноценный upgrade/downgrade и межпроцессная координация |
| 00-007 | Seed 0x5eed003: 200 commands/10 async workers с production lane/FSM, typed losers, парные terminal events, финальный disconnect и 0 fake PID/TUN | Натурный PID-реестр Windows и полная матрица фоновых entrypoints |
| 00-008 | Dashboard component frames с production FSM/lane; revision fence; Soft через owned IPC; visual fixtures light/dark; native production contextBridge snapshots/disposer | Полная матрица всех операций, тем, размеров и entrypoints; browser fixtures не заменяют native resources |
| 00-009 | Release registry четырёх функций off/null; production main/preload status/activation gate; schema reject fake evidence; production Sidebar/Settings DOM без planned controls в обычном/advanced режиме с forged flags; настоящий Electron проверяет четыре refusal и persisted JSONL audit/correlation; #76 принят после full/Qodo/CI | Адресная приёмка release admission завершена; реализация и собственная лабораторная приёмка WP-12 остаются отдельным пакетом |
| 00-010 | История подключений: настоящий Conf backend, 100 записей, повторная загрузка, повреждённый JSON/схема, `history.corrupted`, сохранение валидных записей и последующая запись; текущий участок переносит проверку на существующие app.log/app.prev.log | Общий audit/event history: final full/build и собственный Qodo/CI текущего участка; это не полная матрица всех producers |

Это перечень обнаруженного, а не PASS десяти AT. Ни один новый
неиспользуемый модуль сам по себе не закрывает критерий интеграции.

## Общий audit/event history: целостность JSONL (19.10.2026)

AT-00-005/010, F-143: production appLogger сохраняет существующий JSONL store
и legacy записи; новый shared version1 contract добавляет source/owner/route/
confidence. Source/owner берутся из действующего action scope до queue;
неподтверждённые route/confidence остаются unconfirmed/indeterminate.
Calendar ts фиксируется при событии, monotonicMs — в порядке сериализации.

Перед первым append обе generations сканируются без переписывания старых bytes.
Memory ограничена64KiB chunk/256KiB row, чтение32MiB на generation; unreadable/
incomplete scan получает history.unavailable. Invalid JSON/schema/UTF8/oversized
record получает sanitized history.corrupted с generation/count. Unterminated
current tail отделяется newline, новые записи снова разбираются. Обычная
size-based retention сохраняется; это не бессрочное хранение повреждённых файлов.
Append I/O fault виден как console history.write-failed без exception/path,
но fsync и восстановление потерянного события после disk failure не заявляются.

До fix9/9 новых cases failed. Адресные8 suites52/52 passed,3.22s:100 legacy
записей, обе generations, restart, UTF8 across chunks, oversized skipping,
scan cap, unreadable generation, failure/retry, correlation/clock/redaction.
Typecheck165 channels/0 public any —exit0. Полный набор/build и remote gates
записываются в progress.md. Остальные producers/semantic errors/migrations
остаются открытыми; этот участок не завершает весь WP-0.

Qodo1555507 для initial PR #84 нашёл2 граничных случая. Оба воспроизведены
отдельными production-logger tests до fix: incomplete scan теперь всегда
получает собственный history.unavailable, независимо от найденной коррупции;
startup markers имеют bounded4096-byte rotation allowance, поэтому не стирают
damaged previous раньше обычных событий. Allowance сбрасывается при roll/clear;
последующая обычная ротация тоже проверена. Targeted54/54 passed,3.12s.
Final full/build и новая automatic Qodo/CI проверка требуются на final SHA.

Review final full —4785 passed/5 skipped/0 failed,360.34s,exit0. До него
два full имели по одному outer5000ms timeout в прежних native helper/export
fixtures. Их outer budgets согласованы с native boundaries (20s/15s), safety
assertions и production responsiveness не менялись. Targeted78/78 passed,
typecheck/build/6 Electron fixtures/coverage/diff —exit0. Полная история failures
и точные команды в progress.md; remote gate проверяется на новом SHA.

## Config workflow: отмена при unmount (19.10.2026)

AT-00-001/003/008: ImportExportSettings создаёт UUID до IPC. Main принимает
optional token для browse/validate/apply/export; config:cancel ограничен парой
requester WebContents + token. Один import token связывает весь workflow,
включая idle snapshot; cancellation отзывает capability. Main operationId и
correlationId сохраняются отдельно. Duplicate/malformed/foreign/stale requests
не повреждают законную операцию. Legacy вызовы без token сохраняются.

Unmount отменяет active/idle workflows и очищает success timers. Поздние ответы
не вызывают следующий этап или UI updates. Проверки включают удержанные
browse/validate/apply/export, idle cancel/unmount, duplicate queued apply,
отмену в write queue без поздней записи и нормальный новый import после cancel.

`npm.cmd run build` и повторный `npm.cmd run typecheck` — exit 0, 164 канала,
0 public any. `node scripts/test-electron-runtime.mjs` — четыре PASS, включая
CONFIG_REQUEST_NATIVE_PASS: production handlers/stores/registry/guard/preload,
настоящий sandbox/contextBridge, controlled dialogs/queue, cancel <900 ms,
отдельный main UUID и исходная correlation, отказ чужому/stale token, отсутствие
export-файла/поздней записи и успешный новый import. Это локальный Electron 44.4.3
fixture, без настоящей маршрутизации/VPN. `node scripts/test-wp1-native.mjs
--ipc-only` — WP1_NATIVE_PASS; traceability AC 927/927, F 210/210 и diff check —
exit 0. Финальный `npm.cmd test` — **4639 passed /5 skipped /0 failed**,
281 files passed /2 skipped, 418.05 s, exit 0. Предыдущий full имел один
устаревший error-category assertion, следующий — 5000 ms timeout существующего
Windows ACL test. Assertion разделён по новому token contract; budget только
этого многопроцессного ACL test — 15000 ms. Production deadlines и проверки
отмены/ACL не ослаблены. Все неудачные прогоны сохранены в progress.md.
Config workflow принят в #79; результаты final SHA приведены ниже.

Первое Qodo #79 (1546103, SHA 1577193) выявило overlap legacy/tokened registry
cleanup и потерю видимых import choices после apply error. Оба замечания
воспроизведены отдельными failing regressions. Cleanup сверяет identity Map;
после ошибки choices остаются видимыми, apply consumed token disabled,
новый native browse доступен и создаёт новый token. Main одноразовое разрешение
не продлевается. Адресные три suites — 72 passed, 58.44 s; build/typecheck,
четыре Electron fixtures, native IPC/CSP, traceability и diff check — exit 0.
Полный `npm.cmd test` после Qodo fixes — **4641 passed /5 skipped /0 failed**,
281 files passed /2 skipped, 420.88 s, exit 0. Initial CI 39225869946 success;
он не заменяет CI/Qodo следующего SHA с исправлениями.
Final SHA 589490b: Qodo 1546296 completed без открытых findings и CI
39227466851 success. Merge/main d7a4378 совпал по tree с reviewed head.
Следующий участок — SPA unmount ручных import/refresh на странице Servers;
background refresh остаётся отдельным владельцем.

## Servers: requester lifetime ручного import/refresh (следующий участок)

AT-00-001/003/008: optional UUID token добавлен к servers:add/add-to-group и
groups:refresh; operations:cancel-request ограничен своим sender+token.
Main operationId/correlation, deadline, commit и physical drain остаются у
существующего registry. Отмена после terminal commit — false. Duplicate,
malformed, foreign/stale и legacy overlap проверены отдельно.
SPA unmount Servers отменяет принадлежащие странице ручные import/refresh,
блокирует late reads/state/log/nav и удаляет toast timers. Background refresh
не становится собственностью renderer; export/key workflows остаются отдельно.

До исправления: main token case — 1 failed /40 skipped; UI unmount —
2 failed /1 passed. После: 7 suites **157 passed**, 4.92 s, exit 0.
Build/typecheck — exit 0, 165 channels/0 public any. Пять Electron fixtures —
PASS, включая SERVER_REQUEST_NATIVE_PASS с actual handlers/stores/registry/
guard/preload, controlled resolver/runtime boundaries. Refresh/import/target/
repaste cancel <900ms с исходной correlation/main UUID, no late writes,
foreign/stale refusal, retained drain/listener cleanup, fresh successful import.
Native IPC/CSP и traceability/diff check — exit 0. Final npm.cmd test —
**4660 passed /5 skipped /0 failed**, 335.97 s. Предыдущий full имел три
5000 ms timeout в прежнем adaptiveNetworkIdentity native suite; отдельно
он прошёл 25/25, полный повтор прошёл без изменения его кода/budgets.
История сохранена в progress.md. Участок принят в #80: Qodo 1553608 completed, CI 39290006611 success, merge/main e0b45b7.

## Main connection lane — приоритеты, deadline и позднее расписание

`ConnectionLifecycle` расширяет существующее владение нативными эффектами:
операция запуска имеет UUIDv4, owner, timestamp, deadline (по умолчанию 120 s)
и конечный status. Приоритеты из тома 3 §1.2 проверены попарно. Более высокий
приоритет прерывает фоновый startup, дожидается фактических native effects
и штатной очистки, затем допускает новый startup. Отказ очистки запрещает
автоматический replacement. Конфликт, отмена и deadline имеют стабильные
OPERATION_CONFLICT / OPERATION_CANCELLED / OPERATION_TIMEOUT и категории.

Ручные Hard/Direct и Soft из tray используют этот lane. Scheduled startup
получает owner=schedule **до** поиска прокси и выбора профиля; позднее завершение
детектора после ручной остановки не запускает VPN и не меняет выбранный профиль.
Удалённый scheduled profile теперь даёт отказ вместо подключения произвольного
текущего профиля. Уведомления об успешном scheduled connect/stop выдаются после
успеха операции. Эффекты старта/остановки вынесены из admission wrappers без
переписывания нативного rollback pipeline.

Перед сменой режима и после stop env проверяется через строгий `isApplied`,
а не UI `getStatus`, который подавляет ошибки чтения. Если rollback возвращает
false, следующий startup и уведомление об успешной очистке запрещены. Проверка
использует настоящий autoconfig dispatcher с подменёнными OS targets.

Deadline и manual cancellation немедленно устанавливают конечный status и abort
signal. После #59 caller Promise запуска возвращается отдельно от native drain:
отмена/timeout больше не ждут неотменяемый I/O. Busy lease, shutdown и stop
по-прежнему ждут фактическое завершение эффектов, затем очистку. Это адресное
доказательство для connection startup, **не** предел ≤1 s для всех долгих операций.
Deadline запуска инициирует штатный stop после drain.
История connections пока не коррелирована со всеми этими operationId; observer
пишет только ограниченные метаданные, не профиль/адрес/AbortSignal.

Остаток: единая FSM, protected restarts/rotation/AutoPilot/adaptive, прямые
autoconfig IPC entrypoints, deadline остановки, все прочие долгие операции,
сквозная корреляция и полные model/race/UI AT. AT-00-002/003/005/007/008 целиком
не объявляются PASS. Команды и результаты этого участка записываются в progress.md.

## Первый адресный regression

Revix `4304732489` из PR #46: повторный passive status polling повреждённого
манифеста заполнял журнал одинаковыми critical events. Теперь одинаковый
отказ подавляется до изменения evidence или успешного trusted read.
Hash повреждённого содержимого входит в fingerprint. Явные операции
сохраняют отдельные события, состояние остаётся unknown, native effects отсутствуют.

- До исправления: `npm.cmd test -- src/main/firewallTransactions.test.ts -t 'deduplicates passive'`
  — 2 failed / 96 skipped, exit 1 (`.tmp/wp0-rejection-dedup-before.log`).
- После: `npm.cmd test -- src/main/firewallTransactions.test.ts`
  — 97 passed / 1 skipped, 9.16 s, exit 0.
- Общие проверки перед коммитом записываются в `progress.md`.

## AT-00-010 — история подключений

`connectionHistoryStorage.test.ts` использует настоящий файловый backend Conf
(тот же backend electron-store), заменяя только обнаружение Electron userData
и версии приложения. Это L2: повторное создание сервиса читает файл заново;
полный перезапуск Electron/Windows этим стендом не заявляется.

- 100 событий сохраняются после повторной загрузки, старые записи без outcome
  и errorMessage поддерживаются; CSV/JSON читаются.
- Обрезанный JSON, мусор в хвосте, неверная корневая схема и повреждённые
  отдельные записи вызывают `history.corrupted`. Валидные записи массива
  сохраняются; отбракованные элементы удерживаются в rejectedConnectionHistory
  при последующих записях, включая outcome из более нового приложения. Raw payload, имена профилей и ошибки парсера в событие не попадают.
- Новый write атомарно сохраняет исправленную историю через Conf. До записи
  повреждённый файл не стирается: возвращается безопасное представление,
  а событие явно сообщает о повреждении. Повторное чтение одного повреждения
  подавляется до изменения содержимого, успешного чтения/записи либо очистки.
- Ошибки файловой системы не превращаются в пустую историю. Невалидные новые
  записи отклоняются до записи файла.

До production-исправления: 8 failed / 2 passed,
`npm.cmd test -- src/main/connectionHistoryStorage.test.ts`, exit 1;
`.tmp/wp0-history-before.log`. Проверки итогового кода — в progress.md.
Это не завершает AT-00-005 или весь WP-0.

Revix PR #48 suggestion 4306503597 закрыт сохранением отбракованных
элементов в том же store и общим runtime SESSION_OUTCOME_KINDS для union-типа
и reader. Повторная запись не дублирует отбракованные элементы; явная очистка
удаляет их вместе с остальной историей. Question 4306503603: оба production
call site addEntry в index.ts catches, исключение записи не выходит в teardown.

## Следующий участок — AT-00-001

Первичный AST-инвентарь текущих исходников: 157 уникальных invoke-каналов
preload, 78 строковых деклараций в *Channels интерфейсах shared,
44 прямых ipcMain.handle регистрации и 9 мест регистрации через wrapper.
78 включает event-only progress каналы: их следует разделить с invoke API,
а не объявлять отсутствующими request handlers. Wrapper calls требуют
разрешения до реальных channel arguments.

Это подтверждает недостаточность нынешнего string-presence теста, но
не доказывает отсутствия 113 main handlers: большая часть зарегистрирована
через wrapper. Полный паритет, схемы входа и envelope остаются открытыми.
Артефакт первичного сканирования: .tmp/wp0-ipc-inventory.json (не норматив).

## Реализованная граница IPC — 18.10.2026

`shared/ipc-contract.ts` (реэкспорт из ipc-types) содержит 157 request channels,
имена публичных методов и runtime-схемы wire arguments. `electron-api.ts`
содержит прежний публичный API; preload сохраняет прежние типовые экспорты.
События не смешиваются с request registry. Неиспользуемый дубликат
`diagnostics:run-leak-check` и осиротевшие старые *Channels удалены.

`scripts/check-ipc-contract.mjs` разбирает TypeScript AST реальных исходников,
разрешает девять обёрток регистрации, сравнивает множества и имена методов.
Комментарии не считаются регистрациями; неизвестные динамические регистрации,
дубликаты, лишние декларации, прямой обход preload decoder вызывают ошибку
с указанием имени. Проверка входит в typecheck и build.

Все зарегистрированные handlers проходят sender-frame/origin guard,
ограничение структуры/размера и схему аргументов перед вызовом listener.
`ipMonitor` больше не регистрирует handlers при импорте: main явно вызывает
registrar после установки guard. Регрессия проверяет импорт с process.type=browser,
отказ чужому кадру без эффектов и успешные suspend/resume через guard.

Wire response: `{version:1, correlationId:UUIDv4, ok:true, result}` либо
`{version:1, correlationId:UUIDv4, ok:false, error:{category,code,message}}`.
Preload снимает transport envelope; существующие domain result, в том числе
`undefined` и `{ok:false}`, сохраняются. Исключения и отказы transport становятся
`IpcRemoteError` внутри preload; повреждённый ответ и reject Electron имеют
безопасную внутреннюю ошибку. Перед contextBridge request-обёртка преобразует
исключение в `IpcRemoteErrorData`: plain-object Promise rejection с name,
category, code, каноническим message и optional correlationId. Никакие stack,
cause или произвольный текст exception не копируются. main world проверяет
форму через isIpcRemoteErrorData; instanceof Error для этих данных неверен.
Все 157 request methods выбираются из того же registry; subscriptions и их
синхронные unsubscribe handles не оборачиваются. Даже локальная валидация
параметров теперь отклоняет Promise, как объявлено публичным API; main IPC
не вызывается и correlationId не выдумывается. Сквозная domain correlation
AT-00-005 ещё не реализована.

Revix PR #50 suggestion 4306715099 учтён: локальные валидаторы явно бросают
`IpcValidationError`; неожиданные `TypeError`/`RangeError` внутри preload
остаются `internal`. Ошибка сериализации входного объекта классифицируется
валидатором до IPC. Регрессии различают ошибку параметров и внутренний сбой.
Nitpick 4306715102 о loose assert не применим: native fixture уже импортирует
`node:assert/strict`, поэтому `assert.equal` выполняет строгое сравнение.

| category | Стабильный code | Условие transport |
| --- | --- | --- |
| validation | IPC_VALIDATION_ERROR | Отказ схемы/лимитов либо typed validation fault |
| permission | IPC_PERMISSION_DENIED | Чужой sender/frame/origin, EACCES, EPERM |
| network | IPC_NETWORK_ERROR | ECONNRESET/ECONNREFUSED/ENOTFOUND/EAI_AGAIN/ENETUNREACH/EHOSTUNREACH |
| conflict | IPC_STATE_CONFLICT | Явный IpcFault(conflict) |
| internal | IPC_INTERNAL_ERROR | Неизвестное исключение/некорректный transport |
| cancelled | IPC_CANCELLED | AbortError либо typed fault |
| timeout | IPC_TIMEOUT | ETIMEDOUT либо typed fault |

Сообщения заданы константами в `ipc-result.ts`; произвольный текст исключения
не сериализуется. Даже бросающий getter code/name остаётся внутри safe envelope.
Bounded guard audit metadata использует обратимое `ipc_` + UUID без дефисов:
все 128 бит сохранены и однозначно соответствуют envelope correlationId.
Голый UUID redactor справедливо скрывает как потенциальный credential;
политика редактирования секретов не ослаблена. `ipcAuditLog.test.ts` проверяет
настоящую guard, настоящий logger/redactor и файл app.log, включая positive
control скрытия голого UUID. Это закрывает Revix issue 4306608229.

Canonical сообщения имеют en/ru варианты. Preload выбирает исходный язык
из navigator так же, как renderer i18n, затем учитывает persisted get-locale,
успешный set-locale и межоконное событие locale-changed. Текст main exception
при этом по-прежнему не используется. Unit и native smoke подтверждают
English/Russian без зависимости от языка Windows. Это ответ на 4306608232.
Suggestion 4306608234 учтён сужением документации и комментария реестра:
bounded legacy object не объявлен полной field schema; остаток явный.

`ipcContractAcceptance.test.ts` проводит все 157 channels через production guard:
допустимые wire args, неверный тип каждого аргумента, лишний аргумент, чужой
кадр и все семь исключений. Feature listeners в этой матрице заменены на
контролируемые эффекты; это не исполнение 157 настоящих подсистем.
Plain-object inputs legacy API ограничены по размеру/форме, но не все имеют
глубокую field schema. Старые domain-result ошибки пока не переведены
в новую taxonomy. Поэтому AT-00-001/004 и WP-0 целиком не объявлены PASS.

Native Electron 44.4.3: `node scripts/test-electron-runtime.mjs` — exit 0,
production preload/contextBridge, reload, loopback dev parity, unknown sender,
navigation rejection, native safeStorage. `node scripts/test-wp1-native.mjs --ipc-only`
— exit 0, настоящий hostile subframe с нулём effects и production CSP.
Режим явно ограничен IPC/CSP, не выполняет ACL/ZIP/clipboard или OS matrix.
Исправлена сборка native fixture: koffi остаётся external native dependency.
Полные команды DoD и результаты записаны в progress.md.

## Main-world typed errors — 18.10.2026, после PR #49

До исправления усиленный `node scripts/test-electron-runtime.mjs` завершился
exit 1: native renderer получил undefined вместо IPC_VALIDATION_ERROR
(`.tmp/wp0-renderer-error-before.log`). Unit mock сохранял поля Error и
этого не обнаруживал. Promise rejection plain object решает реальную
границу; синхронный throw через contextBridge тоже теряет поля, поэтому
валидация request methods возвращает rejected Promise.

Теперь native Electron 44.4.3 проверяет все семь категорий в en/ru (14 вызовов)
через production guard/preload/contextBridge, уникальный UUID каждого ответа,
code/category/message и отсутствие exception text/stack/path. Отдельно
проверяет typed local validation без main correlation. Listener get-settings
в этом native стенде управляемый; полноценная semantic matrix feature handlers
этим не подменяется. Windows CI выполняет production build, этот native smoke
и IPC/CSP subset в каждом PR; OS/installed/L3 matrix не заявлена.

Quick server picker распознаёт plain-object ошибку и показывает message,
вместо `[object Object]`; остальные существующие `.message` catches совместимы.
Root unhandledrejection handler тоже распознаёт типизированную ошибку.
Оба глобальных error handlers наблюдают rejected logRenderer Promise:
сбой самого reporting IPC не порождает рекурсивную unhandled rejection.
Это покрыто функциональными renderer tests, вместе с прежним Error fallback.
Legacy any/deep object schemas/domain-result failures и остальные AT остаются
в работе; WP-0 не завершён.

## AT-00-001 — вложенные object contracts

На ветке codex/wp0-ipc-object-schemas 12 прежних bounded object inputs
уточнены: scheduler create/update, rotation config, kill-switch exception,
DNS create/update, domain rule add/update, history filter, notification patch,
theme create и live-check history filter. Проверяются типы вложенных полей,
элементы и длина массивов, числовые диапазоны и перечень разрешённых ключей.
Массивы с пустыми слотами не обходят проверку через Array.every.

Одинаковая схема применяется в production preload и main guard. До исправления
21 некорректный объект достигал listener: `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
— 21 failed / 321 skipped, exit 1 (.tmp/wp0-object-schema-before.log).
После исправления негативные запросы имеют validation и ноль эффектов.
Таблица положительных примеров отдельно сохраняет пустые patches, дни 0/6,
nullable/отсутствующий secondary DNS, исходные семь цветов темы, 1000 profileIds
и конечные интервалы вне 5…1440: clamp выполняет существующий rotation service,
wire contract не подменяет его политикой отказа.

У этих функций убраны any из публичных входов/результатов. NextEvent, filters
и aggregated stats переехали в shared с совместимыми type-only reexports из
main. Logs использует тип фильтра. Семантические feature validators по-прежнему
проверяют адрес DNS, доменный шаблон, время и hex-палитру. Уточнённый контракт
не объявлен доказательством всех негативных сценариев реальных handlers.

Native production contextBridge smoke проверяет отказ scheduler.days=[7]
до effects и успешный partial update. Команды, итоговые counts и удалённая
приёмка записываются в progress.md. save-settings остаётся единственным
object() без fields; его глубокая схема и оставшиеся any ответов — следующий
остаток AT-00-001, наряду с общей работой WP-0 по матрице выше.

## AT-00-001 — общий settings contract

AppSettings больше не дублируется в main и renderer: общий тип находится
в shared/settings.ts, старые импорты сохранены через type-only reexport.
getSettings/saveSettings/setLoginItem используют его в public ElectronAPI.
Схема save-settings описывает все 39 полей и имеет compile-time ключи
Record<keyof AppSettings,...>: добавленное или удалённое поле требует
синхронного обновления runtime-схемы. Последний object() без fields устранён.

Новые IPC-патчи проверяют boolean/enum/number/string, profile arrays и
рекурсивные JSON-shaped outbound values до любых effects. Произвольные
функции/необычные prototype/нечисловые числа не проходят; JSON ограничен
по глубине и числу значений. Тип outbound не содержит any; optional значения
undefined до JSON persistence поддержаны. Это схема значений transport,
а не замена semantic protocol validators sing-box/Xray.

До исправления `npm.cmd test -- src/main/ipcContractAcceptance.test.ts -t 'rejects invalid nested'`
— 13 failed / 27 passed / 343 skipped, exit 1
(.tmp/wp0-settings-schema-before.log): строковые флаги и другие неверные
типы достигали listener. Production contextBridge smoke отдельно проверяет
строковый autoStart без эффектов и успешный boolean partial update.
Неверный checkInterval:NaN теперь отклоняется самим preload, поэтому у
этой локальной ошибки нет выдуманного main correlation; main correlation
по-прежнему проверяется нативной матрицей 7 категорий × 2 языка.

Нормализация исторических store и DPAPI migration не изменены. Numeric
clamp по-прежнему выполняет settingsStore, а пустые/частичные patches,
nullable cachedAt и вложенные cache JSON сохраняют поддержку. Целевые
feature/renderer/migration tests и полный DoD — в progress.md. Оставшиеся
any ответов других функций и legacy domain failures сохраняются в остатке
WP-0; отсутствие bounded legacy object() не объявляет весь пакет завершённым.

## AT-00-001 — типы результатов диагностики и проверка listeners

Встроенный в typecheck/build checker теперь использует TypeScript program:
для каждого из 157 реальных listeners (включая локальные registration wrappers)
сравнивает awaited return с методом ElectronAPI. Несовместимые вложенные поля,
nullable branches и any внутри результата при конкретном public type приводят
к ошибке с именем канала. Неразрешённая сигнатура или непроверенный канал также
не считаются успехом. Отдельно учитываются legacy public types с any, включая
вложенные поля, массивы, словари и aliases: их остаётся 37, поэтому полный
AT-00-001 и WP-0 пока не объявлены PASS.

14 public methods диагностики и логов получили конкретные результаты:
proxy detection, adaptive status/retry/reset, leak/system checks, routing plan,
full logs, renderer logging/clear, URL availability/history и speed test/history.
Чистые типы собраны в shared/diagnostics.ts; main сохраняет type-only reexports,
renderer использует те же определения вместо независимых копий. SpeedTestResult
уже находился в shared и переиспользован.

Проверка обнаружила четыре случая расширения true в boolean; as const сохраняет
реальное значение без изменения runtime. Ещё шесть обработчиков могли вернуть
объект в error вместо обещанной строки: notifications reset/open, group health
и три file exports. Преобразование в строку и функциональные негативные тесты
с нестроковым message фиксируют контракт; обычные строковые сообщения сохранены.
Это не закрывает оставшуюся задачу canonical domain failures: legacy business
results и их тексты ещё требуют отдельного аудита. Результаты команд и CI/review
фиксируются в progress.md; нормативные docs/ не менялись.

## AT-00-001 — результаты остальных сервисов

Ещё 28 public result contracts используют конкретные pure types:
network maintenance (baseline/firewall/adapters/DNS), browser hardening/location,
AutoPilot, rule-sets, autoconfig, traffic history/forensics, server probe,
пять split-tunnel methods и пять group methods. Существующие модели
SplitTunnelApp/Config и ServerGroup переиспользованы; RefreshGroupResult
переехал в shared. У nullable splitTunnelAddApp и serverProbe сохранён null.
Blocked/skipped branches ремонта включены в публичный тип.

Типы network.ts и traffic.ts не имеют runtime dependencies. Старые main imports
совместимы через type-only reexports. Server probe использует существующий AsnInfo
из shared, остальные probe types добавлены в diagnostics.ts. UI-копии заменены
shared types; локальный AutoconfigTarget дополняет transport type только UI-флагом
enabled, который main не обещает возвращать.

Read-only проверка transpilation сравнивает исполняемые токены 22 изменённых
production-модулей с HEAD при одинаковых переводах строк: идентичны. Новые shared
modules испускают только пустой export. Это подтверждает границу type-only change,
а не заменяет unit/native tests. Source regression для protectedTunnelActive
проверяет новую shared declaration и её импорт, сохраняя прежние проверки label.

В inventory остаются 9 profile results с any; AT-00-001 не объявлен PASS.
Canonical domain failures, интегрированный FSM, cancellation/deadline,
correlation/history, migrations, flags и race/UI матрицы остаются в WP-0.
Команды, фактические результаты полного прогона и CI/review — в progress.md.

## AT-00-001 — оставшиеся profile results

На ветке codex/wp0-profile-results поверх открытого #54 все 9 оставшихся
methods используют ServerProfile: list/get-active/ping-all/resolve-ips,
verify-active-country/verify-country, add/add-to-group и set-client-device.
Nullable active profile и discriminated country results сохранены.
ServerProfile.outbound использует общий рекурсивный IpcJsonValue вместо any;
тип допускает JSON-расширения протоколов и не является заменой protocol validator.
Определение JSON переехало из settings.ts в shared/json.ts с совместимым reexport.

Доступ к вложенным TLS/Reality/ECH/uTLS/ALPN полям уточняет контейнер и тип
значения. asJsonObject проверяет только внешний контейнер; функция не обещает
полную валидацию его полей. Массив reality:[] не считается camouflage:
describeProbeTarget сохраняет tlsLeaksSni:true вместо ошибочного false.
Production call sites describeProbeTarget/tlsLeaksSni не найдены: текущий
checkProfileHealth использует checkOutboundHealth и полный outbound, поэтому
исправление классификатора не заявляется устранением активной SNI-утечки.
Реальные прежние pickServerName/describeProbeTarget извлечены
из parent и текущего файла без I/O: baseline false, исправленный true; три
корректных случая Reality/disabled/absent совпадают. Это локальная регрессия,
а не packet oracle или лабораторная приёмка сетевой изоляции.

Functional tests сохраняют корректные badges и handshake evidence, не считают
array TLS/Reality/OBFS валидными объектами и не возвращают numeric/object-valued
transport или ALPN. Настоящие picker handlers сохраняют вложенные JSON extensions
в list/get-active. Native production preload/contextBridge отдельно проверяет
неизменённый JSON ответа и null у active profile; service I/O в этом smoke
заменён fixture handlers. Эти доказательства не смешиваются.

Typecheck проверяет 157 listeners и 0 legacy any. Contract regression требует
пустой legacy inventory, поэтому возврат публичного any обнаруживается. Полный
набор тестов, CI и review записываются в progress.md; оставшиеся 9 AT WP-0,
canonical domain failures и весь WP-2 не объявлены завершёнными.


## AT-00-004 — доменные ошибки конфигурации

Config export/import/apply больше не возвращают raw business error внутри
успешного transport envelope. Handler бросает исходную ошибку для общей
классификации либо IpcFault с явной категорией; boundary возвращает стабильные
IPC_* code, category, canonical message и correlationId. Shared ElectronAPI
описывает только успешные results. ImportExportSettings обрабатывает canonical
rejection; raw/поддельный message заменяется generic internal, отмена save
остаётся без уведомления об успехе/ошибке. Browse cancellation сохраняет null.

configIpcErrors.test.ts использует настоящие feature handlers и production
installTrustedIpcBoundary. Ошибки всех семи категорий внедряются на store.get
и native-dialog boundary, проверяя отсутствие FAKE-SECRET, stack и абсолютных
Windows paths в ошибках renderer. Electron/dialog/store mocked; выбранный JSON
и файловая логика настоящие. Дополнительно проверяются malformed JSON/version,
array object sections, отсутствующая selection capability, cancelled save,
partial import и rollback после ошибки поздней записи. Capability после apply
расходуется даже при ошибке. Откат сохраняет system DNS (null), вместо выбора
первого builtin профиля. Пустой/неизвестный/отсутствующий выбранный раздел не
вызывает запись. Полная валидация содержимого каждого раздела этим изменением
не заявляется; проверки контейнеров не заменяют nested schema validation.

Компонентные тесты проверяют canonical ошибки на export/browse/import/apply,
локализованный fallback, отсутствие успеха после ошибок/отмены, выбор режима
экспорта, pending state и успешный apply. Имеющиеся security tests сохраняют
проверки native consent, sender authority, snapshot bytes, expiry и single-use.

Это адресная матрица четырёх каналов. AT-00-004 требует semantic error matrix
остальных privileged features; общий guard и native contextBridge fixtures
не заменяют её. FSM/coordinator, cancellation/deadline, correlation/history,
migrations, flags и race/UI остаются в работе. Команды и CI — в progress.md.


### Qodo #55 — импорт должен сохранять profile result contract

Qodo 6251403696 подтвердил сквозную дыру: typed ServerProfile[] не мешает
config import записать profiles:[null]. Новый regression вызывает настоящий
selected-file import/apply и проверяет отказ до записи и неизменность прежних
профилей. validateImportData проверяет поля ServerProfile, включая required
strings, numeric port, status и типы известных optional metadata. Профиль без
outbound поддерживается для backward compatibility; вложенные JSON extensions
сохраняются. Это validation входного config, а не полная protocol semantics
или отдельная приёмка уже повреждённых исторических stores. Результаты в progress.md.

### Qodo #56 — успешный DNS import и диагностика отказов

Успешный DNS import сохраняет null (system DNS), включая импорт без active id
при прежнем null. Явный imported null заменяет прежний custom выбор; отсутствие
поля сохраняет прежний выбор. Это проверяется настоящими selected-file handlers
с production IPC boundary; store и Electron/dialog остаются test doubles.

Cancelled export сохраняет canonical rejection без error-level записей feature,
wrapper и boundary. Для остальных отказов в config logs сохраняются ограниченные
I/O codes из allowlist. Произвольный error.code и raw message/stack не попадают
в журналы. Отказы JSON/schema/section selection получают стабильный validationCode,
который позволяет различить безопасные причины без содержимого файла.

Замечания Qodo подтверждены регрессиями до исправления. Эти тесты не заменяют
матрицу остальных privileged features, интегрированный lifecycle или L3.
Фактические результаты локальных проверок и CI фиксируются в progress.md.

### Второй проход Qodo #56 — форма rotation и файловые отказы

Структурированный Qodo API подтвердил implemented для четырёх прежних находок
на 132c3e5 и сообщил два новых замечания. При импорте rotation проверяются все
обязательные поля RotationConfig, включая profileIds, числовые поля, enabled и
order. Неполный объект отклоняется до persistence; сохранность прежних stores
и работоспособность следующего корректного импорта проверяются настоящими
feature handlers. Это не миграция уже повреждённых historical stores и не
полная nested schema validation остальных разделов.

File-size, non-regular и changed-during-read отказы теперь имеют ограниченные
диагностические коды; категории validation/conflict сохранены. Тесты также
проверяют отсутствие capability и listener после отказа. Итоги Qodo читаются
через get-pr-review-findings, включая status и commit_sha, вместо интерпретации
пустого GitHub summary. Статусы findings вручную не менялись.

### Qodo #57 — ownership: очистка, расписания и корреляция

Операции сохраняют нормативный UUIDv4 и получают производный безопасный
correlationId для логов: реальный файловый logger/redactor сохраняет корреляцию
начала/завершения и маскирует секреты. Полная корреляция IPC/history ещё впереди.

Stop после доказанного выхода runtime завершает независимую очистку даже при
ошибке env recovery, возвращает failure и запрещает replacement; retry остаётся
возможен. Приоритетный startup по-прежнему требует подтверждённой очистки.
Повторные stops присоединяются к одной очистке независимо от приоритета.

Scheduler продолжает перебор только при явной недоступности профиля и только
в активном окне. Ручное действие, stop/reinit, изменение/импорт расписания
инвалидируют pending продолжение. Проверки исполняют production helper/lane,
реальные main effect bodies с fake OS, restart и timer пути. Это подмножества
AT-00-003/005/007 и AT-10-006, а не принятие полной FSM/registry/UI matrix.
Четыре исходные находки Qodo воспроизведены регрессиями; результаты — progress.md.


## Интегрированная FSM — текущий участок WP-0

TunnelSnapshot разделяет стабильный state, transient operation, health, mode,
processState/PID и proxyStatus. Main lifecycle публикует connected после всех
owned effects и положительного evidence; raw running этого не доказывает.
Ошибка/blocked/unknown сохраняются до owned recovery. Отказ evidence и наличие
процесса без подтверждённого состояния дают unknown с обязательством cleanup.
Устранение конкурирующего интерфейса снимает только competingTun.

Фоновый native startup публикует begin/finished с монотонной generation;
запоздалый receipt предыдущего старта не подтверждает новый restart или stop.
Неожиданный throw подготовки публикует failure receipt и освобождает owner.
Полный admission всех protected restarts в общей registry ещё не завершён.

Soft Dashboard использует start-soft-protection и единый stop-tun. Startup
recovery читает строгий env isApplied; rollback проходит через rollbackApplied.
Retained Soft может быть принят recovery owner только после строгой проверки
и при отсутствии recovery faults. Наличие env само по себе не очищает unknown.
IPC-паритет теперь 158 channels / 0 public any.

Renderer получает snapshot одним событием/ответом getTunStatus и отбрасывает
старые revision. Legacy process events и поздний successful result не включают
защиту поверх canonical FSM. Dashboard и tray отображают progress/fault;
competing-interface warning в tray не называется недоступностью сервера.

Tests: 4096 tours покрывают только алфавит connect/disconnect/crash/retry и его
недопустимые события. Seeded race использует десять асинхронных исполнителей,
не OS threads. PID/TUN ledger имитирует ОС. Это адресные L2 evidence, не полная
приёмка AT-00-002/007 и не Windows network isolation. Полная registry/history,
остальные долгие операции, семантика errors, migrations и flags остаются открыты.

Playwright показал production Dashboard с управляемой FSM в light/dark: pending
connect, confirmed connected, reconnect и unknown/blocked. Просмотрены PNG;
контролы start/confirm/cleanup переключали состояние. Временный harness в .tmp
не меняет сеть. Vite HMR после завершения fixture server выдавал connection
refused; это не результат production VPN. Полная visual/a11y/responsive matrix
не заявляется; отсутствующие scripts design-doctrine не заменены фиктивным PASS.

Native Electron smoke использует production preload/contextBridge, реальную
FSM/lane, fake OS evidence и isolated userData: ранний running остаётся pending,
owned Soft проходит validation, stop очищает состояние, disposer снимает listener.
Старые security/CSP assertions сохранены. Точные команды/результаты — progress.md.


### Qodo #58 — реальные producers и entrypoints

Начальные model/component fixtures задавали positive PID самостоятельно и не
доказали совместимость с native status producer. Production startup poll теперь
получает PID с точным ExecutablePath/единственностью и передаёт его в FSM.
Новый integration regression исполняет сам poll callback и настоящий lane/model;
PowerShell predicate отдельно исполняется с подменённым CIM enumeration для
owned/foreign/prefix collision/ambiguous/unreadable. Настоящий Windows runtime
этими тестами не запускается. Неудачная main confirmation вызывает cleanup.

Env через legacy autoconfig IPC проходит тот же Soft owner; прямой rollback под
active native mode отклоняется. App bootstrap использует owned Soft method и
не очищает unknown. Исполняемые App callbacks
с настоящим Zustand/FSM/lane проверяют leak guard после connect и во время stop,
включая stale revision. Tray сохраняет firewall/leak warnings без active process.
Failed adaptive fallback устанавливает unknown после stop/failure, завершая
transient reconnect. Это пять проверенных замечаний Qodo, не общая приёмка WP-0.

### Повторный Qodo #58 — обновление выбранного Soft-прокси

Qodo run 1540463 completed на cb4b134: пять прежних findings implemented,
новый action_required — renderer reload сохранял старый env-прокси после смены
настроек. Retained Soft теперь повторно применяет выбранный адрес и протокол
через main connection lane. Исключение admission ограничено connected/soft
без transition; новый native connect по-прежнему отклоняется. Это обновление
env с сохранением исходного backup, без stop/restart TUN. Ошибка apply не даёт
успеха; отмена удерживает native effects до drain и последующей очистки.

Регрессии исполняют App bootstrap, реальные main Soft effects с production
FSM/lane и fake OS. Тест настоящего env-модуля проверяет все три proxy values
после смены адреса/протокола и восстановление исходного baseline. Это не
натурная проверка доставки Windows environment notification приложениям.

### Третий Qodo #58 — компенсация частичного Soft refresh

Qodo run 1540530 completed на 67fc70c: шесть прежних findings implemented,
новый action_required — частичный env.apply откатывал к pre-Soft baseline.
Перед refresh теперь строго читаются все текущие user env values. При отказе
обновления восстанавливается этот отдельный snapshot с read-back каждой записи;
исходный durable backup и pending marker остаются для eventual stop. Неизвестное
текущее значение запрещает изменения. Даже первая команда, вернувшая ошибку
после изменения registry, компенсируется. Неудачный refresh остаётся ошибкой
FSM (не успешным применением новых настроек); при отказе компенсации cleanup
обязателен. Достоверность нового endpoint не заявляется.

Исполняемые env regressions проверяют отказ каждой из четырёх записей после
mutation, отказ snapshot read и повторный отказ компенсации; original baseline
впоследствии восстанавливается штатным stop. Windows registry/process.env
подменены; это L1/L2, не натурная приёмка глобального environment broadcast.

### Собственная проверка #58 — startup receipt не доказывает active Soft

Qodo run 1540585 completed на 470d679: все семь прежних findings implemented,
новых нет. Дополнительная собственная регрессия обнаружила, что boot adoption
принимала backup receipt за доказательство ранее успешного env.apply. Теперь
recovery owner разрешает выбранный прокси и выполняет настоящий Soft apply
перед первым connected. Отсутствующий прокси, ошибка детектора/apply или чтения
receipt дают unknown. Существующий recovery fault не очищается автоматически.
Исполняется actual adoption + actual Soft effects + production lane/FSM с fake OS;
backup остаётся основанием cleanup, а не самостоятельным protection evidence.

## Версии electron-store — AT-00-006, часть F-074

storeSchema содержит inventory поддерживаемых версий: settings/server-picker — 2,
остальные 18 файлов пока имеют существующий unversioned format (0). VersionedStore
исполняет guard до Conf defaults merge и до custom repairing deserializer.
Неизвестный будущий номер и неверный тип версии дают стабильный StoreSchemaError
без raw JSON/пути; IPC сохраняет категорию conflict/validation. Имя нового store
должно быть зарегистрировано. AST contract проверяет все production constructors
и запрещает runtime-обход адаптера, включая дублирующие configManager entrypoints.

Serialize guard повторно читает текущий файл, защищая set/whole-store replacement/
clear/delete/reset после обнаруживаемой подмены на более новую версию. Real Conf
fixtures сверяют SHA-256 всех 20 future-version файлов, custom deserializer и
serializer не вызываются до отказа. Отдельно исполняются imports настоящих settings,
server-picker/server-groups/granular-kill-switch и connection-history: ни defaults,
ни repairing history reader, ни secret migration не опережают guard.

Metadata versions absent/0/1/2 в settings сохраняются вместе с неизвестными полями;
это совместимость admission, а не миграция исторических payload. Existing history
corruption и secret-store regressions также выполняются. Реестр ordered
migrations, backup/checksum/dry-run/rollback для всех persisted JSON и полный
cross-version upgrade/downgrade остаются открыты. Межпроцессный lock этим адаптером
не вводится: гонка внешней записи между проверкой и atomic rename отдельно не
доказана. Точные команды и фактические результаты — progress.md.

### Qodo #59 — понятный отказ до app.ready

Qodo run 1540747 completed на 1d9f844: constructor settings выполняется во время
static import, раньше main startup/crash boundary. Замечание подтверждено:
StoreSchemaError теперь до app.ready показывает нативное сообщение с причиной
отказа и рекомендацией, пишет только стабильный code в stderr и завершает
процесс с exit 1. app.log этим ранним путём не заявляется. Main network teardown
не запускается; runtime errors после ready остаются у существующей boundary.

Unit fixtures проверяют три кода, отсутствие raw path/JSON/secret в UI/stderr
и exit даже при отказе native dialog. Отдельный тест запускает настоящий pinned
Electron с production Store adapter и isolated userData: до ready сообщение
предшествует реальному exit 1, после ready typed error попадает в caller catch
без раннего dialog/exit. SHA-256 future-version файла неизменен в обоих случаях.
Перехвачен только native dialog, чтобы fixture не показывала popup на рабочем
столе. Это адресный startup subset, не installed upgrade/downgrade acceptance.

## AT-00-003 — быстрый ответ отменённого запуска, отдельный native drain

ConnectionLifecycle возвращает typed cancellation/timeout вызывающему коду,
сохраняя внутреннюю задачу и admission lease до завершения startup/retained
effects. stop/close ждут внутреннее completion, а новый start получает conflict.
Позднее отклонение нативного Promise наблюдается; terminal event не дублируется.
Если ошибка была известна до отмены, её исходная причина сохраняется. Отмена
из синхронного admission observer не допускает первый effect.

Fixtures на 10/50/90% оставляют native gate закрытым после ответа; fake clock
подтверждает settlement за 1 ms, удержание lease до drain и последующей cleanup,
отсутствие late publish и возможность retry. Отдельно проверены deadline с raw
Promise (без owner.wait), поздний reject и close с retained native effect.
Actual main Hard/Direct callbacks проходят preflight/native/fault boundaries:
ответ проверяется до release gate с timeout 900 ms, поздняя история/успешный
статус не публикуются, stop effect ждёт gate. Нативные OS effects подменены.
Native smoke дополнительно проверяет тот же порядок через настоящий production
preload/contextBridge: ответ до 900 ms при закрытом gate, conflict нового start,
затем drain/stop без кадра connected. Это Electron integration с fake OS.

Общий registry refresh/speed/import/export/rotation, deadline stop, полный
алфавит модели и Windows resources остаются в работе. F-021 опровергнута и
не объявляется исправленной. Точные результаты — progress.md.

## AT-00-002 — алфавит timeout/cancel и незавершённый native startup

connectionModelTours исполняет все 7^6 = 117649 последовательностей с seed
0x5eed002 и фиксированным порядком connect/complete/disconnect/crash/timeout/
cancel/retry. Complete — отдельное завершение fake native gate, поэтому cancel,
timeout, crash и disconnect встречаются как до подтверждения connect, так и
после него. Используются production ConnectionLifecycle и TunnelStateMachine;
oracle состояния и fake PID/TUN ведётся отдельно от snapshot.

После каждого шага проверяются state/transition/processState, отсутствие второго
core и TUN без PID, busy lease и баланс running/terminal operation events по ID.
Недопустимые terminal events и повторные connect/retry дают typed conflict без
изменения snapshot. Deadline вызывается настоящим production timer callback под
fake clock; caller отвечает до release gate, cleanup ждёт drain. Crash до complete
запрещает connected даже после позднего success. Каждый тур завершается cleanup
с нулевыми fake ресурсами. Префиксы включают все длины до шести; прежние 4096
stable tours и seeded 200-command race сохранены.

Это L2 с fake OS и in-memory event ledger, не durable audit history, не полный
обход всех blocked/unknown/background entrypoints и не Windows resource oracle.
Весь AT-00-002 целиком пока не объявляется PASS. F-021 остаётся опровергнутой.

### Qodo #61 — отсутствие обоих событий остановки

Qodo run 1541078 на b979009 подтвердил пробел oracle: если для stop не поступили
ни running, ни terminal, проверка только существующих ID могла это не заметить.
Теперь число принятых connect/disconnect считается независимо от observer по
командам модели и сверяется с уникальными ID каждого вида после каждого шага
и финальной cleanup. Для timeout auto-stop и explicit join ожидается одна
операция disconnect. Два mutation fixtures запускают настоящие start/stop,
удаляя оба события connect либо disconnect: oracle обязан отклонить такой ledger.
До исправления обе регрессии падали (Missing expected exception).

## AT-00-005 — общий ID действия в IPC, lifecycle и JSONL

До изменения transport возвращал bare UUID, audit писал ipc_<hex>, а lifecycle
создавал отдельный op_<hex>. Один IPC action теперь получает main-generated
ipc_<UUIDv4 hex>: ровно эта строка проходит response/error, audit details,
operation events и top-level correlationId JSONL. AsyncLocalStorage сохраняет
ID через native waits и late drain; независимые параллельные действия и nested
scopes изолированы. Standalone lifecycle по-прежнему создаёт op_<UUIDv4 hex>.
Manual stop имеет ID своего нового действия; timeout recovery сохраняет ID
прерванного старта. Контекст принимает только canonical main ID, не raw payload.

Shared decoder/serializer поддерживает новые prefixed IDs и прежний UUIDv4
без изменения wire version. Политика redaction credentials не ослаблена.
Интеграционный fixture пишет JSONL на настоящий диск и читает его production
getFullLogs с повторной redaction: ID сохраняется, credential UUID и password
отсутствуют. Native Electron fixture проверяет production contextBridge для
всех семи error categories в обеих локалях и context до/после native wait.

До исправления адресная регрессия — 1 failed: IPC и operation IDs различались.
Точные команды и результаты итоговой проверки записываются в progress.md.
Durable connection history ещё не включена в этот контекст; source/owner/route/
confidence и monotonic ordering остаются. Это subset, не PASS всего AT-00-005.

### Qodo #62 — время жизни action context

Qodo 1541356 completed на 11b8acc подтвердил два дефекта: timer расписания
наследовал ID редактирования и повторно использовал его при re-arm; периодические
tunnel timers сохраняли ID завершённого connect. Контекст теперь содержит lease,
который истекает по sync return/throw или settlement исходного Promise. Унаследованный
store в detached callbacks после этого не выдаёт ID. Identity/rejection Promise
не меняются. Внутренняя native drain task имеет отдельный lease до фактического
завершения, поэтому caller cancellation не обрывает нужную корреляцию.

Регрессии используют настоящие Node timers: sync/async success/rejection,
периодическая tunnel работа, late native drain и production scheduler с тремя
последовательными connect/stop/connect. Только большие задержки планировщика
сжаты, fake timers не используются для проверки AsyncLocalStorage inheritance.
До исправления — 6 failed / 6 passed; после адресный набор — 74 passed.

## AT-00-005 — ID исходного подключения в истории сессии

LiveSession захватывает текущий main action ID при openSession. Общий writer
переносит именно его при закрытии, даже под контекстом нового manual stop
либо без активного контекста. Failed-start writer сохраняет ID своей попытки.
ConnectionLogEntry получает optional correlationId: прежние записи и untracked
sessions остаются без ID. Canonical ipc_/op_ UUIDv4 проверяются при read и write;
недопустимые поля сохраняются в rejected history с history.corrupted.
Поле переживает real Conf reload и JSON export; в CSV добавлен отдельный столбец.

Fixtures исполняют настоящие четыре session tracking функции index.ts, production
guarded IPC/lane и real Conf disk backend с подменёнными OS/Electron discovery
границами. Новый stop action имеет другой ID, а persisted history — ID start
response. До исправления адресная регрессия — 9 failed / 37 passed; точные
итоговые команды и результаты — progress.md. Это адресное L2 доказательство,
не installed restart/Windows acceptance. Source/owner/route/confidence, monotonic
ordering и полная матрица background/Soft history paths ещё не завершены.

### Qodo #63 — действие из трея до поиска прокси

Qodo 1541555 на 8f0288a подтвердил путь без контекста: Hard start из трея
при missing proxy записывал failure раньше lifecycle admission. Теперь граница
startProtectionFromTray создаёт свежий op_ action ID до proxy detection;
тот же ID доступен раннему failure/notification и последующему lifecycle.
Две повторные missing-proxy попытки проверены actual main bodies и real Conf:
история содержит два разных ID, каждый совпадает с контекстом уведомления.
До исправления — 1 failed; после адресный набор — 261 passed. Результаты полного
набора и проверки итогового SHA — progress.md. Остальные границы AT сохранены.

## AT-00-005 — происхождение записи истории сессии

Новые записи обязательно содержат provenance. Источник ipc/tray/lifecycle
захватывается в main action context, owner берётся из фактического admission
ConnectionLifecycle. При закрытии сессии новым stop действием исходные поля
сохраняются. Untracked runtime не получает выдуманный manual owner:
source=runtime, owner=unknown. Ранний отказ из трея имеет tray/manual ещё до
поиска прокси. Истёкший action scope не выдаёт metadata фоновым callbacks.

Route обозначает настроенный механизм: tun для Hard/Direct, soft-env для Soft,
unconfirmed для неудавшегося запуска. Это не packet-level доказательство защиты.
Confidence относится к классификации причины завершения: observed для явных
действий/отказа запуска, inferred для эвристических причин, indeterminate для
unknown. Полная трассировка фактических Soft/background sessions ещё остаётся.

Legacy записи без provenance читаются; новые записи без него отклоняются.
Reader/writer проверяют четыре enum-поля, согласованность route/mode и отсутствие
лишних полей. Повреждённые записи сохраняются в rejected history с событием
history.corrupted. Real Conf reload, JSON и CSV сохраняют provenance; четыре
CSV-столбца добавлены после correlationId, прежние позиции не сдвигаются.
Fixtures исполняют actual main session bodies и production lane для трёх
источников и всех шести владельцев; проверяют все outcome kinds и режимы.

До production-исправления — 29 failed / 47 passed; адресный итог — 311 passed
в шести файлах. Команды и общие результаты — progress.md. Это L2 subset,
не PASS всего AT-00-005: монотонный порядок и полные фоновые пути остаются.

## AT-00-005 — порядок времени внутри main (19.10.2026)

JSONL сохраняет реальное календарное ts и отдельные monotonicMs/clockId.
Монотонное elapsed время process.hrtime.bigint задаёт порядок внутри main;
clockId отличает новый origin после перезапуска. Миллисекундные метки могут
совпадать; очередь JSONL сохраняет порядок записи. Deadline остаётся setTimeout.

Session startedAt/endedAt, lifecycle dates и notifications следуют календарным
часам. Длительность сессии хранится отдельно в durationMs, вычисленном по
монотонным часам. Stats и UI duration/sort/start-failure classification используют
общий helper; legacy строки без durationMs получают безопасный fallback.
Новые записи требуют конечный неотрицательный durationMs; CSV добавляет его
последним столбцом, JSON сохраняет поле. Malformed durations удерживаются в
rejected history с history.corrupted.

Qodo 1541885 на первоначальном 20e6802 обнаружил неверную подмену календарного
времени process-anchored epoch: после коррекции история расходилась с фильтрами
и day/week/month stats. Замечание подтверждено и подход исправлен до слияния.
Clock fixture проверяет backward/forward jumps и точное elapsed время.
Production IPC/lane/logger пишет настоящий JSONL; real Conf session fixture
проверяет календарные даты, filter/stats и elapsed duration при коррекции часов
на час назад и 40 дней вперёд. Renderer проверяет реальную строку сессии с
endedAt < startedAt и durationMs=65000: она остаётся сессией с длительностью 1m 5s.
Полный AT ещё не закрыт: все реальные Soft/background entrypoints остаются
отдельной интеграционной работой. Точные команды и результаты — progress.md.

## AT-00-005 — интеграция Soft history (19.10.2026)

Успешный env apply теперь открывает сессию с оригинальными correlation/source/
owner/route/confidence. Одинаковый refresh не создаёт искусственный server-switch;
смена адреса или протокола закрывает предыдущую сессию и открывает следующую.
Failed refresh сохраняет предыдущую live-сессию только после read-back всех
четырёх переменных реестра и process env для прежнего endpoint. Несовпадение
или ошибка чтения закрывает её с confidence=indeterminate, переводит FSM в
unknown и сохраняет cleanup obligation. Попытка записывается отдельно.
При подтверждённом прежнем endpoint неуспешная операция остаётся error, но
FSM и renderer сохраняют connected/soft. Это отдельное подтверждение текущего
refresh, не переносимое на следующую операцию, fault или отмену.
Отмена/late completion не открывают сессию. Native status/restart callbacks
не подменяют историю env-only маршрута.

Stop/shutdown сохраняют Soft session при неподтверждённом env rollback и пишут
конечную запись только после успешного retry. Переключение на Hard/Direct
закрывает её после проверенного env cleanup с отдельным неопределённым итогом
следующего запуска, без утверждения о продолжении сессии на новом сервере.
Retained Soft reconciliation
использует owner=recovery, а tray failure до admission — source=tray/owner=manual.
Native counters для Soft не измеряются: нули в этих полях не доказывают отсутствие
трафика. Duration берётся из монотонной шкалы, route остаётся configured mechanism.

L2 fixtures исполняют actual main functions/callbacks, production lane/FSM и real
Conf backend для owned/legacy/tray/recovery путей, заменяя OS effects. Full native
Windows env/packet matrix этим не заявляется. Остатки общего operation registry,
фоновых native restarts и остальных AT сохранены. Команды/результаты — progress.md.

## AT-00-003 — общий реестр и отмена speed test (19.10.2026)

`OperationRegistry` назначает main UUIDv4, original correlation/source/owner,
deadline и terminal status; ресурс удерживается до фактического завершения
захваченных эффектов. Abort/deadline возвращают caller типизированную ошибку
немедленно, не освобождая ресурс раньше времени. Higher-priority replacement
дожидается drain; его ожидание тоже отменяемо, входит в deadline и прекращается
при shutdown. Монотонный бюджет не меняется при коррекции календарных часов.

Speed test использует registry вместо отдельного busy-флага. Signal проходит
через latency/download/upload/egress lookup; отмена запрещает fallback,
следующий progress и запись результата. Уничтожаются upload streams и download
streams, включая поздние headers и отмену между headers и началом чтения.
IP monitor получает canPublish по signal, запрещая late shared IP/health/recovery
publication после отмены; его raw verification тоже удерживает lease до drain.
Shutdown одновременно отменяет connection lane и feature registry и ждёт оба
drain перед native cleanup. `operations:list/cancel` проходят общий IPC guard;
прогресс содержит operationId, stale ID не отменяет следующий запуск.

L2 исполняет настоящий speed runner, guard и Conf backend с управляемыми
сетевыми границами: отмена при порогах 10/50/90/100%, таймаут, поздние ответы,
ошибки UUID и история. Отдельный тест использует настоящий axios и локальный HTTP
server: abort закрывает сокет. Native Electron smoke проверяет production
handlers/preload/contextBridge, typed cancellation с исходным correlation,
удержание ресурса и отказ чужому WebContents; сеть в нём управляемая.

Это частичная реализация AT-00-003. Остальные feature entrypoints, UI cancel /
unmount, durable audit history и ресурсная Windows-матрица остаются открытыми.
Общий registry хранит только ограниченный in-memory список (1000), не заменяет
устойчивую историю AT-00-010. Полные результаты и PR gate — progress.md.

Qodo #67 выявил четыре дополнительных границы. Feature JSONL получает
обратимый operationKey при сохранении маскирования raw UUID. Refused quit
возобновляет feature admission только после drain, с generation fence для старых
ожидающих запусков. Неудачный download round отменяет соседей и дожидается их
до fallback; canPublish IP-monitor дополнен реальным abort provider wave.
Coalescing разрешён лишь для одинаковых owner и signal. Actual JSONL/diagnostic
read-back, before-quit callback и network-boundary fixtures проверяют эти пути.

## Обновление подписок: отмена, physical drain и очередь записи

`refreshGroup` использует общий registry с ресурсом конкретной группы и deadline
120 s. Ручной вызов имеет owner=manual, автоматический — schedule. Ручной
вызов отменяет автоматический и ждёт фактического завершения его эффектов;
равноприоритетный конфликт возвращается типизированно. После cancel/timeout
caller получает отказ сразу, а lease удерживается до raw settlement.

Signal проходит все device/redirect/retry/DoH границы. `curl.exe` получает
адрес и чувствительные headers через stdin; отмена вызывает kill конкретного
дочернего процесса. Kill не считается завершением: Promise ждёт close процесса
и stdio, в том числе для DoH fallback. Отмена не запускает следующий fallback.
Независимые callers одного URL не делят cancellable сетевой запрос.

Commit сериализован с существующим append импорта через общую очередь.
Внутри очереди повторно проверяются lease и существование/источник группы,
перечитывается актуальный массив профилей. Поздний fetch не затирает другую
группу, concurrent import или переименование. Удалённая группа не воскресает.
Остановка scheduled sweep отменяет его запрос и запрещает запуск следующей
группы. При допуске фиксируется lastFetchAttemptAt; cancel сохраняет последний
provider outcome. Сам deadline переводит существующий неизменённый источник
в unreachable с явной timeout error и новым attempt time, обеспечивая backoff
до следующего штатного интервала. Поздний network callback ничего не пишет.
Отмена sweep/manual replacement не увеличивает счётчик failed.

L2 выполняет production refresh/registry/IPC guard с управляемыми границами:
отмена между device fetches и перед queued commit, deadline, shutdown и manual
replacement. Отдельный стенд использует настоящий `curl.exe`, loopback HTTP и
Conf backend: проверяются завершение процесса/сокета, неизменность файла после
отмены и сохранение параллельных записей после повторного чтения с диска.
Хранилище в этом стенде подменяет Electron/DPAPI boundary; это не новая
проверка шифрования. Полная AT-00-003 остаётся открытой, UI не менялся.

Production refresh дополнительно проверен с настоящими logger/redactor и JSONL:
две concurrent группы имеют различные operationKey и собственный IPC correlation,
одна cancelled, вторая success; diagnostic read-back сохраняет эти связи после
повторного redaction. Raw UUID и контрольный пароль отсутствуют в обоих выводах.

## Импорт профилей: lifetime запроса и сохранение в очереди (19.10.2026)

Новые подписки, одиночные URI и append в выбранную группу используют общий
registry: UUIDv4, исходный correlation, deadline 120 s, prompt cancellation,
physical drain. Ключ ресурса — SHA-256 канонического input/device/target;
чувствительный input не включён в metadata реестра. Совпадающий незавершённый
импорт даёт typed conflict, независимые импорты получают отдельные lifetime.
Re-paste существующей подписки делегируется единственному refresh owner;
возвращаются только новые профили его группы, без чужого concurrent import.

Signal проходит в настоящий resolver/curl. Группа создаётся внутри общей
очереди одновременно с append профилей: отменённый ожидающий запрос не создаёт
пустую группу. Lease проверяется до commit и success log. Append повторно
проверяет existence/source целевой группы; удалённый или заменённый источник
не получает поздних профилей. Разные device imports одного нового URL повторно
ищут группу в очереди и используют одну запись. При ошибке записи восстанавливаются
предыдущие профили, active selection и список групп; ошибка самого восстановления
явно сообщает internal failure без успешного результата.

Controlled fixture выполняет production picker/refresh/registry/guard: abort
на сетевой границе и в очереди для subscription/URI/target, deadline, shutdown,
удаление/замена target, конкурирующие commits/device variants/re-paste, ошибки
profiles/active/groups и неуспешный rollback. Отдельный loopback fixture использует
настоящий curl, Conf disk backend и logger/redactor: отмена завершает процесс/сокет,
поздний HTTP не меняет файл; concurrent imports сохраняют собственные IPC correlation
и operationKey в JSONL и diagnostic read-back. Успешный URI/import перечитывается
новым Conf handle. Electron/DPAPI boundary заменён, новое доказательство encryption
не заявляется. UI и config browse/import/apply ещё не интегрированы; AT-00-003
и весь WP-0 остаются открытыми. Проверки и PR gate — progress.md.

Qodo #69 выявил race в re-paste continuation: проверка внешнего signal после
успешного refresh могла переименовать уже сохранённый результат в cancelled.
Решение принимает единственный refresh owner; abort после terminal success
не заменяет его результат. Regression синхронно отменяет внешний signal при
публикации refresh success и проверяет сохранённые profiles и успешный ответ.
При отказе rollback журнал дополнительно сохраняет bounded commitStep и
категорию исходной ошибки; произвольные message/stack/path не записываются.

PR #69 слит после Qodo 1542807 completed (оба прежних findings implemented,
новых нет) и CI 39179194108 success на a5cf69e. Отдельный REST GET подтвердил
merge 639ade1. Это закрывает текущий участок profile import, сохраняя перечисленные
границы общего AT; config import/export и UI остаются открытыми.


## Конфигурация: отмена, async file I/O и terminal commit (19.10.2026)

Browse/validate/apply/export используют общий operation registry: UUIDv4,
исходный IPC correlation, deadline 120 s, prompt cancellation и physical drain.
Уничтожение renderer отменяет его запрос; завершившийся поздний dialog/read
не выдаёт capability и не сохраняет настройки. Grant по-прежнему main-only,
привязан к sender, snapshot выбранных байтов и сроку 60 s; apply забирает его
однократно при invocation и повторно проверяет authority внутри общей очереди
profile writes. Expiry/new selection не разрешают старому queued apply запись.
Merge перечитывает актуальные stores в очереди и сохраняет concurrent profiles.

Чтение выполняется асинхронно через один handle, ограничено 16 MiB + 1,
проверяет regular file, длину и size/mtime до/после чтения. Экспорт сначала
пишет собственный wx/0600 temp рядом с назначением, делает fsync/close,
затем синхронный rename в финальном lease.commit. Cancel сохраняет прежний
файл и ждёт raw I/O/close перед удалением своего temp. Ошибка write/rename
возвращается явно; после terminal commit поздний abort не превращает уже
сохранённый успех в cancelled. Registry запрещает commit при незавершённом
tracked I/O и диагностирует feature throw после commit без изменения результата.

Controlled fixture выполняет production config/registry/IPC guard и настоящие
файлы, Conf, logger/redactor/JSONL/diagnostic read-back. Покрыты held dialogs,
secret consent, open/read/write/fsync, queued cancel/destroy/expiry/replacement/
shutdown, single-use, concurrent merge, persistence/rollback и rename failures,
terminal abort и deadline. Electron/DPAPI boundary и native dialogs заменены;
новая приёмка DPAPI, системных ACL и самого Windows dialog этим не заявляется.
UI cancel/unmount и прочие операции остаются в общем остатке WP-0. Команды,
фактические результаты и Qodo/CI gate фиксируются в progress.md; завершение
всего AT-00-003 или WP-0 не заявлено.


Qodo #70 уточнил этот участок: staging получает настоящий Windows security
descriptor до plaintext; существующие owner/group/DACL сохраняются, новый
файл получает protected user/SYSTEM DACL. Destination snapshot проверяется
снова перед rename, включая metadata change при изменении ACL. Реальный
Windows fixture проверяет ACL round-trip, новый protected файл и conflict
после изменения ACL. Ошибка удаления temp фиксируется отдельно с cleanupFailed
и исходной correlation, не подменяя первичный результат. Постоянный отказ
удаления не заявляется успешной очисткой. Native consent/picker приостанавливают
рабочий budget; ожидание решения пользователя допускает deadline=null, но
остаётся отменяемым. После ответа deadline снова ограничивает настоящую работу.
Initial Qodo/CI относятся к первому head; исправления требуют повторного gate.

Qodo 1543042 подтвердил три прежних исправления и выявил ошибку путей с
типографскими апострофами. Paths helper теперь передаёт их как base64 data,
без вставки символов имени в PowerShell literal. Четыре дополнительных native
cases с U+2018…U+201B проверяют создание и перезапись; новый PR gate обязателен.


PR #70 слит: Qodo 1543096 completed на ceaa20b (все 4 findings implemented,
новых нет), CI 39183295438 success на том же head. Отдельный REST GET подтвердил
merge 2e61411. Это завершает текущий config участок; общий остаток AT и WP-0
сохранён. Следующий участок — экспорт VPN-ключей. Полный локальный набор:
4346 passed / 5 skipped, typecheck/build/native PASS; подробности — progress.md.


## Экспорт ключей: общий lifetime и terminal persistence (19.10.2026)

Пять production handlers (renderer URI/JSON, main clipboard, single key file,
bulk key file и proxy-list) подключены к registry с отдельными ресурсами
keys:renderer/clipboard/file. Native consent и save picker сохраняют quiet
{ok:false,cancelled:true}; registry фиксирует это как cancelled. Ожидание
пользователя не расходует work budget. Cancel/destroy/shutdown/deadline запрещают
поздний выбор файла/раскрытие; physical resource удерживается до raw settlement.

Три file exports переиспользуют staging/Windows ACL/fsync/terminal rename из
config export #70. Ошибка записи возвращается через безопасную taxonomy,
сохраняя предыдущий destination. URI/JSON/mixed batch и counts не изменены.

Native clipboard write в Electron не поддерживает отзыв уже выданного вызова.
Отмена caller prompt, но resource ждёт write и компенсирующую очистку только
неизменённого owned значения. Новые пользовательские text/formats не стираются;
ошибка native cleanup логируется cleanupFailed с retry. Если владение форматами
не доказано, данные не стираются и невозможность очистки видна в журнале.
Не заявляется отсутствие кратковременной native записи после abort или очистка
Windows clipboard history/cloud. Это ограничение отдельно сохраняется для
полной приёмки; новый clipboard L3 этим fixture не выполнен.

L2 использует actual picker/registry/IPC guard, настоящие files/Conf/exporters и
logger/redactor/JSONL/diagnostic read-back. Dialogs/clipboard/Electron DPAPI boundary
заменены. Включены cancel до/после native boundaries, sender destroy/shutdown,
рабочий deadline и long user wait, file-handle drain, queue cancellation,
неизменность destination/temp cleanup, terminal abort и correlation/redaction.
Общие actual Windows ACL tests shared writer повторно прошли. Полный AT и WP-0
остаются открытыми: rotation, UI cancel/unmount, migration/audit/semantic matrices
и полная native/state/resource приёмка ещё нужны. Проверки и remote PR gate — progress.md.


Qodo #71 выявил три границы наблюдаемости/сохранения policy. Key failures теперь
сохраняют allowlisted errno вместе с category/destination в исходном correlation,
без raw exception data; этот безопасный allowlist общий с config diagnostics.
Bulk success снова пишет total/exported/skipped в actual JSONL, без path/content.
POSIX branch сохраняет uid/gid/mode до plaintext и проверяет read-back, иначе
экспорт отклоняется. Этот POSIX тест управляет filesystem/identity boundary;
натурная Linux приёмка не заявляется, actual Windows ACL cases сохранены.
Все 14 новых cases падали до исправления, адресный набор 167 passed после.
Initial CI 39185510421 success относится к cdb1229; новый head требует
повторных full tests, completed Qodo и CI success. Attribution не менялся вручную.


PR #71 слит после Qodo 1543309 completed (3 implemented, новых нет) и
CI 39186437502 success на c8be3ba. Отдельный REST GET подтвердил merge
273a93d / merged=true / state=closed. Полный локальный набор: 4393 passed /
5 skipped; typecheck/build/native PASS, адресно 167 passed. Git tree merge
совпадает с проверенным head. Следующий участок — ротация; это завершает
текущий key export участок, сохраняя общий остаток AT и всего WP-0.


## Ротация: один owner подготовки, native swap и физического завершения (19.10.2026)

Rotation IPC/timer используют общий registry и connection lane с одной identity:
UUIDv4, original correlation, owner rotation, work deadline 120 s. Admission
предшествует availability/fingerprint, поэтому manual/schedule вытесняют также
подготовку ротации. Rotation может вытеснить только меньший priority startup,
ожидая его actual drain/cleanup; равный/больший priority даёт typed conflict.

Cancel/deadline/destroy/config replacement/reload/stopTimer/shutdown запрещают
поздние select/broadcast/notification/config writes. Caller cancellation prompt,
но lane/resource держатся до actual native effects. При отмене до beginRestart
FSM сохраняет прежнюю защиту только после проверки неизменных runtime evidence
и отсутствия fault. После начала swap нужна подтверждённая ordinary cleanup;
новый startup не обходит эту границу. Native restart signal переживает reset
старого transition flag; late success после abort заканчивается teardown.
Финальное scheduling и успешный result выполняются одним registry commit.

Endpoint probe с managed signal ждёт обе physical TCP/ICMP ветви. После abort
следующая interface/fallback/DNS continuation не запускает новую сетевую попытку.
Уже выданные OS probes завершаются под физическим lease; их моментальная отмена
не заявляется. Shared lookup физических адаптеров не отменяется другим caller.

L2 fixture выполняет actual rotation/registry/lane/FSM/IPC guard с реальными
Conf и logger/redactor/JSONL. Проверяются три управляемые границы, bounded cancel,
deadline, sender destruction, configuration reload, timer, manual/schedule
replacement, unchanged file bytes, terminal correlation и сохранение состояния
preflight. Native restart/probes/fingerprint/notification заменены; отдельный
extracted-body fixture выполняет production restart/probe функции с управляемыми
OS/DNS boundaries. Это не новая native Windows/TUN приёмка. Финальные проверки
и review gate фиксируются в progress.md.

Существующий Health-Before-Commit/возврат старого сервера после failed rotation
(WP-10 F-124, том 3 §2.2) этим lifetime участком не реализован и не объявляется
PASS: selection/первичное уведомление по-прежнему предшествуют проверке нового
сервера. UI cancel/unmount, прочие background/native entrypoints, durable audit,
migration/semantic matrices и полная ресурсная приёмка сохраняются в WP-0.

Qodo #72 подтвердил четыре дополнительные границы: timer независимо
восстанавливает следующий tick после отмены/timeout/conflict, но generation
запрещает retry после stop/disable/config replacement/shutdown. Для живого
туннеля выбор и announce кандидата перенесены после отменяемой подготовки;
при idle входят в terminal commit. Исключение preflight сохраняет прежний
confirmed state только после повторного сравнения original runtime evidence
после drain. Log operationId использует обратимый op_ key без маски UUID;
IPC DTO и cancel API по-прежнему используют исходный UUIDv4. Actual JSONL и
diagnostic read-back проверяют оба одинаковых ID поля и correlation. Это
не отменяет перечисленные остатки WP-0/WP-10; финальные checks/review — progress.md.

Повторный Qodo потребовал сохранить явное предупреждение после failed native
restart: connectionError сообщает, что защита после перезапуска не подтверждена
и трафик может идти по обычному маршруту. Preflight failure, не трогавший native
туннель, сохраняет отдельный нейтральный текст. Ни успешная ordinary teardown,
ни отключённый firewall не предполагаются только по факту ошибки restart.
Production rotation regression проверяет оба исхода native failure — result
и exception — и отсутствие предупреждения о снятой защите при preflight error.

Сохранение эквивалентного config patch (включая новый массив прежних profileIds)
не отменяет admitted rotation, не переписывает файл и не сбрасывает countdown.
Реальная замена конфигурации по-прежнему отменяет работу со старыми значениями.
L2 regression проверяет signal, прежний nextRotationAt и успешное завершение
удержанного native restart без ordinary cleanup для четырёх no-op patch.

## Stop deadline — bounded caller и обязательная очистка

ConnectionLifecycle.stop получает deadline 120 s по умолчанию и отдельный
AbortSignal; ожидание startup drain входит в срок. Timeout/cancel возвращают
конечный typed отказ без ожидания неотменяемого OS I/O. Уже принятый rollback
продолжается до физического завершения под занятым native lane. Повторные
stop callers присоединяются к прежнему result; shutdown и rotation registry
по-прежнему ждут physical Promise, включая его поздний отказ.

Terminal event один: поздняя очистка не превращает timeout в success. После
таймера нельзя объявлять ресурсы освобождёнными; фактическая очистка сети и
закрытие завершившейся connection session при этом не запрещаются. Signal
не является основанием бросить обязательный rollback. Controller остаётся
в main и не сериализуется в IPC metadata.

L2 cases: deadline во время cleanup и startup drain; prompt external cancel;
pre-aborted signal без admission; invalid timeout; coalescing после timeout;
shutdown с поздним success/failure; rotation registry lease после stop deadline;
исходные correlation/UUID и единственный terminal. Настоящий Electron с
production preload/contextBridge дополнительно проверяет timeout stop за 900 ms,
original metadata, запрет нового старта до drain и отсутствие позднего success.
OS boundaries управляемые; полная native Windows resource matrix, UI lifetime,
background admission, durable audit, migrations/semantic errors/flags остаются
открытыми. Финальные full/review/CI результаты фиксируются в progress.md.

Qodo #73 уточнил границы cleanup failure и представления stop ID. Physical
failure сохраняется отдельно от bounded terminal: close наблюдает false result
и throw даже после окончания drain. Успешный подтверждённый reconnect или cleanup
retry снимает прежний failure. Независимый shutdown pipeline может снять его
только после успешных native/network/env/capture backstops, при закрытом,
полностью drained lane и свежем stopped evidence FSM. Старый failure остаётся
в журнале; неуспешное восстановление запрещает выход.

Stop operationId теперь до публикации в owner/FSM/IPC представлен как
op_<32 hex>: все 128 бит сгенерированного UUIDv4, включая version/variant,
сохраняются; префикс и отсутствие дефисов исключают маскирование ID как секрета.
Fallback correlationId равен этому ID. Это уточняет прежние записи о raw UUID
в stop receipt: они относятся к более ранним коммитам PR #73. Managed feature
и operations:cancel сохраняют прежние UUIDv4; credential redactor не ослаблен.
operationLogDetails идемпотентен для canonical op_ ID. Реальный JSONL двух stop
операций и diagnostic read-back сохраняют исходные receipt ID и различают их,
маскируя credential и посторонний UUID. Финальные проверки — в progress.md.

## Follow-up Revix #70 — synchronous commit и secret export

Needs changes уже слитого #70 проверяется отдельным follow-up. commit теперь
отвергает Promise/thenable callback на уровне TypeScript, native/bound async
callback до выполнения; malformed untyped JS thenable сохраняет physical drain
до validation terminal. Cancel test на native dialog использует fake timers,
сохраняя отказ поздних эффектов и ожидание drain.

Secrets mode проходит от config:export до файлового writer и ACL helper:
перед plaintext назначается protected user/SYSTEM DACL, включая replacement
существующего широкодоступного файла. Redacted export сохраняет прежнюю
destination policy. POSIX branch секретов требует текущего owner/mode 0600.
Реальный killed writer fixture доказывает private DACL crash residue и
неизменность прежнего destination. Plaintext staging после аварии может остаться;
автоматическая очистка произвольных выбранных каталогов не заявляется.
Финальные проверки и оба reviewer verdict записываются в progress.md.

PR #74 расширил эту гарантию на все три key/proxy file handlers: mode у writer
и ACL helper обязателен, malformed/omitted mode отвергается. Реальные Windows
handler regressions проверяют закрытые права после замены широкодоступного файла.
POSIX secrets не заменяет чужой destination. Bound async с изменённым toStringTag
отвергается до вызова; при malformed untyped thenable timeout/cancel не заменяет
validation terminal во время обязательного drain. Это исключительный invalid-code
путь; prompt cancellation корректных операций сохраняется. Проверки — в журнале.

Повторный Qodo #74 выявил окно inherited ACL при создании пустого Windows
staging. Secrets теперь получает private FileSecurity атомарно в FileStream
CreateNew, до возможности открыть файл другим reader. Node открывает уже
private staging; последующие проверки и terminal replacement сохраняются.
Actual handler tests проверяют ACL на границе Node open при broad parent DACL;
collision test подтверждает неизменность существующего файла.

Protected creation handle передаёт volume/file ID; opened handle Node до записи
обязан иметь тот же ID. Shared-directory substitution до открытия отвергается
без записи plaintext в подмену. Перед commit повторно проверяются staging ID и
snapshot; cleanup не удаляет substitute с другим ID. Два настоящих filesystem
regressions покрывают оба handoff/commit окна, включая заранее открытый reader.
Если helper не подтвердил ID после CreateNew, возможный пустой private residue
не удаляется наугад: пишется явный cleanupFailed warning. Проверки — в progress.md.

Qodo 1544270 на 6c691f1 обнаружил оставшееся окно между последним lstat и
path-based rename. Windows export теперь допускается только на локальном диске
в namespace с доверенным владельцем и ACL всех родительских каталогов до корня.
Другие principals не могут иметь DELETE/DELETE_CHILD, WRITE_DAC/WRITE_OWNER,
изменение атрибутов или generic write/all. Null DACL, UNC и reparse-каталоги
отвергаются permission до plaintext. Read-only sharing разрешён. Доверенная
граница — текущий пользователь, SYSTEM, Administrators и TrustedInstaller;
защита от malicious code под тем же пользователем не заявляется. ACL выбранных
каталогов приложение не меняет. Это ограничение экспорта в shared writable
namespace, а не обещание атомарного handle-based rename.

Native regression fixtures создаются отдельно под user profile, с private DACL
только нового временного каталога, и удаляются после теста. Workspace/OS Temp
в локальной среде дают sandbox principals права изменения entries и не подходят
для положительного оракула; отрицательные случаи явно добавляют такие права.
Revix minors: перед commit проверяется identity без соседних избыточных snapshots;
подтверждённый отказ до создания и CreateNew collision не помечаются cleanupFailed.
Indeterminate creation по-прежнему предупреждает о возможном пустом private residue.

## Speed test — lifetime страницы и явная отмена

Страница создаёт отдельный requestId UUIDv4 до invoke, принимает progress только
этого запроса и при unmount отменяет его, даже если первый progress ещё не пришёл.
Main сохраняет собственный operationId/correlation: requestId не подменяет audit ID.
Новый speed-test:cancel привязан к requesting WebContents; чужой/stale запрос
возвращает false. Destroyed WebContents, render-process-gone и полная навигация
main frame прерывают принадлежащий странице тест; same-document/subframe
navigation не прерывают. Все lifetime listeners снимаются при bounded terminal.
После bounded cancel/deadline native lease продолжает drain, поздняя история
не коммитится. Legacy speedTestRun() без аргументов сохранён.

Mounted/request/revision fences защищают result/error/progress/history после
unmount и медленный initial history от перезаписи post-run history. У отмены
есть loading и retry при IPC failure; typed cancelled не показывается как ошибка.
Результат завершает running, не ожидая чтения истории. Узкие result/history cards
переносят метрики и длинные имена вместо обрезания за пределами карточки.

L2 использует production page/handlers/registry с управляемыми границами.
Native Electron smoke использует настоящий production preload/contextBridge и
WebContents; подменены только HTTP transport и VPN readiness. Проверены immediate
run+cancel без progress/list, native UUID/correlation, cancel <900 ms, retained
drain, foreign/stale cancellation, destroyed requester и настоящий reload без
уничтожения WebContents/записи истории.
Внешний трафик/VPN при этом не запускаются. Browser fixture проверяет actual page
в light/dark, keyboard cancel, navigate/remount и завершение; на viewport
280/320/414 px длинные server/profile не выходят за экран. Это адресный вклад в
AT-00-003/008, не полная приёмка всех UI/native/background entrypoints. Команды,
результаты и границы доступных design gates записываются в progress.md.

## Плановые функции — release admission

WP-12 функции mihomo, AmneziaWG, процессный монитор и browser boxes в текущем
релизе имеют enabled=false и laboratoryAdmission=null. Реестр shared используется
actual main handlers и production preload, а не существует только в тесте.
Допуск является решением релиза с лабораторными критериями, не пользовательским
boolean setting. Приём caller evidence не предусмотрен; добавление реализации
и положительного admission возможно только в согласованном WP-12 после прежних
пакетов. Functional IPC/страницы WP-12 сейчас отсутствуют.

planned-features:status возвращает отдельный snapshot с requiredTests;
его редактирование caller'ом не меняет runtime policy. planned-features:activate
отвергает известную функцию typed permission и пишет feature.activation-denied
с laboratory-evidence-missing, перечнем критериев и исходной IPC correlation.
Неизвестный ID и лишние аргументы (включая fake evidence) отвергаются схемой.
Настоящий Electron проверяет все четыре отказа, JSONL read-back, неизменность
реестра и foreign WebContents; UI tests проверяют production Sidebar/Settings
при обычном и advanced режиме, включая forged saved flags. Это адресное
доказательство AT-00-009/AT-12-002, не запуск planned VPN/monitor/boxes функций.
Команды, полные результаты и remote gate — в progress.md.

## Реестр secret-store migrations — PR #77

Actual facades settings/server-picker/server-groups используют общий dry-run и
синхронный runner: detached preparation, encrypted backup точных исходных bytes,
input/output/backup SHA-256, migrationHistory, atomic Conf replacement и read-back.
Success записывается после read-back. Ошибки подготовки сохраняют исходный файл;
ошибки commit/read-back не выдают неподтверждённый успех. Старый backup и backup
другого исходника сохраняются отдельно. Constructor defaults больше не изменяют
исходный файл до snapshot, неизвестные поля сохраняются.

После замечаний Qodo 1545089 миграция выполняется только при plaintext: реальные
settings/picker 0/1 → 2, current plaintext 2 → 2 repair; groups 0 → 0, поскольку
выпущенный schema-0 reader уже понимает SecretRef. Уже encrypted/empty/public
legacy stores сохраняют совместимую версию, fresh reads не создают файл или
фиктивную migrationHistory. Пустые groups без backup читаются без DPAPI.
Проверка/защита существующего backup по-прежнему обязательна.

Размер исходника и authenticated plaintext ограничен 16 MiB; encrypted envelope
имеет отдельный предел 32 MiB с проверкой до записи. Base64/DPAPI expansion больше
не ломает restart допустимого исходника. Real Conf regressions включают backup
больше 16 MiB с повторным import/read, три отказа size bounds, fresh stores всех
трёх видов, пустые groups без DPAPI и совместимость с прежним group admission.

Это часть AT-00-006 / AT-01-001/010 / F-074. Остальные 17 electron-store форматов
остаются 0; startup классификация/переносы, другие persisted JSON, полноценный
upgrade/downgrade и межпроцессный CAS остаются открыты. Pre-commit comparison
не является OS-level CAS; native same-version smoke не заменяет OS/VM matrix.
Точные команды, результаты и remote gate записываются в progress.md.

## Lifetime документа для import/refresh/config/key IPC

Main-only requestDocumentLifetime связывает вызов с текущим requesting document:
destroyed, render-process-gone и полная main-frame navigation отменяют его сигнал.
Same-document/subframe navigation и события чужого WebContents не отменяют вызов.
После Qodo 1545426 используется main-frame did-navigate: попытка перехода,
заблокированная will-navigate guard, сохраняет документ, запрос и idle approval.
Real Electron регрессия сначала воспроизвела ошибку на did-start-navigation,
затем прошла на committed navigation; настоящие reload/destroy остались зелёными.
Внешняя main cancellation объединяется с lifetime без подмены operation UUID или
correlation; renderer не передаёт AbortSignal. Слушатели снимаются при bounded
terminal, а registry сохраняет физическую аренду до drain.

Actual servers:add/add-to-group, groups:refresh, config browse/validate/apply/export,
все пять key exports и прежний speed-test wrapper используют общую границу.
Scheduled refresh сохраняет собственное main-only владение. Выбранный через
config:browse-import snapshot привязан к документу до consume/expiry: reload/crash
отзывает разрешение и очищает raw, даже если активной операции уже нет.

25 регрессий production handlers воспроизведены до fix; проверены typed cancelled,
исходный IPC correlation, отсутствие поздней записи и снятие listeners. Real
Electron fixture проверяет production registry/helper на настоящем reload/destroy,
prompt result <900 ms, retained drain, отсутствие commit и допустимые foreign/
same-document navigation. Физический I/O в fixture управляемый; это не VPN/L3 test.
SPA unmount без native navigation остаётся отдельной задачей page request/cancel.
Команды, результаты полного набора и remote gate — progress.md.

## Servers: requester lifetime экспорта ключей (19.10.2026)

Предыдущий import/refresh участок принят в #80: final head 5a9285e,
Qodo 1553608 completed без findings, CI 39290006611 success;
merge/main e0b45b7 совпал по tree с reviewed head. Revix full review
недоступен из-за квоты; его отсутствие не approval.

Пять key export main entrypoints принимают optional requester token через
существующий helper. Отмена ограничена sender+token, operation UUID/correlation
и terminal commit принадлежат registry. Четыре workflows страницы Servers
создают token до invoke; SPA unmount отменяет owned requests и очищает flash
timers. Late success/error не вызывают UI/log effects. Native main-only consent,
clipboard ownership и private file handling сохранены.

До fix main 5 failed и UI 4 failed. L2 включает retained consent/save selection,
file open/write/sync и clipboard write, foreign/stale/duplicate/malformed token,
reentrant terminal commit, current success/quiet cancellation и flash cleanup.
Настоящий Electron 44.4.3 с production preload/handlers/stores проверил все пять
entrypoints на controlled consent: cancel <900ms, original correlation, retained
drain, no late save/file и fresh successful export. Clipboard OS не изменяется.
Build, пять Electron fixtures, IPC/CSP — exit 0. Полный run выполняется;
этот участок не объявляет все AT-00-003/008 завершёнными.

Final npm.cmd test — **4691 passed /5 skipped /0 failed**, 273.53 s, exit 0.
Первый полный run имел два failure: literal old preload source assertion и
5000ms harness timeout native file preparation. Передачу token/legacy args
проверяют пять executable preload regressions; harness budget long-consent
cases 15000ms, production deadlines/cancel assertions сохранены. Полная
история failures и команды записаны в progress.md. Typecheck — exit 0,
165 channels/0 public any; traceability AC 927/927, F 210/210 и diff check —
exit 0. PR требует собственного completed Qodo/CI до следующего участка.


## ServerDetailModal: lifetime экспорта (19.10.2026)

Экспорт страницы принят в #81: final head 34d4efc, Qodo 1553954 completed
без findings, CI 39293792384 success; merge/main ab531c4 совпал по tree
с reviewed head. Revix full review отсутствует из-за квоты, не approval.

Оставшийся modal export использует эти же main channels и tokens. Open/profile
scope отменяется при закрытии, выборе другого id, profile=null и unmount.
Повторное открытие того же profile получает новый scope; metadata refresh
того же id сохраняет активные запросы. Late success/error старого scope
не создаёт flash/timer и не меняет результат текущего. Завершённые запросы
забываются, flash timers очищаются, typed cancellation тихая.

До fix — 10 failing tests actual React modal; адресный набор после fix —
88 passed, 4.54 s. Затем добавлены два profile=null cases; полный run и
build выполняются. Это адресные AT-00-003/008 UI regressions, не полная
приёмка всех оставшихся background/diagnostic entrypoints WP-0.

Final полный npm.cmd test — **4706 passed /5 skipped /0 failed**,
287.12 s, exit 0; build/typecheck и coverage/diff — exit 0. Первый full
имел два default5000ms timeout в прежних bootRecoveryExecution и
physicalAdapterDnsScript; отдельно 30/30 и 4/4 passed, затем полный default
повтор без изменения их кода/budgets. Все команды/неудачные результаты в
progress.md. Следующий участок требует Qodo/CI этого опубликованного head.

## Диагностический ZIP: lifetime экспорта (19.10.2026)

Предыдущий modal участок принят в #82: final head64e089e, Qodo1554278
completed без findings, CI39297189492 success, merge/main1549a64.

AT-00-003/004/005/008: snapshot → native picker → staging → compression →
потоковая atomic file replacement имеют одного main owner, work deadline,
request token и physical drain. Queued/cancelled snapshot не публикуется.
Сборка ZIP не пишет в выбранный destination до terminal commit. Состав
архива и redaction сохранены. Очистка awaited, cleanup-failed отражается
в результате и UI. Main faults typed; renderer не получает сырые exception.

DiagnosticsCard/Settings используют общий owned workflow: unmount отзывает
token, stale replies не сбрасывают новый busy state и не создают UI/log/toast
effects. Вложенные forensics queue/summary прекращают следующие этапы при
отмене и удерживают raw эффекты до settlement.

До fix 1 failing regression. Адресный набор8 suites —103 passed/11.22s;
после него добавлены2 UI cases для typed errors. Native Electron44.4.3:
6 PASS fixtures, включая actual ZIP/ACL/stream/read-back и cancel<900ms.
Build/typecheck/traceability — exit0. Финальный полный npm.cmd test:4735 passed /5 skipped /0 failed,323.76s,exit0. Предыдущий full имел один
5000ms timeout в прежнем serverKeyOperations; отдельно57/57 passed, затем
полный default повтор без изменения кода/budgets. Remote gates pending.
Это адресная часть WP-0, не приёмка всего WP-0/WP-8 или OS/L3 matrix.

PR #83 review follow-up: Qodo1554946 completed с6 findings на b870f009.
Подтверждённые mixed-summary и cleanup-warning исправлены; export-owned
summary writes только в bundle, retained session byte-invariance проверяется.
Общий ZIP work budget600s, terminal success audit и manual picker cancellation
log восстановлены. Namespace ACL safety сохраняется. Третий entrypoint
Maintenance использует общий owned hook. Final build/typecheck,6 native
Electron fixtures и IPC/CSP passed; final full/новый head review pending.

Review final full:4746 passed /5 skipped /0 failed,323.00s,exit0.
Build/typecheck,6 Electron fixtures,IPC/CSP,coverage/diff —exit0.
Remote approval требуется на новом опубликованном SHA.

Qodo1555116 отметил5 findings implemented. Для оставшегося namespace finding
реализована предложенная Qodo безопасная альтернатива: typed permission
показывает инструкцию выбрать local private folder; ACL не ослаблены. Actual
namespace refusal и все3 UI проверены. Final full4747 passed /5 skipped,
317.26s,exit0;build/typecheck и6 Electron fixtures —exit0. Новый head
требует своего completed Qodo и CI success.

## Групповая проверка ключей: requester lifetime (19.10.2026)

Предыдущий audit/event участок принят в #84: final head7c716fe,
Qodo1555833 completed,2/2 implemented, CI39315249433 success;
merge/main5641f2b совпал по tree с reviewed head.

AT-00-003/004/005/008: groups:check-health использует существующий
requester token/document lifetime и registry kind health-check/deadline600s.
Main отменяет caller promptly, удерживая raw workers, late SOCKS connections,
закрытие sockets/child и cleanup. После отмены следующие stages, запись
profiles и completion log запрещены. Перед terminal persistence общий
import/refresh writer queue повторно проверяет исходные credentials.
Servers использует свои page tokens и не показывает late success/error;
canonical IPC fault заменяет raw error строку. Legacy preload arity сохранена.

До fix13 main и3 UI regressions failed; targeted58/58 passed после fix.
Полная приёмка этого участка, команды и remote gates записываются в progress.md.
Это адресная часть WP-0; WP-2 и остальные producers остаются открытыми.

Дополнительные negative cases: local config/pidfile I/O denial, sync/async
spawn failure и TLS construction error теперь дают typed operational failure,
сохраняя прежний verdict ключа. Remote SOCKS failure остаётся sanitized
per-key observation. Targeted260/260 passed; final build/typecheck и6 native
fixtures passed. Default full выявил два native fixture timeout; полный
serial run выполняется, результаты/границы доказательств в progress.md.

Финальный полный npm.cmd test -- --maxWorkers=1:4827 passed/5 skipped/0 failed,
321.42s,exit0. Build/typecheck,6 native fixtures,coverage/diff —exit0.
Default failures сохранены в progress.md; remote Qodo/CI требуются на head PR.

PR #85 Qodo1556439 completed с4 findings на22e1348. Исправления дополняют
receipts сохраняемым при UUID-redaction operationKey, допускают разные группы
с исключением дублей одной группы до physical drain, и переводят HTTP errors
в canonical message/соответствующий status без локальных путей. Token обязателен
и404 для missing/empty сохранён. Конкурентные commits не теряют результаты;
отмена одного group scope не отменяет другой. Targeted8 suites269/269 passed,
5.26s;build/typecheck и6 native fixtures —exit0. Final full и automatic review
нового SHA требуются до следующего участка; атрибуция Qodo вручную не менялась.

Review final full npm.cmd test -- --maxWorkers=1:4835 passed/5 skipped/0 failed,
271.89s,exit0. Build/typecheck,6 native fixtures,coverage/diff —exit0.
Initial CI39322197254 success относится к22e1348; fixes требуют новых gates.

## URL availability: requester lifetime (20.10.2026)

#85 принят: final head97c3059,Qodo1556605 completed4/4 implemented,
CI39323879365 success,merge/main23eca26; tree совпал с reviewed head.

AT-00-003/004/005/008: URL check имеет общий owner/UUID/correlation/deadline60s,
document lifetime и optional requester token. Отмена прекращает caller promptly;
raw DNS/HTTP/socket/window commands остаются owned до settlement/close.
Late callbacks не продолжают pipeline и не записывают history. History commit
terminal, новые строки имеют correlation/provenance, legacy rows сохранены.
UI unmount отменяет запрос и ограждает поздние UI/log/history effects.

До fix22 main failures и4 UI failures. Адресные6 suites164/164 passed,
2.24s;build/typecheck165 channels/0 public any —exit0. Полная история
промежуточных failures/остановленного full в progress.md; final full/native
и remote gates требуются отдельно. Реальные сети/геоблокировки WP-7,
routing self-test и остальные live/background producers остаются открытыми.

Final full npm.cmd test -- --maxWorkers=1:4871 passed/5 skipped/0 failed,
291.14s,exit0. Build/typecheck,6 native regression fixtures,coverage/diff —exit0.
URL workers проверены на controlled OS boundaries; remote gates pending.

Qodo1556823: executeJavaScript hang после close воспроизведён на настоящем
Electron44.4.3. Native window-close revocation и отдельные in-memory sessions
снимают зависание, не смешивая выходы измерений. Новый штатный native fixture
проверил2 concurrent окна, реальные redirect/loading/pending script и cancel9ms;
runner7 PASS. DNS использует private bounded Resolver/cancel; независимые checks
не конфликтуют. Proxy setup refusal даёт typed network, а не неподтверждённый
положительный verdict. Safe diagnostic причины и validation hint сохранены.
Targeted175/175 passed;build/typecheck/coverage —exit0. Final full/new gates pending.

Review final full:4882 passed/5 skipped/0 failed,329.74s,exit0;
295 files passed/2 skipped. Production/test tree не менялся во время прогона.
Build/typecheck,7 native fixtures,coverage/diff —exit0. Новые remote gates pending.

## Routing self-test: requester lifetime (20.10.2026)

#86 принят: final head150670b,Qodo1556986 completed6/6 implemented,
CI39328685275 success,merge/main288a998; tree совпал с reviewed head.

AT-00-001/003/004/005/008: production routing self-test входит в общий registry
с manual owner,UUID/correlation и deadline60s. Main document lifetime и optional
requester token, legacy zero-token call, sender isolation/duplicate conflict.
HTTP/raw SOCKS negotiation удерживаются до settlement, socket —до actual close;
late socket после отмены не отправляет HTTP. Guarded fallback/RU echo/completed
log, независимые concurrent checks. Availability и protection action Maintenance
отменяют routing при unmount и не публикуют поздние UI/log/toast effects.
Companion leak failure отменяет pending routing; сам leak probe и остальные
maintenance/live/server entrypoints этим участком не приняты.

Targeted8 suites184/184 passed,3.68s;typecheck165 channels/0 public any,
coverage AC927/927,F210/210,diff check —exit0. Все промежуточные failures
сохранены в progress.md. Final full/build/native и новые remote gates pending.

Final full2:4915 passed/5 skipped/0 failed,297 files passed/2 skipped,
312.84s,exit0. Перед ним один full получил outer5000ms timeout в прежнем
adaptiveNetworkIdentity native fixture (8.3s); isolated25/25 passed,outer budget
согласован с30s process bound без изменения assertions. Targeted9 suites209/209,
5.49s;final typecheck,build/7 native fixtures,coverage/diff —exit0.
Новые remote gates pending; весь WP-0 остаётся в работе.

#87 initial Qodo1557229 completed нашёл1 informational: перенос handler потерял
per-call started/timed finished/failed IPC trail. Регрессия до fix1 failed/17 skipped;
trail восстановлен без request token/IP payload. Targeted9 suites210/210 passed,
5.40s;build/typecheck,7 native fixtures,coverage/diff —exit0. Новый full/remote
gates требуются на review-fix SHA; initial review не заменяет их.

Review full до CI fixture fixes:4916 passed/5 skipped,312.08s. Initial remote
CI39331654687 failed: два native outer5s timeouts и actual-file sync polling1s.
Isolated3 suites137 passed/1 skipped,58.21s. Native outer budgets20s/15s
согласованы с helpers; actual-file boundary ждёт readiness Promise,outer15s.
Safety/data assertions сохранены. Новый final full и remote gates pending.

Final после последних test-only изменений:4916 passed/5 skipped/0 failed,
297 files passed/2 skipped,309.54s,exit0. Targeted12 suites347 passed/1 skipped,
56.21s. Typecheck165 channels/0 public any,build/7 native fixtures,coverage/diff
—exit0. Qodo/CI требуются на новом SHA. Весь WP-0 остаётся в работе.

#87 принят: final head8a06034,Qodo1557391 completed1/1 implemented,
CI39333883253 success. Merge/main4ff734f; tree совпал с reviewed head.
Следующий участок —server:probe и modal requester lifetime,AT-00-001/003/004/005/008.

## Server probe/modal requester lifetime (20.10.2026)

AT-00-001/003/004/005/008: production server:probe с owner/UUID/correlation,
deadline9s,private bounded DNS,actual DNS/socket drain,guarded HTTP/fallback.
TCP использует проверенный IP; private/mapped answers и empty DNS получают
typed permission/network. Modal отменяет main/geo по cleanup/deadline10s;
late replies/fallback/group updates ограждены. TLS/banner остаются выключены.
Beforefix и все промежуточные failures записаны в progress.md. Final targeted
8 suites210/210 passed,4.45s;typecheck165 channels/0 public any,coverage/diff
—exit0. Final full/build/native и exact-head Qodo/CI pending.

Full2:4951 passed/5 skipped/0 failed,312.58s. После него собственная
регрессия выявила включение close-drain времени в RTT; до fix samples250ms
вместо0,1 failed/21 skipped. Замер фиксируется на connect,raw socket до close.
Targeted9 suites212/212 passed,4.52s. Final full3/build/new gates pending.

Final full3 после RTT fix:4952 passed/5 skipped/0 failed,298 files passed/
2 skipped,303.79s,exit0. Final build/typecheck165 channels/0 public any,
7 native fixtures,coverage/diff —exit0. Новый exact-head Qodo/CI pending;
весь WP-0 остаётся в работе.

#88 принят: final head2c52db0,Qodo1557666 completed без findings,
CI39337723907 success. Merge/mainca15040; tree совпал с reviewed head.
Следующий участок —physical queue/process foundations live-check; весь WP-0 в работе.

## Live-check: physical queue/process foundations (20.10.2026)

AT-00-003/007: cancelled/expired queue slot удерживает порядок за previous
handshake worker; execPs ждёт actual child close на cancel/timeout/error.
До fix6 failed/2 passed. После fix адресные5 suites76/76 passed,5.16s,
включая2 native PowerShell cancellation/timeout cases с actual close.
Coverage/diff —exit0; final full/build и exact-head Qodo/CI pending.
Общий lifetime/progress/history/raw DNS/TCP/TLS/HTTP live-check ещё в работе.

Final full:4962 passed/5 skipped/0 failed,299 files passed/2 skipped,308.02s,
exit0. Build/typecheck165 channels/0 public any,coverage/diff —exit0.
Новые native PowerShell cases прошли;7-fixture Electron runner не повторялся
при неизменных IPC/preload/bridge. Exact-head Qodo/CI pending.

#89 принят: final head8e32fdf,Qodo1557804 completed без findings,
CI39339629394 success. Merge/main5268e74; reviewed/main tree совпал.
Revix по квоте полного review не выполнил; это не approval.

## Live-check: DNS/TCP/TLS/traceroute physical drain (20.10.2026)

AT-00-003/007: DNS держит private bounded resolver до raw settlement и не
принимает late answers после cancel/timeout; TCP/TLS держат socket до actual
close,RTT/handshake duration не включают drain. Terminal TLS failure защищён
от late ready. Traceroute ждёт child close и сохраняет partial hops/first error,
не называет kill завершением команды; output ограничен64KiB.
До fix17 failed/1 passed. Final targeted6 suites101/101 passed,5.47s,exit0,
включая4 настоящих loopback cases (TCP connect/cancel,TLS cancel,UDP DNS).
Все промежуточные failures и ошибка форматирующего edit записаны в progress.md;
source восстановлен и typecheck165 channels/0 public any,coverage/diff прошли.
Full/build и exact-head Qodo/CI pending. HTTP/media/SOCKS,общий live operation
lifetime/progress/history и renderer ещё не приняты; весь WP-0 в работе.

Final full:4987 passed/5 skipped/0 failed,300 files passed/2 skipped,312.04s,exit0.
Production/test tree не менялся во время прогона. Build/typecheck165 channels/
0 public any,coverage AC927/927,F210/210,diff check —exit0. Native evidence —4
loopback resource cases;7-fixture Electron runner не повторялся при неизменных
IPC/preload/bridge. Новые exact-head Qodo/CI pending; весь WP-0 в работе.

#90 принят: final head991f079,Qodo1557968 completed без findings,
CI39341834240 success. Merge/maincf8adf1; reviewed/main tree совпал.
Revix полного review по квоте не выполнил;отсутствие review не approval.

## Live-check: HTTP attempt/resource drain (20.10.2026)

AT-00-003: каждый request/response/socket удерживается до actual close;
agent:false,redirect/HEAD->GET после полного drain,cancel/deadline fencing,
8KiB cap и измерение до final drain. Premature close конечен;late reset имеет
listener до close и не заменяет terminal result. До fix10 failed/1 passed;
отдельная late-reset regression тоже failed до fix. Final targeted7 suites
115/115 passed,5.90s,exit0,включая2 native loopback HTTP cases. Все
промежуточные результаты и fixture correction записаны в progress.md.
Typecheck165 channels/0 public any,coverage/diff exit0. Новый full/build и
exact-head Qodo/CI pending;media/SOCKS/throughput,isolated child cleanup и
общий live lifetime/history/UI ещё открыты. Весь WP-0 остаётся в работе.

Final HTTP full:5001 passed/5 skipped/0 failed,301 files passed/2 skipped,
325.81s,exit0. Production/test tree во время full не менялся. Build/typecheck
165 channels/0 public any,coverage AC927/927,F210/210,diff check —exit0.
Native evidence —2 loopback HTTP checks;7-fixture Electron runner при
неизменных IPC/preload/bridge не повторялся. Exact-head Qodo/CI pending.

## Handshake/media/throughput physical drain (20.10.2026)

#91 принят: final head2163427,Qodo1558121 completed без findings,
CI39343736114 success;merge/main88bca27,reviewed/main tree совпал.
AT-00-003/007: SOCKS late dial/raw/TLS физически retained;media cancel активен,
late HEAD/GET не отправляются;throughput sample ждёт close до следующего,
метрика duration не включает drain,header cap64KiB. Изолированный child/
readiness poll удерживают queue до physical cleanup;workDir удаляется после
child close. Ранняя ошибка child во время PID persistence не теряется.
Targeted8 suites139/139 passed,5.97s,включая2 native cases:loopback TLS cancel
и actual child close. Промежуточные failures/fixture corrections в progress.md.
Нужны final full/build и exact-head Qodo/CI. Общий live lifetime/history/UI
ещё открыт;весь WP-0 в работе.

Final production full5025 passed/5 skipped/0 failed,302 files passed/2 skipped,
329.86s,exit0. Production source не менялся с начала final full;2 усиленных
terminal-event assertions отдельно проверены в24/24 suite,1.24s. Final build/
typecheck165 channels/0 public any exit0. Предыдущий superseded full имел
1 native identity timeout;отдельно25/25 passed,причина не установлена.
Exact-head Qodo/CI требуются до следующего участка.

#92 initial Qodo1558277 нашёл2 reliability gaps. SOCKS transport теперь owned
до TCP connect и уничтожается abort/deadline;native negotiation fixtures
проверяют abort,timeout и успешный SOCKS. Public media/handshake используют
registry:caller terminal prompt,shutdown/worker физически retained. Confirmed
child exit закрывает собственные pipes;таймер не подменяет смерть процесса.
Revix swallowed rm assertion исправлен внешней проверкой;integration suites
перенесены в itest и явно добавлены в CI. Unit172/172 и integration31/31
passed;build/typecheck/coverage/diff exit0. Новый full и exact-head gates pending.

Final #92 follow-up:full unit5004 passed/5 skipped/0 failed,302 files passed/
2 skipped,318.23s;integration отдельно31/31 passed. Последний полный прогон
без изменений production/test tree. Build/typecheck165 channels/0 public any,
coverage/diff прошли. Исправлен старый residual fixture (неучтённая новая TCP
граница);все промежуточные результаты сохранены. Follow-up exact-head
Qodo/Revix/CI pending.

#92 второй follow-up:Qodo1558452 автоматически принял SOCKS fix,child finding
ещё pending;attribution не менялся. Добавлены captured-handle escalation
SIGTERM->SIGKILL через1.5s и5s cleanup deadline. Registry выдаёт timeout и
blocked event,продолжая удерживать physical resource/worker/workDir до close.
Ни timer,ни ответ kill не подменяют подтверждённый exit/close. Regression
registry87/87 и integration32/32 passed;новые full/build/exact-head gates pending.

Stop escalation теперь начинается при первом abort/cleanup request,в том числе
при pending readiness/PID persistence. Actual child close снимает budgets сразу;
worker остаётся retained до readiness settlement. Новая regression failed до fix,
final integration33/33 и targeted109/109 прошли;build/typecheck165/0any,coverage
927/927 и210/210,diff exit0. CI0a42 упал на прежнем5s native JSON export fixture:
его бюджет согласован с соседними PowerShell ACL cases (15s),assertions сохранены.
Новый full и exact-head Qodo/Revix/CI остаются обязательными.

Final второго follow-up: full5005 passed/5 skipped/0 failed,304.20s,
302 files passed/2 skipped. Targeted109/109,integration33/33,build/typecheck,
traceability/diff exit0. После начала final full код и тесты не менялись.
Exact-head Qodo/Revix/CI pending;весь WP-0 ещё не завершён.

#92 third follow-up:Qodo1558570 на5269ba3 оставил child finding pending.
Теперь5s cleanup budget завершает execution queue и отзывает admission:
queued/new probes получают conflict,новые children не стартуют до physical
settlement. Полный work retained операцией;shutdown/resources/workDir не
освобождаются по таймеру. После drain admission восстанавливается.
Revix trailing-output вопрос подтверждён:после proven exit до1.5s читается
stderr/stdout,затем inherited pipes закрываются с incomplete warning;actual
close отменяет timer. Data listeners устанавливаются до PID-persistence await.
До fix regressions failed;final integration35/35,targeted127/127 passed.
Новые full/build и remote gates pending;attribution не менялся.

Final third follow-up:unit5005 passed/5 skipped/0 failed,325.89s,
302 files passed/2 skipped;integration35/35,targeted127/127,build/typecheck,
coverage/diff exit0. Source/test tree не менялся во время full.
Новый exact-head Qodo/Revix/CI обязателен;WP-0 остаётся в работе.

Qodo1558657 наba353ed автоматически принял оба reliability fixes,но нашёл
новый observability gap:queue expiry записывалсяsuccess. Regression failed до fix;
теперь typed timeout проходит через registry,публичная диагностика формируется
после него. Queued cancel и expiry сверены с operation records. Integration37/37,
targeted127/127 passed;новые full/build/exact-head gates pending.

Final queue-taxonomy full5005 passed/5 skipped/0 failed,312.16s,
302 files passed/2 skipped. Integration37/37,targeted127/127,build/typecheck,
coverage/diff exit0. Exact-head Qodo/Revix/CI pending;весь WP-0 ещё в работе.

Qodo1558731 на3eb8ab2 completed,все3 findings implemented,новых нет.
Revix дал2 подтверждённых issue:fragile message classification и skipped media
при timeout. Queue теперь сама выбрасывает IpcFault;public media fallback
различает cancelled/skipped и timeout/error. До fix regressions failed,
final targeted127/127 и integration37/37 passed. Новые full/build/gates pending.

Final Revix follow-up:full5005 passed/5 skipped/0 failed,307.72s,
302 files passed/2 skipped;targeted127/127,integration37/37,build/typecheck,
coverage/diff exit0. Source/test tree не менялся во время full.
Exact-head Qodo/Revix/CI pending;весь WP-0 ещё не завершён.

#92 принят:final0ae31ed,Qodo1558804 completed —все3 findings implemented,
новых/pending нет;Revix118402877903 Low risk/neutral без нерешённых подтверждённых
issue. Stale nit и вопросы разобраны в progress.md. CI39353480596 success
на том же SHA. Merge/main4410b62,reviewed/main tree422af1b004d73ef3a043e093556d65c7f48adecb
совпал. Local final5005/5/0,37/37 integration,127/127 targeted,build/typecheck/
coverage/diff прошли. Это приёмка slice,а не всех AT WP-0.
Следующий slice —общий live operation owner,поздние progress/history/document/UI.

## Общая live-проверка: root operation (20.10.2026)

AT-00-003/005/007,F-021/F-143:root runLiveServerCheck теперь получает registry
UUID/correlation/owner и deadline25s/60s;lease.wait ограждает все фазы,
а handshake physical worker retained самой root lease. Ответ на cancel/
deadline prompt,shutdown ждёт actual DNS/socket/child/readiness drain.
Поздние progress и следующие фазы подавлены;history записывается через
synchronous active-only commit,receipt operationKey связан с internal operationId.
Delayed split import и оба ASN provider не читают/не меняют state после abort.
11/11 новых регрессий failed на baseline4410b62;после fix targeted59/59,
explicit integration37/37,build/typecheck165/0any,coverage927/927 и210/210,
diff check passed. Full и exact-head PR gates pending.
Это не закрывает requester/document/batch/UI и provenance/corruption history;
весь WP-0 остаётся в работе.

Final root slice full:5016 passed/5 skipped/0 failed,303 files passed/2 skipped,
432.03s,exit0. Первые3 failures были прежними cancellation fixtures;
они теперь проверяют typed cancelled и два настоящих завершённых loopback
check для UUID/diff. Targeted70/70,integration37/37,build/typecheck165/0any,
coverage/diff passed. Exact-head Qodo/Revix/CI ещё pending;WP-0 в работе.

Qodo #93 follow-up:receipt id=op_32hex,operationKey/correlationId сохраняют
связь после production credential redaction;raw cancellation UUID остаётся
в registry. Optional поля сохраняют совместимость legacy history.
Single/batch admission slots и destroyed listener удерживаются через readonly
lease.drained,включая prompt cancel/deadline;повтор/лимит —typed conflict.
Четыре sender-limit regressions (single/batch×cancel/deadline) плюс настоящий
redactor двух loopback receipts воспроизвели замечания;targeted145/145,
integration37/37,coverage/diff passed. Новые full/build и exact-head gates pending.

Qodo follow-up local final:full5020 passed/5 skipped/0 failed,440.20s,
303 files passed/2 skipped;build/typecheck165/0any,targeted145/145,
integration37/37,coverage/diff passed. Старый CI39356680659 success;
приёмка исправлений требует нового exact-head Qodo/Revix/CI.

#93 принят:final28540de,Qodo1559138 completed,оба findings implemented,
новых/pending нет;Revix118417529584 Low risk/neutral,вопрос о renderer catch
разобран по коду и существующему UI+IPC набору37/37. CI39358091824 success
на том же SHA. Merge/main d96af0a,reviewed/main tree8f2d463a95861fe7da73e11e0fd20da7f44fdca4
совпал. Это приёмка slice;WP-0 в работе. Далее —document reload/crash и batch UI.

### WP-0 — lifetime документа и batch UI (20.10.2026)

- Single/batch IPC используют requestDocumentLifetime: destroyed, main-frame
  did-navigate и render-process-gone отменяют только запрос владельца. Admission
  и listeners удерживаются до физического drain. Batch cancellation не становится
  ошибкой профиля; поздний result/progress не добавляется после abort.
- Batch UI создаёт UUID до IPC, показывает подготовку и отмену до первого progress,
  проверяет requestId/sequence/generation, инвалидирует старые ответы/errors/finally
  на cancel/hide/unmount. Reopen изолирован от прежней подписки. Single UI также
  использует UUID; canonical IPC_CANCELLED обрабатывается тихо, timeout виден.
- Baseline main: 5 failed/16 passed (.tmp/wp0-live-document-red.log); batch UI:
  7 failed/1 passed (.tmp/wp0-live-batch-ui-red.log). Single UUID:2 failed/8 passed
  (.tmp/wp0-live-single-ui-red.log). Первый объединённый прогон:62 passed/1 failed
  из-за двукратного отображения timeout в существующем UI; исправлен matcher теста.
- npm.cmd test -- src/renderer/components/LiveServerBatchComparison.test.tsx
  src/renderer/components/LiveServerUiRegression.test.tsx
  src/renderer/components/LiveServerCheckSection.test.tsx
  src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts
  src/main/requestDocumentLifetime.test.ts —64/64,6 suites,8.60s,exit0
  (.tmp/wp0-live-document-ui-targeted.log). Traceability:AT-00-003/004.
- npm.cmd run build —exit0,typecheck165 channels/0 public any
  (.tmp/wp0-live-document-build.log). npm.cmd test -- --mode integration
  src/main/liveServerProbe.handshakeDrain.itest.ts
  src/main/keyHealthChecker.transportDrain.itest.ts —37/37,2.08s,exit0
  (.tmp/wp0-live-document-integration.log).
- Playwright CLI/Chromium headed,реальный компонент и production CSS,изолированный
  mock IPC стенд .tmp/wp0-live-ui:pending до progress,cancel,progress,result,timeout.
  Light/dark screenshots в output/playwright/wp0-live-*.png просмотрены;отмена
  возвращает старт без alert,timeout виден. Таблица результата сохраняет прежний
  горизонтальный scroll. Это renderer fixture,не live network/Electron/L3.
  Единственный console error —favicon404 стенда. Связанные scripts design-doctrine
  отсутствуют в установленном skill;использованы реальные project gates/visual QA,
  численная WCAG/contrast оценка не заявлена. Стенд и browser остановлены.
- python -X utf8 ../docs/04-приёмочные-тесты/traceability/check-coverage.py —
  AC927/927,F210/210,exit0 (проверка трассировки,не выполнения всех AT).
  Полный npm.cmd test ещё выполняется;commit/push/exact-head review pending.
  Нормативные docs/ не изменялись;WP-0 в работе,WP-2 не начат.

- Final local: npm.cmd test —5037 passed/5 skipped/0 failed,304 files passed/2 skipped,
  444.15s,exit0 (.tmp/wp0-live-document-full.log). Build/typecheck165/0any,
  targeted64/64,integration37/37,coverage927/927,210/210,diff0.
  Во время full изменены только AT labels в двух tests,без изменения поведения.
  Commit/PR и exact-head Qodo/Revix/CI —следующий gate.

- PR #94 initial813c4a6:Qodo1559260 completed,2 informational findings.
  Attribution не менялся. Snapshot .tmp/qodo94-initial.json.
  (1) Quick cancel/restart может дать typed conflict до physical drain:это
  преднамеренный bounded admission,покрытый sender-limit tests single/batch×
  cancel/deadline. Он не означает успешный новый запуск;ресурсы остаются owned,
  после drain retry допускается. Это информационное UX-ограничение,а не основание
  убирать safety limit. (2) Cancel между child commit и batch continuation терял
  уже сохранённый receipt из batch result —воспроизведено и исправлено:возвращённый
  committed child остаётся в receipt,последующий progress и новый child подавлены.
- Revix118424075836 Needs changes:новый preparing text без i18n (issue) и sync act
  в новых tests (suggestion). Добавлен liveCheck.preparing в ru/en,используется t();
  listener updates ожидают async act. Два locale tests используют настоящий i18n.
  Объединённый red:2 failed/31 passed (.tmp/wp0-live-document-review-red.log),
  английская локаль и committed receipt. После fix targeted6 suites67/67,9.38s,
  exit0 (.tmp/wp0-live-document-review-targeted.log).
- Review follow-up:npm.cmd run build —exit0,typecheck165/0any
  (.tmp/wp0-live-document-review-build.log);explicit integration37/37,2.27s,exit0
  (.tmp/wp0-live-document-review-integration.log);coverage927/927,210/210,diff0.
  Playwright updated preparing ru/light,en/dark проверены на actual i18n+CSS,
  output/playwright/wp0-live-preparing-*.png;stand/browser остановлены.
  Новый full выполняется;исправления ещё не приняты новым exact-head review/CI.

- Initial CI39360106142 на813c4a6 failure:bootRecoveryExecution.test.ts266
  (corrupt trusted firewall) превысил outer Vitest5000ms. Native helper уже имеет
  timeout15000ms;describe budget согласован до20000ms,assertions не менялись.
  Лог .tmp/wp0-live-document-initial-ci-failed.log. Следующий SHA требует нового CI.
- Review full после длительной паузы выполнения завершился exit1:5038 passed/
  5 skipped/2 failed,6451.15s. lifecycleCleanup resolver case и configIpcErrors
  private-export PowerShell boundary каждый получили около6046s. Это observed
  elapsed gap,причина паузы на уровне ОС не установлена;PASS не заявлен.
  Лог .tmp/wp0-live-document-review-full.log. Их test budgets не изменялись.
  Повтор targeted и новый полный прогон запущены после паузы.

- После паузы npm.cmd test -- src/main/bootRecoveryExecution.test.ts
  src/main/lifecycleCleanup.test.ts src/main/configIpcErrors.test.ts —252/252,
  3 suites,54.05s,exit0 (.tmp/wp0-live-document-ci-regressions.log).
  npm.cmd run build повторно exit0,typecheck165/0any,
  .tmp/wp0-live-document-final-build.log. Source/test tree frozen для full.

- Final full (maxWorkers2) без длительной паузы:exit1,5038 passed/5 skipped/
  2 failed,304.42s (.tmp/wp0-live-document-final-full.log). Оба —native CIM
  failure fixtures adaptiveNetworkIdentity.test.ts92:10465/10436ms против outer5s;
  runNative уже имел30s process timeout. Только этой группе дан outer35s,
  assertion fixture failure и production budgets не менялись. Targeted25/25,
  3.23s,exit0 (.tmp/wp0-live-document-cim-regressions.log). Новый full идёт
  с --maxWorkers=1;это обычный прежний режим полного локального прогона.

- Продолжение после interruption:handle23165 отсутствует,Win32_Process не показывает
  живых vitest;final2 log обрывается без итогового отчёта. Прогон не засчитан.
  Новый full запущен с --maxWorkers=1 в .tmp/wp0-live-document-final3-full.log;
  exit отдельно фиксируется в .tmp/wp0-live-document-final3-exit.txt.

- Final3 full завершился exit1:5039 passed/5 skipped/1 failed,322.15s.
  Осталась другая группа того же30s helper:adaptiveNetworkIdentity neither
  identity fixture10563ms против outer5000ms. Ей также дан35s runner budget,
  как уже было у последнего native fixture в этом файле. Assertion unchanged.
  .tmp/wp0-live-document-final3-full.log;новый full final4 выполняется.

- Review final local: npm.cmd test -- --maxWorkers=1 —5040 passed/5 skipped/
  0 failed,304 files passed/2 skipped,334.55s,exit0
  (.tmp/wp0-live-document-final4-full.log,отдельный exit marker0).
  Build/typecheck165/0any,targeted67/67,integration37/37,
  timeout-suite repetition252/252,CIM25/25,coverage927/927,210/210,diff0.
  Source/test tree не менялся во время успешного full. Новый SHA ещё требует
  completed Qodo,разбора Revix и CI success.

## 20.10.2026 — PR #94 принят; целостность live history (WP-0)

PR #94 слит в main: 85edf73ca36a8a5a92c50374db28c581a36e502b. Проверенный head
 d7bdc4fd507fe593fd6626c798d0361c90f631c9 и merge имеют одинаковое дерево (git diff пуст).
CI 39372090694 completed/success (Windows, Rust, site); Qodo 1559916 completed
на этом SHA. Dropped committed receipt автоматически implemented. Осталось
informational/Low: быстрый cancel/restart может получить typed conflict до
physical drain; safety admission и retry после drain покрыты тестами. Attribution
не менялся. Revix 118462005020 completed/success, title Ready to merge на том же
SHA; старый badge в summary не является актуальным verdict. Это minor-ограничение,
допустимое по решению владельца; не объявляется исправленным.

Следующий участок: AT-00-006/010, F-074/F-143, live-server-checks.json.
Подтверждены подавленные read/write ошибки и in-memory успех до disk commit.
Новые 29 real-file cases до fix: 29 failed,395ms,exit1
(.tmp/wp0-live-history-red.log). Теперь staged memory, temp+fsync+rename,
exact prior-file backup, bounded diagnostics history.corrupted/unavailable/
write-failed/recovered, salvage валидных строк и восстановление из backup,
проверка всех diagnostic shapes, detached read view. Явный clear обновляет
backup пустым содержимым, чтобы удалённые строки не воскресли после corruption.
При I/O failure сохраняются предыдущие committed memory/file, наружу идёт
IpcFault с категорией; raw paths/stack не копируются в error или log.

Это существующий plain JSON target-map v0, отдельный от 20 electron-store stores.
Добавлен schemaVersion:0 на записи; legacy без marker читается без переписывания.
Неподдерживаемый/невалидный marker в main или backup отказывается до writes,
также при замене файла после init. Миграции новой версии здесь не заявляются.
Сквозной receipt/correlation сохранён; полная provenance всех producers и
межпроцессная координация ещё остаются задачами WP-0. Нормативные docs/ не менялись.

npm.cmd test -- src/main/liveServerHistory.integrity.test.ts
src/main/liveServerHistory.test.ts src/main/liveServerProbe.operation.test.ts
src/main/liveServerAuditRegression.test.ts —77/77,4 suites,5.17s,exit0
(.tmp/wp0-live-history-targeted4.log). Включены 100 legacy records/5 targets,
malformed nested diagnostics, future SHA-256 invariance, denied read,
copy/write/fsync/rename failures, final commit failure после успешного backup,
retry/restart/clear, реальный loopback receipt и failed operation history commit.
npm.cmd run typecheck —165 channels/0 public any,exit0.
Полный набор и build запускаются; commit/review/CI для этого участка ещё pending.

- Final local live-history integrity: npm.cmd test -- --maxWorkers=1 —5075 passed,
  5 skipped,0 failed;305 files passed/2 skipped,273.24s,exit0
  (.tmp/wp0-live-history-full.log; .tmp/wp0-live-history-full-exit.txt=0).
  npm.cmd run build —exit0,включая typecheck165 channels/0 public any
  (.tmp/wp0-live-history-build.log). Targeted77/77; python -X utf8
  ../docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,
  exit0;git diff --check —exit0. Source/test tree не менялся во время full.
  Commit/PR и exact-head Qodo/Revix/CI —следующий gate.

- PR #95 initial885e4ec: Qodo1560044 completed, remediation recommended
  Missing main file hides saved checks. Две регрессии (missing main + valid
  backup; missing main + future backup) до fix:2 failed/34 passed,465ms,exit1
  (.tmp/wp0-live-history-review-red.log). Исправлено admission/recovery при
  отсутствии основного файла; следующий save/restart сохраняет backup rows,
  future backup отказывается без изменения файлов. Targeted4 suites79/79,
  4.98s,exit0 (.tmp/wp0-live-history-review-targeted.log). Attribution не менялся.
- Revix118466883332 completed/neutral,Low risk,title 2 issue(s) found:
  suggestion о сохранении исходных повреждённых bytes и question о init callers.
  Фактические production callers (rg по src,исключая tests): только
  liveServerProbe.ts3543 getPreviousSuccessfulCheck,3606 addCheck внутри owned
  async operation и3791 guarded history IPC. Отдельного startup init нет;
  read failures отклоняют этот запрос typed error,а не прерывают startup.
  Raw rejected rows не сохраняются в отдельный файл после следующей записи:
  AT-00-010 допускает честную маркировку corruption;history.corrupted сообщает
  потерю до следующей записи,валидные rows сохраняются,валидный backup не
  заменяется повреждённым файлом. Восстановление отвергнутых rows и сохранение
  их исходных bytes не заявляются. Это minor suggestion,не скрытое исправление.
  Полный повтор/build и новое exact-head review/CI ещё требуются.

- Initial CI39373659588 success на885e4ec (Windows7m34s,Rust,site),но это не
  проверка follow-up. Review local full:5076 passed/5 skipped/1 failed,
  263.93s,exit1 (.tmp/wp0-live-history-review-full.log). Прежний
  liveServerProbe.test.ts209 ожидал отказ на фиксированном 127.0.0.1:65432,
  но получил ok. После прогона listener отсутствует;владение портом в момент
  теста не установлено. Фикстура могла получить этот ephemeral port сама;
  причинный вердикт о конкретном процессе не делается.
  Заменён только тест: connect принудительно получает ECONNREFUSED,используются
  настоящий Socket error/close и пять попыток;assertions не ослаблены,добавлена
  проверка error code. Production TCP probe не менялся.
  npm.cmd test -- src/main/liveServerProbe.test.ts
  src/main/liveServerHistory.integrity.test.ts src/main/liveServerHistory.test.ts
  src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts
  —102/102,5 suites,5.06s,exit0 (.tmp/wp0-live-history-final-targeted.log).
  Build/новый full запускаются;провал не засчитан как PASS.

- Review final local: npm.cmd test -- --maxWorkers=1 —5077 passed/5 skipped/
  0 failed;305 files passed/2 skipped,263.46s,exit0
  (.tmp/wp0-live-history-final-full.log,exit marker0).
  npm.cmd run build —exit0,typecheck165 channels/0 public any
  (.tmp/wp0-live-history-final-build.log);targeted5 suites102/102;
  coverage927/927,210/210,diff0. Source/test tree frozen во время full.
  Новый SHA ещё требует completed Qodo,разбора Revix и CI success.

## 20.10.2026 — PR #95 принят; live provenance/redaction (WP-0)

PR #95 слит:6539b12e6b73cfe248a26a8f9114d45551779318. Проверенный final head
3bdee0d538cac70b7aaa61ffbbde9f0205cabd50 и merge имеют одинаковое дерево.
CI39375050945 success (Windows/Rust/site);Qodo1560112 completed на этом SHA,
единственная прежняя finding автоматически implemented,новых нет. Attribution
не менялся. Revix118471219707 completed/neutral,Low risk,title1 issue(s) found;
это question:при partly valid main сначала используются salvaged main rows,
backup —если их нет. Это явная recovery policy,а не слияние более старой истории
поверх новых валидных записей. Corruption логируется;backup остаётся сохранённым.
Предыдущие suggestion/question и границы source-byte retention описаны выше.
Допустимые minor questions не называются исправленными или approval.

Следующий участок AT-00-005/006,F-074/F-143: новые live receipts получают
provenance из admitted lease (source/owner). Общий route unconfirmed/confidence
indeterminate: DNS,endpoint и isolated proxy могут идти разными путями,их
наблюдения остаются в собственных diagnostic fields. Старым записям provenance
не выдумывается;невалидные metadata отсеиваются с history.corrupted.

Три новые проверки до fix:3 failed/47 passed,5.01s,exit1
(.tmp/wp0-live-provenance-red.log): отсутствующие metadata и секреты в nested
text. sanitizeLiveCheckForStorage использует общий redactSensitiveText для
каждого string leaf,сохраняя типы/booleans,и удаляет credential evidence keys.
Main-generated receipt/profile/correlation identities сохраняются;diagnostic
credential UUID,пароли,Bearer,VPN URI,user paths маскируются. Legacy read view
тоже маскируется;точный старый migration backup не переименовывается в sanitized
copy. Это не заявление об очистке исходных секретов из исторического v0 backup.

Plain JSON schema v0→v1:реестр одного фактического шага live-history-provenance-v1,
marker с from/to/id/SHA-256 входных bytes,exact prior valid file backup перед
записью. Read не переписывает v0;marker и history.migrated появляются только
после успешной записи,повтор v1 сохраняет lineage без повторного шага. Новая
версия ограждает downgrade к strict v0 reader из #95;future version+1 отказана.
Migration red:1 failed/39 skipped (.tmp/wp0-live-provenance-migration-red.log).

Исправлена изоляция прежнего liveServerHistory.test:main-only cleanup оставлял
.bak в OS temp. Теперь каждый case создаёт собственный каталог внутри project
.tmp и удаляет его целиком;начальная история проверяется пустой. Чужие/прежние
артефакты не удалялись.
Адресно4 suites84/84,4.94s,exit0 (.tmp/wp0-live-provenance-targeted3.log),
typecheck165 channels/0 public any exit0. Усилен failure во втором rename
migration commit. Полный набор/build/remote gate ещё pending;WP-0 в работе,
WP-2 не начат. Нормативные docs/ не изменялись.

Первый full после общего redactor: npm.cmd test -- --maxWorkers=1 —5080 passed/5 skipped/2 failed,255.66s,exit1 (.tmp/wp0-live-provenance-full.log). Две прежние regression suites обнаружили UUID-like credentials вне RFC version/variant. Сохранена прежняя широкая UUID-маска [REDACTED_UUID] до общего redactor,на каждом string leaf;internal identities восстанавливаются отдельно. Старые assertions не ослаблялись.
Адресно npm.cmd test -- src/main/extendedReviewFixed.test.ts src/main/liveServerProbe.extended.test.ts src/main/liveServerHistory.integrity.test.ts src/main/liveServerHistory.test.ts src/main/liveServerProbe.operation.test.ts src/main/liveServerAuditRegression.test.ts —122/122,6 suites,5.80s,exit0 (.tmp/wp0-live-provenance-targeted-final.log).
Повторный npm.cmd run build включает typecheck:165 channels,0 public any,exit0 (.tmp/wp0-live-provenance-final-build.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0;git diff --check —exit0. Новый full выполняется;remote gate pending.

Final local: npm.cmd test -- --maxWorkers=1 —5082 passed/5 skipped/0 failed,305 files passed/2 skipped,258.89s,exit0 (.tmp/wp0-live-provenance-final-full.log,exit marker0). Source/test tree frozen во время полного прогона. build/typecheck165 channels/0 public any,coverage AC927/927 F210/210,diff check —exit0. Remote CI/Qodo/Revix pending;WP-0 в работе,WP-2 не начат.

Qodo1560244 completed на a68a750 нашёл4 findings (3 medium,1 low). Все4 воспроизведены до fix:4 failed/41 skipped,403ms,exit1 (.tmp/wp0-live-provenance-qodo-red.log). Сохраняется отдельная exact .v0.bak с проверкой checksum при retry,не перезаписываемая обычными saves;явный clear удаляет её вместе с историей и очищает rolling backup. Это намеренное удаление владельцем,не бессрочное сохранение очищенной истории. При восстановлении из backup migration origin следует фактическому источнику строк;malformed main marker восстанавливается только из валидной lineage (v0/valid marker),иначе запись отказана без изменения bytes. Новые valid main rows не заменяются старыми backup rows. Safe redirect destination пересобирается из protocol/host/path без URL auth/query/fragment;decoded path снова проходит credential/UUID masking.
Адресно6 suites128/128,4.98s,exit0 (.tmp/wp0-live-provenance-qodo-targeted2.log),включая конфликт migration backup и восстановление marker без потери новых строк. Final-main rename failure передвинут на третий rename после отдельных migration/recovery backups. Attribution Qodo не менялся. Revix118477991519 success/Ready to merge на initial SHA;CI39377221905 и новое remote review после fix учитываются отдельно. Новый full/build запущены;WP-0 в работе.

Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5088 passed/5 skipped/0 failed,305 files passed/2 skipped,280.90s,exit0 (.tmp/wp0-live-provenance-qodo-full.log,exit marker0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-live-provenance-qodo-build.log);targeted128/128;coverage AC927/927 F210/210,diff check exit0. Code/test tree frozen во время full. Нужны новые автоматические Qodo/Revix и CI на fix SHA.

## 20.10.2026 — PR #96 принят; background correlation (WP-0)

PR #96 слит:31730b90f49e275e4ba2f07bb95c92c3b62daf0c. Final head831efc1e7f8128bc9bba606915b31ac1adc03695 и merge имеют одинаковое дерево35a41eaea2a98f1ba8c994f6d00fc3efcea0ed44. CI39378399442 success (Windows/Rust/site,включая unit/live drain/native Electron/WFP ABI fixtures). Qodo1560323 completed на final SHA:все4 initial findings автоматически implemented,новых нет;attribution не менялся. Revix118481636610 completed/success,Ready to merge. Local final5088 passed/5 skipped,build/typecheck/coverage/diff exit0.
Следующий участок AT-00-005,F-143:pre-admission schedule events и startup crash recovery получают один scope на всё async действие с source lifecycle и соответствующим owner. Конечные результаты ещё проверяются;WP-0 в работе,WP-2 не начат.

Production callbacks index.ts: schedule connect/disconnect целиком в withCorrelation(op_UUID,{source:lifecycle,owner:schedule}),включая initial trigger log,preflight,admitted lane,terminal log и notification. Disconnect возвращает Promise вместо fire-and-forget;notification awaited без продления native lane. Startup recovery получает отдельный lifecycle/recovery scope до runtime/baseline checks;сетевые эффекты и recovery policy не менялись.
Runtime tests компилируют actual index.ts callbacks/declarations с controlled effects,используя настоящий withCorrelation,ConnectionLifecycle/runScheduledConnection. До fix5/5 failed (553ms,exit1,.tmp/wp0-background-correlation-red.log). Дополнительная delayed notification regression1 failed/5 skipped (482ms,.tmp/wp0-background-notification-red.log). Первый targeted после fix имел1 failure/34 passed:ошибка test fixture lane.stop options переданы строкой;исправлена фикстура на {owner:schedule},production stopProtection уже передаёт этот owner.
Final targeted npm.cmd test -- src/main/backgroundActionCorrelation.test.ts src/main/actionCorrelation.test.ts src/main/scheduledConnection.test.ts src/main/mainIpcRegression.test.ts src/main/connectionLifecycle.test.ts —45/45,5 suites,965ms,exit0 (.tmp/wp0-background-correlation-targeted3.log). Проверены overlapping IDs,error recovery/schedule,async stop и delayed notification. Full/build запущены;coverage927/927,210/210 и diff exit0. Native network recovery этими controlled effects не объявлена PASS;WP-0 в работе.

Build initial exit2:новая schedule fixture не содержала обязательный profileId (TS2741),исправлена на пустой legacy-compatible profileId. Начатый full прерван (exit1),не засчитан как проверка;последующий build2 exit0. При сверке recovery обнаружен аналогичный preflight gap в adoptRetainedSoftProtection:2 failing runtime cases (492ms,.tmp/wp0-background-soft-red.log),обёрнут в отдельный lifecycle/recovery scope до trust inspection и reconciliation,включая failure log. Policy reconciliation не менялась. Final targeted5 suites47/47,966ms,exit0 (.tmp/wp0-background-correlation-final-targeted.log). Новый final full/build запущены после замораживания кода/тестов;coverage/diff exit0.

При сверке поздних effects обнаружено:warning dialog failure после завершения startup recovery теряет active async scope. Regression1 failed/8 skipped (556ms,.tmp/wp0-background-dialog-red.log). Зафиксирован recovery correlationId и explicit scope только для позднего error-log;dialog остаётся nonblocking,исходное действие не удерживается до ответа пользователя. Оба dialog catch используют общий reporter. Для исправления предыдущий ещё незавершённый full остановлен (exit1,не PASS). Final targeted48/48,5 suites,1.01s,exit0 (.tmp/wp0-background-correlation-final-targeted2.log). Новый final-full2/build2 запущены;до их результата дальнейших code/test edits не планируется.

Full2 завершён с20 failed/5077 passed/5 skipped,278.36s,exit1 (.tmp/wp0-background-correlation-final-full2.log). Причины:старые source-extraction fixtures lifecycleCleanup/connectionHistoryStorage не подключали новые private Effects declarations и реальные correlation bindings. Обновлены только harness dependencies/declaration sets;старые safety/history assertions сохранены. Адресно npm.cmd test -- src/main/backgroundActionCorrelation.test.ts src/main/actionCorrelation.test.ts src/main/scheduledConnection.test.ts src/main/mainIpcRegression.test.ts src/main/connectionLifecycle.test.ts src/main/connectionHistoryStorage.test.ts src/main/lifecycleCleanup.test.ts —334/334,7 suites,18.09s,exit0 (.tmp/wp0-background-correlation-regressions.log). Запущены final-full3/build3;новый код заморожен.

Final local: npm.cmd test -- --maxWorkers=1 —5097 passed/5 skipped/0 failed,306 files passed/2 skipped,272.27s,exit0 (.tmp/wp0-background-correlation-final-full3.log,exit marker0). Source/test tree frozen на время full. npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-background-correlation-final-build3.log);targeted334/334,7 suites;python docs/04-приёмочные-тесты/traceability/check-coverage.py AC927/927 F210/210 и git diff --check exit0. Новый PR требует exact-head Qodo/Revix/CI. WP-0 в работе,WP-2 не начат;normative docs/ не менялись.

## 20.10.2026 — PR #97 принят; leak self-test lifetime (WP-0)

PR #97 слит:e3e4d4b74ac678a12b8a615fafd928fa0153c739. Final reviewed head b72aa0c192cfb322506e35fb4c1677bc2c986103 и merge имеют одинаковое дерево43a185dca2e467caa03bdca3a92862af4d0b0e8a. CI39381109296 success,все3 jobs. Qodo1560573 completed exact SHA,0 findings. Revix118490208184 completed/neutral,Low risk:один nitpick на currentCorrelationId()! в private effect,доступном только через withCorrelation wrapper;этот invariant покрыт runtime tests. Принят как minor по решению владельца,не назван approval/исправленным. Attribution не менялся.
Следующий AT-00-003/005/008 участок:раздельные subscriber leases общей leak self-test,physical curl/PS cancellation/drain и delayed forensic import fencing. WP-0 в работе,WP-2 не начат.

### Leak self-test: владение общей проверкой и физический drain

AT-00-003/005/008: каждый подписчик общей проверки получил собственную managed operation leak-check (deadline 60 s), отмену и отдельную копию результата. Отмена одного не останавливает остальных; последняя отмена или global stop завершают принадлежащий проверке curl/PowerShell. execFile без shell удерживает callback и close; новая проверка отклоняется conflict до физического drain. Неотменяемый native read и delayed forensic import удерживаются до завершения, после отмены не запускаются fallback/probes и не публикуется forensic event. Global stop сохраняет совместимый sanitized cancelled result, индивидуальные cancel/deadline типизированы. Periodic/event owners — adaptive-retry; shutdown registry удерживает все эффекты.

Добавлены 12 lifetime scenarios, включая настоящий принадлежащий тесту Node child без сетевых запросов; сохранены 10 прежних behavioral tests. Начальный red:3 failed,10.20s,exit1 (.tmp/wp0-leak-lifetime-red.log); expanded boundaries:1 failed/8 passed,1.47s,exit1 (.tmp/wp0-leak-boundaries.log). Старые mocks без ChildProcess.close дали7 failed/12 passed и8 unhandled errors,31.74s,exit1 (.tmp/wp0-leak-legacy-red.log); адаптирован harness, прежние assertions сохранены. Correlation regression изначально зелёная (1 passed/2 skipped,462ms), несмотря на имя wp0-leak-shared-correlation-red.log. Последний адресный npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/operationRegistry.test.ts —97/97,3 suites,2.36s,exit0 (.tmp/wp0-leak-targeted3.log). Предварительный typecheck165 channels/0 public any exit0;traceability AC927/927,F210/210 exit0 не означает выполнение приёмки.

Requester IPC cancellation и unmount UI намеренно остаются следующим отдельным участком; текущий main handler ещё вызывает API без requester token. Full/build и remote gate текущего участка pending. WP-0 в работе,WP-2 не начат; нормативные docs/ не менялись.

Final local: npm.cmd test -- --maxWorkers=1 —5113 passed/5 skipped/0 failed,307 files passed/2 skipped,281.92s,exit0 (.tmp/wp0-leak-final-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-final-build.log). Адресно npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/operationRegistry.test.ts —97/97,3 suites,2.45s,exit0 (.tmp/wp0-leak-final-targeted.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0;git diff --check —exit0. Source/test tree frozen во время полного прогона;remote CI и автоматические Qodo/Revix pending. WP-0 в работе,WP-2 не начат.

Qodo1560809 completed на2695b33:2 findings —action_required Reliability (forensic promise не awaited) и informational Observability (verdict log до delayed import). Оба воспроизведены:2 failed/11 skipped,752ms,exit1 (.tmp/wp0-leak-qodo-red.log). Реальная recordTrafficForensicsAppEvent также начинала append после cancellation во время manifest read:1 failed/8 skipped,291ms,exit1 (.tmp/wp0-leak-forensic-red.log). Теперь await удерживает всю forensic promise и её rejection;optional assertActive проверяется до/после manifest read и после уже начатого append,поздний append/late warning запрещены. Уже начатая запись не объявлена физически отменяемой:её завершение удерживается. Verdict log перенесён за awaited forensic boundary и final session/signal fence.
Первый targeted fix:1 failed/153 passed,6.89s —новый held forensic mock сохранял implementation между тестами;beforeEach явно сбрасывает его к resolved true. Final targeted npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/trafficForensicsSessionSecurity.test.ts src/main/trafficForensics.test.ts src/main/operationRegistry.test.ts —156/156,5 suites,3.57s,exit0 (.tmp/wp0-leak-qodo-targeted2.log). Добавлены реальные writer tests:cancel на manifest read и удержание successful/failed append без позднего warning. Attribution Qodo не менялся. Revix5581750763 на initial SHA сообщил free-quota-reached до21.10 00:00UTC;полного ревью нет,это не approval. Новый full/build/automatic review pending.

Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5117 passed/5 skipped/0 failed,307 files passed/2 skipped,281.60s,exit0 (.tmp/wp0-leak-qodo-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-qodo-build.log). Targeted156/156,coverage AC927/927 F210/210 и git diff --check exit0. Код/тесты не менялись во время full. Нужны exact-head CI и автоматический completed Qodo после push.

## 20.10.2026 — PR #98 принят; requester lifetime leak self-test (WP-0)

PR #98 слит:f903715da4a0f7565242a600f93ba42fe5d1c7a3. Reviewed head38c58745abce387e945312ef3505e46b39dd1781;CI39385160293 success,все3 jobs (Windows unit/live drain/contextBridge/native Electron/WFP ABI fixtures,Rust,site). Qodo1560893 completed exact SHA:оба initial findings автоматически implemented,новых нет;attribution не менялся. Revix по квоте полного ревью не выполнил (initial review5581750763 free-quota-reached до21.10 00:00UTC);это не approval. Local final5117 passed/5 skipped,281.60s;targeted156/156;build/typecheck/coverage/diff exit0.
Следующий AT-00-001/003/005/008 участок:optional requester UUID в IPC/preload,document cancellation,отдельные токены leak/routing в Maintenance,DiagnosticsCard unmount fencing. Диагностический snapshot при обнаружении утечки должен удерживаться тем же subscriber lease до физического завершения. WP-0 в работе,WP-2 не начат.

Requester integration:run-leak-self-test принимает optional UUIDv4 через shared contract/electron API/preload;legacy zero-token сохранён,main handler использует настоящий runRequesterOperation. Subscriber lease дополнительно удерживает afterResult diagnostic snapshot с тем же signal/deadline;global stop охватывает подписчиков после завершения shared probes. Физический snapshot collector остаётся неотменяемым на уже начатой native boundary,но его promise удерживается,дальнейшая публикация fenced существующим captureSnapshot API.
DiagnosticsCard создаёт UUID,при unmount отзывает запрос;late success/error не мутируют store/log/local busy state,typed cancellation quiet. Maintenance использует разные UUID leak/routing;unmount отменяет оба,ошибка одного отменяет оставшийся pending companion. Завершённые tokens очищаются;старое mounted action не очищает новое.
Red UI:7 failed/6 passed,1.43s,exit1 (.tmp/wp0-leak-request-ui-red.log);red actual-source main handler:4 failed/13 skipped,1.01s,exit1 (.tmp/wp0-leak-request-main-red.log). Первый targeted55/55,4.20s. Расширенный targeted1 failed/147 passed,5.93s —старый MaintenanceSource ожидал literal runLeakSelfTest() без token;обновлён точный assertion нового вызова. Final targeted npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/requesterOperation.test.ts src/main/operationRegistry.test.ts src/main/systemSnapshotLifetime.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/components/DiagnosticsCard.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts —152/152,10 suites,6.38s,exit0 (.tmp/wp0-leak-request-targeted3.log). Проверены malformed/duplicate/foreign/same-token-different-sender,document loss,peer survival,snapshot drain/timeout/global stop и best-effort failure.
Initial build exit1:IPC result mismatch any —в index.ts пропущен import runRequesterOperation;добавлен импорт,повторный build выполняется (.tmp/wp0-leak-request-build2.log). Coverage AC927/927,F210/210 exit0 не считается выполненной приёмкой. UI layout/copy/styles не менялись;functional jsdom states проверены,visual/browser и отсутствующие scripts design-doctrine не объявлены PASS. Full/remote gates pending;WP-0 в работе,WP-2 не начат.

Повторный npm.cmd run build —exit0 (.tmp/wp0-leak-request-build2.log),typecheck165 channels/0 public any. Код/тесты заморожены перед полным набором. При сверке AT-00-008 обнаружен ещё существующий gap:Maintenance считает inconclusive только routing verdict/cancelled summary,а LeakResultPanel красит любой non-leak ответ зелёным,даже при physicalAdapterInspectionComplete=false или неизвестном IP. Это не изменено текущим lifetime patch;предлагается отдельная fail-closed UI проверка по принятому общему scope WP-0. Полная приёмка WP-0 поэтому не объявлена.

Final local: npm.cmd test -- --maxWorkers=1 —5132 passed/5 skipped/0 failed,308 files passed/2 skipped,275.82s,exit0 (.tmp/wp0-leak-request-full.log,EXIT_CODE=0). Final code/test tree frozen во время full. npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-request-build2.log). Targeted152/152,10 suites;python docs/04-приёмочные-тесты/traceability/check-coverage.py AC927/927 F210/210 и git diff --check exit0. Automatic Qodo и exact-head CI следующего PR ещё pending;WP-0 в работе,WP-2 не начат.

Qodo1561100 completed на4ada55f нашёл remediation_recommended Correctness:ожидание snapshot под тем же leak-check deadline могло заменить известную утечку timeout/cancelled. Исправление принято в scope PR99. Начальный regression run имел transform error из-за CRLF-sensitive temporary edit (no tests,136ms,exit1,.tmp/wp0-leak-request-qodo-transform-red.log);исходные lifetime tests/cleanup восстановлены из HEAD,не удалены. Настоящий red:3 failed/18 skipped,4.23s,exit1 (.tmp/wp0-leak-request-qodo-red.log).
Итоговая архитектура обновлена:afterResult и продление subscriber lease убраны. Main немедленно возвращает готовый verdict;diagnostic snapshot запускается отдельной managed operation snapshot с60s deadline,owner manual,исходной correlation и exclusive resource. Одновременные leak verdicts используют один активный snapshot. Snapshot не отменяется поздней потерей requester/global leak stop после выданного verdict;его отменяет/удерживает общий shutdown registry. Уже начатый native collector не объявлен физически прерываемым. Его retained promise ждёт drain,а существующий signal fence не допускает позднюю запись. Snapshot failure/timeout не меняют leak verdict.
Адресно npm.cmd test -- src/main/leakSelfTest.lifetime.test.ts src/main/leakSelfTest.test.ts src/main/requesterOperation.test.ts src/main/operationRegistry.test.ts src/main/systemSnapshotLifetime.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/components/DiagnosticsCard.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts —158/158,10 suites,6.41s,exit0 (.tmp/wp0-leak-request-qodo-targeted2.log). Дополнительно проверены сохранение verdict при queued snapshot/deadline/global stop,shutdown drain,один capture при peers и correlation обеих операций. Attribution Qodo не менялся. Revix5582044411 на initial SHA:free-quota-reached,полного ревью нет. Новый full/build/remote gate pending.

Initial CI39387530878 на4ada55f failed:1 failed/5132 passed/4 skipped,356.48s. Единственная ошибка прежней native quarantine fixture recoveryManifestStorage.test.ts:spawnSync powershell.exe ETIMEDOUT на15s (variant same);дальнейшие native jobs этого run были skipped. Лог .tmp/wp0-leak-request-ci-failed.log сохранён. Отдельная локальная проверка с явным VPNTE_PWSH, npm.cmd test -- src/main/recoveryManifestStorage.test.ts -t 'native quarantine' —5 passed/55 filtered skipped,4.93s,exit0 (.tmp/wp0-leak-request-native-quarantine.log),все пять вариантов реально исполнены в собственном project .tmp folder. Production/recovery safety assertions и deadlines не менялись;один remote timeout не объявлен опровергнутым локальным PASS. Новый exact-head CI после Qodo fix обязателен.

Qodo fix final local: npm.cmd test -- --maxWorkers=1 —5138 passed/5 skipped/0 failed,308 files passed/2 skipped,268.94s,exit0 (.tmp/wp0-leak-request-qodo-full.log,EXIT_CODE=0). Source/test tree frozen. npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-request-qodo-build.log). Targeted158/158,10 suites;native quarantine5/5 с55 filtered skips;traceability AC927/927 F210/210 и git diff --check exit0. Нужны автоматический completed Qodo и успешный CI на новом fix SHA.


## 20.10.2026 — PR #99 принят; достоверность leak verdict (WP-0)

PR #99 слит: ef6390f4960eceed73f33acd256154482bd8578a; reviewed head f09cff8cef7adf6c119aecc1e3f9631cc753938e. Деревья head/merge совпадают: ab51df94144dca4d8ab224348c801ae69f35e44a. CI 39389031477 success, все 3 jobs; Qodo 1561232 completed exact SHA, initial Correctness finding автоматически implemented, новых нет; attribution не менялся. Revix 5582044411 на initial SHA: free-quota-reached до 21.10 00:00 UTC, полного ревью нет, это не approval. Final local: 5138 passed/5 skipped, 268.94s; targeted 158/158; npm.cmd run build (typecheck 165 channels/0 public any), traceability AC927/927 F210/210 и diff check exit0.

Следующий подтверждённый gap AT-00-008: Maintenance выдаёт success при incomplete/empty physical inspection или отсутствующем IP; DiagnosticsCard красит любой non-leak зелёным. Принятый общий scope WP-0 охватывает исправление; норматив docs/ не меняется. Новый regression red: 10 failed/15 passed и 1 failed suite из-за ещё отсутствующего shared helper, 1.65s, exit1 (.tmp/wp0-leak-verdict-red.log). Общий evidence verdict требует explicit complete=true, корректный default IPv4 и измеренные adapter probes; zero samples/unknown launch/DNS/TLS response не подтверждают защиту. Полученный physical egress IP сохраняет leak при позднем curl failure. Применяется также к periodic/event clean callbacks и VPN IP baseline adoption. Типы результата объединены, публичная форма сохранена.

Первый адресный run: 2 failed/63 passed (старые clean fixtures не имели ни одной physical пробы). Второй: 1 failed/83 passed (source literal assertion обновлён на вызов общего verdict). Final targeted перед UI осмотром: npm.cmd test -- src/shared/leak-self-test.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/main/leakSelfTest.test.ts src/main/leakSelfTest.lifetime.test.ts src/main/indeterminateIpAutoVerify.test.ts src/renderer/components/DiagnosticsCard.test.tsx src/renderer/MaintenanceSource.test.ts src/main/ipcChannelContract.test.ts — 115/115,9 suites,6.30s,exit0 (.tmp/wp0-leak-verdict-targeted4.log). build/typecheck165/0,coverage927/927 F210/210,diff exit0. Full идёт на frozen code/test tree.

Playwright UI fixture с настоящими DiagnosticsCard/Maintenance: пять состояний × две темы проверены; 280/320/414px без document overflow (scrollWidth272/312/406). Светлая/тёмная warning screenshots просмотрены: output/playwright/wp0-leak-verdict-{light,dark}-unknown.png. Визуально обнаружен ещё legacy summary OK при новом warning/leak: планируется вычислять пользовательский текст по evidence, а не доверять старой summary. Эти результаты не означают реальную сетевую L3-приёмку. design-doctrine accuracy_report/verify_states scripts и referenced rule files отсутствуют; формальный design gate PASS не заявлен. WP-0 в работе, WP-2 не начат.


Initial full на неизменном первом code/test tree: npm.cmd test -- --maxWorkers=1 —5166 passed/5 skipped/0 failed,309 files passed/2 skipped,281.42s,exit0 (.tmp/wp0-leak-verdict-full.log). После его завершения пользовательский текст вынесен в общий leakSelfTestMessage: UI/log/toast не доверяют legacy summary; причины incomplete/missing-IP/empty/unknown показываются явно. Backend details/forensic summary сохранены. Добавлен message regression, invalid-IP auto-baseline test изолирован от неизвестного curl; прежние redaction tests теперь явно подтверждают проход каждой из четырёх веток с корректным verified IP.
Final targeted —116/116,9 suites,6.35s,exit0 (.tmp/wp0-leak-verdict-targeted-final.log). npm.cmd run build (включая typecheck165/0) —exit0 (.tmp/wp0-leak-verdict-final-build.log). Final UI:10 сценариев5×2 темы,противоречивый OK отсутствует в panel и Maintenance;30 responsive сценариев5×2×3 ширины280/320/414px без document overflow (.tmp/wp0-leak-verdict-final-ui.log,final-responsive.log). Final light/dark screenshots визуально просмотрены:output/playwright/wp0-leak-verdict-final-{light,dark}.png. Оба временных browser/Vite процесса остановлены. Новый full на frozen final code/test tree выполняется.


Final local frozen tree: npm.cmd test -- --maxWorkers=1 —5167 passed/5 skipped/0 failed,309 files passed/2 skipped,276.13s,exit0 (.tmp/wp0-leak-verdict-final-full.log,EXIT_CODE=0). npm.cmd run build (включая typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-verdict-final-build.log). Targeted116/116,9 suites;traceability AC927/927 F210/210 и git diff --check exit0. UI fixture10 состояний и30 responsive случаев описаны выше. Remote exact-head CI/automatic Qodo ещё pending; WP-0 не завершён, WP-2 не начат.


PR #100 открыт на 69693b654d4018cacfb17aafbe21d9abbe31b042. Qodo1561598 completed exact SHA: два remediation_recommended — Correctness (потеря IP/adapter evidence и DNS-разницы в Maintenance/log) и Observability (global cancellation выглядела как неполная инспекция). Оба воспроизведены: npm.cmd test -- src/shared/leak-self-test.test.ts src/renderer/components/DiagnosticsCard.requestLifetime.test.tsx src/renderer/pages/Maintenance.requestLifetime.test.tsx src/main/leakSelfTest.test.ts —10 failed/48 passed,3.02s,exit1 (.tmp/wp0-leak-verdict-qodo-red.log). Attribution не менялся; review saved .tmp/qodo100-final.json (это initial review,не final fix review).

Fix: общий evidence message снова включает названия достигнутых физических адаптеров,их IP и TUN IP,а также dnsLeakDetail при расхождении сервисов. Старой summary статус по-прежнему не доверяет. Legacy global-stop result дополнен совместимым optional cancelled:true; cancelled всегда inconclusive,видно «Тест отменён»,без ложной причины об adapter coverage. Положительное leak evidence имеет приоритет. Адресно те же9 suites:125/125,6.73s,exit0 (.tmp/wp0-leak-verdict-qodo-targeted.log); npm.cmd run build (typecheck165/0) —exit0 (.tmp/wp0-leak-verdict-qodo-build.log). Final code/test tree frozen для нового full. Playwright:7 состояний×2 темы×3 ширины=42 случая,overflow0,сохранённые leak/cancel screenshots визуально просмотрены (.tmp/wp0-leak-verdict-qodo-ui.log,output/playwright/wp0-leak-verdict-qodo-*.png). Временные browser/Vite процессы остановлены.

Revix5582479023 на initial SHA сообщил free-quota-reached до21.10 00:00UTC:полного ревью нет,это не approval. CI39392273503 initial SHA ещё выполняется. Новый exact-head Qodo/CI после fix обязателен. Пока ждём gates,только read-only inventory: предыдущие104 literal success:false включали log payloads. Уточнённый AST inventory success/ok:false нашёл123 literals,из них81 непосредственно возвращаемый;это не число дефектов:есть уже typed results,guard envelopes и HTTP control responses. .tmp/wp0-domain-return-inventory.{cjs,json}. Semantic matrix настоящих feature handlers ещё не завершена.


Qodo fixes final local: npm.cmd test -- --maxWorkers=1 —5176 passed/5 skipped/0 failed,309 files passed/2 skipped,270.84s,exit0 (.tmp/wp0-leak-verdict-qodo-full.log,EXIT_CODE=0). npm.cmd run build (typecheck165 channels/0 public any) —exit0 (.tmp/wp0-leak-verdict-qodo-build.log). Targeted125/125,9 suites;traceability AC927/927 F210/210 и diff check exit0. Full выполнялся на frozen final code/test tree. CI39392273503 на initial69693b6 завершён success,все3 jobs;это не CI нового fix SHA. Требуются новый exact-head CI и автоматический completed Qodo.


## 20.10.2026 — WP-0: типизированные ошибки обновления подписок

PR #100 принят: final head b28317f67c208a4a14ea3eed0b924fdf031ec3f8, Qodo1561768 completed, оба замечания initial review1561598 автоматически implemented; новых нет. CI39393579304 success (Windows/Rust/site). Merge/main b444af53d8b320c2f179aa8835039a9125f141dd; reviewed и merge trees идентичны:0578af70bee580b98b6d8e7e975c0213ad59ba20. Revix5582479023 сообщил free-quota-reached до21.10 00:00UTC, полного review нет; это не approval. Attribution findings вручную не менялся.

AT-00-004/005, F-074/F-143, cross-regression AT-04-007/F-064: production groups:refresh возвращал обычный {ok:false,error:exception.message}; guard оборачивал его в outer ok:true. Raw error также попадал в lastFetchError и затем groups:list. Уточнение инвентаризации: текущий OperationRegistry уже распознавал returned ok:false как terminal error; предположение о ложном success в истории не подтвердилось. Недоставало категории ошибки и единого отказа на IPC boundary.

Refresh теперь бросает canonical IpcFault внутри operation owner, сохраняя исходную известную category; неизвестные исключения консервативно internal. Missing group=conflict, manual/no-subscription=validation, empty provider list=validation с безопасной статической причиной в group metadata. Последние профили/active ID/lastFetchedAt сохраняются, partial device fetch не коммитится; network/timeout даёт unreachable, local/internal error не доказывает expiry. Успешный retry очищает lastFetchError. Scheduler продолжает sweep после отказов; re-paste получает исходный typed fault. Ошибки refresh-policy также validation/conflict. Новые сообщения в metadata и локальные feature logs не копируют exception text. Servers перечитывает group metadata после typed failure; requester cancellation остаётся quiet. Success shape прежний, plain false union удалён.

Проверки: новый real-handler/guard/registry matrix сначала имел17 setup failures из-за mock defaults и UI regression (18 failed/24 passed,4.53s); после исправления только mock setup, до production fix —11 failed/31 passed,4.39s. Это meaningful red (.tmp/wp0-refresh-domain-red.log). После fix первые2 suites42/42; final targeted command: npm.cmd test -- src/main/serverGroupsRefresh.test.ts src/main/serverGroupsIpcErrors.test.ts src/renderer/pages/Servers.requestLifetime.test.tsx src/main/ipcChannelContract.test.ts —102 passed,4 files,3.51s,exit0 (.tmp/wp0-refresh-domain-targeted.log). Matrix7 resolver categories +7 store categories +7 secondary-device categories; canonical response, safe metadata/list, correlated terminal history, lock/listener cleanup; missing/manual/empty/policy/scheduler cases и UI metadata/cancel.

Первый npm.cmd run build обнаружил устаревшую false-result ветку re-paste (TS2339); удалена. Повтор npm.cmd run build, включая typecheck165 channels/0 public any —exit0 (.tmp/wp0-refresh-domain-build.log). node scripts/test-electron-runtime.mjs —первый запуск: новая7-category native matrix прошла, следующий старый assertion требовал новый импортированный профиль, уже созданный новым successful refresh; фикстура использует отдельный fresh-native.example.test. Повтор —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-native-final.log): настоящий Electron44.4.3, production handlers/guard/preload/registry/DPAPI stores, typed categories/codes/correlation через настоящий sandbox contextBridge, safe group metadata, unchanged saved profiles, no stale cancellation token/listeners, successful retry. Resolver контролируемый; это не натурная сетевая L3-приёмка. python ../docs/04-приёмочные-тесты/traceability/check-coverage.py (из приложения; эквивалентный запуск из корня выполнен) —AC927/927,F210/210,exit0; git diff --check —exit0.

Полный npm.cmd test -- --maxWorkers=1 и final typecheck выполняются. Remote Qodo/CI следующего PR ещё не запущены. WP-0 не завершён: semantic inventory остальных domain results и финальная актуальная AT-матрица остаются; HTTP/TLS/parser exceptions, потерявшие structured code ранее в resolver, пока честно internal — этот участок не доказывает их полную taxonomy. WP-2 ещё не начат. Нормативные docs/ не изменялись.

Первый full завершён: npm.cmd test -- --maxWorkers=1 —5203 passed/5 skipped/0 failed,310 files passed/2 skipped,279.27s,exit0 (.tmp/wp0-refresh-domain-full.log). Final повторный typecheck —exit0 (.tmp/wp0-refresh-domain-typecheck.log). Собственное review затем нашло stale-status edge: local refresh failure перезаписывал новый expired старым active. Регрессия сначала1 failed/25 passed,0.38s (.tmp/wp0-refresh-domain-status-red.log); обработчик теперь изменяет status только для network/timeout, остальные сохраняют актуальное значение. Final targeted те же4 suites —103 passed,4.00s,exit0 (.tmp/wp0-refresh-domain-targeted-final.log). Final full/build повторяются после этой конкретной правки; предыдущий зелёный full не подменяет их.

Final local verification после stale-status fix: npm.cmd test -- --maxWorkers=1 —5204 passed/5 skipped/0 failed,310 files passed/2 skipped,291.86s,exit0 (.tmp/wp0-refresh-domain-full-final.log,EXIT_CODE=0). npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-refresh-domain-build-final.log). Повтор node scripts/test-electron-runtime.mjs —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-native-current.log). Code/test tree во время final full не менялся. Следующий шаг —commit/push/PR, completed Qodo и CI на его точном head; до этого следующий кодовый участок не начинается.


Qodo1562107 completed exact initial baeab38bee0dca9336c2e96b86599f771bc2022c выявил2 remediation_recommended (утрата диагностической причины и сохранение active после реального resolver failure) и1 informational (empty subscription показывалась как invalid parameters). Замечания подтверждены8 failing regressions/51 passed,5.29s,exit1 (.tmp/wp0-refresh-domain-qodo-red.log); attribution вручную не менялся. Initial CI39396385972 не заменяет проверки следующего SHA.

Исправление включает настоящий producer: execSubscriptionCurl сохраняет категории DNS/TCP/TLS/HTTP/timeout; malformed request/redirect и полученный неподдерживаемый provider payload имеют validation. Fetch retry aggregation больше не стирает категорию; all-timeout остаётся timeout, полученный невалидный ответ приоритетнее более позднего fallback timeout. Resolver diagnostic message редактируется существующим redactor и сохраняется локально. Feature logs снова передают оригинальный Error в production appLogger, который редактирует message/stack; IPC и group metadata содержат только canonical текст. Network/timeout →unreachable, provider validation →expired, local/internal не перезаписывает новый status. При empty/неподдерживаемом provider response Servers показывает отдельный ru/en текст с сохранением ключей после чтения group metadata; cancellation quiet.

Actual resolver→feature catch→guard→history regression теперь проходит с controlled child_process.spawn: curl6 DNS,7 TCP,60 TLS,22 HTTP,28 timeout,3 invalid URL,0 invalid provider body. Category/code/status и сохранение профилей проверяются через production resolver, не через заранее созданный IpcFault. Actual appLogger + actual redactors сохраняют HTTP/TLS/DNS причину и file:line, удаляя credential URL/token/user path. Финальные targeted6 suites: npm.cmd test -- src/main/serverGroupsIpcErrors.test.ts src/main/serverGroupsRefresh.test.ts src/main/vpnProfilesRegression.test.ts src/main/appLoggerRedaction.test.ts src/renderer/pages/Servers.requestLifetime.test.tsx src/main/ipcChannelContract.test.ts —125 passed,3.83s,exit0 (.tmp/wp0-refresh-domain-qodo-targeted.log). Предыдущий targeted124/124 был до второго UI provider-validation case. Final full/build/native выполняются заново после исправлений Qodo. Прежняя граница этого slice про утраченную resolver category устранена; остальные domain handlers и полная WP-0 matrix остаются.

Initial CI39396385972 на baeab38 завершился failure в SERVER_REQUEST_NATIVE: assertion ожидал русское canonical message, Windows runner выбрал English navigator.language (actual Network operation failed / expected Сетевая операция не выполнена). Исправлена только locale-зависимая fixture: production preload явно получает en/ru через i18nSetLocale, native matrix теперь7 categories×2 locales, persisted metadata остаётся canonical ru. Повтор node scripts/test-electron-runtime.mjs —все7 *_PASS,exit0 (.tmp/wp0-refresh-domain-qodo-native-final.log); первоначальный local native тоже прошёл (.tmp/wp0-refresh-domain-qodo-native.log), но не выявлял English default. История failure сохранена (.tmp/wp0-refresh-domain-ci-initial-failed.log). Build после source/Qodo fixes —exit0,165 channels/0 public any (.tmp/wp0-refresh-domain-qodo-build.log). Traceability AC927/927 F210/210 и diff check exit0.

Final local после Qodo fixes: npm.cmd test -- --maxWorkers=1 —5214 passed/5 skipped/0 failed,310 files passed/2 skipped,274.74s,exit0 (.tmp/wp0-refresh-domain-qodo-full.log,EXIT_CODE=0). Production src и unit-test tree во время full не менялись; отдельная native fixture locale fix проверена своим повторным native прогоном. Build/typecheck165 channels/0 public any —exit0; targeted125/125; native7 *_PASS, включая14 category×locale cases; traceability/diff check exit0. Исправления готовы к commit/push; требуются новый exact-head CI и completed автоматический Qodo.


## 20.10.2026 — принят PR #101; следующий участок WP-0: ошибки уведомлений

PR #101 слит после исправления всех3 замечаний Qodo. Final head b026c9bd4428aac6bc5180ef248c8ab18d73a82c: Qodo1562325 completed, все3 findings автоматически implemented, новых нет; CI39398190723 success, все3 jobs (Windows/Rust/site). Merge/main22c4052f16fdf5d7064221e3a4a037156c3d9272; reviewed и merge trees идентичны:ef7c5169aa227105f97ef2f35f38987c335416b2. Initial CI39396385972 failure (locale-dependent native assertion) и Qodo1562107 сохранены как история, не заменены новым PASS. Revix на initial head сообщил free-quota-reached до21.10 00:00UTC, полного review нет, это не approval. Attribution вручную не менялся.

Read-only инвентаризация уточнена: исходный AST scan пропускал false as const; новый .tmp/wp0-domain-return-inventory-current.cjs учитывает wrapper expressions. 146 false literals/104 непосредственно возвращаемых объектов —кандидаты для семантической проверки, не104 дефекта; туда входят guard envelopes, HTTP control responses, штатные measurement outcomes и уже типизированные отказы. TypeScript inventory всё ещё165 handlers. Новые .tmp/wp0-domain-*-current.json сохраняют данные. В уведомлениях подтверждены returned raw string errors, catch fallback enabled:true и UI callbacks, проглатывающие reset failure/open-settings rejection. Следующий участок ограничен WP-0 error boundary; частичный reset report нельзя потерять при типизации.


## 20.10.2026 — WP-0: ошибки уведомлений и частичный сброс Windows-блокировки

Подтверждены нарушения AT-00-001/004/005/008 (F-074/F-138/F-143): check-os-state скрывал сбой чтения реестра за enabled:true; reset/open-settings возвращали сырые строки внутри успешного guard envelope; UI игнорировал partial report и отклонение открытия настроек. Новые production-handler/guard/source regressions сначала36 failed/5 passed,0.33s,exit1 (.tmp/wp0-notification-domain-red.log); UI regressions5 failed/6 passed,4.44s,exit1 (.tmp/wp0-notification-domain-ui-red.log). Первый main-only red до добавления source tests:27 failed/4 passed; неудачная Python-правка пути не изменила source test и затем была повторена с правильным cwd.

Теперь unexpected faults проходят через общий canonical envelope; NotificationResetReport сохраняет cleared AUMIDs и типизированные per-AUMID errors без command output. Ошибки patch имеют validation. Истинное отсутствие значения —default allowed; permission/timeout/unknown/malformed REG_DWORD больше не маскируются. Только Enabled=0 удаляется через reg.exe execFile с отдельными аргументами; explicit Enabled=1 и другие значения не удаляются. Отказы сохраняют локальный Error diagnostic через production redactor. Инвалидация cache не позволяет старому in-flight read снова заполнить cache. На реальной русской Windows read-only query заведомо отсутствующего HKCU fixture key подтвердил OEM866 stderr, который UTF8 повреждал; чтение buffer и распознавание UTF8/OEM866/1251 добавлены с реальной byte regression. Реестр пользователя не менялся.

NotificationSettings показывает reset/open failures и количество cleared/failed с canonical ru/en причиной; cancellation quiet. Повторный reset блокируется, устаревший OS ответ не заменяет новый, unmount запрещает поздние rechecks/state updates и очищает таймер. Регрессии покрывают оба unmount сценария (pending reset и уже назначенный poll). UI проверен настоящим Chromium через playwright-cli на изолированном harness production component+styles+i18n с controlled IPC: ru/en partial text, отказ Open Settings, screenshots dark/ru,dark/en,light/ru визуально просмотрены (.tmp/notification-visual/). Первая навигация до запуска loopback-сервера дала ERR_CONNECTION_REFUSED; повтор после старта успешен. Передача URL с & через Windows npx.cmd отрезала lang; locale затем проверена отдельным URL. Формальный design gate отсутствует в проекте и не заявляется.

Адресно npm.cmd test -- src/main/notificationResultContract.test.ts src/main/notificationsReset.test.ts src/main/notificationsGating.test.ts src/main/notificationPrefs.test.ts src/renderer/components/NotificationSettings.test.tsx src/main/ipcChannelContract.test.ts —72 passed,6 files,2.17s,exit0 (.tmp/wp0-notification-domain-targeted-final.log). Во время разработки typecheck выявил имя ipcError, затенённое UI state (исправлено alias), затем Buffer|string в test Error constructor (исправлено String); эти запуски не были PASS. npm.cmd run build после исправлений —exit0,165 channels/0 public any (.tmp/wp0-notification-domain-build.log). node scripts/test-electron-runtime.mjs —8 *_PASS,exit0 (.tmp/wp0-notification-domain-native.log), в том числе новый NOTIFICATIONS_NATIVE_PASS: настоящий Electron44.4.3, production source/handlers/guard/preload/DPAPI store,7 categories×2 locales, partial clear, retry/default, unchanged preferences и rejection Open Settings. Только reg execution/Settings launch управляемые; это не натурная доставка Windows toast и не полная L3-приёмка. Traceability AC927/927,F210/210 и git diff --check —exit0.

Полный npm.cmd test -- --maxWorkers=1 выполняется; его результат ещё не объявлен. Source дерево во время полного прогона не менялось; тип test Error(message) был исправлен на Error(String(message)) после запуска, поэтому после этого full нужен финальный прогон с неизменным деревом. Qodo/CI нового PR ещё не запускались. WP-0 остаётся активным; WP-2 не начат, остальные domain partial results и финальная AT-матрица впереди. Нормативные docs/ не изменены.


Финальный полный прогон на неизменном source/test tree: npm.cmd test -- --maxWorkers=1 —5258 passed/5 skipped/0 failed,310 files passed/2 skipped,274.28s,exit0 (.tmp/wp0-notification-domain-full-final.log,EXIT_CODE=0). Первый full также5258/5 skipped/0 failed,273.68s (.tmp/wp0-notification-domain-full.log); повтор после type-only fixture correction подтвердил окончательное дерево. Финальный targeted72/72, build/typecheck165 channels/0 public any,8 Electron *_PASS,traceability AC927/927 F210/210,diff check —exit0. Browser и loopback harness server завершены. Готово к commit/push/PR; для перехода дальше нужны completed automatic Qodo и зелёный CI на exact head.


PR #102 создан и attached: initial head58360032fb02629c32ca89fcce29ca84019c1268, CI39401779024. Для освобождения лимита100 attachments убрана только карточка давно merged PR #2; GitHub PR не менялся. Qodo1562727 completed exact initial head дал2 remediation_recommended: locale-dependent missing-registry detection и задержка/утрата OS delivery при persistent read failure. Revix сообщил free-quota-reached до21.10 00:00UTC, полного review нет, отсутствие не approval. Один read-only Qodo status запрос вернул transient fetch failed, следующий успешно прочитал completed review; attribution вручную не менялся.

Оба замечания подтверждены2 failed/14 passed,0.21s,exit1 (.tmp/wp0-notification-domain-qodo-red.log). Решение по первому заменяет прежний reg.exe текстовый парсер целиком: notificationRegistry использует Microsoft.Win32.Registry через bounded PowerShell, типизированные JSON receipts missing/value/error и числовой HRESULT/тип .NET исключения в локальной диагностике. Base64 AUMID не интерполируется как PowerShell source. Язык Windows и OEM decoding больше не участвуют. Reset за одно открытие конкретного key проверяет DWORD и удаляет только Enabled=0, сохраняя partial report и остальные настройки. Прежние OEM tests/green относятся к initial реализации и не являются доказательством нового helper.

По второму: strict Settings API сохраняет typed error, не выдаёт enabled. Notify не ждёт read-only probe: при unknown пробует системный toast и in-app fallback; доказанный blocked использует только fallback. Одновременные probes coalesced; negative cache хранит ошибку30s без ложного enabled и без повторного spawn/warnings на каждом notification. Явный check из Settings делает force read; reset инвалидирует cache с revision fence. Tests подтверждают pending query, OS show сразу, fallback, один spawn/diagnostic при persistent failure, strict rejection, fresh retry, сохранение block, parsed malformed receipts и encoded AUMID. Gating tests теперь детерминированно mock Windows registry и не запускают реальный процесс фоном.

Final targeted npm.cmd test -- src/main/notificationsReset.test.ts src/main/notificationResultContract.test.ts src/main/notificationsGating.test.ts src/main/notificationPrefs.test.ts src/renderer/components/NotificationSettings.test.tsx src/main/ipcChannelContract.test.ts —75 passed,6 files,2.11s,exit0 (.tmp/wp0-notification-domain-qodo-targeted-final.log). Новый mock сначала вызвал TS7053 при Symbol index, исправлен Object.defineProperty; финальный npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-notification-domain-qodo-build.log). node scripts/test-electron-runtime.mjs —8 *_PASS,exit0 (.tmp/wp0-notification-domain-qodo-native.log): production .NET helper дополнительно реально прочитал заведомо отсутствующий изолированный AUMID на этой Windows (actualMissingRegistryRead:true), не меняя registry; error/partial matrix остаётся controlled boundary. Traceability927/927,210/210,diff check exit0. Полный набор после Qodo fixes выполняется заново; новые exact-head remote gates ещё нужны.


Final local после Qodo fixes: npm.cmd test -- --maxWorkers=1 —5261 passed/5 skipped/0 failed,310 files passed/2 skipped,276.35s,exit0 (.tmp/wp0-notification-domain-qodo-full.log,EXIT_CODE=0). Source и unit-test tree во время этого full не менялись. Build/typecheck165 IPC channels/0 public any, targeted75/75,8 native *_PASS,traceability/diff check —exit0. Initial CI39401779024 также success на5836003, но не заменяет новый CI после исправлений. Исправления готовы к commit/push; нужен повторный automatic Qodo на окончательном SHA. WP-0 в работе, WP-2 не начат.


## 20.10.2026 — принят PR #102; WP-0: честная очистка диагностики

PR #102 слит: exact final head b9394b29207f9fef179744e20c03c13084c29e89, Qodo1562926 completed, оба initial findings автоматически implemented, новых нет. CI39403368777 success: Windows/Rust/site. Merge/main c14cd759633e53a4bf7c30a33c71341b83dd487c; reviewed и merge trees совпадают:35771beb4bf62d6c43d578edf5e8c5b7ca86380b. Revix по квоте не выполнил полного review до21.10 00:00UTC, отсутствие не approval. Attribution вручную не менялся. Первые git rev-parse без кавычек вокруг ^{tree} PowerShell разобрал как scriptblock, проверки завершились ошибкой; повтор с кавычками дал одинаковые trees.

Следующий bounded slice AT-00-001/004/005/008, cross-regression AT-08-005; F-074/F-138/F-143: clear-diagnostic-artifacts подавлял rm failures; clearAppLog отдельно подавлял отказы engine/previous files; open-snapshots-folder сериализовал raw shell exception, open-tun-log-folder/open-log-folder игнорировали nonempty shell receipt. Четыре production handlers перенесены без изменения поведения в diagnosticMaintenance; новые guard regressions дали22 failed/8 passed,344ms (.tmp/wp0-maintenance-red.log). Logger regression на async EACCES дала1 failed/3 passed,293ms (.tmp/wp0-maintenance-logger-red.log); первый вариант mock ошибочно бросал синхронно, затем исправлена только async граница. UI первый запуск5 setup failures из-за неверного имени кнопки; после использования существующей locale string meaningful red4 failed/1 passed,1.56s (.tmp/wp0-maintenance-ui-red.log).

DiagnosticClearReport теперь сохраняет подтверждённые clears и canonical per-artifact IpcError, без absolute paths/raw error strings. ENOENT у optional previous logs означает отсутствие файла, остальные ошибки не скрываются. Capture running/cleanupPending даёт conflict до удаления; untrusted namespace permission до эффектов. Если log preflight падает после directory clears, эти clears сохраняются. Original errors пишутся через production redactor локально после очистки app.log, чтобы вызов не стёр собственную диагностику. Open folder failures проходят общий outer envelope; success contracts сохранены. Logs вызывает единственный artifact cleanup, ждёт все3 independent requests через allSettled, сохраняет failed history, показывает ru/en partial counts и canonical причины, блокирует duplicate click и поздние effects после unmount/старого read. Нормативные docs/ не менялись. Остальные maintenance/runtime/partial network results ещё не исправлялись; WP-0 в работе, WP-2 не начат.

Адресно npm.cmd test -- src/main/diagnosticMaintenance.test.ts src/main/appLoggerCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/renderer/pages/Logs.cleanup.test.tsx src/renderer/pages/Logs.render.test.tsx src/renderer/LogsSource.test.ts src/renderer/components/DiagnosticsCard.test.tsx —89 passed,8 files,3.20s,exit0 (.tmp/wp0-maintenance-targeted-final.log). npm.cmd run build —exit0,165 channels/0 public any (.tmp/wp0-maintenance-build-final.log). node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-maintenance-native-final.log): новый MAINTENANCE_NATIVE_PASS использует настоящие production handlers/logger/guard/preload/sandbox,7 categories×2 locales и реальные файлы только в выделенной .tmp run directory. Controlled capture/ACL/path/shell и syscall faults; это не натурная ACL или сетевая L3-приёмка. Проверены оставшиеся после частичного отказа файлы, подтверждённые clears, сохранение failure evidence в app.log после clear, retry. Первый native assertion ожидал исходный xray.log, уже очищенный ранее успешным log step в category matrix; fixture пересоздаёт отдельное evidence перед partial сценарием. Повтор прошёл.

UI partial toast визуально проверен Chromium/playwright-cli: ru/dark,en/dark,ru/light, screenshots просмотрены в .tmp/maintenance-visual. Production Logs/MacToast/styles/i18n с controlled IPC. Первое открытие до CLI bundling дало404 bundle.js; после сборки reload успешен. Node REPL import esbuild CJS дал module is not defined, CLI сборка успешна. Существующий MacToast выдаёт React warning о ref/PopChild; он не менялся в этом slice. Design accuracy/state/responsive scripts отсутствуют в проекте, формальный gate PASS не заявляется. Browser и loopback server закрыты. Traceability AC927/927,F210/210 и git diff --check exit0. Полный npm.cmd test -- --maxWorkers=1 ещё выполняется на неизменном source/test tree; результат не объявлен.


Final local verification: npm.cmd test -- --maxWorkers=1 —5305 passed/5 skipped/0 failed,312 files passed/2 skipped,263.66s,exit0 (.tmp/wp0-maintenance-full.log,EXIT_CODE=0). Source и unit-test tree во время full не менялись. Final build/typecheck165 channels/0 public any,89 targeted tests,9 native *_PASS,traceability/diff check —exit0. Для следующего PR освобождена одна из100 карточек: убрана только attachment давно merged PR #3 (merged19.06.2026), GitHub PR не менялся. Следующий кодовый участок начнётся только после completed automatic Qodo и exact-head CI.


## 20.10.2026 — PR #103: исправления по automatic Qodo

Qodo1563327 completed на initial5e3a53f89d259a619ce434fbf42b5166829519dd подтвердил4 remediation_recommended: rejected cleanup оставлял logger queue сломанной; failed history clear отзывал pending read без повторного чтения; ENOENT завышал число удалений; вложенный Error терял non-enumerable message/stack. Все4 проверены и исправлены; attribution вручную не менялся. Revix сообщил free-quota-reached до21.10 00:00UTC; полного review нет, отсутствие не approval. Initial CI39406660402 не заменяет будущий exact-head CI.

Caller по-прежнему получает reject cleanup, но shared log lane восстанавливается и сохраняет следующий diagnostic event. Watcher stop включён в try/finally. Current files очищаются truncate, previous unlink; ENOENT не создаёт новые файлы и попадает в отдельный absent, успешные syscall в cleared. Directory rm без force также различает absence. Partial report сохраняет cleared/absent/per-artifact errors. Ошибки передаются appLogger как top-level Error после очистки, production redactor сохраняет санитизированные message/stack. Logs после failed history clear повторно читает историю и статистику с текущими фильтрами, отвергая старые ответы. RU/EN partial toast отдельно показывает cleared/absent/failed.

Meaningful red: npm.cmd test -- src/main/appLoggerCleanup.test.ts src/renderer/pages/Logs.cleanup.test.tsx —4 failed/10 passed,2.65s,exit1 (.tmp/wp0-maintenance-qodo-red.log). После исправления первоначальный targeted имел1 failed/51 passed из-за устаревшего expected absent для отсутствующего forensic namespace; expectation исправлен. Final targeted: npm.cmd test -- src/main/diagnosticMaintenance.test.ts src/main/appLoggerCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts src/renderer/pages/Logs.cleanup.test.tsx src/renderer/pages/Logs.render.test.tsx src/renderer/LogsSource.test.ts src/renderer/components/DiagnosticsCard.test.tsx —95 passed,8 files,3.63s,exit0 (.tmp/wp0-maintenance-qodo-targeted-final.log).

Final npm.cmd test -- --maxWorkers=1 —5311 passed/5 skipped/0 failed,312 files passed/2 skipped,269.36s,exit0 (.tmp/wp0-maintenance-qodo-full.log,EXIT_CODE=0). Source/unit-test tree не менялся во время full. npm.cmd run build —exit0,165 IPC channels/0 public any (.tmp/wp0-maintenance-qodo-build.log). node scripts/test-electron-runtime.mjs —все9 *_PASS,exit0 (.tmp/wp0-maintenance-qodo-native-final.log). Native дополнительно проверил запись после rejected preflight, absence totals, сохранённые файлы и настоящий redactor message/stack без user path. Первый correction assertion требовал путь maintenance.cjs в stack, который production redactor правильно удаляет; заменён на наличие stack frames и отсутствие user path, redaction не ослаблена. Capture/ACL/shell/fault boundaries управляемые, настоящая сетевая/ACL L3-приёмка не заявляется.

Final partial toast визуально просмотрен в Chromium en/dark и ru/light (.tmp/maintenance-visual/*-partial-final.png); initial ru/dark также проверен. Существующий React warning MacToast ref/PopChild остаётся; формальные accuracy/state/responsive gates отсутствуют, PASS не заявляется. Browser закрыт, loopback server остановлен. python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Оба журнала актуализированы. Исправления готовы к commit/push; до следующего кодового участка нужны completed automatic Qodo и CI на окончательном SHA. WP-0 остаётся активным, WP-2 не начат; нормативные docs/ не изменялись.


Дополнительное собственное review PR #103 подтвердило гонку: filter read, начатый во время успешной очистки, имел уже новый epoch и мог вернуть удалённые строки после success. Regression npm.cmd test -- src/renderer/pages/Logs.cleanup.test.tsx —1 failed/7 passed,1.80s,exit1 (.tmp/wp0-maintenance-during-clear-red.log). Завершение clear теперь отзывает также reads, начатые во время удаления; failed clear по-прежнему запускает fresh reload с текущим filter. Final targeted те же8 suites —96 passed,3.31s,exit0 (.tmp/wp0-maintenance-during-clear-targeted.log). Final npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,269.09s,exit0 (.tmp/wp0-maintenance-during-clear-full.log,EXIT_CODE=0), неизменный source/test tree. npm.cmd run build —exit0 (.tmp/wp0-maintenance-during-clear-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-maintenance-during-clear-native.log). git diff --check exit0. Визуальный вид не менялся. Qodo1563526 completed на17c2efe47eefb7a5e0ac0c162a8ec2588ab315fd автоматически implemented все4 initial findings, новых нет; это не заменяет новое review после дополнительной правки. Следующий кодовый участок всё ещё ожидает final exact-head Qodo/CI.


CI39409150654 на2fdc7b5a04907fe9e0aae953527775f86395211c завершился failure: единственный splitTunnelDiscovery.test.ts / finds sibling products under the same vendor dir превысил outer5000ms;5312 passed/4 skipped/1 failed,400.31s (.tmp/wp0-maintenance-final-ci-failed.log). Обнаружена ошибка изоляции fixture: виртуальный fs не ограничивал PowerShell registry queries, и suite запускал три реальных host registry scan перед проверкой Programs tree. Child-process boundary этого unit теперь mock empty registry response; проверяется3 calls к powershell.exe, реальные directory/junction/helper assertions сохранены, timeout не повышен. Production-код не менялся. npm.cmd test -- src/main/splitTunnelDiscovery.test.ts src/main/splitTunnelProcess.test.ts src/main/splitTunnelPath.test.ts —36 passed,3 files,509ms,exit0 (.tmp/wp0-maintenance-ci-fixture-targeted.log). npm.cmd run typecheck —exit0,165 channels/0 public any (.tmp/wp0-maintenance-ci-fixture-typecheck.log); traceability AC927/927,F210/210 и diff check exit0. Full после fixture correction выполняется, результат ещё не объявлен. Qodo1563638 completed на2fdc7b5 без открытых findings; CI39408233088 предыдущего17c2efe автоматически cancelled после нового push. Оба предыдущих remote результата не заменяют проверки следующего commit.


Final full после изоляции registry boundary: npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,269.50s,exit0 (.tmp/wp0-maintenance-ci-fixture-full.log,EXIT_CODE=0). Source/unit-test tree не менялся во время прогона. Последнее изменение затрагивает только unit fixture; build/native9 PASS для production tree сохраняют силу, новый CI повторит их на окончательном SHA. Для перехода дальше по-прежнему нужны новый automatic Qodo и успешный exact-head CI.


Qodo1563861 completed на851144cfc05920277bba0ab175c382b14c344f0e сохранил4 initial findings implemented и дал1 maintainability remediation_recommended: новый assertion числа registry calls не доказывал состав hives. Усиление проверяет decoded UTF16LE EncodedCommand и точное множество/порядок трёх Uninstall roots: HKLM native, HKLM WOW6432Node, HKCU. Изменение только в unit fixture; timeout и production discovery прежние. npm.cmd test -- src/main/splitTunnelDiscovery.test.ts src/main/splitTunnelProcess.test.ts src/main/splitTunnelPath.test.ts —36 passed,3 files,478ms,exit0 (.tmp/wp0-maintenance-hive-targeted.log). npm.cmd run typecheck —exit0,165 channels/0 public any (.tmp/wp0-maintenance-hive-typecheck.log). Attribution вручную не менялся. Full выполняется на неизменном source/unit-test tree; после push потребуется новый automatic Qodo и CI точного head.


Окончательный full после hive assertion: npm.cmd test -- --maxWorkers=1 —5312 passed/5 skipped/0 failed,312 files passed/2 skipped,272.80s,exit0 (.tmp/wp0-maintenance-hive-full.log,EXIT_CODE=0). Unit/source tree во время full не менялся. Targeted36/36, typecheck165 channels/0 public any, traceability927/927 и210/210, diff check —exit0. Новые remote gates требуются после commit/push. WP-0 не завершён, WP-2 не начат.


## 20.10.2026 — PR #103 принят; типизированные отказы runtime/maintenance (WP-0)

PR #103 слит: 3554beb2819bec6b96e2fc15f2e3dfc6c235af17; reviewed head 6923f7b30c25a983868ade4b96c313b2173d2c77. Деревья reviewed/merge совпадают: 6144e1314e51146cec6cb6699c1fec2b988fb259. Exact-head CI39411986600 success во всех трёх jobs; automatic Qodo1563978 completed, все5 findings автоматически implemented, новых нет. Revix на initial5e3a53f —free-quota-reached до21.10 00:00UTC, полного review нет; это не approval. Attribution вручную не менялся.

AT-00-001/004/005/008; F-074/F-138/F-143: active-TUN guards baseline/firewall/adapter/runtime возвращали success либо нетипизированный отказ. Теперь success:false + canonical conflict, без мутаций; firewall health сохранён. Runtime failures больше не содержат raw exception text или выдуманные нулевые counts. Подтверждённый partial receipt сохранён с success:false; внутренний lifecycle owner всё ещё отклоняет partial и отдельно доказывает exit. Stop dispatch не повторяется после timeout/exited/protocol/rejected/busy/closed; fallback только при настоящем pre-dispatch RecoveryWorkerError unavailable. Worker timeout классифицирован как timeout, busy/closed —conflict; fallback EACCES/EPERM —permission, ETIMEDOUT и настоящий execFile killed/SIGTERM/null-code —timeout; maxBuffer не считается deadline. Неизменны ownership, строгая валидация keys/counters/names, native deadlines и fresh exit proof. Принятый scope общего WP-0 охватывает эти исправления; норматив docs/ не меняется.

Red: npm.cmd test -- src/main/ownedRuntimeStop.test.ts src/main/runtimeMaintenance.test.ts —38 failed/12 passed,730ms,exit1 (.tmp/wp0-runtime-maintenance-red.log). First targeted7 suites —290/290,18.50s. Typecheck сначала выявил widening literal success в новой union; исправлено false as const. Final targeted: npm.cmd test -- src/main/ownedRuntimeStop.test.ts src/main/runtimeMaintenance.test.ts src/main/ownedRuntimeStatus.test.ts src/main/tunRuntimeExitProof.test.ts src/main/lifecycleCleanup.test.ts src/main/mainIpcRegression.test.ts src/main/ipcChannelContract.test.ts —316 passed,7 files,20.35s,exit0 (.tmp/wp0-runtime-maintenance-targeted.log). Реальные AST-extracted main handlers + handleLogged исполняются через production trusted boundary:4 guards без эффектов,7 категорий на каждом канале, canonical payload без raw path/stack, общий correlation id, health failure, confirmed empty и partial receipts. Native/network boundaries в этих регрессиях управляемые; L3 не заявляется.

Final npm.cmd test -- --maxWorkers=1 —5360 passed/5 skipped/0 failed,313 files passed/2 skipped,272.70s,exit0 (.tmp/wp0-runtime-maintenance-full.log,EXIT_CODE=0), source/unit-test tree frozen. npm.cmd run typecheck —165 channels/0 public any,exit0 (.tmp/wp0-runtime-maintenance-typecheck.log). npm.cmd run build —exit0 (.tmp/wp0-runtime-maintenance-build.log); node scripts/test-electron-runtime.mjs —9 *_PASS,exit0 (.tmp/wp0-runtime-maintenance-native.log). python docs/04-приёмочные-тесты/traceability/check-coverage.py —AC927/927,F210/210,exit0; git diff --check —exit0. Traceability не заменяет исполнение AT. До следующего кодового участка обязательны automatic completed Qodo и successful CI на окончательном SHA после push. WP-0 остаётся активным: остаток —network/firewall/browser domain reports и final AT matrix; WP-2 не начат.
