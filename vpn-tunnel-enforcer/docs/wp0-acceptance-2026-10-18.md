# WP-0: контракты и наблюдаемость — 18.10.2026

Статус: **в работе**. Основание: том 3 §1.1–1.2, ТЗ-06 WP-0
и решения владельца §10, AT-00-001…010. WP-3 завершён в PR #46;
его L3 `SKIPPED_BY_OWNER` не распространяется на WP-0.
Главный ревьюер — Qodo по решению владельца от 18.10. CodeRabbit исключён
из ожидания; окончание trial Greptile не блокирует работу. CI и review обязательны.
18.10 владелец разрешил продолжать WP-0 при открытом PR #54, сохраняя запрет
его слияния до отдельного решения. Полного Revix для #54 не было из-за квоты.
Позднее 18.10 владелец разрешил сливать PR после пройденных проверок.
#54/#55/#56/#57/#58/#59/#60/#61/#62/#63/#64/#65/#66/#67/#68/#69/#70/#71 слиты в main после exact-head CI success и completed Qodo,
без открытых findings; прежний запрет слияния отменён.

## Полная область и первоначальная инвентаризация

| AT | Найденная реализация / доказательства | Остаток до приёмки |
| --- | --- | --- |
| 00-001 | AST-проверка 160 main/preload/shared request channels, общий реестр входов и versioned transport envelope; object contracts проверяют поля/массивы, save-settings покрывает все 39 общих полей AppSettings; TypeScript checker проверяет results всех 160 listeners, public results с `any` больше нет; native contextBridge сохраняет JSON профиля и nullable active result, feature list/cancel | Завершить проверку текущего PR; отдельная semantic matrix ошибок остаётся в 00-004 |
| 00-002 | Production TunnelStateMachine интегрирована в main lane/IPC/Soft/tray/UI; 4096 stable tours и 117649 tours семи событий глубиной 6, включая timeout/cancel и native completion, с fake PID/TUN ledger и балансом operation events; sticky faults и generation fencing | Общая durable operation history/counters; все blocked/unknown/background paths; native Windows resources; общий admission фоновых restart |
| 00-003 | Main connection lane: UUIDv4, owner, deadline запуска, priority admission; ручные Hard/Direct и Soft из tray, scheduled startup вместе с proxy detection; общий feature registry с prompt cancellation/deadline и physical drain, speed test, refresh подписок и импорт профилей, включая curl/DoH и commit queue; config browse/validate/apply/export, async file I/O и terminal commit приняты в PR #70; key renderer/clipboard/file exports в PR #71 | Ротация и UI cancel/unmount; deadline остановки, все entrypoints и полная матрица поздних эффектов |
| 00-004 | Общая классификация transport; 157 каналов × 7 категорий через guard; native contextBridge сохраняет code/category/correlation в en/ru; typed local validation; 4 настоящих config handlers × 7 категорий, canonical domain failures | Миграция legacy domain-result `{success:false,error}` и semantic matrix настоящих feature handlers; transport fixtures не доказывают её |
| 00-005 | Один action correlation id в guarded IPC response/error, lifecycle connect/stop и JSONL logger; async isolation, native wait/drain, diagnostic read-back с повторной redaction; ID исходного connect и source/owner/route/confidence в session history/JSON/CSV; JSONL clockId/monotonicMs отдельно от календарных дат и durationMs; реальные owned/legacy/tray/recovery Soft sessions | Все native/background entrypoints и полная матрица событий/истории автоматизаций, live-check и recovery |
| 00-006 | Локальные миграции; общий version admission для 20 electron-store файлов / 28 constructors; future-version SHA-256 invariance на real Conf backend до defaults/repair и при записи через ранее открытый handle | Централизованный упорядоченный migration registry, fixtures всех исторических преобразований, остальные persisted JSON, полноценный upgrade/downgrade и межпроцессная координация |
| 00-007 | Seed 0x5eed003: 200 commands/10 async workers с production lane/FSM, typed losers, парные terminal events, финальный disconnect и 0 fake PID/TUN | Натурный PID-реестр Windows и полная матрица фоновых entrypoints |
| 00-008 | Dashboard component frames с production FSM/lane; revision fence; Soft через owned IPC; visual fixtures light/dark; native production contextBridge snapshots/disposer | Полная матрица всех операций, тем, размеров и entrypoints; browser fixtures не заменяют native resources |
| 00-009 | Плановые функции WP-12 не приняты в production | Проверить реестр production flags, отсутствие DOM и отказ включения без laboratory evidence с audit event |
| 00-010 | История подключений: настоящий Conf backend, 100 записей, повторная загрузка, повреждённый JSON/схема, `history.corrupted`, сохранение валидных записей и последующая запись | Адресная L2-матрица истории подключений добавлена; перенос той же гарантии на общий audit/event history всех операций после его введения |

Это перечень обнаруженного, а не PASS десяти AT. Ни один новый
неиспользуемый модуль сам по себе не закрывает критерий интеграции.

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
