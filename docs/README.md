# Техническое задание и архитектурная документация VPN Tunnel Enforcer

В данном каталоге размещены официальные утверждённые тома технического задания (ТЗ) проекта **VPN Tunnel Enforcer**, консолидированные по смысловым блокам на основе глубокого технического аудита, анализа протоколов и утверждённых решений владельца продукта (Product Owner).

---

## Приёмочные тесты (критерии приёмки в виде тестов)

### [04-приёмочные-тесты/](./04-приёмочные-тесты/)
*Исполняемая система проверки: 140 детальных тестов + 5 сквозных прогонов, покрывающих все 927 критериев приёмки и находки F-001…F-210.*
- **Методология (`00`):** уровни L0–L4 (static/contract → unit → integration → Windows E2E → exploratory), таксономия из 15 типов тестов (property-based, metamorphic, fuzzing, fault injection/chaos, model-based, pairwise, soak, a11y, localization и др.), вердикты PASS/FAIL/NOT-CHECKED/INDETERMINATE, двойные оракулы для инвариантов безопасности, матрица сред и сетевых профилей, гейты качества.
- **Наборы по рабочим пакетам (`01`…`13`):** каждый тест `AT-<WP>-<NNN>` с трассировкой на AC/REQ/F/WP, средой, шагами и измеримым оракулом.
- **Сквозные прогоны (`14`):** pairwise-матрица ОС×режим×протокол×сеть, бюджеты производительности, soak 72 ч, исследовательские уставы, регрессионный контур аудита.
- **Трассировка (`traceability/`):** машиночитаемый инвентарь всех 927 AC и скрипт сверки `check-coverage.py` (запуск: `python3 traceability/check-coverage.py`; выход 0 = покрытие полное).

---

## Структура консолидированного ТЗ (3 тома)

Спецификация сведена в три исчерпывающих тома, исключающих дублирование и объединяющих архитектуру, системную безопасность, протоколы, UI/UX и жизненный цикл:

### 1. [01-ТЗ-СЕТЕВОЕ-ЯДРО-ПРОТОКОЛЫ-И-МАРШРУТИЗАЦИЯ.md](./01-ТЗ-СЕТЕВОЕ-ЯДРО-ПРОТОКОЛЫ-И-МАРШРУТИЗАЦИЯ.md)
*Сетевое ядро, протоколы туннелирования, виртуальные адаптеры Wintun, маршрутизация и DNS.*
- **Сетевые движки и адаптеры:** `sing-box` (схемы 1.13 и 1.14, `endpoints[]`, замена `download_detour` на `http_clients`), `xray-core` (VLESS-REALITY на динамическом порту `pickFreeLocalPort()` / `18010..18019`, обоснование `minClientVer` F-026, порядок старта/очистки F-022), `amneziawg-go.exe` (сателлит AWG 1.0/2.0 с параметрами `Jc, Jmin, Jmax, S1..S4, H1..H4`, ping probe, интерфейс `awg-tun`), альтернативное ядро `mihomo` (`CoreAdapter`, модель `UnifiedVpnProfile`, REST API `127.0.0.1:9090`).
- **Сетевой стек Wintun:** жизненный цикл адаптеров (`VPNTE-TUN`, `awg-tun`), stealth-маскировка под псевдонимы `Ethernet 5..12` (по умолчанию `Ethernet 5`), системная метрика интерфейса `5` (`InterfaceMetric 5` против коллизий с loopback), предотвращение self-proxy loop, MTU, MSS clamping, разрешение конфликта двух активных туннелей (`canStartHard`).
- **Протоколы:** WireGuard (endpoints), VLESS Reality, Hysteria 2 (сохранение параметров RFC для 1.14+, маскирование для 1.13, F-028), Shadowsocks 2022 AEAD (SIP002 IPv6 декодирование), VMess (нормализация `alter_id: 0`, F-050), NaiveProxy (`tls.insecure`), ECH.
- **Маршрутизация и DNS:** Smart RU (проверка хеша/подписи, локальный fallback `gov-ru.srs` с предупреждением в UI), детерминированная таблица приоритетов с защитными пинами (чекеры, Google/Gemini, CDN перед прямыми RU-правилами, обособленный прямой обход Kimi/Moonshot AI), точные доменные правила (домен + поддомены), действие «Блокировать», независимые счетчики попаданий, Split Tunneling по абсолютному `process_path`, Bootstrap DNS с уведомлением, фильтрация RFC 1918 / SSRF в DNS-ответах.
- **Локальный прокси (Happ):** выделенные порты `17990..17999`, защита токена NTFS DACL, проверка заголовка `Host` против DNS Rebinding, синхронизация портов с UI, детекция SOCKS/HTTP, graceful 1.5с остановка + force kill, атомарное выделение портов `SO_EXCLUSIVEADDRUSE`.
- **Рабочие пакеты:** WP-2, WP-4, WP-6, WP-12 (сетевой трек).

---

### 2. [02-ТЗ-СИСТЕМНАЯ-БЕЗОПАСНОСТЬ-ЗАЩИТА-ОТ-УТЕЧЕК-И-ОС.md](./02-ТЗ-СИСТЕМНАЯ-БЕЗОПАСНОСТЬ-ЗАЩИТА-ОТ-УТЕЧЕК-И-ОС.md)
*Системная безопасность, защита от утечек, транзакционный откат, доверенные границы и ОС.*
- **Windows Firewall & Kill-Switch:** дефолт строго `false`, нормализация не включает kill-switch в `true`; минимальный allowlist, LAN и Wintun stealth-алиасы `Ethernet 5..12`; автономная IPv6-политика в собственном WFP sublayer с persistent/boot-time блокировкой и узкими soft permit (App ID + endpoint `/128` + LUID). NAT64-префикс используется для синтеза точного VPN endpoint, целиком не разрешается; `ms_tcpip6` на мобильном тетеринге сохраняется. Валидация IP/CIDR и путей `.exe`; live-apply исключений без перезапуска туннеля. Механизм уточнён владельцем 07.10.2026, реальная Windows/L3-приёмка отдельно.
- **Транзакционные манифесты и откат:** хранилище `%ProgramData%\VPNTE\manifests\` с жестким DACL (SYSTEM/Admins), атомарная запись `temp+rename`, пошаговый независимый rollback с логированием и всплытием ошибок (F-148), норматив поврежденного манифеста (fallback в `Allow` с обязательным громким предупреждением и переводом статуса в `unknown`), обязательная регистрация задачи Boot Recovery от `SYSTEM` при установке, полное нормативное предписание по удалению скрипта `vpnte-eos-compat.ps1`.
- **Сетевой Lockdown:** проверка физических адаптеров (`NoPhysicalAdaptersDetected`), отключение Teredo/6to4/ISATAP только при фактическом обнаружении, режим Captive Portal (`forceDns: false`).
- **Криптография и секреты:** шифрование ключей, паролей, UUID и ссылок подписок через Windows DPAPI / Electron `safeStorage` (префикс `enc:dpapi:v1:`), версионированная миграция хранилища с backup `.bak`, права доступа к бэкапам `locationPrivacy` в ProgramData, экспорт полного URI разрешён с предупреждением и очисткой буфера через 60 с, единый сервис `RedactionService`.
- **IPC и доверенная граница:** валидация `senderFrame` и URL origin для привилегированных каналов, типизированная runtime-валидация параметров, CSP (без сторонних ресурсов картинок вроде `flagsapi.com`) и `sandbox: true`, защита каталога runtime NTFS ACL до старта, проверка путей процессов со строгим слэшем.
- **Chromium Browser Boxes (изоляция мультиаккаунтов):** единый sing-box с пулом SOCKS5-инбаундов (`127.0.0.1:10801..10850`), запуск Chromium с флагами `--proxy-server`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`, WebRTC policy, `--password-store=basic`, DPAPI-шифрование сессий на диске, диалог при выходе, сессионный файл `boxes-session.json` с детекцией orphan PID при старте, внешняя верификация выхода IP и WebRTC STUN.
- **Поставка и инсталлятор NSIS:** безопасный shutdown с rollback вместо `taskkill /F /T` в `build/installer.nsh`, интеграция `make-icon.js`, публикация SHA-256 `checksums.txt`, фиксация хэшей бинарников в `binaries-manifest.json`, статус подписи кода `NotSigned` с 3 вариантами решения, автообновление через GitHub Releases (`latest.yml`), поддержка Windows 10 с предупреждением об EOS, переход на Electron 42 с плановой миграцией на актуальную поддерживаемую мажорную версию Electron 44 до окончания трёхмажорного окна upstream (20.10.2026), стек Vitest `^4.1.11`.
- **Рабочие пакеты:** WP-1, WP-3, WP-11, WP-12 (security трек).

---

### 3. [03-ТЗ-ЖИЗНЕННЫЙ-ЦИКЛ-АВТОМАТИЗАЦИЯ-UI-И-ДИАГНОСТИКА.md](./03-ТЗ-ЖИЗНЕННЫЙ-ЦИКЛ-АВТОМАТИЗАЦИЯ-UI-И-ДИАГНОСТИКА.md)
*Жизненный цикл, автоматизация, мониторинг, интерфейс, доступность и диагностика.*
- **Lifecycle Coordinator & State Machine:** 5 стабильных состояний (`disconnected`, `connected`, `error`, `blocked`, `unknown`) и 3 переходные операции; субстатус `health: 'degraded'` строго внутри `connected`; запрет отображения переходов как «Подключено»; перехват `uncaughtException` (rollback при активном туннеле и сброс в `unknown` с кодом `crashRollback`); иерархия приоритетов `Recovery > Manual > Schedule > Rotation > AutoPilot > Adaptive Retry`; ручное действие прерывает автоматизацию через `AbortController`; централизованный PID супервизор; уничтожение Tray при выходе; очистка слушателей `nativeTheme`.
- **Подсистемы автоматизации:** Scheduler с поддержкой таймзон, DST и объединением перекрывающихся окон; ротация серверов по принципу Health-Before-Commit; адаптивный обход блокировок (окно стабильности 20 с, 2 из 3 проб, расширенный отпечаток профиля, миграция legacy `stealthMode`, AmneziaWG как целевой этап WP-12); Soft-режим (актуальный `proxy.settings.xml` Android Studio, селективный откат Git/Gradle, обход лимита 1024 символов `setx` через прямую запись в `HKCU\Environment`).
- **Серверы и подписки:** конвейер импорта без повторного декодирования; SIP002 authority; форматы Happ crypt4 и add JSON; сохранение uTLS/ALPN с предупреждением; сериализованная очередь записи профилей; явный возврат ошибки при сбое подписки; минимальный порог автообновления 15 минут (F-179); архив ключей с TTL 30 дней; история live-проверок `live-server-checks.json` с полным 10-полевым диффом, кнопками очистки и экспорта; интеграция истории подключений в экран трафика.
- **Мониторинг и самопроверка:** 64-битные счетчики байт; таймзоны `+0300`; фоновый опрос с проверкой `document.hidden`; нормализация URL (`https://`); разделение TCP latency и HTTP 200; HTTP 401/403 как «требует авторизации»; статус `possibleDnsLeak`; статус `notChecked` при отсутствии логов ядра; тест скорости с предупреждением при несовпадении egress IP; санитизация диагностического ZIP; предупреждение при сбое удаления staging.
- **Форензика трафика и ETW-сайдкар:** постоянный сбор сокетов во время VPN (< 0.5% CPU); адаптивная буферизация 200-300 мс / 1-1.5 с / 2-3 с; база 50 МБ / 24 ч с ротацией FIFO; гибридная атрибуция через `Microsoft-Windows-TCPIP` + WinsockAFD + `GetExtendedTcpTable` (4-tuple сопоставление с кэшем процессов); устранение паник unwrap в Rust; потоковый разбор `events.ndjson` для защиты от OOM (F-197); сверка PID при остановке захвата (F-198); сборка через cargo в CI; захват `pktmon --pkt-size 0` с предупреждением; graceful 5с остановка; обязательное удаление устаревшего каталога `diag/` в WP-8.
- **UI/UX, доступность и локализация:** устранение вложенных кнопок; `MacModal` с динамическими ID заголовков, Focus Trap и возвратом фокуса; очистка таймеров в `useEffect`; динамический `<html lang>`; сохранение настроек строго по кнопке «Сохранить»; дизайн-токены Windows Fluent; 100% двуязычная локализация ru/en; обязательная архитектурная декомпозиция монолитных компонентов `Servers.tsx` и `LiveServerCheckSection.tsx` в WP-9; локальные метрики успеха продукта (Leak-Free Rate, MTTR, успешность, чистота отката, время старта) без внешней телеметрии.
- **Рабочие пакеты:** WP-0, WP-5, WP-7, WP-8, WP-9, WP-10, WP-12 (диагностический трек), комплексный Definition of Done.

---

## Рекомендуемый порядок реализации рабочих пакетов

Порядок выстроен по принципу «сначала то, что горит по сроку или по безопасности, потом фундамент, потом фичи». Оценки трудоёмкости в ТЗ не фиксируются и определяются владельцем при планировании итераций.

| # | Пакет | Почему в этой позиции | Срок / условие |
|---|---|---|---|
| 1 | **WP-11 (только миграция Electron 42 → 44)** | Единственный жёсткий внешний дедлайн: после окончания окна поддержки Electron 42 перестаёт получать security-патчи Chromium. | **Миграция выполнена 30.09.2026** (44.4.3, native smoke и build); оставшаяся приёмка WP-11 отдельно. Исходный дедлайн — 20.10.2026. |
| 2 | **WP-1** Секреты, IPC и доверенная граница | Защита секретов, безопасный экспорт и доверенная граница расширены в PR #21. | **Завершён — решение владельца от 07.10.2026.** #21 слит (`5764bc8`); default masking/opt-in export, DPAPI preflight, IPC/CSP и runtime ACL/SHA-256 реализованы. Границы записанных проверок сохранены в отчёте; решение о завершении не добавляет отсутствующие результаты тестов. |
| 3 | **WP-3** Firewall, baseline, recovery | Fail-closed, транзакционный откат, Boot Recovery, узкие CLAT-исключения без обхода kill-switch. | **Частично (сверка 07.10.2026), следующий фокус**: исходный код и локальные проверки есть; #22 сохраняет защиту до runtime exit proof. Все 12 AT нужно адресно сверить; packet oracle, SYSTEM reboot, NAT64/hot-plug/OS matrix не приняты. |
| 4 | **WP-0** Контракты, FSM, наблюдаемость | Фундамент для WP-2 и WP-10: единый автомат состояний, `operationId`, `AbortController`. | До WP-2 и WP-10 |
| 5 | **WP-2** Процессы, runtime, lifecycle туннеля | Зомби-процессы, гонки таймаутов, порядок запуска Xray (F-022, F-025, F-191, F-194). | После WP-0 |
| 6 | **WP-10** Scheduler, rotation, AutoPilot, adaptive bypass | Health-Before-Commit ротации (F-124), баг ночных окон (F-193). | После WP-0 |
| 7 | **WP-6**, **WP-4** Маршрутизация и импорт | Целостность rule-sets, `process_path` в split tunneling, парсеры протоколов. | Параллельно |
| 8 | **WP-7**, **WP-8** Мониторинг и диагностика | Честные статусы проверок, OOM-защита форензики (F-197). | Параллельно |
| 9 | **WP-5**, **WP-9** История проверок, Soft-режим, UI | Пользовательский слой, a11y, декомпозиция монолитных компонентов. | Параллельно |
| 10 | **WP-11 (остаток)** | Installed upgrade/uninstall, release integrity и автообновление. NSIS controlled shutdown уже реализован в #21/#22. | До публичного релиза: собрать installer с последними stop/env fixes и выполнить AT-11/OS matrix; publication `checksums.txt`/`binaries-manifest.json` и update E2E не приняты. |
| 11 | **WP-12** Planned features | AmneziaWG, Mihomo, Chromium Browser Boxes, ETW-процессный монитор. Каждый трек выпускается **отдельным релизом** и стартует только после закрытия WP-0…WP-11. | Последним |

### Следующая рекомендуемая итерация — WP-3 (сверка 07.10.2026)

WP-3 уже реализовывался в PR #13 и lifecycle-работах; PR #21/#22 дополнительно усилили runtime/shutdown boundary. 07.10 исправлены ложный успех Stop при неполном rollback, preflight повреждённых/будущих recovery-схем и смена NIC внутри apply; добавлены отдельная IPv6 WFP-политика и независимый откат WFP/Firewall. Следующий шаг — Windows/L3 по [AT-03-001…012](./04-приёмочные-тесты/04-WP-3-firewall-baseline-recovery.md), включая фактическую установку фильтров и positive/negative CLAT. Код и автоматические регрессии не закрывают системную приёмку; пакет остаётся частичным.

- Вначале сверить доступные L1/L2: частичный отказ независимых шагов rollback и честный общий результат (AT-03-007), конкурентное обновление исключений (008), canonical path/IP/CIDR validation (009), локальные ветки повреждённых манифестов (003).
- Затем Windows/L3: двойной packet oracle при разрыве (001), настоящий SYSTEM reboot recovery (002), чужие firewall rules (004), отсутствие NIC и hot-plug (005/006), IPv6/NAT64/464XLAT (010), DNS failure (011), поддельные ACL-манифесты (012) и поддерживаемая OS-матрица. L2 fixtures не заменяют эти проверки.
- По выявленным пробелам — небольшие адресные исправления; при отсутствии требуемой среды сохранять NOT-CHECKED, а не закрывать пакет по unit PASS.

После этого в рекомендуемом порядке идёт **WP-0**, затем WP-2 и WP-10. **WP-1 завершён по прямому решению владельца от 07.10.2026.** [Матрица отчёта WP-1](../vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md#границы-по-at) сохраняет фактические результаты и NOT-CHECKED; она не является текущим статусом пакета. Раздел 7 ТЗ-06 согласован с этим порядком; историческая запись о завершении WP-3 не является текущим вердиктом; актуальное завершение WP-1 зафиксировано решением владельца.

---

## Связанные папки и репозитории документации

- [docs-factory8090/](../docs-factory8090/): Полный архивный каталог Software Factory 8090, включающий 44 фичи по подсистемам, журнал аудита находок F-001..F-210 (210 находок), реестр вопросов и архитектурные контейнеры.
- [vpn-tunnel-enforcer/docs/](../vpn-tunnel-enforcer/docs/): Технические RFC и дорожные карты приложения (Censorship Resilience Phases 1-8, Traffic Observability RFC, Adaptive Bypass, Multi-Account Isolation).

## Реестр сверки статусов реализации — 04.10.2026

**Дополнение 07.10.2026:** адресно обновлены WP-1/WP-3/WP-11 в порядке работ, плане ТЗ-06 и срезе тома 2; в томе 3 уточнены lifecycle, env cleanup и форензика. Основание — слитые PR #21 (`5764bc8`) и #22 (`324c7cc`), текущие функции экспорта/остановки и NSIS hooks. Остальные срезы от 04.10 не объявляются заново проверенными; нормативные требования перед срезами не изменены.

Срезы реализации находятся в конце каждого из трёх томов. Ниже перечислены источники, учтённые при их исправлении: требования, записанные результаты, границы планов и адресные проверки текущего кода. Записанный старый PASS не означает повторный запуск сейчас; наличие AC/F в таблице трассировки не означает PASS его оракула. В сверке 04.10 полный Vitest и Windows/L3-приёмка не запускались; проверки уточнения 07.10 перечислены отдельно ниже.

| Источник | Что сверено и как отражено в срезах |
| --- | --- |
| [Том 1](./01-ТЗ-СЕТЕВОЕ-ЯДРО-ПРОТОКОЛЫ-И-МАРШРУТИЗАЦИЯ.md), [том 2](./02-ТЗ-СИСТЕМНАЯ-БЕЗОПАСНОСТЬ-ЗАЩИТА-ОТ-УТЕЧЕК-И-ОС.md), [том 3](./03-ТЗ-ЖИЗНЕННЫЙ-ЦИКЛ-АВТОМАТИЗАЦИЯ-UI-И-ДИАГНОСТИКА.md) | Нормативные разделы сопоставлены со статусами; существующий текст требований сохранён. Исправлены WireGuard endpoints, периодическая ротация, adaptive chain, границы мониторинга и состав onboarding. |
| [Методология AT](./04-приёмочные-тесты/00-методология.md) и наборы WP-1/2/3/6/7/9/10/11 | Критерии затронутых утверждений: native smoke не равен всем AT-01; fixtures не равны AT-03 L3; AT-02-008 требует WG endpoints; AT-10-004 требует health-before-commit; AT-09-013 проверяет persistence, AT-09-014 отдельно проверяет импорт ключа и автозапуск. Это сверка критериев, не их исполнение. |
| [ТЗ-06](../docs-factory8090/06-ТЗ-исправление-и-развитие.md) и [решения владельца](../docs-factory8090/05-открытые-вопросы.md) | Пакеты и границы принятых решений; В сверке 04.10 WP-1/WP-3 отмечались частичными; 07.10 владелец подтвердил завершение WP-1. WP-3 остаётся частичным, WP-11 разделён на выполненную миграцию и остаток. Подпись не решена, WP-12 остаётся планом. |
| [Журнал аудита F](../docs-factory8090/00-журнал-аудита.md) и [исходный аудит сентября](../vpn-tunnel-enforcer/docs/audit-findings-2026-09.md) | Сопоставлены статусы и более поздние изменения. Старое F не объявляется закрытым только по новому описанию; опровергнутые находки не возвращаются в план исправлений. |
| [Журнал ускорения lifecycle](../docs-factory8090/07-журнал-ускорения-lifecycle.md), этапы 1–38 | Тематическая сверка изменений, замеров и ограничений: firewall/rollback, recovery worker, startup/stop ownership, CIM/COM, маршруты/IP, DNS, геопроверки, смена сервера и отмена UI. Учитываются ранние этапы, а не только 31–38; benchmark отдельных helpers не засчитывается как время всей операции. |
| [Журнал прогресса](../progress.md) | Миграция Electron 44, восемь native smoke checks и build; отдельно указаны непроверенные cross-version store migration и Windows install/upgrade/uninstall matrix. |
| [Happ compatibility audit](../vpn-tunnel-enforcer/docs/happ-compatibility-audit-2026-10-02.md) | Native Xray JSON/graph, transport/mux/Reality и границы подтверждённой совместимости; успешная конкретная раздача не считается всей протокольной матрицей. |
| [Roadmap](../vpn-tunnel-enforcer/docs/censorship-resilience-roadmap.md) и [индекс фаз](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/README.md) | Даты и локальные статусы фаз имеют приоритет над общим старым roadmap. Фазы 3–6 содержат выполненный слой и конкретный остаток, а не полную приёмку. |
| [Фаза 1 — sing-box](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-01-sing-box-upgrade.md) | Записаны bundled 1.13.13, staging/diagnostics и проверки конфигурации; это не доказывает матрицу 1.13/1.14. |
| [Фаза 2 — rule-set](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-02-dynamic-rule-sets.md) | Managed cache, размер/SHA-256, temp+rename и bundled fallback учтены как сделанные части. Независимый источник доверенного checksum/signature остаётся отдельным требованием. |
| [Фаза 3 — протоколы](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-03-protocol-coverage.md) | URI/JSON parser/export для новых протоколов не равен успешному handshake. В документе прямо оставлена WireGuard endpoint/route integration; текущий генератор подтверждает этот остаток. |
| [Фаза 4 — Naive/ECH](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-04-naive-ech.md) | Parser/config/export и capability diagnostics есть по записанным результатам; known-good remote Naive/ECH matrix и stealth presets остаются. |
| [Фаза 5 — Hysteria2](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-05-hysteria2-advanced.md) | Salamander/mport/hop/bandwidth normalization, capability warnings и schema checks — реализованный слой. Реальный known-good handshake и расширения 1.14 этим не подтверждены. |
| [Фаза 6 — bootstrap](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-06-bootstrap-chaining.md) | Общая policy auto/direct/localProxy для служебных загрузок существует по документу; cold-start через selected VPN profile и external bootstrap profile не реализованы. |
| [Фаза 7 — AmneziaWG](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-07-amneziawg-spike.md), [фаза 8 — CoreAdapter/Mihomo](../vpn-tunnel-enforcer/docs/censorship-resilience-phases/phase-08-core-adapter-mihomo.md) | Проектные чеклисты и лабораторные границы; production runner/adapter и допуск по WP-12 не засчитаны как выполненные. |
| [Adaptive plan](../vpn-tunnel-enforcer/docs/adaptive-bypass-plan.md) и [implementation log](../vpn-tunnel-enforcer/docs/adaptive-bypass-implementation-log.md) | Старые compatibility retries сверены с более поздним этапом 32. Наличие fallback и health window не доказывает нормативный порядок Direct → Reality → HY2 → SS. |
| [Traffic Observability RFC](../vpn-tunnel-enforcer/docs/traffic-observability-rfc.md) | Отделена реализованная фаза ETW sidecar от проектных flow correlation/driver и постоянного монитора WP-12. Ограничение PID attribution сохранено. |
| [Multi-account isolation plan](../vpn-tunnel-enforcer/docs/multi-account-isolation-plan.md) | Исторический проект архитектуры; production Browser Boxes не реализованы. Решения владельца проверяются по ТЗ-06, а не по старому списку вопросов этого плана. |
| [VLESS/QUIC investigation](../vpn-tunnel-enforcer/docs/vless-quic-fallback-investigation.md) | Историческое исследование транспорта; не принимается за свежий proof всех UDP/QUIC маршрутов. |
| [Architecture README](../vpn-tunnel-enforcer/docs/architecture/README.md), [module map](../vpn-tunnel-enforcer/docs/architecture/module-map.md), [review guide](../vpn-tunnel-enforcer/docs/architecture/review-guide.md) | Карта модулей и границ проверки использована для адресной сверки parser/generator, rotation, adaptive bypass и wizard. |
| [Split tunneling](../vpn-tunnel-enforcer/src/main/splitTunneling.ts), [NSIS hooks](../vpn-tunnel-enforcer/build/installer.nsh), [config export](../vpn-tunnel-enforcer/src/main/configManager.ts) | Сверка PR #20 за 04.10 фиксировала отсутствие трёх реализаций. Уточнение 07.10: F-076 по `process_name` сохраняет прежний остаток; #21 реализовал default masking и main-owned opt-in export (F-144), controlled shutdown вместо force-kill в NSIS hooks (F-183); #22 усилил exit proof. Полные AT-01-008/AT-11-002/009 не приняты; реализация этих участков не равна закрытию всех находок/пакетов. |
| [PR #21](https://github.com/newnout6-a11y/vpn/pull/21), [отчёт WP-1](../vpn-tunnel-enforcer/docs/wp1-security-acceptance-2026-10-04.md) | 10 коммитов, merge `5764bc8` от 06.10. DPAPI/SecretRef, export policy, IPC/CSP, runtime ACL/hash; связанные capture/shutdown/env cleanup fixes. Матрица AT-01 различает native subsets, envelope fuzz, same-version migration и полный installed/L3 остаток. |
| [PR #22](https://github.com/newnout6-a11y/vpn/pull/22), [progress](../progress.md) | Merge `324c7cc` от 06.10: сохранение upstream/watchdog/защиты при неподтверждённом runtime stop (`14b33fe`, `dcabbb2`, `18ee27c`), engine-log retention, installer task cleanup и Xray routeOnly. Это поддерживает WP-2/3/8/11; не закрывает все AT-03. Последний NSIS на `9b7bc93` предшествует последующим stop/env fixes. |
| [Scheduler](../vpn-tunnel-enforcer/src/main/scheduler.ts), [domain routing](../vpn-tunnel-enforcer/src/main/domainRouting.ts), [availability verdict](../vpn-tunnel-enforcer/src/main/urlAvailability.ts), [speed test](../vpn-tunnel-enforcer/src/main/speedTest.ts) | Повторно подтверждены F-193 (нет предыдущего дня `dayOffset=-1`), F-011 (hit recorder отсутствует и постоянного счётчика нет), F-210/F-085 (direct-only 401/403 даёт ложный `works-only-with-vpn`) и F-010 (egress mismatch подавляется пустым catch). Обновлены срезы требований и статусы WP-6/7/10; адресные проверочные сценарии привязаны к AT-10-002, AT-06-003 и AT-07-006. |

Архивные 44 feature requirements/blueprint пары из `docs-factory8090/01…04` не перепроверялись построчно в этой сверке. Их находки учитываются через журнал F, ТЗ-06 и нормативные тома; этот реестр не заявляет полного повторного чтения всех Markdown репозитория.

### Записанные измерения, учтённые в статусе производительности

Этап 36 lifecycle-журнала фиксирует connect **4317/2719 мс**, смену на Sweden **3270 мс**, отмену Norway **1751 мс**. Это отдельные пользовательские IPC-операции; отмена не засчитывается как успешное подключение. Прежние 23–50 мс после отмены были сохранением offline-профиля и не отражали реальную смену туннеля. Этапы 14/28 фиксируют ускорение recovery transport и Firewall API, но их microbenchmarks не заменяют эти измерения. Выборки для продуктовой медианы и прямого сопоставимого замера Happ недостаточно.

### Проверки документационной сверки 04.10.2026

- В `vpn-tunnel-enforcer/`: `npm.cmd run typecheck` — exit 0; `npx.cmd vitest run src/renderer/components/LiveServerCheckSection.test.tsx --maxWorkers=4` — 1 файл, 4 теста passed, exit 0. Это адресная регрессия history IPC, а не проверка всех 10 diff-веток.
- Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — exit 0, AC 927/927, F 210/210.
- Проверены 42 локальные Markdown-ссылки в пяти изменённых файлах, четыре столбца таблиц среза и неизменность нормативного текста до срезов; `git diff --check` — exit 0.

### Проверки адресного уточнения 07.10.2026

- В `vpn-tunnel-enforcer/`: `npm.cmd run typecheck` — exit 0; `npm.cmd test -- --reporter=dot` — **211 файлов passed / 2 skipped; 2648 тестов passed / 9 skipped / 0 failed**, 157.84 с, exit 0.
- Из корня: `python -X utf8 docs/04-приёмочные-тесты/traceability/check-coverage.py` — AC 927/927, F 210/210, exit 0.
- Inline Python-проверка (`python -X utf8 -`): 52 локальные ссылки, четыре столбца таблиц срезов, неизменность требований перед срезами томов 2/3 и согласованность следующего WP-3 → WP-0 — PASS. Первый запуск проверки завершился на слишком строгом строковом ожидании формулировки порядка; после исправления самого checker все проверки прошли.
- `git diff --check` — exit 0. Изменена только документация; installed/Windows L3, native acceptance, полный fuzz, миграция 42→44 и сборка NSIS в этой задаче не выполнялись. Новых закрытий F/AC/AT не объявлено.
