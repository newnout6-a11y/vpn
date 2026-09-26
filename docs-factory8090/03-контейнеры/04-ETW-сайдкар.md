# ETW-сайдкар

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/18b4a605-0ce4-4e22-92dc-c34a31202d11

# ETW-сайдкар

## Container Summary

Нативный Windows-процесс `vpnte-etw-sidecar.exe`, собранный из Rust-крейта `native/vpnte-etw-sidecar`. Он создаёт real-time ETW-сессию через `ferrisetw`, слушает провайдеры TCPIP, DNS-Client, WFP, Winsock-AFD и WebIO и пишет нормализованные NDJSON-события для форензики трафика.

Связанная область: [@Форензика трафика](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/2228c0c0-e5ba-4d14-ae00-693962666363).

## Infrastructure

* Windows native executable, packaged как `extraFiles`.
* Rust edition 2021; зависимости включают `ferrisetw 1.2.0`, `time` и `serde_json`.
* Стабильное имя ETW-сессии `VPNTE-ETW`; процесс пишет heartbeat и ограничивает объём data events.

## Entry Points and Boundaries

* Main запускает sidecar с параметрами `--events`, `--session`, `--providers`.
* Sidecar создаёт каталог события, записывает lifecycle-строки и нормализованные события в `events.ndjson`.
* Main читает manifest/session output и использует события в `trafficForensics.ts` и `trafficForensicsSummary.ts`.
* Остановка инициируется main через stdin/завершение дочернего процесса; sidecar закрывает ETW trace при graceful stop.

## System Contracts

### Key Contracts

* Формат строк должен оставаться совместимым с потребителем форензики: lifecycle/health и data events.
* Если provider не разрешён, sidecar записывает health-событие; если ни один provider не включён, процесс завершается с ошибкой.
* Стабильное имя ETW-сессии используется для reclaim orphaned trace.

### Integration Contracts

* CLI-контракт: `--events <path> --session <id> --providers <csv>`.
* File contract: NDJSON с полями provider, category, event и контекстом события.
* Main ожидает sidecar executable рядом с packaged resources.

### Integration Boundaries

* Sidecar имеет доступ к ETW-провайдерам Windows и системному трафику только для диагностической форензики.
* Он не владеет VPN lifecycle, firewall или пользовательскими настройками.
* Sidecar является предпочтительным движком относительно PowerShell poller, но в коде сохраняются fallback-пути.

## Architecture Decision Records

### ADR-001: Нативный ETW consumer

**Context:** PowerShell polling недостаточно хорошо подходит для real-time форензики.

**Decision:** Использовать Rust и `ferrisetw` для real-time ETW trace.

**Consequences:** События поступают с меньшей задержкой, но сборка требует Rust toolchain и Windows ETW.

### ADR-002: Нормализованный NDJSON

**Context:** Main и summary должны читать единый поток событий независимо от провайдера.

**Decision:** Писать по одной нормализованной JSON-строке на событие.

**Consequences:** Потребитель прост, а размер и чувствительность журнала требуют ограничений и редактирования.
