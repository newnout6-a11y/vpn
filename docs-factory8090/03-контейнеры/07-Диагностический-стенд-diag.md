# Диагностический стенд diag (инструмент разработчика)

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/d130ceae-73e6-478b-95a4-4a0c20ab5d68

# Диагностический стенд diag (инструмент разработчика)

## Container Summary

`diag/` содержит автономный PowerShell/Node.js стенд разработчика для ручной проверки sing-box TUN. Он устанавливает scheduled task, копирует sing-box и Wintun в диагностический runtime, запускает тестовый цикл и собирает краткую сводку.

Связанная область: [@Диагностика](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/5baba2e5-3ca5-4fa3-bf3d-eab4cb6ed8f7).

## Infrastructure

* Windows PowerShell, `schtasks`, `Get-NetAdapter`, `Test-NetConnection`, процессы sing-box и Happ.
* Конфиг `diag/tunnel-config.json` задаёт диагностический TUN-профиль.
* Runtime и лог находятся в `%APPDATA%\\vpn-tunnel-enforcer\\diag-runtime`.
* Стенд ожидает Happ в Proxy mode на `127.0.0.1:10808`.

## Entry Points and Boundaries

* `install.ps1` создаёт диагностическую scheduled task и копирует runtime artifacts.
* `run-test.ps1` останавливает старый sing-box, проверяет TUN/Happ, запускает task, ждёт процесс и записывает результат.
* `summary.ps1` и `tail-log.ps1` читают диагностический лог.
* `uninstall.ps1` останавливает процесс и удаляет диагностическую установку.
* `detect-tun.js` классифицирует сетевые адаптеры по именам.

## System Contracts

### Key Contracts

* Стенд предназначен для ручной диагностики и не является runtime-контуром продукта.
* Тестовый цикл не должен восприниматься как замена main lifecycle или production recovery.
* Проверка внешнего proxy использует loopback `127.0.0.1:10808`.

### Integration Contracts

* Scheduled task запускает `resources/sing-box.exe` с `diag/tunnel-config.json`.
* Лог `sing-box.log` является входом для summary/tail scripts.
* Сетевые проверки используют Windows PowerShell cmdlets и локальный Happ listener.

### Integration Boundaries

* Стенд напрямую управляет процессом sing-box и TUN, вне IPC main.
* Он использует устаревшие диагностические сценарии, что отмечено F-170, F-171 и F-172.
* Артефакты стенда могут конфликтовать с рабочим VPN runtime, поэтому граница должна оставаться developer-only.

## Architecture Decision Records

### ADR-001: Отдельный ручной harness

**Context:** Нужен быстрый ручной цикл проверки TUN без запуска полного Electron UI.

**Decision:** Сохранить scripts в `diag/` с отдельным runtime и логами.

**Consequences:** Диагностика проще для разработчика, но сценарии требуют синхронизации с текущим runtime и не являются production source of truth.
