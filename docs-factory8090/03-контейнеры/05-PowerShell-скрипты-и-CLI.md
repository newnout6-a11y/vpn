# PowerShell-скрипты восстановления и CLI

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/ed567a87-6a3a-44a3-bff8-b9c0ad659b85

# PowerShell-скрипты восстановления и CLI

## Container Summary

Windows-скрипты, которые обеспечивают boot recovery, EOS-совместимость и внешний CLI для управления локальными proxy-процессами. Основные артефакты находятся в `resources/`: `vpnte-recover.ps1`, `vpnte-eos-compat.ps1`, `vpnte-proxy.ps1` и `vpnte-proxy.cmd`.

Связанные области: [@Восстановление сети после сбоя](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/c7f263d1-2de1-4316-9941-819877c1817d), [@Внешний локальный прокси](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/0364ee3d-d6fd-4bf4-9de8-09e94f157a53), [@Автоматизация](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/aafe4727-39c9-416d-95f9-a65b44ebfa9b).

## Infrastructure

* Windows PowerShell и системные командлеты сетевого стека, firewall, реестра, DNS и scheduled tasks.
* `VPNTE Boot Recovery` регистрируется как задача `ONSTART` от `SYSTEM` через `schtasks`.
* Локальный HTTP API внешнего proxy-контроллера слушает `127.0.0.1:17873`.
* Скрипты поставляются через `extraResources` и `extraFiles` electron-builder.

## Entry Points and Boundaries

* Boot recovery читает manifest lockdown и восстанавливает firewall, DNS, IPv6, transition adapters, registry policy, env proxy и stale TUN.
* `vpnte-proxy.ps1/.cmd` принимают CLI-действия и обращаются к локальному API на `127.0.0.1:17873`.
* `vpnte-eos-compat.ps1` запускается установщиком для совместимости EOS-среды.
* Main создаёт scheduled task при синхронизации login item, а не при каждом произвольном запуске скрипта.

## System Contracts

### Key Contracts

* Recovery должен восстанавливать только известное состояние из manifest, а не переписывать произвольные пользовательские настройки.
* Внешний API требует control token для status и mutation paths.
* Скрипты должны сохранять диагностический журнал в ProgramData или fallback TEMP.
* Запуск recovery от SYSTEM создаёт высокий trust boundary: manifest и пути должны считаться чувствительными.

### Integration Contracts

* Manifest `latest-physical-adapter-lockdown.json` связывает состояние адаптеров, DNS, IPv6 и registry с откатом.
* CLI передаёт параметры профиля/группы в HTTP API и получает JSON или text response.
* `vpnte-recover.ps1` управляет Windows Firewall cmdlets, DNS cmdlets, registry и `netsh`.

### Integration Boundaries

* Scheduled task действует в контексте SYSTEM и меняет глобальное состояние Windows.
* CLI является локальной внешней границей для Happ/других клиентов и не заменяет IPC renderer-main.
* API не проверяет Host header, F-006.
* Recovery читает пользовательские manifest-пути без полноценной проверки владельца/ACL, F-038.
* EOS-скрипт содержит необратимые изменения без полного rollback, F-040.

## Architecture Decision Records

### ADR-001: Recovery через ONSTART task

**Context:** После падения приложения сеть может остаться заблокированной до входа пользователя.

**Decision:** Регистрировать `VPNTE Boot Recovery` как SYSTEM scheduled task на старте Windows.

**Consequences:** Восстановление возможно до входа пользователя, но task и manifest становятся критической системной границей.

### ADR-002: Локальный HTTP CLI

**Context:** Внешним локальным клиентам нужен независимый от renderer путь управления proxy-профилями.

**Decision:** Предоставить API на loopback `:17873` и thin CLI-обёртки PowerShell/CMD.

**Consequences:** API удобно автоматизировать, но нужно поддерживать token и защиту loopback boundary.
