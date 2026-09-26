# Сетевое ядро: sing-box и Xray

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/c9536d0b-e41f-43cb-bca2-32481a1f85cc

# Сетевое ядро: sing-box и Xray

## Container Summary

Контейнер включает управляемые внешние сетевые бинарники sing-box и Xray, которые запускаются main-процессом Windows. sing-box создаёт TUN/Wintun, применяет сгенерированный конфиг и маршрутизацию; Xray используется как локальный SOCKS upstream для профилей с REALITY в Direct VPN.

Связанные области: [@Подключение VPN](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/cd855824-11c3-4932-aa27-8c69b7d00a28), [@Маршрутизация](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/dd03ac0b-2faf-44c8-ba8d-383aad183285), [@Защита от утечек](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/f3017099-e483-4400-9819-910d61196d52).

## Infrastructure

* Windows runtime-каталог создаётся приложением и содержит staged `sing-box.exe`, `xray.exe`, `wintun.dll` и `libcronet.dll`.
* Установщик требует административные права; запуск TUN и системных изменений использует elevated PowerShell/Windows API.
* `tunController.ts` генерирует конфигурацию sing-box в runtime-каталоге.
* `xrayEngine.ts` создаёт конфиг Xray и запускает `vpnte-xray.exe` с loopback SOCKS-портом.

## Entry Points and Boundaries

* Main вызывает start/stop для sing-box и Xray через контроллеры и IPC-команды подключения.
* sing-box принимает сгенерированный конфиг, поднимает Wintun/TUN и выполняет DNS/rule-set/маршрутизацию.
* Xray принимает преобразованный профиль и предоставляет локальный SOCKS upstream для sing-box.
* Управление firewall kill-switch и baseline остаётся в main, рядом с запуском ядра.

## System Contracts

### Key Contracts

* Runtime-процессы должны запускаться только из управляемого runtime-каталога.
* Остановка приложения должна остановить принадлежащие процессы и откатить системные изменения.
* При REALITY в автоматическом выборе engine используется Xray, остальные совместимые outbound остаются на sing-box.
* Конфиг передаётся бинарнику через файл, а статус и ошибки возвращаются в main для UI и recovery.

### Integration Contracts

* Вход: `ServerProfile.outbound` и параметры режима подключения.
* Выход sing-box: TUN-интерфейс, локальные proxy listeners и события процесса.
* Выход Xray: loopback SOCKS-порт, который указывается как upstream в конфиге sing-box.
* Wintun и Windows Firewall являются платформенными контрактами, а не частями renderer.

### Integration Boundaries

* Бинарники являются внешними процессами, но их жизненным циклом владеет main.
* Wintun и firewall меняют глобальное состояние Windows и требуют отката.
* Поддержка WireGuard между README/парсером и sing-box 1.13 расходится, F-047. Это вопрос совместимости, а не утверждение о гарантированной работе.
* Runtime инициализируется с повышенными правами, поэтому контроль пути, ACL и принадлежности процессов критичен, F-002 и F-003.

## Architecture Decision Records

### ADR-001: sing-box как TUN-движок

**Context:** Приложению нужен Windows TUN с маршрутизацией и защитой от утечек.

**Decision:** Передавать сгенерированный конфиг bundled sing-box и использовать Wintun.

**Consequences:** Основной сетевой поток централизован в sing-box; изменения версии требуют проверки схемы конфигурации.

### ADR-002: Xray для REALITY

**Context:** Код содержит отдельный преобразователь REALITY-профилей в Xray-конфигурацию.

**Decision:** Запускать Xray на loopback и подключать его как локальный upstream для sing-box.

**Consequences:** Улучшается совместимость с REALITY-профилями, но появляется второй runtime-процесс и отдельный lifecycle.
