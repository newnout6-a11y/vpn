# Electron main-процесс

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/ea90c1bf-9dea-405d-9d34-6de5ad5bbab0

# Electron main-процесс

## Container Summary

Главный процесс приложения Electron для Windows. Он управляет жизненным циклом приложения, окном, системным треем, восстановлением состояния сети, IPC-границей и запуском runtime-процессов. Реализация сосредоточена в `src/main`, включая крупный orchestration-файл `src/main/index.ts` (аудит F-019).

Связанные области: [@Подключение VPN](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/cd855824-11c3-4932-aa27-8c69b7d00a28), [@Защита от утечек](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/f3017099-e483-4400-9819-910d61196d52), [@Восстановление сети после сбоя](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/c7f263d1-2de1-4316-9941-819877c1817d).

## Infrastructure

* Windows desktop runtime на Electron 42.
* Main bundle собирается `electron-vite` в `out/main`.
* В packaged-режиме single-instance lock запрашивается только при `app.isPackaged`.
* Приложение может требовать административные права через установщик и запускает сетевые операции с повышенными правами.
* Зависит от BrowserWindow, `ipcMain`, системного трея, Windows Firewall, сетевых API Windows и дочерних runtime-процессов.

## Entry Points and Boundaries

* Electron lifecycle events: `app.whenReady`, `activate`, `before-quit`, `window-all-closed`.
* Renderer вызывает main через зарегистрированные `ipcMain.handle` каналы. Main возвращает сериализованные результаты и отправляет события в renderer через `webContents.send`.
* При готовности приложения сначала выполняется crash recovery, затем создаются окно и tray. Это обеспечивает восстановление до показа окна.
* Tray вызывает запуск защиты и восстановление/фокус окна.
* Main регистрирует IPC-обработчики для туннеля, настроек, маршрутизации, серверов, диагностики, форензики и внешнего прокси.

## System Contracts

### Key Contracts

* При втором packaged-запуске процесс не выполняет recovery и завершается, а первый получает событие фокуса.
* При завершении main выполняется best-effort остановка TUN, Xray, внешних proxy-процессов и откат сетевого baseline, kill-switch, lockdown адаптеров и env proxy.
* Startup recovery не должен запускаться вторым экземпляром.
* Ошибки фоновых операций журналируются и не должны оставлять stale pointer на уничтоженное окно.

### Integration Contracts

* `ipcMain.handle` принимает команды от `contextBridge` API preload и вызывает доменные модули main.
* Main публикует события статуса TUN, публичного IP, трафика, уведомлений, tray и прогресса live-check.
* Main передаёт `tunController` сгенерированный конфиг и управляет внешними процессами sing-box/Xray.

### Integration Boundaries

* Renderer не получает прямой доступ к Node.js и Windows API, граница проходит через preload IPC.
* Main имеет доступ к секретам, файловой системе, дочерним процессам и системным изменениям.
* Внешние сетевые сервисы вызываются из main, а не из renderer.

## Architecture Decision Records

### ADR-001: Восстановление до создания окна

**Context:** Сбой может оставить firewall, DNS, IPv6 или TUN в изменённом состоянии.

**Decision:** В `app.whenReady` выполнить crash recovery до `createWindow`.

**Consequences:** Пользователь видит окно после попытки восстановления. Ошибки recovery остаются диагностируемыми через журнал.

### ADR-002: Single instance только для packaged-сборки

**Context:** Разработка требует возможности запускать несколько экземпляров, а установленное приложение должно исключать конкурирующий recovery.

**Decision:** Вызывать `requestSingleInstanceLock()` только когда `app.isPackaged`.

**Consequences:** Dev-режим сохраняет гибкость. Установленная версия защищает сетевое состояние от конкурирующих экземпляров.

### ADR-003: Orchestration в main

**Context:** Lifecycle, IPC и запуск подсистем сосредоточены в `index.ts`.

**Decision:** Сохранять main как boundary и orchestration-слой, а работу делегировать модулям `src/main`.

**Consequences:** Граница видима и централизована, но размер god-file остаётся техническим долгом F-019.
