# Renderer и preload

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/8ac6e832-e39d-4d69-8502-f0ea4cfbef86

# Renderer и preload

## Container Summary

Renderer и preload образуют клиентскую часть Electron-приложения. Renderer использует React 18, Zustand 4 и Tailwind CSS 3; preload публикует ограниченный `window.electronAPI` через `contextBridge` и проксирует вызовы в IPC. Навигация хранится локально в `App.tsx`, без router-библиотеки.

Связанные области: [@Настройки](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/13f9bb36-2b19-4672-8824-a905be2c406b), [@Мониторинг](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/922a4ecc-77bc-49b3-a290-b7978a878172), [@Диагностика](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/5baba2e5-3ca5-4fa3-bf3d-eab4cb6ed8f7).

## Infrastructure

* Renderer собирается `electron-vite` из `src/renderer` в `out/renderer`.
* React 18.3, Zustand 4.5, Tailwind CSS 3.4, i18next и связанные UI-библиотеки указаны в `package.json`.
* Preload собирается отдельно в `out/preload`.
* `src/shared/ipc-types.ts` содержит общие типы моделей и IPC-контрактов, но в публичном API остаются `any` (аудит F-019).

## Entry Points and Boundaries

* Renderer загружает десять lazy-страниц: Dashboard, SplitTunnel, Servers, SpeedTest, Availability, TrafficHistory, Schedule, Settings, Logs и Maintenance.
* `App.tsx` хранит текущую страницу в `useState` и переводит событие `vpnte:navigate` в `setPage`.
* Preload вызывает `ipcRenderer.invoke` для команд и регистрирует подписки `ipcRenderer.on` для событий main.
* `contextBridge.exposeInMainWorld('electronAPI', ...)` публикует API для renderer.
* CSP добавляется обработчиком `session.defaultSession.webRequest.onHeadersReceived` только в packaged-контуре, что отмечено F-132.

## System Contracts

### Key Contracts

* Renderer не должен использовать Node.js API напрямую.
* Входы основных preload-функций проверяются assertion-функциями, однако некоторые ответы и настройки типизированы через `any`.
* IPC-события должны корректно отписываться при размонтировании React-компонентов.
* Навигация ограничена перечислением `AppPage` и не требует отдельного маршрутизатора.

### Integration Contracts

* `ElectronAPI` является boundary-контрактом между renderer и main.
* `src/shared/ipc-types.ts` описывает `ServerProfile`, `ServerGroup`, статусы и параметры live-check, которые проходят через IPC.
* Main отправляет renderer события `tun-status-changed`, `ip-changed`, обновления трафика, темы, локали и прогресса операций.

### Integration Boundaries

* Preload является единственной экспонированной границей main API.
* Проверка `senderFrame` в проверенных IPC-обработчиках не подтверждена, это открытый security-вопрос F-139.
* CSP не применяется одинаково в dev и packaged режимах, F-132.
* Стек Electron 42 и часть frontend-инструментов требуют планового обновления, F-159.

## Architecture Decision Records

### ADR-001: API через contextBridge

**Context:** Renderer должен вызывать операции Windows и main без прямого Node.js доступа.

**Decision:** Экспортировать `ElectronAPI` через `contextBridge`, а команды реализовать через `ipcRenderer.invoke`.

**Consequences:** Граница API явная. Дальнейшее усиление должно включать проверку источника IPC, включая вопрос F-139.

### ADR-002: Локальная навигация без router

**Context:** Набор страниц конечен, а переходы инициируются из разных компонентов.

**Decision:** Использовать `App.tsx` с `setPage` и CustomEvent `vpnte:navigate`.

**Consequences:** Меньше инфраструктуры, но состояние маршрута не представлено URL.
