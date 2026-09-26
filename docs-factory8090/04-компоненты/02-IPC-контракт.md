# IPC-контракт main и renderer

> Источник: https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/4557635c-3284-4d06-b149-256a551f38db

# IPC-контракт main и renderer

## Capability Summary

Возможность задаёт мост между renderer и main через contextBridge, общие типы каналов и регистрацию обработчиков `ipcMain.handle`. Preload публикует большой интерфейс `ElectronAPI`, а main журналирует вызовы и результаты. Текущее состояние содержит открытые вопросы безопасности и согласованности, зафиксированные как F-139, F-140, F-141 и F-142.

## Core Components

### Контракт и мост

```component
name: PreloadIpcBridge
container: Preload, Renderer
responsibilities:
	- Экспортирует ElectronAPI через contextBridge.
	- Вызывает ipcRenderer.invoke для команд и регистрирует подписки на события main.
	- Передаёт в renderer типизированные и частично типизированные результаты.
```

```component
name: SharedIpcTypes
container: Preload, Main Process, Renderer
responsibilities:
	- Определяет модели данных, перечисления и типы параметров каналов в src/shared/ipc-types.ts.
	- Служит общей декларацией формата данных между процессами.
```

```component
name: MainIpcDispatcher
container: Main Process
responsibilities:
	- Регистрирует обработчики через ipcMain.handle.
	- Оборачивает обработчик журналированием старта, результата и ошибки.
	- Передаёт event и аргументы конкретному слушателю.
```

#PreloadIpcBridge зависит от `SharedIpcTypes` на уровне типов и вызывает #MainIpcDispatcher по именам каналов. #MainIpcDispatcher возвращает значения, которые renderer использует как API приложения.

## System Contracts

### Key Contracts

* Канал должен иметь одну согласованную декларацию имени, параметров и результата в preload, main и shared типах.
* Доверенный renderer должен вызывать только опубликованные методы ElectronAPI.
* Ошибка main-обработчика должна возвращаться как ошибка IPC и фиксироваться журналом.
* Нужны отдельные решения по проверке `senderFrame`, runtime-валидации и форме передачи URI. Текущие ограничения отмечены F-139, F-140 и F-141.

### Integration Contracts

* Preload предоставляет `window.electronAPI` для команд, запросов и событий.
* Main использует `ipcMain.handle(channel, listener)` для request/response-вызовов.
* `src/shared/ipc-types.ts` содержит общие структуры, включая профили, группы, диагностику, kill-switch и историю.
* Полный URI профиля сейчас доступен renderer через экспортный контракт. Это требует решения о минимально необходимой видимости, F-140.

## Architecture Decision Records

### ADR-001: Изолированный preload-мост

**Context:** Renderer должен управлять приложением без прямого доступа к Node.js и Electron IPC API.

**Decision:** Публиковать ограниченный интерфейс через contextBridge.

**Consequences:** Поверхность доступа видна и централизована, но безопасность зависит от проверки входных данных и источника сообщения.

### ADR-002: Общие типы без полного runtime-контракта

**Context:** Общие TypeScript-типы уменьшают расхождения при компиляции.

**Decision:** Хранить модели в shared/ipc-types.ts и выполнять runtime-проверки только для части входов.

**Consequences:** Типы улучшают разработку, но не защищают от произвольного IPC-вызова без runtime-валидации, F-141 и F-142.

## Traceability

Связанные feature-блюпринты: [@Подключение VPN](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/cd855824-11c3-4932-aa27-8c69b7d00a28), [@Настройки](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/13f9bb36-2b19-4672-8824-a905be2c406b), [@Диагностика](https://factory.8090.ai/project/992274e4-1c6b-4d44-8c22-e4c038e690c2/blueprints/5baba2e5-3ca5-4fa3-bf3d-eab4cb6ed8f7).

Аудит: F-139, F-140, F-141, F-142.
