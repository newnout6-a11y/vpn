# Диагностический harness для sing-box TUN

Автоматизация тестирования маршрутизации **без пересборки Electron и без UAC на каждом цикле**.

## Как это работает

1. `install.ps1` **один раз** регистрирует Scheduled Task `VPN-Diag-SingBox` с правами админа.
2. После этого любой запуск/остановка `sing-box` идёт через `schtasks.exe` — **UAC больше не спрашивает**.
3. Конфиг лежит в `diag/tunnel-config.json` — редактируется напрямую, без перекомпиляции.
4. Лог пишется в `%APPDATA%\vpn-tunnel-enforcer\diag-runtime\sing-box.log`.

## Первичная установка (один раз)

От пользователя нужно **только это**:

```powershell
# 1. PowerShell от администратора
cd <корень репозитория>\vpn-tunnel-enforcer
.\diag\install.ps1
```

UAC-запрос один раз — соглашаешься. Всё.

## Запуск Happ

Перед тестами должен работать Happ в **Proxy mode** на `127.0.0.1:10808`.
Если порт другой — отредактируй `diag/tunnel-config.json` (`server_port`).

## Цикл тестирования (делает Cascade, без участия пользователя)

```powershell
# Полный прогон: stop → apply config → start → wait → stop → summary
.\diag\run-test.ps1 -DurationSec 5
```

Скрипт:
1. Останавливает любой старый `sing-box`
2. Копирует `diag/tunnel-config.json` в runtime
3. Запускает задачу (без UAC)
4. Ждёт указанное число секунд
5. Параллельно в отдельном окне делает HTTP-тест (`curl https://api.ipify.org`)
6. Останавливает
7. Выводит сводку: старт-OK, DNS-правило которое сработало, исходящий IP

## Удаление

```powershell
.\diag\uninstall.ps1  # UAC один раз
```

## Файлы

| Файл | Назначение |
|---|---|
| `install.ps1` | Регистрирует Scheduled Task (UAC один раз) |
| `uninstall.ps1` | Удаляет Scheduled Task (UAC один раз) |
| `tunnel-config.json` | Редактируемый конфиг sing-box |
| `run-test.ps1` | Полный цикл теста (без UAC) |
| `tail-log.ps1` | Показать хвост лога |
| `summary.ps1` | Быстрый анализ лога (DNS/маршруты/ошибки) |
