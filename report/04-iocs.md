# Indicators of Compromise (IOC)

> Все IOC в этом документе являются **синтетическими** и приведены только для образовательных целей. Они не соответствуют реальным угрозам.

## 1. Файловые IOC

| Файл | Путь | SHA256 (синтетический) | Описание |
|------|------|------------------------|----------|
| `Invoice_Q3_2024.docm` | `%USERPROFILE%\Downloads\` | `a2b3c4...` | Фишинговый документ с макросом |
| `svchost_.exe` | `%TEMP%\` | `f1e2d3...` | Обфусцированный лоадер |
| `payload.bin` | в памяти `explorer.exe` | – | Расшифрованная полезная нагрузка |
| `decryptor.dll` | `%APPDATA%\Microsoft\` | `b5c6d7...` | Модуль расшифровки |

## 2. Сетевые IOC

| Тип | Значение | Описание |
|-----|----------|----------|
| Домен C2 | `update-srv.acme-cdn.net` | Загрузка второй стадии |
| IP-адрес | `203.0.113.25` | C2-сервер (синтетический) |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` | Использовался для HTTPS-запросов |
| Порт | `443` | Шифрованный канал |
| JA3-фингерпринт | `6734f374...` | Синтетический, для примера |

## 3. Реестр и система

| Ключ / значение | Данные | Описание |
|-----------------|--------|----------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `"Updater" = "%APPDATA%\Microsoft\decryptor.dll, Run"` | Персистентность через автозапуск |
| Mutex | `Global\SvcHostUpdateMutex` | Мьютекс, используемый лоадером |
| Запланированная задача | `\Microsoft\Windows\Update\ScheduledTask` | Запуск лоадера каждые 30 мин (синтетический пример) |

## 4. События Sysmon (кратко)

- **EventID 1** – Process Create: `svchost_.exe` из `%TEMP%`.
- **EventID 7** – Image Loaded: `decryptor.dll` (без подписи).
- **EventID 8** – CreateRemoteThread: из `svchost_.exe` в `explorer.exe`.
- **EventID 10** – ProcessAccess: `PROCESS_ALL_ACCESS` к `explorer.exe`.
- **EventID 25** – ProcessTampering: модификация `explorer.exe`.

Полные примеры событий – в [`artifacts/sysmon-events.json`](../artifacts/sysmon-events.json).
