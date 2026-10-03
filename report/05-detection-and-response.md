# Detection and Response

## 1. Детекты (Sigma / YARA)

### 1.1 Sigma: подозрительная инъекция из Temp/AppData

**Файл:** [`detections/sigma/injection_temp.yaml`](../detections/sigma/injection_temp.yaml)

```yaml
title: Suspicious Process Injection from Temp or AppData
id: 6f3a2b4c-1d2e-4f5a-9b8c-7d6e5f4a3b2c
status: experimental
description: |
  Detects process injection from an executable located in Temp or AppData
  into a trusted system process (e.g., explorer.exe).
  Intended for training and requires tuning in production.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        SourceImage|contains:
            - '\Temp\'
            - '\AppData\'
        TargetImage|endswith:
            - '\explorer.exe'
            - '\svchost.exe'
            - '\lsass.exe'
    condition: selection
falsepositives:
    - Debuggers, installers, некоторые EDR-агенты могут создавать удалённые потоки.
level: high
```

### 1.2 YARA: подозрительный расшифровщик (decryptor stub)

**Файл:** [`detections/yara/susp_decryptor.yar`](../detections/yara/susp_decryptor.yar)

```yara
rule Suspicious_Decryptor_Stub_Training {
    meta:
        description = "Training rule to detect common decryptor stub patterns in loaders"
        author = "SOC Team"
        severity = "high"
        disclaimer = "For educational use only; may produce false positives on legitimate tools"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $mz = { 4D 5A }
    condition:
        $mz at 0 and 2 of ($api*)
}
```

> ⚠️ Правила предназначены для обучения и требуют валидации и настройки под вашу среду.

---

## 2. Процесс реагирования SOC

### 2.1 Первичное обнаружение (L1)

- Алерт от EDR на аномальную инъекцию в `explorer.exe`.
- L1 проверяет:
  - источник процесса (`svchost_.exe` из `%TEMP%`);
  - наличие других алертов на этом хосте;
  - контекст пользователя (бухгалтерия, HR и т.п.).

### 2.2 Эскалация и анализ (L2)

- L2 анализирует:
  - цепочку процессов (Word → PowerShell → `svchost_.exe` → `explorer.exe`);
  - события Sysmon (ProcessCreate, ImageLoaded, CreateRemoteThread, ProcessAccess);
  - сетевые соединения (подозрительные домены/IP).
- Принимается решение о классификации инцидента как **confirmed malicious**.

### 2.3 Изоляция и containment

- Хост изолируется от сети (через EDR isolation или вручную).
- Блокируются IOC на периметре:
  - домен C2;
  - IP-адрес;
  - хеши файлов.

### 2.4 Сбор артефактов

- Снимается дамп памяти (winpmem, DumpIt).
- Копируются:
  - файлы из `%TEMP%`, `%APPDATA%`;
  - реестр (ключи автозапуска);
  - журналы Sysmon, Security, PowerShell.
- Собираются сетевые логи (NetFlow, pcaps).

### 2.5 Eradication и восстановление

- Удаляются вредоносные файлы и записи персистентности.
- Пересоздаётся учётная запись пользователя (при подозрении на компрометацию).
- Проводится проверка других хостов на наличие аналогичных артефактов.

### 2.6 Post-incident activity

- Проводится разбор инцидента (PIR – Post-Incident Review).
- Обновляются:
  - правила детектов (Sigma, YARA, корреляции в SIEM);
  - плейбуки реагирования;
  - политики (ASR-правила, ограничения на макросы, PowerShell).
- Планируются тренировки для сотрудников (фишинг) и SOC (разбор кейса).

---

## 3. MITRE ATT&CK Mapping

Основные техники, затронутые в кейсе:

- **T1566.001** – Phishing: Spearphishing Attachment  
- **T1059.001** – Command and Scripting Interpreter: PowerShell  
- **T1027** – Obfuscated Files or Information  
- **T1055** – Process Injection  
- **T1547.001** – Boot or Logon Autostart Execution: Registry Run Keys  
- **T1562.001** – Impair Defenses: Disable or Modify Tools (попытки воздействия на AV/EDR)

Детальная карта техник и их проявлений в логах описана в [`03-technical-analysis.md`](03-technical-analysis.md).
