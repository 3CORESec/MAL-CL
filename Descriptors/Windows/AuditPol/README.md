# AuditPol

## Table of Contents

- [AuditPol](#auditpol)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
  - [Versions History](#versions-history)
  - [Common CommandLine](#common-commandline)
  - [Threat Actor Ops (TAOps)](#threat-actor-ops-taops)
  - [Common Process Trees](#common-process-trees)
  - [Default Install Location](#default-install-location)
  - [DFIR Artifacts](#dfir-artifacts)
  - [Examples In The Wild](#examples-in-the-wild)
  - [Documentation](#documentation)
  - [Blogs / Reports References](#blogs--reports-references)
  - [ATT&CK Techniques](#attck-techniques)
  - [Telemetry](#telemetry)
  - [Detection Validation](#detection-validation)
  - [Detection Rules](#detection-rules)
  - [LOLBAS / GTFOBins References](#lolbas--gtfobins-references)

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **AuditPol is a utility that displays information about and performs functions to manipulate audit policies.** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)

## Versions History

- TBD

## Common CommandLine

```batch
auditpol /set /category:[Category] /success:disable /failure:disable

auditpol /clear /y

auditpol /remove /allusers

auditpol /restore /file:[RestoreFile]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\auditpol.exe

C:\Windows\SysWOW64\auditpol.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 611c662a013dd45db702741076115fa324308a62c93fa95f2a4724cee8ec30a6.exe](https://app.any.run/tasks/bf867825-dc8b-4990-a41f-7d6b56698c12/)
- [ANY.RUN - exotron.zip](https://app.any.run/tasks/b90c0b84-9e69-49ee-9050-dd41b4bee6d5/)

## Documentation

- [Microsoft Docs - AuditPol](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)

## Blogs / Reports References

- [Microsoft Security Blog - Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)
- [Cybereason - Prometei Botnet Exploiting Microsoft Exchange Vulnerabilities](https://www.cybereason.com/blog/prometei-botnet-exploiting-microsoft-exchange-vulnerabilities)

## ATT&CK Techniques

- [T1562.002 - Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Security Event ID 4719 - System Audit Policy Was Changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4719)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Impair Windows Audit Log Policy](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md#atomic-test-3---impair-windows-audit-log-policy)
  - [Clear Windows Audit Policy Config](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md#atomic-test-4---clear-windows-audit-policy-config)

## Detection Rules

- **Elastic**
  - [Disable Windows Event and Security Logs Using Built-in Tools](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_disabling_windows_logs.toml)

- **Azure-Sentinel**
  - [Audit policy manipulation using auditpol utility](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/AuditPolicyManipulation_using_auditpol.yaml)

- **Sigma**
  - [Disabling Windows Event Auditing](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_disable_event_logging.yml)
  - [Suspicious Auditpol Usage](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_sus_auditpol_usage.yml)

## LOLBAS / GTFOBins References

- None
