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

- For more information on specific versions check [auditpol.exe - Winbindex](https://winbindex.m417z.com/?file=auditpol.exe)

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 10.0.22000.1 (x86)    | 3ba6045fe86db8906dfb1d3dfc37dccc33c00514 | [LINK](https://www.virustotal.com/gui/file/a86acb5e6ff088b72de41fd187d4caac9bdfa6624d3d28b1a4aed299580ac872)                                                                                                             |
| 10.0.22000.1 (x64)   | e494fdfcbe1ab2b19ef1e2c873e0f1253f8466e9 | [LINK](https://www.virustotal.com/gui/file/a60d60a9b0427e962284683fa4091d0dc34c508fe74ef3d28c2db9bc5ff044bd)                                                                                                             |
| 10.0.19041.546 (x86)   | e6a50645a361d5c763802ffa6e3c749fb81e96d7 | [LINK](https://www.virustotal.com/gui/file/92274459d15dd69e20598f5ce54933635c2bd916ca2b0a039f96be782fac1ca6)                                                                                                             |
| 10.0.19041.546 (x64)    | 51c97ebe601ef079b16bcd87af827b0be5283d96 | [LINK](https://www.virustotal.com/gui/file/d1c6ec7f394b59d067dfd47a6a65978e4c2cc73437457a4b78209e5f516471cc)                                                                                                             |
| 10.0.19041.1 (x86)    | 2c7ac7ff170567bc2eb4578ba2242220f5bc997a | [LINK](https://www.virustotal.com/gui/file/ce7c5bbc024f803e35d1486585941f7ba6338543ccde606fc04138a22ac763bc)                                                                                                             |
| 10.0.19041.1 (x64)    | 40b872e7a01dde110206a7b422db4135301d620d | [LINK](https://www.virustotal.com/gui/file/8362dded162b118d02528afeeb3af60ce0ecd60015ff9a65812f69619d3742a2)                                                                                                             |
| 10.0.18362.1 (x86)   | 58da09e70e2d6ee47bfe3e2fa447f37e15abefbe | [LINK](https://www.virustotal.com/gui/file/f2700c63442130158f3b685f99045198ea696497b23146391213574c17456dd5)                                                                                                             |
| 10.0.18362.1 (x64)    | e8de077e9fb7aa7220a8f1343051cf2c9a7e12ae | [LINK](https://www.virustotal.com/gui/file/643278719c680385d173588fdf2acd752a65e12180d416d07c1be79b49231d73)                                                                                                             |
| 10.0.17763.1 (x86)   | 2e4c06a8d3a26e7c04bbfdcbd3807a2773eb2bd4 | [LINK](https://www.virustotal.com/gui/file/b01b1fad43094c5b336f8ed8818013db66d2a71141ee5c3602b951a7bf78b989)                                                                                                             |
| 10.0.17763.1 (x64)    | 0a81854c79d49ef3241a962ebfbaee438cef1160 | [LINK](https://www.virustotal.com/gui/file/969306e33a469096efa20bee264fb37ac4da86899f2659007d6be0d1eb666b1c)                                                                                                             |

## Common CommandLine

```batch
auditpol /set /category:[Category] /success:disable /failure:disable

auditpol /clear /y

auditpol /remove /allusers

auditpol /restore /file:[RestoreFile]
```

## Threat Actor Ops (TAOps)

- [Disabling and re-enabling "Detailed tracking" only after execution of malicious commands](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)

```batch
auditpol /set /category:"Detailed Tracking" /success:disable /failure:disable
[execution of several commands and actions]
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
```

## Common Process Trees

- Auditpol launched from CMD or PowerShell

```yaml
.
└── cmd.exe
    └── auditpol.exe

.
└── powershell.exe
    └── auditpol.exe
```

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
