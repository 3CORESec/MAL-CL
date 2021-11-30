# Defender Control

## Table of Contents

- [Defender Control](#defender-control)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
  - [Versions History](#versions-history)
  - [File Metadata](#file-metadata)
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

<p align="center"><img src="/Images/Screenshots/DefenderControl.png"></p>

> **Defender Control is a small Portable freeware which will allow you to disable Microsoft Defender in Windows 10 completely.** — [Sordum](https://www.sordum.org/9480/defender-control-v2-0/)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 2.0    | 2421ff6f2cfc1aa807eb5781b2980a6e493b31d0 | [LINK](https://www.virustotal.com/gui/file/20c730c7033b5bdc0a6510825e90449ba8f87942d2d7f61fa1ba5f100e98c141)                                                                                                             |
| 1.9    | 755309c6d9fa4cd13b6c867cde01cc1e0d415d00 | [LINK](https://www.virustotal.com/gui/file/6606d759667fbdfaa46241db7ffb4839d2c47b88a20120446f41e916cad77d0b)                                                                                                             |
| 1.8    | 30d262d526c7d7b34a8ea02765641a7dae51a867 | [LINK](https://www.virustotal.com/gui/file/94cd357b51381f164ed17ff16a1c036ab228350fc41fa78507ce611f3dec0efd)                                                                                                             |
| 1.7    | 0237408cdb74ad6b8d340cdf0d03c1b1f820ce17 | [LINK](https://www.virustotal.com/gui/file/ce3a6224dae98fdaa712cfa6495cb72349f333133dbfb339c9e90699cbe4e8e4)                                                                                                             |
| 1.6    | 5da4de1dbba55774891497297396fd2e5c306cf5 | [LINK](https://www.virustotal.com/gui/file/a201f7f81277e28c0bdd680427b979aee70e42e8a98c67f11e7c83d02f8fe7ae)                                                                                                             |
| 1.5    | dc74a9fd5560b7c7a0fc9d183de9d676e92b9e8b | [LINK](https://www.virustotal.com/gui/file/c576f7f55c4c0304b290b15e70a638b037df15c69577cd6263329c73416e490e)                                                                                                             |
| 1.4    | c88adeb1552f1a3e9d35e7a8e5fb7daa654c072f | [LINK](https://www.virustotal.com/gui/file/09d874b2d30d1418677618751ae57f219c062944f00d4b2def1f90a4ae9d3745)                                                                                                             |
| 1.3    | fa003104e8e8e6646049a49bd517224ba34ac4b6 | [LINK](https://www.virustotal.com/gui/file/5161a16217b9d8b9817ad1f6e1020e2eb625bbd6ccf82fbf9423077d0c966aa0)                                                                                                             |

## File Metadata

- TBD

## Common CommandLine

```batch
DefenderControl.exe /E

DefenderControl.exe /D /ID:[Defender PID]

DefenderControl.exe /D
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- ``DefenderControl`` is a downloadable portable executable so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [HYBRID-ANALYSIS — Def.exe](https://www.hybrid-analysis.com/sample/a201f7f81277e28c0bdd680427b979aee70e42e8a98c67f11e7c83d02f8fe7ae/5ef3dc0f4ef6473e02070a78)
- [ANY.RUN — Medusa Crypter.exe](https://app.any.run/tasks/54e660eb-4cab-4280-be27-11333838a5eb/)

## Documentation

- [Sordum - Defender Control v2.0](https://www.sordum.org/9480/defender-control-v2-0/)

## Blogs / Reports References

- [The DFIR Report  - Dharma Ransomware](https://thedfirreport.com/2020/04/14/dharma-ransomware/)
- [The DFIR Report  - Defender Control](https://thedfirreport.com/2020/12/13/defender-control/)
- [MORPHISEC - AHK RAT LOADER USED IN UNIQUE DELIVERY CAMPAIGNS](https://blog.morphisec.com/ahk-rat-loader-leveraged-in-unique-delivery-campaigns)

## ATT&CK Techniques

- [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- N/A
