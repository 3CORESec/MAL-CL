# IntelliAdmin Network Administrator - ManageService

## Table of Contents

- [IntelliAdmin Network Administrator - ManageService](#intelliadmin-network-administrator---manageservice)
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

<p align="center"><img src="/Images/Screenshots/IntelliAdmin-Network-Administrator.png"></p>

> **ManageService.exe is one of the tools available in the IntelliAdmin Network Administrator software. It can stop, start and set the startup status of services**

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Unknown    | 9592d40783fe5714b7a61957050de3cc8eb18a8f | [LINK](https://www.virustotal.com/gui/file/4e2b90d81bb2f3dd2b9c0daa1bde4352ab31193f1e0b6130e5e97fb351b38a59)                                                                                                             |

## File Metadata

- TBD

## Common CommandLine

```batch
ManageService /Host:[RemoteHost] /Action:[ActionToTake] /Service:[ServiceName]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- If the ``IntelliAdmin Network Administrator`` tool is installed the tool will be located in the following directory:

```batch
C:\Program Files (x86)\IntelliAdmin\Plugins\Tools\ManageService.exe
```

- This utility can also be copied and used in a standalone way.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

```batch
Usage:

ManageService.exe [Options]

Possible optins:

/HOST: {REMOTE_HOST} - Optional
/SERVICE: {Service Name} - Required
/ACTION: {START|STOP|SET_AUTOMATIC|SET_MANUAL|SET_DISABLED} - Required
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
