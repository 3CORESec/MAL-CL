# IntelliAdmin Network Administrator - RegistrySet

## Table of Contents

- [IntelliAdmin Network Administrator - RegistrySet](#intelliadmin-network-administrator---registryset)
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

> **RegistrySet.exe is one of the tools available in the IntelliAdmin Network Administrator software. It can create, modify or delete registry keys**

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

```batch
RegistrySet /key:[Registry Key] /name:[Registry Value Name] /Value:[Registry Value] /Type:[Type]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- If the ``IntelliAdmin Network Administrator`` tool is installed the tool will be located in the following directory:

```batch
C:\Program Files (x86)\IntelliAdmin\Plugins\Tools\RegistrySet.exe
```

- This utility can also be copied and used in a standalone way.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

```batch
Usage:

RegistrySet.exe [Options]

Possible optins:

/HOST: {REMOTE_HOST} - Optional
/KEY: {Registry Key} - Required
/NAME: {Registry value name} - Required
/VALUE: {Registry value} - Required
/EVALUE: {Registry value (Encrypted) - Optional
/TYPE: {REG_DWORD|REG_SZ|DELETE} - Optional (Defaults to REG_SZ)
/HIVE: {HKCU|HKLM} - Optional (Defaults to HKLM)
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 12 - RegistryEvent (Object create and delete)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012)
- [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)
- [Sysmon Event ID 14 - RegistryEvent (Key and Value Rename)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90014)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
