# Nircmd

## Table of Contents

- [Nircmd](#nircmd)
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

- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface.** — [NirSoft](https://www.nirsoft.net/utils/nircmd.html)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 2.86 (nircmd.exe) (x86) | 60e2f48a51c061bba72a08f34be781354f87aa49 | [LINK](https://www.virustotal.com/gui/file/b994ae5cbfb5ad308656e9a8bf7a4a866fdeb9e23699f89f048d7f92e6bb8577) |
| 2.86 (nircmd.exe) (x64) | 20cd453fcac9d9960b0076715d985a55784a6b53 | [LINK](https://www.virustotal.com/gui/file/7160db2b7a6680480e64f0845512d203a575f807831faf9a652aaef0988f876c) |
| 2.86 (nircmdc.exe) (x86) | 21c4cc08d3600c564bd0d04c8553e59f564bfff4 | [LINK](https://www.virustotal.com/gui/file/67e0d635825cbf7cc213670f671544da9ff18047742dd4a0696a508b79eef607) |
| 2.86 (nircmdc.exe) (x64) | 5640391e8cd2b58ccafc038d18eab4c1ec824d9f | [LINK](https://www.virustotal.com/gui/file/3c8fca34b2568cfd9cf54809160468ee0e06c12e80f194519a3aea3b6ca166bd) |

## File Metadata

- This metadata information is based on the latest version available as of this writing (2.86).

| Attribute     | Value |
|---------------|-------|
| Copyright     | Copyright © 2003 - 2019 Nir Sofer |
| Product       | NirCmd |
| Description   | NirCmd |
| Original Name | NirCmd.exe |
| Internal Name | NirCmd |

## Common CommandLine

```batch
nircmd.exe execmd [Command]

nircmd.exe elevatecmd runassystem [Command]

nircmd.exe service stop [ServiceName]

nircmd.exe exec hide [Command]

nircmd.exe killprocess [ProcessName]
```

## Threat Actor Ops (TAOps)

- [Save screenshot](https://www.mandiant.com/resources/head-fake-tackling-disruptive-ransomware-attacks)

```batch
C:\Users\User\AppData\Local\Temp\nircmdc.exe savescreenshot
```

## Common Process Trees

- TBD

## Default Install Location

- Nircmd is a downloadable portable package so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - combofix.exe](https://app.any.run/tasks/877e28f0-bdbf-4e15-8797-f71e45239825/)
- [ANY.RUN - SETUP_EC.exe](https://app.any.run/tasks/9a210b9f-2697-4ded-bc74-01826204c0a1/)

## Documentation

- [NirSoft - Nircmd](https://www.nirsoft.net/utils/nircmd2.html#using)

## Blogs / Reports References

- [Securelist By Kaspersky - Shade: not by encryption alone](https://securelist.com/shade-not-by-encryption-alone/75645/)
- [Mandiant Blog - Head Fake: Tackling Disruptive Ransomware Attacks](https://www.mandiant.com/resources/head-fake-tackling-disruptive-ransomware-attacks)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: xHunt Actor’s Cheat Sheet](https://unit42.paloaltonetworks.com/xhunt-actors-cheat-sheet/)

## ATT&CK Techniques

- [T1588.002 - Obtain Capabilities: Tool](https://attack.mitre.org/techniques/T1588/002/)

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
