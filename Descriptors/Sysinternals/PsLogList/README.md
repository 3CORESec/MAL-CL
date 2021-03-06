# PsLogList

## Table of Contents

- [PsLogList](#psloglist)
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

> **PsLogList lets you dump the contents of an Event Log on the local or a remote computer** - [MSDN](https://docs.microsoft.com/en-us/sysinternals/downloads/psloglist)

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

- Note that most of the time the process is renamed but the flags are the same
- Note that the "/" can be used instead of the "-" when calling the flags.

```batch
psloglist.exe -accepteula -x security -s -a <current_date>

psloglist.exe security -d [NumOfDays] /accepteula
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- PsLogList is a downloadable portable utility so no installation is required to execute it.

- The Sysinternals suite is available in the Microsoft Store. If downloaded from there then the `PsLogList` utility will be installed in the following location:

```batch
C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_[Version]\Tools\PsLogList.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [Github Gist - winlogfinder](https://gist.github.com/jabedude/dfb103cde4e4b908fa5ac2ea2f15d774)

## Documentation

- [Microsoft Docs - PsLogList](https://docs.microsoft.com/en-us/sysinternals/downloads/psloglist)
- [SS64.com - Windows CMD - PsLogList](https://ss64.com/nt/psloglist.html)

## Blogs / Reports References

- [nccgroup - Abusing cloud services to fly under the radar](https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/)
- [Cybereason - DeadRinger: Exposing Chinese Threat Actors Targeting Major Telcos](https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos)

## ATT&CK Techniques

- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)

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
