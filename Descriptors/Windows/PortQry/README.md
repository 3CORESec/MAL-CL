# PortQry

## Table of Contents

- [PortQry](#portqry)
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

> **Portqry is a command-line utility that you can use to help troubleshoot TCP/IP connectivity issues. The utility reports the port status of TCP and UDP ports on a computer that you select.** - [MSDN](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/portqry-exe-command-line-utility)

## Versions History

- TBD

## Common CommandLine

```batch
portqry -local

portqry -local -l [Logfile Name] -v

portqry -n [@IP] -e [PortToQuery]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- PortQry is a downloadable portable utility so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - Office 2010 Activator.exe](https://app.any.run/tasks/1470ee4c-d58a-480d-8ecd-1204b0e7bd19/)

## Documentation

- [Microsoft Docs - Portqry](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/portqry-exe-command-line-utility)
- [SS64.com - Windows CMD - Portqry](https://ss64.com/nt/portqry.html)

## Blogs / Reports References

- [Cybereason - DeadRinger: Exposing Chinese Threat Actors Targeting Major Telcos](https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos)
- [Cybereason - Operation Soft Cell: A Worldwide Campaign Against Telecommunications Providers](https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers)
- [WeLiveSecurity - BackdoorDiplomacy: Upgrading from Quarian to Turian](https://www.welivesecurity.com/2021/06/10/backdoordiplomacy-upgrading-quarian-turian/)

## ATT&CK Techniques

- [T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)

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
