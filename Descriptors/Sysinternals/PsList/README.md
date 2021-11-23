# PsList

## Table of Contents

- [PsList](#pslist)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
  - [Versions History](#versions-history)
  - [Common CommandLine](#common-commandline)
  - [Default Install Location](#default-install-location)
  - [DFIR Artifacts](#dfir-artifacts)
  - [Examples In The Wild](#examples-in-the-wild)
  - [Documentation](#documentation)
  - [Blogs / Reports References](#blogs--reports-references)
  - [ATT&CK Techniques](#attck-techniques)
  - [Eventlog / Sysmon Events to Monitor](#eventlog--sysmon-events-to-monitor)
  - [Detection Validation](#detection-validation)
  - [Detection Rules](#detection-rules)
  - [LOLBAS / GTFOBins References](#lolbas--gtfobins-references)

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Process Status, list information about processes running in memory.** - [SS64](https://ss64.com/nt/pslist.html)

## Versions History

- TBD

## Common CommandLine

- Note that most of the time the process is renamed but the flags are the same
- Note that the "/" can be used instead of the "-" when calling the flags.

```batch
pslist -accepteula

pslist \\[RemoteComputerIP]
```

## Default Install Location

- PsList is a downloadable portable utility so no installation is required to execute it.

- The Sysinternals suite is available in the Microsoft Store. If downloaded from there then the `PsList` utility will be installed in the following location:

```batch
C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_[Version]\Tools\PsList.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - reap_full.exe](https://app.any.run/tasks/0fe5c8d8-ef61-402c-8535-11dcb26bdec8/)

## Documentation

- [Microsoft Docs - PsList](https://docs.microsoft.com/en-us/sysinternals/downloads/pslist)
- [SS64.com - Windows CMD - PsList](https://ss64.com/nt/pslist.html)

## Blogs / Reports References

- [Securelist By Kaspersky - GhostEmperor: From ProxyLogon to kernel mode](https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/)
- [Palo Alto Networks - Unite 42 - UBoatRAT Navigates East Asia](https://unit42.paloaltonetworks.com/unit42-uboatrat-navigates-east-asia/)

## ATT&CK Techniques

- [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
