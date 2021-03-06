# NBTscan

## Table of Contents

- [NBTscan](#nbtscan)
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

> **NBTscan is a program for scanning IP networks for NetBIOS name information** — [Inetcat](https://web.archive.org/web/20120420121302/http://www.inetcat.net/software/nbtscan.html)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1.0.35   | 90da10004c8f6fafdaa2cf18922670a745564f45 | [LINK](https://www.virustotal.com/gui/file/c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e)                                                                                                             |

## File Metadata

- TBD

## Common CommandLine

```batch
rem Scans a specific range
nbtscan [X.X.X.X]-[X]
nbtscan [X.X.X.X]/[MASK]

rem Scan IP from file
nbtscan -f [Filename]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- TBD

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - ComputerInfo.exe](https://app.any.run/tasks/32dd6491-6ed6-4ede-b702-51f1d6fcb396/)

## Documentation

- [Inetcat - NBTScan. NetBIOS Name Network Scanner](https://web.archive.org/web/20120420121302/http://www.inetcat.net/software/nbtscan.html)
- [Debian - nbtscan - scan networks for NetBIOS name information](https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html)

## Blogs / Reports References

- [Trend Micro Research - Operation DRBControl - Uncovering a Cyberespionage Campaign Targeting Gambling Companies in Southeast Asia](https://www.trendmicro.com/vinfo/us/security/news/cyber-attacks/operation-drbcontrol-uncovering-a-cyberespionage-campaign-targeting-gambling-companies-in-southeast-asia)
- [McAfee Blog - MVISION Insights: Exchange Servers Under Attack By Multiple Threat Actors](https://kc.mcafee.com/corporate/index?page=content&id=KB94743&locale=en_US)
- [Microsoft Blog - Threat actor leverages coin miner techniques to stay under the radar – here’s how to spot them](https://www.microsoft.com/security/blog/2020/11/30/threat-actor-leverages-coin-miner-techniques-to-stay-under-the-radar-heres-how-to-spot-them/)
- [CISA - Alert (AA21-200B) - Chinese State-Sponsored Cyber Operations: Observed TTPs](https://us-cert.cisa.gov/ncas/alerts/aa21-200b)
- [Expel - How to hunt for reconnaissance](https://expel.io/blog/how-to-hunt-for-reconnaissance/)
- [Cybereason - Operation Soft Cell: A Worldwide Campaign Against Telecommunications Providers](https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers)
- [Secureworks - Threat Group 3390 Cyberespionage](https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage)
- [Secureworks - BRONZE PRESIDENT Targets NGOs](https://www.secureworks.com/research/bronze-president-targets-ngos)
- [WeLiveSecurity - BackdoorDiplomacy: Upgrading from Quarian to Turian](https://www.welivesecurity.com/2021/06/10/backdoordiplomacy-upgrading-quarian-turian/)

## ATT&CK Techniques

- [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046)
- [T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040)
- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **NextronSystems - APTSimulator**
  - [NETBIOS Discovery - Executes nbtscan on the local network](https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/discovery/nbtscan.bat)

## Detection Rules

- **Microsoft 365 Defender**
  - [Detect nbtscan activity](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Discovery/detect-nbtscan-activity.md)

## LOLBAS / GTFOBins References

- None
