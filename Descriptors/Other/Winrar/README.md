# Winrar

## Table of Contents

- [Winrar](#winrar)
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

> **WinRAR is Windows version of the RAR archiver - a powerful tool which allows you to create, manage and control archive files** - [WinRAR](https://documentation.help/WinRAR/HELPRarInfo.htm)

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

- Note that most of the time the process is renamed but the flags are the same

```batch
rar.exe a -r -[password] [file].rar [files to add]

rar.exe a -m5 -[password] -r [file] [file to add]

rar.exe a -k -r -s -m1 -[password] [filename].rar [files to add]

rar.exe x -[password] [file]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- When installed the default location for the WinRAR command-line utility is the following:

```batch
C:\Program Files\WinRAR\rar.exe
```

- Note that the ``rar.exe`` can be copied and used standalone without the need for installation.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - openvhost-7q6eDB6y490C.exe](https://app.any.run/tasks/ac031fb6-5844-4024-a8fa-c7070cc5778d/)
- [ANY.RUN - wbxtraceget2.exe](https://app.any.run/tasks/f306dd82-23a0-4cd2-ab22-fd5c52096a26/)
- [ANY.RUN - wrar600.exe](https://app.any.run/tasks/d3453fad-bd07-48f4-9acf-3a112d314ad4/)
- [Hatching Triage (tria.ge) - Windows_10_pro_100_original_keygen_by_KeygenNinja.zip](https://tria.ge/201129-alcc415ezx)
- [Hatching Triage (tria.ge) - Downloads.rar](https://tria.ge/201118-dj27sn3f52)

## Documentation

- [WinRAR - Common command line syntax](https://documentation.help/WinRAR/HELPCommandLineSyntax.htm)

## Blogs / Reports References

- [Cybereason - Operation Soft Cell: A Worldwide Campaign Against Telecommunications Providers](https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers)
- [Cybereason - Operation GhostShell: Novel RAT Targets Global Aerospace and Telecoms Firms](https://www.cybereason.com/blog/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms)
- [Cybereason - DeadRinger: Exposing Chinese Threat Actors Targeting Major Telcos](https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos)
- [Cybereason - Molerats APT: New Malware and Techniques in Middle East Espionage Campaign](https://www.cybereason.com/blog/molerats-apt-new-malware-and-techniques-in-middle-east-espionage-campaign)
- [Volexity - Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
- [Mandiant - APT1: Exposing One of China's Cyber Espionage Units](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units)
- [Broadcom - Sowbug: Cyber espionage group targets South American and Southeast Asian governments](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=d544bd14-1dd2-4ab6-a5a0-181788b7d73b&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments)
- [WeLiveSecurity - Turla Crutch: Keeping the “back door” open](https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/)
- [WeLiveSecurity - BackdoorDiplomacy: Upgrading from Quarian to Turian](https://www.welivesecurity.com/2021/06/10/backdoordiplomacy-upgrading-quarian-turian/)

## ATT&CK Techniques

- [T1560 - Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [T1560.001 - Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Compress Data for Exfiltration With Rar](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md#atomic-test-1---compress-data-for-exfiltration-with-rar)
  - [Compress Data and lock with password for Exfiltration with winrar](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md#atomic-test-2---compress-data-and-lock-with-password-for-exfiltration-with-winrar)

- **Elastic - Red Team Automation**
  - [Encrypting files with WinRAR](https://github.com/elastic/detection-rules/blob/main/rta/winrar_encrypted.py)

## Detection Rules

- **Splunk**
  - [Detect Renamed WinRAR](https://research.splunk.com/endpoint/detect_renamed_winrar/)

- **Elastic**
  - [Encrypting Files with WinRar or 7z](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_winrar_encryption.toml)

- **Microsoft 365 Defender**
  - [Insider Threat Detection Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/insider-threat-detection-queries.md)
  - [Password Protected Archive Creation](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Exfiltration/Password%20Protected%20Archive%20Creation.md)
  - [Detect Exfiltration to Competitor Organization](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Exfiltration/detect-archive-exfiltration-to-competitor.md)

- **Sigma**
  - [Rar with Password or Compression Level](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_rar_flags.yml)
  - [Data Compressed - rar.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_data_compressed_with_rar.yml)
  - [Suspicious Compression Tool Parameters](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_compression_params.yml)

## LOLBAS / GTFOBins References

- None
