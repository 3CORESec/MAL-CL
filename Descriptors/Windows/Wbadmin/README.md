# Wbadmin

## Table of Contents

- [Wbadmin](#wbadmin)
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

> **Wbadmin is a utility that enables you to back up and restore your operating system, volumes, files, folders, and applications from a command prompt** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)

## Versions History

- For more information on specific versions check [wbadmin.exe - Winbindex](https://winbindex.m417z.com/?file=wbadmin.exe)

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 10.0.22000.1    | c2f5963f4767eff9f4cb870345cf9bc0d9303fe9 | [LINK](https://www.virustotal.com/gui/file/be37e10bfaedc167665ae8c448805ab1def5e299c6acd274113248f8414b0696)                                                                                                             |
| 10.0.19041.1202    | f5671266fbf3ffbc32caa2c1effa1768893d0173 | [LINK](https://www.virustotal.com/gui/file/508e5f70c29502d7ba66a35959a327e3d658514496ee7b9155d95e7409eb4fb8)                                                                                                             |
| 10.0.19041.964    | b3228fecaa4a31ad06b2acd4c6728aea69ef5f9e | [LINK](https://www.virustotal.com/gui/file/9ecf2d0e71a563695765576717b3729bc9b71178eb08c0d6b3b24ff1654bcf71)                                                                                                             |
| 10.0.19041.906    | 4cb05cf56eab145843560f90eebbb718609b72b0 | [LINK](https://www.virustotal.com/gui/file/fd4feca787f78283bf5fc2dafde920904c31773db87f66de2b09233686f871a9)                                                                                                             |

## File Metadata

- This metadata information is based on the latest version available as of this writing (10.0.22000.1).

| Attribute     | Value |
|---------------|-------|
| Copyright     | © Microsoft Corporation. All rights reserved.     |
| Product       | Microsoft® Windows® Operating System     |
| Description   | Command Line Interface for Microsoft® BLB Backup     |
| Original Name | WBADMIN.EXE     |
| Internal Name | WBADMIN.EXE     |

## Common CommandLine

```batch
rem Deletes the backup catalog
wbadmin delete catalog
wbadmin delete catalog -quiet
wbadmin delete catalog -q

rem Deletes backup for Windows Server
wbadmin delete systemstatebackup

rem Deletes the oldest backup
wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest

rem deletes all the system state backups
wbadmin delete systemstatebackup -keepversions:0
```

## Threat Actor Ops (TAOps)

- [Deletes the backup catalog using ``wbadmin``](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)

```batch
wbadmin delete catalog -quiet
```

- [Deletes the system state backups using ``wbadmin``](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)

```batch
wbadmin delete systemstatebackup
```

## Common Process Trees

- Wbadmin launched from CMD or PowerShell

```yaml
.
└── cmd.exe
    └── wbadmin.exe

.
└── powershell.exe
    └── wbadmin.exe
```

## Default Install Location

```batch
C:\Windows\System32\wbadmin.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - Ako.RANSOM](https://app.any.run/tasks/8086af5d-9875-4b81-bcdb-2f171fbf6538/)
- [ANY.RUN - ab.bin](https://app.any.run/tasks/09f6db4a-52bb-48e3-929c-57d93ecb9b26/)
- [ANY.RUN - 8f20197da8f44485dbec10674cc2df0a48422d4c2c1308d17aa065a5c1ce445e.bin](https://app.any.run/tasks/87bbf9f1-86f0-499e-99bb-88a6e0ca761c/)
- [ANY.RUN - svchost.exe](https://app.any.run/tasks/a8bb565a-a575-4836-aced-8f5f1aa9a7b0/)

## Documentation

- [Microsoft Docs - Wbadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)
- [SS64.com - Windows CMD - Wbadmin](https://ss64.com/nt/wbadmin.html)

## Blogs / Reports References

- [Cybereason - Cybereason vs. RansomEXX Ransomware](https://www.cybereason.com/blog/cybereason-vs.-ransomexx-ransomware)
- [Cybereason - Cybereason vs. MedusaLocker Ransomware](https://www.cybereason.com/blog/medusalocker-ransomware)
- [Cybereason - Cybereason vs. Avaddon Ransomware](https://www.cybereason.com/blog/cybereason-vs.-avaddon-ransomware)
- [WeLiveSecurity - Buhtrap backdoor and Buran ransomware distributed via major advertising platform](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)
- [Securelist By Kaspersky - WannaCry ransomware used in widespread attacks all over the world](https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/78351/)
- [The DFIR Report - PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [The DFIR Report - Ryuk’s Return](https://thedfirreport.com/2020/10/08/ryuks-return/)
- [The DFIR Report - Lockbit Ransomware, Why You No Spread?](https://thedfirreport.com/2020/06/10/lockbit-ransomware-why-you-no-spread/)
- [Microsoft Security Blog - WannaCrypt ransomware worm targets out-of-date systems](https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)
- [Microsoft Security Blog - Phorpiex morphs: How a longstanding botnet persists and thrives in the current threat environment](https://www.microsoft.com/security/blog/2021/05/20/phorpiex-morphs-how-a-longstanding-botnet-persists-and-thrives-in-the-current-threat-environment/)
- [Mandiant - WannaCry Malware Profile](https://www.mandiant.com/resources/wannacry-malware-profile)
- [SentinelLabs - How MedusaLocker Ransomware Aggressively Targets Remote Hosts](https://www.sentinelone.com/blog/how-medusalocker-ransomware-aggressively-targets-remote-hosts/)
- [SentinelLabs - Avaddon RaaS | Breaks Public Decryptor, Continues On Rampage](https://www.sentinelone.com/labs/avaddon-raas-breaks-public-decryptor-continues-on-rampage/)
- [SentinelLabs - Ranzy Ransomware | Better Encryption Among New Features of ThunderX Derivative](https://www.sentinelone.com/labs/ranzy-ransomware-better-encryption-among-new-features-of-thunderx-derivative/)
- [Csico Talos - Olympic Destroyer Takes Aim At Winter Olympics](https://blog.talosintelligence.com/2018/02/olympic-destroyer.html)

## ATT&CK Techniques

- [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [wbadmin Delete Windows Backup Catalog](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-3---windows---wbadmin-delete-windows-backup-catalog)
  - [wbadmin Delete systemstatebackup](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-7---windows---wbadmin-delete-systemstatebackup)

- **Elastic - Red Team Automation**
  - [Catalog Deletion with wbadmin.exe](https://github.com/elastic/detection-rules/blob/main/rta/delete_catalogs.py)

## Detection Rules

- **Splunk**
  - [WBAdmin Delete System Backups](https://research.splunk.com/endpoint/wbadmin_delete_system_backups/)

- **Elastic**
  - [Deleting Backup Catalogs with Wbadmin](https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_deleting_backup_catalogs_with_wbadmin.toml)

- **Microsoft 365 Defender**
  - [Check for multiple signs of ransomware activity](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Ransomware/Check%20for%20multiple%20signs%20of%20ransomware%20activity.md)

- **Sigma**
  - [Shadow Copies Deletion Using Operating Systems Utilities](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shadow_copies_deletion.yml)

## LOLBAS / GTFOBins References

- None
