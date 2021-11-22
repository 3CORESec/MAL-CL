# ProcDump

## Table of Contents

- [ProcDump](#procdump)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
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

> **ProcDump is a command-line utility whose primary purpose is monitoring an application for CPU spikes and generating crash dumps during a spike that an administrator or developer can use to determine the cause of the spike** - [MSDN](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

## Common CommandLine

- Note that most of the time the process is renamed but the flags are the same
- Note that the "/" can be used instead of the "-" when calling the flags.

```batch
rem Full Dump of a process
procdump -ma [Process] [FileToSaveOnDisk]
procdump -accepteula -ma [Process] [FileToSaveOnDisk]
procdump64 -ma [Process] [FileToSaveOnDisk]
procdump64 -accepteula -ma [Process] [FileToSaveOnDisk]

rem Mini Dump of a process
procdump -mm [Process] [FileToSaveOnDisk]
procdump -accepteula -mm [Process] [FileToSaveOnDisk]
procdump64 -mm [Process] [FileToSaveOnDisk]
procdump64 -accepteula -mm [Process] [FileToSaveOnDisk]

rem Full Dump using a clone
procdump -accepteula -r -ma [Process] [FileToSaveOnDisk]
procdump64 -accepteula -r -ma [Process] [FileToSaveOnDisk]
```

## Default Install Location

- Procdump is a downloadable portable utility so no installation is required to execute it.

- The Sysinternals suite is available in the Microsoft Store. If downloaded from there then the `procdump` utility will be installed in the following location:

```batch
C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_[Version]\Tools\procdump.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - fe51590db6f835a3a210eba178d78d5eeafe8a47bf4ca44b3a6b3dfb599f1702](https://app.any.run/tasks/ead4a01b-51d7-49bb-aef7-73fee90f0aab/)
- [ANY.RUN - web.zip](https://app.any.run/tasks/23e63b67-9059-4cf1-ab4c-0f7ca9e8cb28/)
- [ANY.RUN - docropool.exe](https://app.any.run/tasks/93b9c322-ecfe-4e1d-80df-9b33759a10d7/)

## Documentation

- [Microsoft Docs - Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)

## Blogs / Reports References

- [The DFIR Report - NetWalker Ransomware in 1 Hour](https://thedfirreport.com/2020/08/31/netwalker-ransomware-in-1-hour/)
- [The DFIR Report - Ryuk in 5 Hours](https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/)
- [The DFIR Report - PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [The DFIR Report - IcedID and Cobalt Strike vs Antivirus](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/)
- [The DFIR Report - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report - Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/)
- [Volexity - Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
- [Mandiant - OVERRULED: Containing a Potentially Destructive Adversary](https://www.mandiant.com/resources/overruled-containing-a-potentially-destructive-adversary)
- [Mandiant - APT40: Examining a China-Nexus Espionage Actor](https://www.mandiant.com/resources/apt40-examining-a-china-nexus-espionage-actor)
- [Mandiant - APT39: An Iranian Cyber Espionage Group Focused on Personal Information](https://www.mandiant.com/resources/apt39-iranian-cyber-espionage-group-focused-on-personal-information)
- [Microsoft Security Blog - HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)

## ATT&CK Techniques

- [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Dump LSASS via procdump](https://research.splunk.com/endpoint/dump_lsass_via_procdump/)

- **Elastic**
  - [Potential Credential Access via Windows Utilities](https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_cmdline_dump_tool.toml)

- **Microsoft 365 Defender**
  - [Procdump dumping LSASS credentials](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Credential%20Access/procdump-lsass-credentials.md)

- **Sigma**
  - [Renamed ProcDump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_procdump.yml)
  - [Suspicious Use of Procdump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_procdump.yml)
  - [Procdump Usage](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_procdump.yml)
  - [Suspicious Use of Procdump on LSASS](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_procdump_lsass.yml)
  - [LSASS Memory Dump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/sysmon_lsass_memdump.yml)
  - [LSASS Memory Dumping](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_lsass_dump.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)
  - [LSASS Memory Dump File Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/sysmon_lsass_memory_dump_file_creation.yml)

## LOLBAS / GTFOBins References

- None
