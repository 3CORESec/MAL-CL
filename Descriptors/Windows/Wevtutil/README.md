# Wevtutil

## Table of Contents

- [Wevtutil](#wevtutil)
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

> **Wevtutil is a utility that enables you to retrieve information about event logs and publishers, install and uninstall event manifests, run queries, and to export, archive, and clear logs** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

```batch
rem Clears event logs 
wevtutil cl [LogName]
wevtutil clear-log [LogName]

rem Enum the event logs
wevtutil el

rem Disable a sepcific event log
wevtutil.exe sl [LogName] /e:false
```

- The most common event logs that get cleared are:
  - Application
  - Security
  - System

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\wevtutil.exe

C:\Windows\SysWOW64\wevtutil.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - hdclean.exe](https://app.any.run/tasks/21052e08-17c5-4744-a75f-746abac623f8/)
- [ANY.RUN - Microsoft Essential Security.exe](https://app.any.run/tasks/d08da167-7823-4063-a955-fe1b1f8e87ce/)
- [ANY.RUN - Invoke-Adversary.ps1](https://app.any.run/tasks/d2f9a3f8-ffd6-4589-ba90-22f2eeb55d4c/)
- [ANY.RUN - 4cae449450c07b7aa74314173c7b00d409eabfe22b86859f3b3acedd66010458.exe](https://app.any.run/tasks/2dc2248c-51a7-445d-a871-de414f22d49c/)
- [ANY.RUN - Browser_Cleaner_1.4.exe](https://app.any.run/tasks/6fe168c9-de89-4d1a-ac7d-25a1dfbf353e/)

## Documentation

- [Microsoft Docs - Wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [SS64.com - Windows CMD - Wevtutil](https://ss64.com/nt/wevtutil.html)

## Blogs / Reports References

- [Cybereason - Cybereason vs. RansomEXX Ransomware](https://www.cybereason.com/blog/cybereason-vs.-ransomexx-ransomware)
- [Cybereason - Petya-like Ransomware Attack: What You Need to Know](https://www.cybereason.com/blog/blog-petya-like-ransomware-attack-what-you-need-to-know)
- [Cybereason - Night of the Devil: Ransomware or wiper? A look into targeted attacks in Japan using MBR-ONI](https://www.cybereason.com/blog/night-of-the-devil-ransomware-or-wiper-a-look-into-targeted-attacks-in-japan)
- [WeLiveSecurity - Buhtrap backdoor and Buran ransomware distributed via major advertising platform](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)
- [The DFIR Report - The Little Ransomware That Couldn’t (Dharma)](https://thedfirreport.com/2020/06/16/the-little-ransomware-that-couldnt-dharma/)
- [The DFIR Report - GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)
- [Crowdstrike Blog - CrowdStrike’s work with the Democratic National Committee: Setting the record straight](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)

## ATT&CK Techniques

- [T1005 - Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1562.002 - Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002)
- [T1070.001 - Indicator Removal on Host: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [WevtUtil Usage To Clear Logs](https://research.splunk.com/endpoint/wevtutil_usage_to_clear_logs/)
  - [Wevtutil Usage To Disable Logs](https://research.splunk.com/endpoint/wevtutil_usage_to_disable_logs/)
  - [Suspicious wevtutil Usage](https://research.splunk.com/endpoint/suspicious_wevtutil_usage/)
  - [Disable Logs Using WevtUtil](https://research.splunk.com/endpoint/disable_logs_using_wevtutil/)

- **Elastic**
  - [Clearing Windows Event Logs](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_clearing_windows_event_logs.toml)

- **Microsoft 365 Defender**
  - [Clearing of forensic evidence from event logs using wevtutil](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Ransomware/Clearing%20of%20forensic%20evidence%20from%20event%20logs%20using%20wevtutil.md)

- **Sigma**
  - [Suspicious Eventlog Clear or Configuration Using Wevtutil](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_eventlog_clear.yml)
  - [Eventlog Cleared (Security Logs)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_susp_eventlog_cleared.yml)
  - [Eventlog Cleared (System Logs)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_system_susp_eventlog_cleared.yml)
  - [Disable of ETW Trace](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_etw_trace_evasion.yml)

## LOLBAS / GTFOBins References

- None
