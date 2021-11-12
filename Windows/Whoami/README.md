# Whoami

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Whoami is command-line utility that displays user, group and privileges information for the user who is currently logged on to the local system.** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)

## Common CommandLine

```batch
rem Displays the current domain and user name.
whoami

rem Display all information in the current access token, including
rem the current user name, security identifiers (SID), privileges, 
rem and groups that the current user belongs to.
whoami /all

rem Display the user groups to which the current user belongs.
whoami /groups

rem Display the security privileges of the current user.
whoami /priv

rem Display the current domain and user name and the security identifier (SID).
whoami /user

rem Display the user name in user principal name (UPN) format.
whoami /upn
```

## Default Install Location

```batch
C:\Windows\System32\whoami.exe

C:\Windows\SysWOW64\whoami.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 05018237fba5a052550b61ac82975dc25f61911964289a7fdf72b601d11c0441](https://app.any.run/tasks/c2fe4e13-9ec5-4216-a11a-57c5077e11ae/)
- [ANY.RUN -  z5122.exe](https://app.any.run/tasks/ec2b6a89-391e-46a6-8838-6c8ac494a2ef/)
- [ANY.RUN - fin7_20190522.js](https://app.any.run/tasks/ebb8e2ba-d6f1-40ef-84a8-93bb98e12a56/)
- [ANY.RUN - setupreport.cmd](https://app.any.run/tasks/938a5d27-6cfe-4153-8f94-6fc6137f3aca/)
- [ANY.RUN - decoded-9868a7cfee0e2cde60d1bef18ef777de.js](https://app.any.run/tasks/9cd59431-026b-4e3f-aec5-e82ed06ac065/)
- [ANY.RUN - update.ps1](https://app.any.run/tasks/86e2a8b5-033b-42c5-a9b1-6d830e19a880/)
- [ANY.RUN - chrome_setup.exe](https://app.any.run/tasks/682a5d77-eed1-4502-8da8-16d7db37fcd4/)

## Documentation

- [Microsoft Docs - Whoami](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
- [SS64.com - Windows CMD - Whoami](https://ss64.com/nt/whoami.html)

## Blogs / Reports References

- [The DFIR Report - Cobalt Strike, a Defender’s Guide](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
- [The DFIR Report - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)
- [The DFIR Report - Bazar Drops the Anchor](https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/)
- [The DFIR Report - PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [The DFIR Report - Ryuk’s Return](https://thedfirreport.com/2020/10/08/ryuks-return/)
- [The DFIR Report - Dridex – From Word to Domain Dominance](https://thedfirreport.com/2020/08/03/dridex-from-word-to-domain-dominance/)
- [The DFIR Report - Tricky Pyxie](https://thedfirreport.com/2020/04/30/tricky-pyxie/)
- [Securelist By Kaspersky - QakBot technical analysis](https://securelist.com/qakbot-technical-analysis/103931/)
- [Securelist By Kaspersky - Operation TunnelSnake](https://securelist.com/operation-tunnelsnake-and-moriya-rootkit/101831/)
- [Securelist By Kaspersky - Lazarus covets COVID-19-related intelligence](https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/)
- [Securelist By Kaspersky - OilRig’s Poison Frog – old samples, same trick](https://securelist.com/oilrigs-poison-frog/95490/)
- [Securelist By Kaspersky - Managed Detection and Response analytics report, H1 2019](https://securelist.com/managed-detection-and-response-analytics-report/94076/)

## ATT&CK Techniques

- [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [T1059.003 — Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- **Splunk**
  - [Check Elevated CMD using whoami](https://research.splunk.com/endpoint/check_elevated_cmd_using_whoami/)
  - [System User Discovery With Whoami](https://research.splunk.com/endpoint/system_user_discovery_with_whoami/)

- **Elastic**
  - [Whoami Process Activity](https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_whoami_command_activity.toml)

- **Sigma**
  - [Whoami Execution Anomaly](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_whoami_anomaly.yml)
  - [Renamed Whoami Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_whoami.yml)
  - [Run Whoami Showing Privileges](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_whoami_priv.yml)
  - [Run Whoami as SYSTEM](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_whoami_as_system.yml)
  - [Whoami Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_whoami.yml)
  - [CobaltStrike Process Patterns](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_cobaltstrike_process_patterns.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)

## LOLBAS / GTFOBins References

- None
