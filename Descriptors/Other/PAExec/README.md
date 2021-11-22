# PAExec

## Table of Contents

- [PAExec](#paexec)
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

> **PAExec lets you launch Windows programs on remote Windows computers without needing to install software on the remote computer first.** - [PowerAdmin](https://www.poweradmin.com/paexec/)

## Common CommandLine

- Note that "PAExec uses the same command-line options as PsExec, plus a few additonal options of its own".
- PAExec is often renamed but the arguments are the same.

```batch
paexec \\[@IP] [Command]

paexec \\[@IP] -u [Username] -p [Password] -s [Command]
```

## Default Install Location

- PAExec is a downloadable portable utility so no installation is required to execute it.

## DFIR Artifacts

- By default PAExec create a service with the following pattern in the following location:

```batch
C:\Windows\PAExec-PID-Hostname.exe
```

## Examples In The Wild

- [ANY.RUN - M300V323.zip](https://app.any.run/tasks/e3e86e64-2890-4ce8-b827-2918ca3c9355/)
- [ANY.RUN - Ransomware.Thanos.zip](https://app.any.run/tasks/3b3996ac-8891-4a9f-aa2f-0ba95b63973f/)

## Documentation

- [PowerAdmin - PAExec](https://www.poweradmin.com/paexec/)

## Blogs / Reports References

- [Cybereason - DeadRinger: Exposing Chinese Threat Actors Targeting Major Telcos](https://www.cybereason.com/blog/deadringer-exposing-chinese-threat-actors-targeting-major-telcos)
- [Cybereason - Operation GhostShell: Novel RAT Targets Global Aerospace and Telecoms Firms](https://www.cybereason.com/blog/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms)
- [Cybereason - Cybereason vs. Prometheus Ransomware](https://www.cybereason.com/blog/cybereason-vs.-prometheus-ransomware)
- [Palo Alto Networks - Unite 42 - Shamoon 2: Delivering Disttrack](https://unit42.paloaltonetworks.com/unit42-shamoon-2-delivering-disttrack/)
- [Microsoft Security Blog - Iranian targeting of IT sector on the rise](https://www.microsoft.com/security/blog/2021/11/18/iranian-targeting-of-it-sector-on-the-rise/)
- [Mandiant - Behind the CARBANAK Backdoor](https://www.mandiant.com/resources/behind-the-carbanak-backdoor)
- [Awake Security - Threat Hunting for PAExec](https://awakesecurity.com/blog/threat-hunting-for-paexec/)

## ATT&CK Techniques

- [T1021.002 - Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1136.002 - Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002)
- [T1543.003 - Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003)
- [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1021/002)
- [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Sysmon Event ID 17 - Pipe Created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017)

## Detection Validation

- TBD

## Detection Rules

- **Microsoft Defender 365**
  - [Detects malicious SMB Named Pipes (used by common C2 frameworks)](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Command%20and%20Control/C2-NamedPipe.md)
  - [Identify use of PAExec](https://www.microsoft.com/security/blog/2021/11/18/iranian-targeting-of-it-sector-on-the-rise/)

- **Sigma**
  - [Renamed PAExec](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_renamed_paexec.yml)
  - [PsExec/PAExec Flags](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_psexex_paexec_flags.yml)
  - [Execution of Renamed PaExec](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_paexec.yml)
  - [Suspicious PsExec Execution - Zeek](https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml)
  - [Suspicious PsExec Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_susp_psexec.yml)
  - [PsExec Pipes Artifacts](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_psexec_pipes_artifacts.yml)

## LOLBAS / GTFOBins References

- None
