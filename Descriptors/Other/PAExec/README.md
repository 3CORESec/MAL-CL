# PAExec

## Table of Contents

- [PAExec](#paexec)
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

> **PAExec lets you launch Windows programs on remote Windows computers without needing to install software on the remote computer first.** - [PowerAdmin](https://www.poweradmin.com/paexec/)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1.29    | 0fc135b131d0bb47c9a0aaf02490701303b76d3b | [LINK](https://www.virustotal.com/gui/file/ab50d8d707b97712178a92bbac74ccc2a5699eb41c17aa77f713ff3e568dcedb)                                                                                                             |
| 1.28    | 5fd0c019e47d19ec1bcef2a0664bd4f7625dc15c | [LINK](https://www.virustotal.com/gui/file/da36e983e207e7def052bb44513fffd7b1a84c45f6275b33e95a92197295188a)                                                                                                             |
| 1.26    | 31754ee85d21ce9188394a939c15a271c2562f93 | [LINK](https://www.virustotal.com/gui/file/01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc)                                                                                                             |
| 1.25    | 3238e8522bd0e9e1a1de8ba5e845bd44131d38b8 | [LINK](https://www.virustotal.com/gui/file/ee0667582457d6b87f69d5457b9d51b5c8a021eea663cd1491fb0aabff98e4b2)                                                                                                             |
| 1.24    | ea9c9799394ab8e6a1374832d5e3eec6830d5e56 | [LINK](https://www.virustotal.com/gui/file/ba4a2878a2ee148052333266f8ae3e0004e03bf4419e0961aa631c69ae4735fb)                                                                                                             |
| 1.22    | f9ff4582f6c3d68c84aa2d1da913b51b440ae68e | [LINK](https://www.virustotal.com/gui/file/c7fb20f529ae2e544acf54dd3ef53bd669f89abebe79c9330eaa374995b29779)                                                                                                             |
| 1.21    | 820dee796573b93f154cfa484c35354e41ef7a51 | [LINK](https://www.virustotal.com/gui/file/550512c2a3651313d031160323379b7ef75df82ada415dbddbbac869334f4a2a)                                                                                                             |
| 1.19    | 8f1646da42c1602de60a61eb6bf10ae10394593b | [LINK](https://www.virustotal.com/gui/file/2760eb4e047484cbfeb007be497ccfa0841003fcfb472652d46df531f3bb3e1c)                                                                                                             |
| 1.18    | 1daf79b3aa3172446b829b04d7478ac8cc0ea130 | [LINK](https://www.virustotal.com/gui/file/4badeff9903c6f347e6158a12ca05b87ba282496bb0785a481bf28d53dd4d1d0)                                                                                                             |
| 1.17    | e742288f30a4c052add983a96ea005e8bfb0bbde | [LINK](https://www.virustotal.com/gui/file/e0596038c0de0de80b81f086d72c24393077593de0e8dc906a3c3fdd98795018)                                                                                                             |

## Common CommandLine

- Note that "PAExec uses the same command-line options as PsExec, plus a few additonal options of its own".
- PAExec is often renamed but the arguments are the same.

```batch
paexec \\[@IP] [Command]

paexec \\[@IP] -u [Username] -p [Password] -s [Command]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

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

## Telemetry

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
