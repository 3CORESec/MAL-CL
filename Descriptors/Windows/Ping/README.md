# Ping

## Table of Contents

- [Ping](#ping)
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

> **Verifies IP-level connectivity to another TCP/IP computer by sending Internet Control Message Protocol (ICMP) echo Request messages** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ping)

## Versions History

- TBD

## Common CommandLine

```batch
ping [IP]

ping -a [IP]

ping -n [Number Of Pings] -4 [IP]

ping  [IP] -n 1 -w 5000

rem 0x7f000001 is localhost in HEX
ping [0x7f000001] -n 5 -w 10000
```

## Default Install Location

```batch
C:\Windows\System32\ping.exe

C:\Windows\SysWOW64\ping.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - КМSрiсо.exe](https://app.any.run/tasks/d1288af2-f988-49e6-90fa-a9a8d8e8dad1/)
- [ANY.RUN - zzz.exe](https://app.any.run/tasks/bdb2a716-bf17-479d-95c0-0af2e688852a/)
- [ANY.RUN - DiscordGenerator.exe](https://app.any.run/tasks/8a5aed7f-b6dd-45a2-858d-de6f5b76d5da/)

## Documentation

- [Microsoft Docs - Ping](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ping)
- [SS64.com - Windows CMD - Ping](https://ss64.com/nt/ping.html)

## Blogs / Reports References

- [The DFIR Report - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report - From Zero to Domain Admin](https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/)
- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - BazarLoader to Conti Ransomware in 32 Hours](https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/)
- [The DFIR Report - Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/)
- [The DFIR Report - IcedID and Cobalt Strike vs Antivirus](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/)

## ATT&CK Techniques

- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

## Eventlog / Sysmon Events to Monitor

- TBD

## Detection Validation

- TBD

## Detection Rules

- **Sigma**
  - [Ping Hex IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_ping_hex_ip.yml)

## LOLBAS / GTFOBins References

- None
