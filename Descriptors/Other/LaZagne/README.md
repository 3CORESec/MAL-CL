# LaZagne

## Table of Contents

- [LaZagne](#lazagne)
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

<p align="center"><img src="/Images/Screenshots/LaZagne.png"></p>

> **The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.** — [LaZagne Github](https://github.com/AlessandroZ/LaZagne/)

## Common CommandLine

```batch
laZagne.exe all

laZagne.exe all -oA -output [Path]

laZagne.exe browsers

laZagne.exe Sysadmin
```

## Default Install Location

- TBD

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - usb Rubber Ducky.7z](https://app.any.run/tasks/d1186820-0a66-425a-a064-9fd69ac269f9/)
- [ANY.RUN - USBStealer-3.zip](https://app.any.run/tasks/62056621-8b6a-4351-887f-fa3ce2bdb7d0/)
- [ANY.RUN - zugu.exe](https://app.any.run/tasks/417c7dee-3da6-4e1b-a9d5-2dafc953eb1d/)
- [ANY.RUN - 6a85c564-2dd3-11e8-8ca9-c8b003f8d9f9](https://app.any.run/tasks/c7fdc9bd-93bf-46cc-9413-3dc38cc2bdfb/)
- [ANY.RUN - cd.exe](https://app.any.run/tasks/3db0de8e-b9a9-4443-93fe-bc0c9e4299a2/)

## Documentation

- [AlessandroZ/LaZagne: Credentials recovery project](https://github.com/AlessandroZ/LaZagne/)

## Blogs / Reports References

- [The DFIR Report  - Cobalt Strike, a Defender’s Guide](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
- [The DFIR Report  - Trickbot Brief: Creds and Beacons](https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/)
- [The DFIR Report  - GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)
- [Trend Micro - Weaponizing Open Source Software for Targeted Attacks](https://www.trendmicro.com/en_us/research/20/k/weaponizing-open-source-software-for-targeted-attacks.html)
- [Yoroi - Shadows From the Past Threaten Italian Enterprises](https://yoroi.company/research/shadows-from-the-past-threaten-italian-enterprises/)

## ATT&CK Techniques

- [T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [T1555.003 — Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [T1555.004 — Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [T1003.004 — OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004/)
- [T1003.005 — OS Credential Dumping: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)
- [T1003.007 — OS Credential Dumping: Proc Filesystem](https://attack.mitre.org/techniques/T1003/007/)
- [T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)
- [T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Credential Extraction indicative of Lazagne command line options](https://research.splunk.com/endpoint/credential_extraction_indicative_of_lazagne_command_line_options/)

- **Sigma**
  - [Credential Dumping by LaZagne](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/sysmon_lazagne_cred_dump_lsass_access.yml)

## LOLBAS / GTFOBins References

- None
