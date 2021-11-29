# Nltest

## Table of Contents

- [Nltest](#nltest)
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

> **Network Location Test — List domain controllers(DCs), Force a remote shutdown, Query the status of trust, test trust relationships and the state of domain controller replication.** — [SS64](https://ss64.com/nt/nltest.html)

## Versions History

- TBD

## Common CommandLine

```batch
rem Returns a list of trusted domains.
nltest /domain_trusts

rem Return all trusted domains.
nltest /domain_trusts /all_trusts

rem List all DCs in the domain.
nltest /dclist:"[DOMAIN NAME]"

rem Query the Domain Name System (DNS) server for a list of DCs and their IP addresses.
nltest /dsgetdc:"[DOMAIN NAME]"
```

## Default Install Location

```batch
C:\Windows\System32\nltest.exe

C:\Windows\SysWOW64\nltest.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 4uKAjQgt.exe](https://app.any.run/tasks/d5ee478f-73ff-42bc-8545-7f8122b8fc02/)
- [ANY.RUN - ZnUmYcC.exe](https://app.any.run/tasks/ed1bf76b-c1ac-4a80-b13d-a5a9b935f072/)
- [ANY.RUN - ConsoleApplication1.exe](https://app.any.run/tasks/e543b470-3597-40fe-8aec-e9a48a9286bc/)

## Documentation

- [Microsoft Docs - Nltest](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
- [SS64.com - Windows CMD - Nltest](https://ss64.com/nt/nltest.html)

## Blogs / Reports References

- [The DFIR Report  - From Zero to Domain Admin](https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/)
- [The DFIR Report  - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report  - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)

## ATT&CK Techniques

- [T1482 — Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [T1016 — System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Sigma**
  - [Recon Activity with NLTEST](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_nltest_recon.yml)

## LOLBAS / GTFOBins References

- None
