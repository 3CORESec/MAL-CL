# AddUsers (AddUsers.exe)

## Table of Contents

- [AddUsers (AddUsers.exe)](#addusers-addusersexe)
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

> **Addusers is autility that uses a comma-delimited file to create, write, and delete user accounts.**

## Versions History

- TBD

## Common CommandLine

```batch
rem Create user[s] from file
AddUsers /c [FileContainingListOfUsers]

rem Dump user accounts, local groups, and global groups to a file
AddUsers /d [Filename]
```

## Default Install Location

- AddUsers is a downloadable portable utility so no installation is required to execute it.

- AddUsers is part of the Microsoft Windows NT Resource Kit.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

- [SS64 - Windows CMD - AddUsers](https://ss64.com/nt/addusers.html)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1136.001 - Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [T1531 - Account Access Removal](https://attack.mitre.org/techniques/T1531/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Security Event ID 4720 - A user account was created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4720)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
