# CleanWipe

![coverage-mindmap](/Images/MindMaps/CleanWipe.png)

## Table of Contents

- [CleanWipe](#cleanwipe)
  - [Table of contents](#table-of-contents)
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

<p align="center"><img src="/Images/Screenshots/CleanWipe.png"></p>

> **Symantec CleanWipe removal tool is a utility that removes any Symantec software, such as Symantec Endpoint Protection**

## Common CommandLine

- When CleanWipe is launched it spawns children processes with the following Command Line

```batch
SepRemovalToolNative_x64.exe

CATClean.exe --uninstall

NetInstaller.exe -r

WFPUnins.exe /uninstall /enterprise
```

- Undocumented Commandline arguments

```batch
-t / --tempdir
-r / --resume
-k / --token
-o / --runonce
-s / --scheduler
--ignore-nco-check
```

## Default Install Location

- CleanWipe is a downloadable portable package so no installation is required to execute it. It's also included in the full installation file for Symantec Endpoint Protection.

## DFIR Artifacts

- Default Log Location

```batch
C:\Windows\Temp\CleanWipe_[YYYY][MM][DD][HH][MM][SS]
```

## Examples In The Wild

- [ANY.RUN - CleanWipe (SymantecUninstaller).zip](https://app.any.run/tasks/d38d569b-dc68-4b0b-b6d2-b7b8244778a1/)

## Documentation

- [Broadcom Techdocs - Download the CleanWipe removal tool to uninstall Endpoint Protection](https://knowledge.broadcom.com/external/article/178870)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
