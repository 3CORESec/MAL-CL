# IntelliAdmin Network Administrator - ManageService

<p align="center"><img src="/Images/Screenshots/IntelliAdmin-Network-Administrator.png"></p>

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **ManageService.exe is one of the tools available in the IntelliAdmin Network Administrator software. It can stop, start and set the startup status of services**

## Common CommandLine

```batch
ManageService /Host:[RemoteHost] /Action:[ActionToTake] /Service:[ServiceName]
```

## Default Install Location

- If the ``IntelliAdmin Network Administrator`` tool is installed the tool will be located in the following directory:

```batch
C:\Program Files (x86)\IntelliAdmin\Plugins\Tools\ManageService.exe
```

- This utility can also be copied and used in a standalone way.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

```batch
Usage:

ManageService.exe [Options]

Possible optins:

/HOST: {REMOTE_HOST} - Optional
/SERVICE: {Service Name} - Required
/ACTION: {START|STOP|SET_AUTOMATIC|SET_MANUAL|SET_DISABLED} - Required
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
