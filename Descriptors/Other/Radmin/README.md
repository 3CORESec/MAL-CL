# Radmin (Server/Viewer)

## Table of Contents

- [Radmin (Server/Viewer)](#radmin-serverviewer)
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

<p align="center"><img src="/Images/Screenshots/Radmin-Viewer.png"></p>

> **Radmin is a remote control program that lets you work on another computer through your own** — [Radmin](https://www.radmin.com/support/radmin3help/files/about.htm)

## Versions History

- TBD

## Common CommandLine

- Radmin Server

```batch
rem Starts Radmin Server. 
rserver3 /start

rem Stops Radmin Server.
rserver3 /stop
```

- Radmin Viewer

```batch
rem Initiates connection to a remote computer.
radmin /connect:<RadminServerIP>:<RadminServerPort>

rem Connects through an intermediate Radmin Server.
radmin /connect:<RadminServerIP>:<RadminServerPort> /through:<SecondaryRadminServerIP>:<SecondaryRadminServerPort>
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- Radmin Server

````batch
C:\Windows\SysWOW64\rserver30\rserver3.exe

C:\Windows\SysWOW64\rserver30\FamItrfc

C:\Windows\SysWOW64\rserver30\FamItrf2
````

- Radmin Viewer

```batch
C:\Program Files (x86)\Radmin Viewer 3\Radmin.exe
```

- There exists a downloadable portable package of ``Radmin.exe``  (Viewer) so no installation is required to execute it.

## DFIR Artifacts

- Radmin Server 3 user information is stored (Password can be decrypted using the following [Radmin3-Password-Cracker](https://github.com/synacktiv/Radmin3-Password-Cracker))

```batch
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security
```

## Examples In The Wild

- TBD

## Documentation

- [Radmin - Radmin3 Online Help](https://www.radmin.com/support/radmin3help/)
- [Radmin - Radmin Viewer command-line switches](https://www.radmin.com/support/radmin3help/files/viewercmd.htm)
- [Radmin - Radmin Server command-line switches](https://www.radmin.com/support/radmin3help/files/cmd.htm)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- TBD

## Telemetry

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
