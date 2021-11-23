# Handle

## Table of Contents

- [Handle](#handle)
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

> **Handle is a utility that displays information about open handles for any process in the system.** - [MSDN](https://docs.microsoft.com/en-us/sysinternals/downloads/handle)

## Versions History

- TBD

## Common CommandLine

- Note that most of the time the process is renamed but the flags are the same
- Note that the "/" can be used instead of the "-" when calling the flags.

```batch
handle -accepteula [Path]

handle [Path] -accepteula -nobanner

handle -a
```

## Default Install Location

- Handle is a downloadable portable utility so no installation is required to execute it.

- The Sysinternals suite is available in the Microsoft Store. If downloaded from there then the `handle` utility will be installed in the following location:

```batch
C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_[Version]\Tools\handle.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

- [Microsoft Docs - Handle](https://docs.microsoft.com/en-us/sysinternals/downloads/handle)

## Blogs / Reports References

- [Securelist By Kaspersky - In ExPetr/Petya’s shadow, FakeCry ransomware wave hits Ukraine](https://securelist.com/in-expetrpetyas-shadow-fakecry-ransomware-wave-hits-ukraine/78973/)

## ATT&CK Techniques

- [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
