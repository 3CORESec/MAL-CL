# Local (local.exe)

## Table of Contents

- [Local (local.exe)](#local-localexe)
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

> **Displays members of local groups on remote servers or domains..**

## Common CommandLine

```batch
local [GroupName] [Domain]

local [GroupName] \\[@IP]
```

## Default Install Location

- Local is a downloadable portable utility so no installation is required to execute it.

- Local is part of the Microsoft Windows NT Resource Kit.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

```yaml
Displays members of local groups on remote servers or domains.

LOCAL group_name domain_name | \\server

  group_name    The name of the local group to list the members of.
  domain_name   The name of a network domain.
  \\server      The name of a network server.

Examples:
  Local "Power Users" EastCoast
  Displays the members of the group 'Power Users' in the EastCoast domain.

  Local Administrators \\BLACKCAT
  Displays the members of the group Administrators on server BLACKCAT.

Notes:
  Names that include space characters must be enclosed in double quotes.
  To list members of global groups use Global.Exe.
  To get the Server name for a give Domain use GetDC.Exe.
```

## Blogs / Reports References

- [Securelist By Kaspersky - Striking Oil: A Closer Look at Adversary Infrastructure](https://unit42.paloaltonetworks.com/unit42-striking-oil-closer-look-adversary-infrastructure/)

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
