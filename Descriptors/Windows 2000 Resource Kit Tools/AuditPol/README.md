# AuditPol (AuditPol.exe)

## Table of Contents

- [AuditPol (AuditPol.exe)](#auditpol-auditpolexe)
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

> **AuditPol is a command-line tool that enables the user to modify the audit policy of the local computer or of any remote computer.**

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Unknown    | 095915e8067493dabe5031331e78b56374024229 | [LINK](https://www.virustotal.com/gui/file/fa575bd24b9a174315bb283c6b47a6c1289b7283b16e699b75e414fb43e8fbdd/details)                                                                                                             |

## Common CommandLine

```batch
rem Disable Process, System and Logon tracking
AuditPol /process:none /system:none /logon:none

AuditPol \\[IP] /disable
```

## Default Install Location

- AuditPol is a downloadable portable utility so no installation is required to execute it.

- AuditPol is part of the Microsoft Windows 2000 Resource Kit Tools.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

```yaml
AuditPol 1.1b @1996-97 Written by Christophe ROBERT.


AuditPol [\\computer] [/enable | /disable] [/help | /?] [/Category:Option] ...

   /Enable   = Enable audit (default).

   /Disable  = Disable audit.

   Category  = System    : System events
               Logon     : Logon/Logoff events
               Object    : Object access
               Privilege : Use of privileges
               Process   : Process tracking
               Policy    : Security policy changes
               Sam       : SAM changes

   Option    = Success   : Audit success events
               Failure   : Audit failure events
               All       : Audit success and failure events
               None      : Do not audit these events


Samples are as follows:

   AUDITPOL \\MyComputer
   AUDITPOL \\MyComputer /enable /system:all /object:failure
   AUDITPOL \\MyComputer /disable
   AUDITPOL /logon:failure /system:all /sam:success /privilege:none

AUDITPOL /HELP | MORE displays Help one screen at a time.
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1562.002 - Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Security Event ID 4719 - System Audit Policy Was Changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4719)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
