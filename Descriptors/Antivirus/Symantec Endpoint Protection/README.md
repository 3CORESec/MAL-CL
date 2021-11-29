# Symantec Endpoint Protection (SEP)

## Table of Contents

- [Symantec Endpoint Protection (SEP)](#symantec-endpoint-protection-sep)
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

> **Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable, disable, export) different components of SEP**

## Versions History

- TBD

## Common CommandLine

```batch
rem Stops the client service and unloads it from memory.
smc -stop
smc -p [password] -stop

rem Disables the Symantec Endpoint Protection firewall and Intrusion Prevention System.
smc -disable -ntp

rem Disables the Symantec Endpoint Protection Memory Exploit Mitigation system.
smc -disable -mem

rem Disables the Symantec Endpoint Protection Generic Memory Exploit Mitigation system
smc -enable -gem

rem Disables Web and Cloud Access Protection
smc -disable -wss
```

## Default Install Location

```batch
C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

- [Broadcom Techdocs - Symantec Endpoint Protection Installation And Administration Guide](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/appendices/windows-commands-for-the-endpoint-protection-clien-v9567615-d19e6200.html)

## Blogs / Reports References

- [c0d3xpl0it - Disabling Symantec Endpoint Protection (SEP) - Misconfiguration](https://www.c0d3xpl0it.com/2014/09/disabling-symantec-endpoint-protection.html)
- [Lab Core - Disable/Enable Symantec Protection via Command Line](http://eddiejackson.net/wp/?p=16129)
- [Broadcom Community - Remove the SMC password without applying policy from Server](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=4e841cf0-671a-4ed4-a463-a628126832ba&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments)

## ATT&CK Techniques

- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
