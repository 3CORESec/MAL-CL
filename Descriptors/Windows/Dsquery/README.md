# Net

## Table of Contents

- [Net](#net)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
  - [Versions History](#versions-history)
  - [File Metadata](#file-metadata)
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

> **Dsquery is a command-line tool that queries the directory by using search criteria that you specify** — [MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

```batch
dsquery subnet -limit 0

dsquery computer -limit 0

dsquery user -limit 0

dsquery group -limit 0

dsquery * -filter "(objectClass=trustedDomain)" -attr *

dsquery group -name "Domain Admins"
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\dsquery.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 3dtap.exe](https://app.any.run/tasks/613cde47-a250-46af-8c15-d1b8e096b625/)

## Documentation

- [Microsoft Docs - Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))
- [SS64.com - Windows CMD - Dsquery](https://ss64.com/nt/dsquery.html)

## Blogs / Reports References

- [The DFIR Report  - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)
- [Palo Alto Networks - Unite 42 - Actor Exploits Microsoft Exchange Server Vulnerabilities, Cortex XDR Blocks Harvesting of Credentials](https://unit42.paloaltonetworks.com/exchange-server-credential-harvesting/)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: xHunt Actor’s Cheat Sheet](https://unit42.paloaltonetworks.com/xhunt-actors-cheat-sheet/)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: Attacks on Kuwait Shipping and Transportation Organizations](https://unit42.paloaltonetworks.com/xhunt-campaign-attacks-on-kuwait-shipping-and-transportation-organizations/)
- [Microsoft Security Blog - Analyzing attacks taking advantage of the Exchange Server vulnerabilities](https://www.microsoft.com/security/blog/2021/03/25/analyzing-attacks-taking-advantage-of-the-exchange-server-vulnerabilities/)
- [Specterops - An Introduction to Manual Active Directory Querying with Dsquery and Ldapsearch](https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb)

## ATT&CK Techniques

- [T1069.002 - Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/)
- [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Discover domain trusts with dsquery](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md)

- **Uber - Metta**
  - [Account discovery commands via net, dsquery, wmic](https://github.com/uber-common/metta/blob/master/MITRE/Discovery/discovery_win_account.yml)

## Detection Rules

- **Splunk**
  - [DSQuery Domain Discovery](https://research.splunk.com/endpoint/dsquery_domain_discovery/)
  - [Domain Group Discovery With Dsquery](https://research.splunk.com/endpoint/domain_group_discovery_with_dsquery/)
  - [Remote System Discovery with Dsquery](https://research.splunk.com/endpoint/remote_system_discovery_with_dsquery/)
  - [Domain Account Discovery with Dsquery](https://research.splunk.com/endpoint/domain_account_discovery_with_dsquery/)

- **Sigma**
  - [Domain Trust Discovery](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_trust_discovery.yml)

## LOLBAS / GTFOBins References

- None
