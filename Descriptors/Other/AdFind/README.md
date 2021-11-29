# AdFind

## Table of Contents

- [AdFind](#adfind)
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

> **Command line Active Directory query tool. Mixture of ldapsearch, search.vbs, ldp, dsquery, and dsget tools with a ton of other cool features thrown in for good measure. This tool proceeded dsquery/dsget/etc by years though I did adopt some of the useful stuff from those tools.** - [Joeware](https://www.joeware.net/freetools/tools/adfind/)

## Versions History

- TBD

## Common CommandLine

```batch
adfind -f objectcategory=computer

adfind -f objectcategory=group

adfind -f objectcategory=person

adfind -f objectcategory=organizationalUnit

rem List Subnets
adfind -subnets -f objectCategory=subnet

adfind -h [host:port] -f name="Domain Admins" member -list

adfind -h [host:port] -f name=administrators

rem Dumps trust objects.
adfind -sc trustdmp
adfind -gcb -sc trustdmp

rem Active Directory Info with whoami info.
adfind -sc adinfo

rem Dump computers set with password not required.
adfind -sc computers_pwdnotreqd

rem  Dump Domain Controllers FQDNs. Return DCs for specific domain by specifying that domain for the base.
adfind -sc dclist

rem Show modes of all DCs in forest from config
adfind -sc dcmodes

rem Dump all Domain NCs in forest in sorted DNS list format
adfind -sc domainlist
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- ``adfind`` is a downloadable portable executable so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- TBD

## Documentation

- [Joeware - adfind Usage](https://www.joeware.net/freetools/tools/adfind/usage.htm)
- [Microsoft Technet - adfind Command Examples](https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx)

## Blogs / Reports References

- [The DFIR Report - adfind Recon](https://thedfirreport.com/2020/05/08/adfind-recon/)
- [The DFIR Report - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - From Word to Lateral Movement in 1 Hour](https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/)
- [Red Canary Blog - A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/)
- [Microsoft Security Blog - Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack, and how Microsoft Defender helps protect customers](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
- [Microsoft 365 Security - How To Hunt For LDAP Reconnaissance Within M365 Defender?](https://m365internals.com/2021/05/22/how-to-hunt-for-ldap-reconnaissance-within-m365-defender/)
- [Mandiant - Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware](https://www.mandiant.com/resources/pick-six-intercepting-a-fin6-intrusion)
- [Mandiant - A Nasty Trick: From Credential Theft Malware to Business Disruption](https://www.mandiant.com/resources/a-nasty-trick-from-credential-theft-malware-to-business-disruption)
- [Wilbur Security - Wilbur Security](https://web.archive.org/web/20200312054414/https://www.wilbursecurity.com/2020/02/trickbot-and-adfind-recon/)

## ATT&CK Techniques

- [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1069.002 - Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002)
- [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002)
- [T1482 - Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)

## Telemetry

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Adfind -Listing password policy](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md#atomic-test-5---adfind--listing-password-policy)
  - [Adfind - Enumerate Active Directory Admins](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md#atomic-test-6---adfind---enumerate-active-directory-admins)
  - [Adfind - Enumerate Active Directory User Objects](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md#atomic-test-7---adfind---enumerate-active-directory-user-objects)
  - [Adfind - Enumerate Active Directory Exchange AD Objects](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md#atomic-test-8---adfind---enumerate-active-directory-exchange-ad-objects)
  - [Adfind - Enumerate Active Directory OUs](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-4---adfind---enumerate-active-directory-ous)
  - [Adfind - Enumerate Active Directory Trusts](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md#atomic-test-5---adfind---enumerate-active-directory-trusts)
  - [Adfind - Enumerate Active Directory Computer Objects](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-10---adfind---enumerate-active-directory-computer-objects)
  - [Adfind - Enumerate Active Directory Domain Controller Objects](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-11---adfind---enumerate-active-directory-domain-controller-objects)
  - [Adfind - Query Active Directory Groups](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md#atomic-test-8---adfind---query-active-directory-groups)
  - [Adfind - Enumerate Active Directory Subnet Objects](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md#atomic-test-6---adfind---enumerate-active-directory-subnet-objects)

## Detection Rules

- **Splunk**
  - [Windows adfind Exe](https://research.splunk.com/endpoint/windows_adfind_exe/)

- **Elastic**
  - [adfind Command Activity](https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_adfind_command_activity.toml)

- **Azure-Sentinel**
  - [Suspicious enumeration using Adfind tool](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/SecurityEvent/Suspicious_enumeration_using_adfind.yaml)

- **Sigma**
  - [Suspicious adfind Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_adfind.yml)
  - [adfind Usage Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_ad_find_discovery.yml)

- **Other**
  - [Vadim-Hunter - Sodinokibi (aka REvil) Ransomware](https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml)

## LOLBAS / GTFOBins References

- None
