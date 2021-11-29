# Systeminfo

## Table of Contents

- [Systeminfo](#systeminfo)
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

> **Systeminfo is a windows utility that displays detailed configuration information about a computer and its operating system, including operating system configuration, security information, product ID, and hardware properties (such as RAM, disk space, and network cards).** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)

## Versions History

- TBD

## Common CommandLine

- The most common usage of this command is without any arguments. But bare in mind that it can be used to query a remote system via the "/S" switch (See [documentation](#documentation) section for more information)

```batch
systeminfo
```

## Default Install Location

```batch
C:\Windows\System32\systeminfo.exe

C:\Windows\SysWOW64\systeminfo.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - da060f48b3c681639d8ec285846285ed8fda300fa9ee69a69d4fa8c0420c8070.exe](https://app.any.run/tasks/4359de42-3a69-4474-b9fd-d00e31a37ebf/)
- [ANY.RUN - 1fcd9892532813a27537f4e1a1c21ec0c110d6b3929602750ed77bbba7caa426.doc](https://app.any.run/tasks/2eef6f80-51f4-449f-93b8-3a6b66c052f0/)
- [Hatching Triage (tria.ge) - emotet_e2_72bb45f25da9afa46d5e326089675c0a79d3ffe30eade356cd8114e74b2e58e9_2020-10-28__182128961946._doc.doc](https://tria.ge/201028-32zsgxr2q6/behavioral2)
- [Hatching Triage (tria.ge) - 2020-07-14-IcedID-EXE-persistent-on-infected-Windows-host.bin.exe](https://tria.ge/200715-krwhh6235j/behavioral2)
- [Hatching Triage (tria.ge) - SecuriteInfo.com.Win32.Heri.23387.26236.exe](https://tria.ge/201109-sxp6zcn2bj/behavioral2)
- [Hatching Triage (tria.ge) - hostsvc.dll](https://tria.ge/210406-5bgafmrjzx/behavioral1)

## Documentation

- [Microsoft Docs - Systeminfo](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [SS64.com - Windows CMD - Systeminfo](https://ss64.com/nt/systeminfo.html)

## Blogs / Reports References

- [The DFIR Report - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - BazarLoader to Conti Ransomware in 32 Hours](https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/)
- [The DFIR Report - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report - IcedID and Cobalt Strike vs Antivirus](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/)
- [The DFIR Report - From Word to Lateral Movement in 1 Hour](https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/)
- [The DFIR Report - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)
- [The DFIR Report - Sodinokibi (aka REvil) Ransomware](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
- [The DFIR Report - Bazar Drops the Anchor](https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/)
- [The DFIR Report - Bazar, No Ryuk?](https://thedfirreport.com/2021/01/31/bazar-no-ryuk/)
- [The DFIR Report - Trickbot Still Alive and Well](https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/)
- [The DFIR Report - Ryuk’s Return](https://thedfirreport.com/2020/10/08/ryuks-return/)
- [Securelist By Kaspersky - Turla renews its arsenal with Topinambour](https://securelist.com/turla-renews-its-arsenal-with-topinambour/91687/)
- [Securelist By Kaspersky - Zebrocy’s Multilanguage Malware Salad](https://securelist.com/zebrocys-multilanguage-malware-salad/90680/)
- [Securelist By Kaspersky - A Zebrocy Go Downloader](https://securelist.com/a-zebrocy-go-downloader/89419/)
- [Palo Alto Networks - Unite 42 - The Fractured Statue Campaign: U.S. Government Agency Targeted in Spear-Phishing Attacks](https://unit42.paloaltonetworks.com/the-fractured-statue-campaign-u-s-government-targeted-in-spear-phishing-attacks/)
- [Palo Alto Networks - Unite 42 - Behind the Scenes with OilRig](https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/)
- [Palo Alto Networks - Unite 42 - Sofacy Creates New ‘Go’ Variant of Zebrocy Tool](https://unit42.paloaltonetworks.com/sofacy-creates-new-go-variant-of-zebrocy-tool/)
- [Palo Alto Networks - Unite 42 - The TopHat Campaign: Attacks Within The Middle East Region Using Popular Third-Party Services](https://unit42.paloaltonetworks.com/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/)
- [Palo Alto Networks - Unite 42 - Dear Joohn: The Sofacy Group’s Global Campaign](https://unit42.paloaltonetworks.com/dear-joohn-sofacy-groups-global-campaign/)
- [Palo Alto Networks - Unite 42 - Sofacy Continues Global Attacks and Wheels Out New ‘Cannon’ Trojan](https://unit42.paloaltonetworks.com/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/)
- [Palo Alto Networks - Unite 42 - Fresh Baked HOMEKit-made Cookles – With a DarkHotel Overlap](https://unit42.paloaltonetworks.com/unit42-fresh-baked-homekit-made-cookles-with-a-darkhotel-overlap/)

## ATT&CK Techniques

- [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Cmdline Tool Not Executed In CMD Shell](https://research.splunk.com/endpoint/cmdline_tool_not_executed_in_cmd_shell/)

- **Elastic**
  - [Suspicious MS Office Child Process](https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_suspicious_ms_office_child_process.toml)
  - [Suspicious MS Outlook Child Process](https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_suspicious_ms_outlook_child_process.toml)
  - [Suspicious PDF Reader Child Process](https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_suspicious_pdf_reader.toml)
  - [Enumeration Command Spawned via WMIPrvSE](https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_enumeration_via_wmiprvse.toml)
  - [Unusual Child Process of dns.exe](https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_unusual_dns_service_children.toml)

- **Sigma**
  - [Quick Execution of a Series of Suspicious Commands](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_multiple_suspicious_cli.yml)
  - [Reconnaissance Activity with Net Command](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_commands_recon_activity.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)

## LOLBAS / GTFOBins References

- None
