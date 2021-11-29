# Netstat

## Table of Contents

- [Netstat](#netstat)
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

> **Netstat is a windows utility that displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics (for the IP, ICMP, TCP, and UDP protocols), and IPv6 statistics (for the IPv6, ICMPv6, TCP over IPv6, and UDP over IPv6 protocols)** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)

## Versions History

- TBD

## Common CommandLine

```batch
netstat

netstat -an

netstat -ano

netstat /ano

netstat -a -n -p tcp

netstat -naop tcp
```

- The most used flags are the following (See the [documentation](#documentation) section for a complete list)

```yaml
-a   Display All connections and listening ports.
-n   Display addresses and port numbers in Numerical form.
-o   Display the Owning process ID associated with each connection.
-p   Show only connections for the protocol specified and can be any of "TCP", "UDP", "TCPv6" or "UDPv6".
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\netstat.exe

C:\Windows\SysWOW64\netstat.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - webexmta.exe](https://app.any.run/tasks/0f35f119-c3a8-474d-9aad-65a35fd6e080/)
- [ANY.RUN - 55_2_.vbs](https://app.any.run/tasks/b696fb48-1378-46c0-8d11-c0e5302646ba/)
- [ANY.RUN - in6_decoded.ps1](https://app.any.run/tasks/5e81dd12-9350-4491-ba71-3950f212aa5a/)
- [ANY.RUN - 038159.exe](https://app.any.run/tasks/850475b7-74fc-4465-aad4-07fc0d9bf102/)
- [ANY.RUN - 3.zip](https://app.any.run/tasks/06ba9da5-9b10-4f61-9185-452fb0b1b2c2/)
- [ANY.RUN - BitRAT.exe](https://app.any.run/tasks/f5400d3b-874b-4f1f-8918-0b0d3021f8ca/)
- [Hatching Triage (tria.ge) - exec.vbs](https://tria.ge/201204-m5yxtltppj/behavioral2)
- [Hatching Triage (tria.ge) - INV73211.scr](https://tria.ge/210512-hb14qepm8e/behavioral1)
- [Hatching Triage (tria.ge) - Claim-1491126902-09242021.xls](https://tria.ge/210924-v23fcshdg8/behavioral1)

## Documentation

- [Microsoft Docs - Netstat](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)
- [SS64.com - Windows CMD - Netstat](https://ss64.com/nt/netstat.html)

## Blogs / Reports References

- [The DFIR Report - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - Tricky Pyxie](https://thedfirreport.com/2020/04/30/tricky-pyxie/)
- [Palo Alto Networks - Unite 42 - Comnie Continues to Target Organizations in East Asia](https://unit42.paloaltonetworks.com/unit42-comnie-continues-target-organizations-east-asia/)
- [Palo Alto Networks - Unite 42 - Behind the Scenes with OilRig](https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/)
- [Palo Alto Networks - Unite 42 - Fresh Baked HOMEKit-made Cookles – With a DarkHotel Overlap](https://unit42.paloaltonetworks.com/unit42-fresh-baked-homekit-made-cookles-with-a-darkhotel-overlap/)
- [Palo Alto Networks - Unite 42 - The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor](https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/)
- [Palo Alto Networks - Unite 42 - TDrop2 Attacks Suggest Dark Seoul Attackers Return](https://unit42.paloaltonetworks.com/tdrop2-attacks-suggest-dark-seoul-attackers-return/)
- [Palo Alto Networks - Unite 42 - Inside TDrop2: Technical Analysis of new Dark Seoul Malware](https://unit42.paloaltonetworks.com/inside-tdrop2-technical-analysis-of-new-dark-seoul-malware/)
- [Securelist By Kaspersky - QakBot technical analysis](https://securelist.com/qakbot-technical-analysis/103931/)
- [Securelist By Kaspersky - Operation TunnelSnake](https://securelist.com/operation-tunnelsnake-and-moriya-rootkit/101831/)
- [Securelist By Kaspersky - Lazarus covets COVID-19-related intelligence](https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/)

## ATT&CK Techniques

- [T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Network Connection Discovery With Netstat](https://research.splunk.com/endpoint/network_connection_discovery_with_netstat/)
  - [Active Directory Discovery](https://research.splunk.com/stories/active_directory_discovery/)

- **Elastic**
  - [Enumeration Command Spawned via WMIPrvSE](https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_enumeration_via_wmiprvse.toml)

- **Sigma**
  - [Lazarus Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_apt_lazarus_activity_dec20.yml)
  - [Reconnaissance Activity with Net Command](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_commands_recon_activity.yml)
  - [Greenbug Campaign Indicators](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_apt_greenbug_may20.yml)

## LOLBAS / GTFOBins References

- None
