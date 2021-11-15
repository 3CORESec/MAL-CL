# SoftPerfect Network Scanner (netscan.exe)

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Powerful multipurpose network administration tool for Windows and macOS. Can ping computers, scan ports, discover shared folders and retrieve practically any information about network devices via WMI, SNMP, HTTP, SSH and PowerShell. It also scans for remote services, registry, files and performance counters; offers flexible filtering and display options and exports NetScan results to a variety of formats from XML to JSON.** — [SoftPerfect Network Scanner](https://www.softperfect.com/products/networkscanner/)

## Common CommandLine

```batch
netscan. exe /hide /auto:"result.xml"

netscan.exe /hide /live:"result.xml"

netscan.exe /hide /auto:"result.xml" /config:netscan.xml /range:[IP RANGE]

netscan.exe /hide /range:all
```

## Default Install Location

- TBD

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - nv.exe](https://app.any.run/tasks/b84f4cbb-e5a3-432d-a842-771e5805938f/)
- [ANY.RUN - ns.exe](https://app.any.run/tasks/97125f23-4d77-4b9d-b294-d58445b9ff30/)
- [ANY.RUN - tll.zip](https://app.any.run/tasks/0ac70424-96fd-4731-a4f1-ad25c86c802a/)
- [JOESandbox - NETscan64-bit.exe](https://www.joesandbox.com/analysis/241436/1/html)

## Documentation

- [SoftPerfect Network Scanner Online User Manual](https://www.softperfect.com/products/networkscanner/manual/)

## Blogs / Reports References

- [The DFIR Report  - Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/)
- [The DFIR Report  - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report  - Bazar, No Ryuk?](https://thedfirreport.com/2021/01/31/bazar-no-ryuk/)
- [Cobalt Strike Manual V2 Active Directory - Leaked Conti Ransomware Playbook](https://github.com/silence-is-best/files)
- [CISA - Analysis Report (AR21-126A) - FiveHands Ransomware](https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a)
- [nccgroup - Handy guide to a new Fivehands ransomware variant](https://research.nccgroup.com/2021/06/15/handy-guide-to-a-new-fivehands-ransomware-variant/)

## ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1135 — Network Share Discovery](https://attack.mitre.org/versions/v9/techniques/T1135/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
