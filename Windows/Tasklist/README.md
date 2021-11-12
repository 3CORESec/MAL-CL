# Tasklist

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Tasklist is a windows utility that displays a list of currently running processes on the local computer or on a remote computer.** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)

## Common CommandLine

```batch
tasklist

tasklist /V

tasklist /svc

tasklist /FI "IMAGENAME eq [ProcessName]"

tasklist /fi "MODULES ne [DLLName]"

tasklist /FI "SERVICES eq [ProcessName]" /svc

tasklist /FI "SERVICES eq [ProcessName]" /FO LIST

tasklist /FO csv
```

## Default Install Location

```batch
C:\Windows\System32\tasklist.exe

C:\Windows\SysWOW64\tasklist.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - in[1].exe](https://app.any.run/tasks/058ad3c9-b95f-46bf-95fb-b64bfd9bcd35/)
- [ANY.RUN - Restoro.exe](https://app.any.run/tasks/fb2c0aa7-15c0-4198-8d0c-114b6cee70c8/)
- [ANY.RUN - dru.exe](https://app.any.run/tasks/0318cefb-a012-4884-87b3-56056b4304a5/)
- [ANY.RUN - dfac3bbabcbd75bd3ecc556d32d2345f3d4d7897697c5f21b17fc25de5294031](https://app.any.run/tasks/46900dbd-3517-4750-9e06-d6963ca2f030/)
- [Hatching Triage (tria.ge) - 4da9eff3a95a5a313218c1a0a4055647.exe](https://tria.ge/210620-xpwffztzae/behavioral1#report)
- [Hatching Triage (tria.ge) - Russian APT29 (2).exe](https://tria.ge/200717-h9ahb75ylj/behavioral1#report)
- [Hatching Triage (tria.ge) - ReimageRepair.exe](https://tria.ge/201211-5fm3dkn39j/behavioral1#report)

## Documentation

- [Microsoft Docs - Tasklist](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)
- [SS64.com - Windows CMD - Tasklist](https://ss64.com/nt/tasklist.html)

## Blogs / Reports References

- [The DFIR Report - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report - Tricky Pyxie](https://thedfirreport.com/2020/04/30/tricky-pyxie/)
- [Palo Alto Networks - Unite 42 - IronNetInjector: Turla’s New Malware Loading Tool](https://unit42.paloaltonetworks.com/ironnetinjector/)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: New BumbleBee Webshell and SSH Tunnels Used for Lateral Movement](https://unit42.paloaltonetworks.com/bumblebee-webshell-xhunt-campaign/)
- [Palo Alto Networks - Unite 42 - The Fractured Statue Campaign: U.S. Government Agency Targeted in Spear-Phishing Attacks](https://unit42.paloaltonetworks.com/the-fractured-statue-campaign-u-s-government-targeted-in-spear-phishing-attacks/)
- [Palo Alto Networks - Unite 42 - Behind the Scenes with OilRig](https://unit42.paloaltonetworks.com/behind-the-scenes-with-oilrig/)
- [Palo Alto Networks - Unite 42 - New BabyShark Malware Targets U.S. National Security Think Tanks](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)
- [Palo Alto Networks - Unite 42 - BabyShark Malware Part Two – Attacks Continue Using KimJongRAT and PCRat](https://unit42.paloaltonetworks.com/babyshark-malware-part-two-attacks-continue-using-kimjongrat-and-pcrat/)
- [Palo Alto Networks - Unite 42 - Dear Joohn: The Sofacy Group’s Global Campaign](https://unit42.paloaltonetworks.com/dear-joohn-sofacy-groups-global-campaign/)
- [Securelist By Kaspersky - KopiLuwak: A New JavaScript Payload from Turla](https://securelist.com/kopiluwak-a-new-javascript-payload-from-turla/77429/)

## ATT&CK Techniques

- [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1518.001 - Software Discovery: Security Software Discovery](https://attack.mitre.org/techniques/T1518/001)
- [T1007 - System Service Discovery](https://attack.mitre.org/techniques/T1007)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- **Elastic**
  - [Process Discovery via Tasklist (Deprecated)](https://github.com/elastic/detection-rules/blob/main/rules/_deprecated/discovery_process_discovery_via_tasklist_command.toml)

## LOLBAS / GTFOBins References

- None
