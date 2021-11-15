# Defender Control

<p align="center"><img src="/Images/Screenshots/DefenderControl.png"></p>

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Defender Control is a small Portable freeware which will allow you to disable Microsoft Defenderr in Windows 10 completely.** — [Sordum](https://www.sordum.org/9480/defender-control-v2-0/)

## Common CommandLine

```batch
DefenderControl.exe /E

DefenderControl.exe /D /ID:[Defender PID]

DefenderControl.exe /D
```

## Default Install Location

- TBD

## DFIR Artifacts

- TBD

## Examples In The Wild

- [HYBRID-ANALYSIS — Def.exe](https://www.hybrid-analysis.com/sample/a201f7f81277e28c0bdd680427b979aee70e42e8a98c67f11e7c83d02f8fe7ae/5ef3dc0f4ef6473e02070a78)
- [ANY.RUN — Medusa Crypter.exe](https://app.any.run/tasks/54e660eb-4cab-4280-be27-11333838a5eb/)

## Documentation

- [Sordum - Defender Control v2.0](https://www.sordum.org/9480/defender-control-v2-0/)

## Blogs / Reports References

- [The DFIR Report  - Dharma Ransomware](https://thedfirreport.com/2020/04/14/dharma-ransomware/)
- [The DFIR Report  - Defender Control](https://thedfirreport.com/2020/12/13/defender-control/)
- [MORPHISEC - AHK RAT LOADER USED IN UNIQUE DELIVERY CAMPAIGNS](https://blog.morphisec.com/ahk-rat-loader-leveraged-in-unique-delivery-campaigns)

## ATT&CK Techniques

- [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- N/A
