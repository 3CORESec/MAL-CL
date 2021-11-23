# Regedit

## Table of Contents

- [Regedit](#regedit)
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

> **Regedit is a GUI based registry editor that can be used via command-line to import, export or delete registry settings from a text (.REG) file.** - [SS64](https://ss64.com/nt/regedit.html)

## Versions History

- TBD

## Common CommandLine

```batch
rem Silent import
regedit  /s [Path to .reg file]
```

- Regedit can also be used to export all or specific keys from the registry with both the `/e` or `/a` switches

```batch
regedit /e [Path to save results]

regedit /e [Path to save results] [RegistryPath]
```

## Default Install Location

```batch
C:\Windows\regedit.exe

C:\Windows\SysWOW64\regedit.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - saunst.exe](https://app.any.run/tasks/33d86d27-df89-44d9-a89e-6918d1a69090/)
- [ANY.RUN - WRCFree.exe](https://app.any.run/tasks/48e4e0b5-0090-43cd-a1f8-408e7986ffde/)
- [Hatching Triage (tria.ge) - R.exe](https://tria.ge/210301-sc8ww8l552/behavioral2#report)
- [Hatching Triage (tria.ge) - SecuriteInfo.com.Trojan.Rasftuby.Gen.14.10239.27368.exe](https://tria.ge/201226-qpcc9747bn/behavioral1#report)
- [Hatching Triage (tria.ge) - 7914dfbc48475ac39fe3e3bd6f062b4f.exe](https://tria.ge/201214-nn7g86q4ka/behavioral2#report)

## Documentation

- [SS64.com - Windows CMD - Regedit](https://ss64.com/nt/regedit.html)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Sigma**
  - [Imports Registry Key From an ADS](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regedit_import_keys_ads.yml)
  - [Imports Registry Key From a File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regedit_import_keys.yml)
  - [Exports Registry Key To an Alternate Data Stream](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/create_stream_hash/sysmon_regedit_export_to_ads.yml)
  - [Exports Registry Key To a File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regedit_export_keys.yml)
  - [Exports Critical Registry Keys To a File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regedit_export_critical_keys.yml)

## LOLBAS / GTFOBins References

- [LOLBAS - Regedit.exe](https://lolbas-project.github.io/lolbas/Binaries/Regedit/)
