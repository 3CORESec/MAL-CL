# Regedit

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Regini is a windows utility that modifies the registry from the command line or a script, and applies changes that were preset in one or more text files** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini)

## Common CommandLine

```batch
rem See the documentation section for examples on the config file

regini [PathToConfigFile]

regini -m [\\ComputerName] [PathToConfigFile]
```

## Default Install Location

```batch
C:\Windows\System32\regini.exe

C:\Windows\SysWOW64\regini.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 3c482c1a2608aa3173bc2bae595cf6bb979e283049e51b7a0e3516a5bde50c29.bat](https://app.any.run/tasks/d0ad644c-4213-4c71-87a5-3017d5a04e08/)
- [ANY.RUN - d87c0fa8caf987457e913bada6c57111f504c4e4e0cb28942bec68bef2b9ee0f](https://app.any.run/tasks/77893f87-8ed9-47b0-a46a-d38929387d78/)
- [ANY.RUN - CAC MUC THANH TOAN 2012.exe](https://app.any.run/tasks/160b5e36-a9ff-4b38-80f7-2a14b7110e59/)

## Documentation

- [Microsoft Docs - Regini](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini)
- [SS64.com - Windows CMD - Regini](https://ss64.com/nt/regini.html)

## Blogs / Reports References

- [Microsoft Docs - How to change registry values or permissions from a command line or a script](https://docs.microsoft.com/en-US/troubleshoot/windows-client/application-management/change-registry-values-permissions)

## ATT&CK Techniques

- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Sigma**
  - [Modifies the Registry From a File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regini.yml)
  - [Modifies the Registry From a ADS](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regini_ads.yml)

## LOLBAS / GTFOBins References

- [LOLBAS - Regini.exe](https://lolbas-project.github.io/lolbas/Binaries/Regini/)
