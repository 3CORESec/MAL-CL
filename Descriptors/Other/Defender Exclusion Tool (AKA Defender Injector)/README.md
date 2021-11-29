# Defender Exclusion Tool (AKA Defender Injector)

## Table of Contents

- [Defender Exclusion Tool (AKA Defender Injector)](#defender-exclusion-tool-aka-defender-injector)
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

<p align="center"><img src="/Images/Screenshots/DefenderExclusionTool.png"></p>

> **Defender Exclusion Tool is a small Portable freeware which will allow you to add/delet Microsoft Defender exclusions.**

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1.3    | d2b13b47eeab95a98ba93fa2bd86419029f2c5b1 | [LINK](https://www.virustotal.com/gui/file/7d8f35945c17c54056d4aaca05c14bd45640a8c9d1d38f646ae06a8b9cb0c117)                                                                                                             |
| 1.2    | aacc088dfbb8a5b97bf0fe1666dd974d6c578383 | [LINK](https://www.virustotal.com/gui/file/3cbbd45d2acc6fe5dbb71faa7febc910329d1b032aaaede54036b203a6563367)                                                                                                             |
| 1.1    | 68bcdb4bd98a710cce5bfc4c6f3cea0b4ce854b4 | [LINK](https://www.virustotal.com/gui/file/4b3a81fe645bae70594161be1c467636b9caf36a1451c615f79e8ae24609f975)                                                                                                             |

## Common CommandLine

- Note that the current version named "Defender Exclusion Tool" doesn't support command-line option. (See [DFIR Artifacts](#dfir-artifacts) section for more information)

```batch
dinjector /A [PathToFileOrFolder]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- ``ExcTool`` (Defender Exclusion Tool) / ``dinjector`` (Defender Injector) are downloadable portable executables so no installation is required to execute them.

## DFIR Artifacts

- ``Defender Injector`` Drop files and delete them immediately in the ``C:\Windows\Temp`` directory.

- ``Defender Exclusion Tool`` doesn't support command line arguments. Instead it drops a powershell file in the %temp% directory and execute it. The powershell script contains the following code:

```powershell
Add-MpPreference -ExclusionPath [PathToFileOrFolder]

Remove-Item $myinvocation.mycommand.Path -Force
Exit
```

- ``Defender Exclusion Tool`` Also drops and delete file into the ``C:\Windows\Temp`` directory.

## Examples In The Wild

- TBD

## Documentation

- [Sordum - Defender Exclusion Tool](https://www.sordum.org/10636/defender-exclusion-tool-v1-3/)

- Command-Line options for previous version (Defender Injector 1.1)

```yaml
Usage: <command> <file or folder path>
Commands:

/A: Add an exclusion to Windows Defender

/D : Delete an Exclusion from Windows Defender
Samples:

dinjector.exe /A “C:\text.exe”

dinjector.exe /D “C:\test.exe”
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)
- [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- N/A
