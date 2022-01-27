# AdvancedRun

## Table of Contents

- [AdvancedRun](#advancedrun)
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

- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **AdvancedRun is a simple tool for Windows that allows you to run a program with different settings that you choose, including - low or high priority, start directory, main window state (Minimized/Maximized), run the program with different user or permissions, Operating system compatibility settings, and environment variables.** — [NirSoft](https://www.nirsoft.net/utils/advanced_run.html)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1.50 (x86) | 7983eb5303fe5c36ff51f5b78e06ec5d372202df | [LINK](https://www.virustotal.com/gui/file/8ef8957a60bc02849e0cde21278c7432f4782e27559ceece306fef2cda70cee8) |
| 1.50 (x64) | 1c742086aebb17ba409f9f2510560c2dcde6d45a | [LINK](https://www.virustotal.com/gui/file/d2b72b003c278fbecf32daedeb9b3cf88746e9ed33b8739f4fd96efab494f244) |

## File Metadata

- This metadata information is based on the latest version available as of this writing (1.50).

| Attribute     | Value |
|---------------|-------|
| Copyright     | Copyright © 2012 - 2021 Nir Sofer |
| Product       | AdvancedRun |
| Description   | Run a program with different settings that you choose |
| Original Name | AdvancedRun.exe     |
| Internal Name | AdvancedRun |

## Common CommandLine

```batch
AdvancedRun.exe /EXEFilename [ExecutableFileName] /WindowState 0 /CommandLine [Command] /StartDirectory "" /RunAs 8 /Run
```

## Threat Actor Ops (TAOps)

- [Stop Windows Defender service through AdvancedRun.exe and delete “C:\ProgramData\Microsoft\Windows Defender” directory](https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3)

```batch
C:\Users\Administrator\AppData\Local\Temp\AdvancedRun.exe /EXEFilename "C:\Windows\System32\sc.exe" /WindowState 0 /CommandLine "stop WinDefend" /StartDirectory "" /RunAs 8 /Run
```

## Common Process Trees

- TBD

## Default Install Location

- AdvancedRun is a downloadable portable package so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - Inv_13450.exe](https://app.any.run/tasks/6548ae0f-f01d-477f-a3f5-9422521f90b5)
- [ANY.RUN - EARTH SUMMT–MAR21-V01VC.exe](https://app.any.run/tasks/88e83328-96c2-432d-9ca5-edd8901b7754)
- [ANY.RUN - 09F2B5D6519152493E6E5DE0DC3491C4.exe](https://app.any.run/tasks/ec45350a-61ac-43d1-9492-c10513ad6468)
- [ANY.RUN - test.exe](https://app.any.run/tasks/7872323f-7541-45cf-bfdb-b674ed10ac13)
- [ANY.RUN - wordart.exe](https://app.any.run/tasks/808dd74a-3b64-4dad-9cf4-7315e2477e05)

## Documentation

- [NirSoft - AdvancedRun](https://www.nirsoft.net/utils/advanced_run.html)

## Blogs / Reports References

- [Elastic Security Research  - Operation Bleeding Bear](https://elastic.github.io/security-research/malware/2022/01/01.operation-bleeding-bear/article/)
- [S2W Blog - Analysis of Destructive Malware (WhisperGate) targeting Ukraine](https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3)

## ATT&CK Techniques

- [T1588.002 - Obtain Capabilities: Tool](https://attack.mitre.org/techniques/T1588/002/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Run NirSoft AdvancedRun](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1588.002/T1588.002.md)

## Detection Rules

- **Splunk**
  - [Windows NirSoft AdvancedRun](https://research.splunk.com/endpoint/windows_nirsoft_advancedrun/)

- **Elastic**
  - [Detect attempts to tamper with Windows Defender](https://elastic.github.io/security-research/malware/2022/01/01.operation-bleeding-bear/article/)
  - [Identifies code injection with InstallUtil](https://elastic.github.io/security-research/malware/2022/01/01.operation-bleeding-bear/article/)

- **Sigma** 
  - [Suspicious AdvancedRun Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_advancedrun.yml)
  - [Suspicious AdvancedRun Runas Priv User](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_advancedrun_priv_user.yml)

## LOLBAS / GTFOBins References

- None
