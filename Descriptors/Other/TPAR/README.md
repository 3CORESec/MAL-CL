# Third Party Application Remover (tpar.exe)

## Table of Contents

- [Third Party Application Remover (tpar.exe)](#third-party-application-remover-tparexe)
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

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Third Party Application Remover or TPAR is a utility that can remove 3rd party security software**

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

The `tpar.exe` executable doesn't support any documented command-line

```batch
tpar.exe
```

Below is the list of the "Security Software" that TPAR is able to remove

```yaml
- AVG Protection
- ESET Endpoint Antivirus / ESET Endpoint Security
- ESET Remote Administrator Agent
- F-Secure Anti-Spyware
- F-Secure Anti-Spyware Scanner
- F-Secure Anti-Virus Client Security Installer
- F-Secure Automatic Update Agent
- F-Secure Backweb
- F-Secure Browsing Protection
- F-Secure CustomizationSetup
- F-Secure DAAS2
- F-Secure Device Control
- F-Secure Diagnostics
- F-Secure E-mail Scanning
- F-Secure FWES
- F-Secure GateKeeper Interface
- F-Secure Gemini
- F-Secure GUI
- F-Secure Help
- F-Secure HIPS
- F-Secure Internet Shield
- F-Secure Localization API
- F-Secure Management Agent
- F-Secure Management Extensions
- F-Secure NAC Support
- F-Secure NAP Support
- F-Secure NIF
- F-Secure Offload Scanning Agent
- F-Secure ORSP Client
- F-Secure Policy Manager Support
- F-Secure Protocol Scanner
- F-Secure Safe Banking Popup
- F-Secure Sidegrade Support
- F-Secure Software Updater
- F-Secure System File Update
- F-Secure TNB
- F-Secure Uninstall
- F-Secure Anti-Virus
- Kaspersky Endpoint Security
- Kaspersky AES Encryption Module
- Kaspersky Anti-Virus for Windows Servers
- Kaspersky Security for Windows Servers
- Kaspersky Anti-Virus for Windows Workstations
- Kaspersky PURE
- Kaspersky Small Office Security
- Kaspersky AntiVirus / Kaspersky Internet Security
- Kaspersky Endpoint Security 8 for Windows Console Plug-in
- Kaspersky Anti-Virus SOS
- Kaspersky Security Center Network Agent
- McAfee Endpoint Security Web Control
- McAfee Endpoint Security Firewall
- McAfee Endpoint Security Threat Prevention
- McAfee Endpoint Security Platform
- McAfee Desktop Firewall
- McAfee VirusScan Enterprise
- McAfee Firewall Protection Service
- McAfee Virus and Spyware Protection Service
- McAfee Browser Protection Service
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- TPAR is a downloadable portable package so no installation is required to execute it. It's also included in the folder of the Endpoint Protection download media in the following location `\Tools\TPAR`

## DFIR Artifacts

- The tool saves `tpar.log` file in the directory it was run from.

## Examples In The Wild

- TBD

## Documentation

- [Broadcom KB - About the third-party security software removal feature in Symantec Endpoint Protection](https://knowledge.broadcom.com/external/article/155734)
- [Broadcom Techdocs - Third-party security software removal in Endpoint Protection 14](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Managing-a-custom-installation/preparing-for-client-installation-v16742985-d21e7/Third-party-security-software-removal-in-Endpoint-Protection.html)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 7 - Image loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?source=Sysmon&eventID=7)
- [PsSetLoadImageNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 5 - ImageLoad](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
