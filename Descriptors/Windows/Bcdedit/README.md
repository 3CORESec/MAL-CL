# Bcdedit

## Table of Contents

- [Bcdedit](#bcdedit)
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

> **BCDEdit is a command-line tool for managing BCD stores. It can be used for a variety of purposes, including creating new stores, modifying existing stores, adding boot menu parameters, and so on** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit)

## Versions History

- TBD

## File Metadata

- TBD

## Common CommandLine

```batch
bcdedit /set {default} bootstatuspolicy ignoreallfailures

bcdedit /set {default} recoveryenabled no

bcdedit /set {default} safeboot minimal

bcdedit /set {current} safeboot minimal

bcdedit /set {default} safeboot network

bcdedit /set {current} safeboot network

bcdedit /set {globalsettings} advancedoptions false
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\bcdedit.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - Sample_5a8297d12e969f4b8bf1fa2d.bin](https://app.any.run/tasks/b2bf56dc-62bc-4e2f-a4b1-a0414acfc77a/)
- [ANY.RUN - test.bat](https://app.any.run/tasks/de163725-db72-42ad-8045-3a458f22f15d/)
- [ANY.RUN - Koth.exe](https://app.any.run/tasks/55e14fd5-c6ac-4d4a-b9dc-63917104ca9c/)
- [ANY.RUN - safe.exe](https://app.any.run/tasks/b4f6293c-51df-4ad0-98eb-788af1315d27/)
- [ANY.RUN - CWT_company_ragnar_locker](https://app.any.run/tasks/1239f486-9579-4121-80a6-9f98ddce7b43/)
- [ANY.RUN - sodin.e](https://app.any.run/tasks/ae04dfa6-6762-4216-bd62-3263f1b64f2a/)

## Documentation

- [Microsoft Docs - Bcdedit](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit)
- [SS64.com - Windows CMD - Bcdedit](https://ss64.com/nt/bcdedit.html)

## Blogs / Reports References

- [BlackBerry Security Blog- Threat Spotlight: Sodinokibi Ransomware](https://blogs.blackberry.com/en/2019/07/threat-spotlight-sodinokibi-ransomware)
- [The DFIR Report - Sodinokibi (aka REvil) Ransomware](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
- [The DFIR Report - Lockbit Ransomware, Why You No Spread?](https://thedfirreport.com/2020/06/10/lockbit-ransomware-why-you-no-spread/)
- [Microsoft Blog - WannaCrypt ransomware worm targets out-of-date systems](https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)
- [Microsoft Blog - Phorpiex morphs: How a longstanding botnet persists and thrives in the current threat environment](https://www.microsoft.com/security/blog/2021/05/20/phorpiex-morphs-how-a-longstanding-botnet-persists-and-thrives-in-the-current-threat-environment/)
- [Red Canary Blog - Detecting Ransomware: Behind the Scenes of an Attack](https://redcanary.com/blog/detecting-ransomware/)
- [Red Canary Blog - The Third Amigo: detecting Ryuk ransomware](https://redcanary.com/blog/ryuk-ransomware-attack/)
- [Cybereason - Cybereason vs. RansomEXX Ransomware](https://www.cybereason.com/blog/cybereason-vs.-ransomexx-ransomware)
- [Cybereason - Cybereason vs. Avaddon Ransomware](https://www.cybereason.com/blog/cybereason-vs.-avaddon-ransomware)
- [Cybereason - Cybereason vs. MedusaLocker Ransomware](https://www.cybereason.com/blog/medusalocker-ransomware)
- [WeLiveSecurity - Buhtrap backdoor and Buran ransomware distributed via major advertising platform](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)

## ATT&CK Techniques

- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [T1562.009 - Impair Defenses: Safe Mode Boot](https://attack.mitre.org/techniques/T1562/009/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Bcdedit Command Back To Normal Mode Boot](https://research.splunk.com/endpoint/bcdedit_command_back_to_normal_mode_boot/)
  - [Prevent Automatic Repair Mode using Bcdedit](https://research.splunk.com/endpoint/prevent_automatic_repair_mode_using_bcdedit/)
  - [Change To Safe Mode With Network Config](https://research.splunk.com/endpoint/change_to_safe_mode_with_network_config/)
  - [BCDEdit Failure Recovery Modification](https://research.splunk.com/endpoint/bcdedit_failure_recovery_modification/)

- **Elastic**
  - [Modification of Boot Configuration](https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_modification_of_boot_config.toml)

- **Microsoft 365 Defender**
  - [Check for multiple signs of ransomware activity](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Ransomware/Check%20for%20multiple%20signs%20of%20ransomware%20activity.md)

- **Sigma**
  - [Possible Ransomware or Unauthorized MBR Modifications](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_bcdedit.yml)
  - [Modification of Boot Configuration](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_bootconf_mod.yml)

- **Other**
  - [Vadim-Hunter - Sodinokibi (aka REvil) Ransomware](https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml)

## LOLBAS / GTFOBins References

- None
