# Reg

## Table of Contents

- [Reg](#reg)
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

> **The reg utility performs operations on registry subkey information and values in registry entries.** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)

## Versions History

- TBD

## Common CommandLine

```batch
reg add [RegKeyPath] /v [Value] /t [REG_SZ/REG_DWORD] /d [Data] /f

reg delete [RegKeyPath] /f

reg export [RegKeyPath] [PathOnDiskToSave] /y

reg query [RegKeyPath] /v [Value] /s

reg save [RegKeyPath] [PathOnDiskToSave]
```

- Below is a list of some of most common registry keys queried/used by the reg command

```batch
rem Persistence
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows
HKCU\Software\Microsoft\Active Setup\Installed Components
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders 
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\System\CurrentControlSet\Control\Session Manager
HKLM\Software\Microsoft\Active Setup\Installed Components

rem Windows Defender (Subkeys included)
HKLM\Software\Policies\Microsoft\Windows Defender
HKLM\System\CurrentControlSet\Services\WdBoot
HKLM\System\CurrentControlSet\Services\WdFilter
HKLM\System\CurrentControlSet\Services\WdNisDrv
HKLM\System\CurrentControlSet\Services\WdNisSvc
HKLM\System\CurrentControlSet\Services\WinDefend
HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger
HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger

rem Remote Desktop
HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
HKLM\System\CurrentControlSet\Control\Terminal Server\fSingleSessionPerUser
HKLM\System\CurrentControlSet\Control\Terminal Server\Licensing Core\EnableConcurrentSessions

rem Creds
HKLM\System\CirrentControlSet\Services\Ntds\Parameters
HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
HKLM\Security\Policy\Secrets

rem Other
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCMD
```

## Default Install Location

```batch
C:\Windows\System32\reg.exe

C:\Windows\SysWOW64\reg.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - HKCU_Reg.bat](https://app.any.run/tasks/14bf6c99-473b-460c-b5b6-c6c939799823/)
- [ANY.RUN - nodefender.exe](https://app.any.run/tasks/a0bc6013-8a08-4a88-b9e7-89e7bad15a32/)
- [ANY.RUN - lox.bat](https://app.any.run/tasks/99dd8ffe-59a4-408a-84ff-2677d300ce49/)
- [ANY.RUN - run.exe](https://app.any.run/tasks/04746d4d-c15f-444b-aa42-0f0560afa723/)
- [Hatching Triage (tria.ge) - Jrrfsorsdnnsvgfslajjordvmzshfpnerx.exe](https://tria.ge/210922-tyn8wsdbh3/behavioral1#report)
- [Hatching Triage (tria.ge) - reg.xls](https://tria.ge/200331-gnknv9zkt2/behavioral2#report)
- [Hatching Triage (tria.ge) - 79323434542bf442218be77d3982e167e118dc9954ce9ea1726db42bcac4d249.bin.sample.exe](https://tria.ge/210528-dxr93gxbxe/behavioral11#report)

## Documentation

- [Microsoft Docs - Reg](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
- [SS64.com - Windows CMD - Reg](https://ss64.com/nt/reg.html)

## Blogs / Reports References

- [The DFIR Report - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report - WebLogic RCE Leads to XMRig](https://thedfirreport.com/2021/06/03/weblogic-rce-leads-to-xmrig/)
- [The DFIR Report - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)
- [The DFIR Report - Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/)
- [The DFIR Report - Trickbot Brief: Creds and Beacons](https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/)
- [The DFIR Report - Sodinokibi (aka REvil) Ransomware](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
- [The DFIR Report - Bazar Drops the Anchor](https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/)
- [The DFIR Report - Trickbot Still Alive and Well](https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/)
- [The DFIR Report - Ryuk Speed Run, 2 Hours to Ransom](https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/)
- [The DFIR Report - Tricky Pyxie](https://thedfirreport.com/2020/04/30/tricky-pyxie/)
- [The DFIR Report - Sqlserver, or the Miner in the Basement](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
- [Palo Alto Networks - Unite 42 - Paranoid PlugX](https://unit42.paloaltonetworks.com/unit42-paranoid-plugx/)
- [Palo Alto Networks - Unite 42 - The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor](https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/)
- [CISA - Alert (TA18-074A) - Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors](https://us-cert.cisa.gov/ncas/alerts/TA18-074A)
- [McAfee Blog - McAfee Uncovers Operation Honeybee, a Malicious Document Campaign Targeting Humanitarian Aid Groups](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-uncovers-operation-honeybee-malicious-document-campaign-targeting-humanitarian-aid-groups/)

## ATT&CK Techniques

- [T1012 - Query Registry](https://attack.mitre.org/techniques/T1012)
- [T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112)
- [T1552.002 - Unsecured Credentials: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Sysmon Event ID 12 - RegistryEvent (Object create and delete)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012)
- [Sysmon Event ID 13 - RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)
- [Sysmon Event ID 14 - RegistryEvent (Key and Value Rename)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90014)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Reg exe Manipulating Windows Services Registry Keys](https://research.splunk.com/endpoint/reg_exe_manipulating_windows_services_registry_keys/)
  - [Extraction of Registry Hives](https://research.splunk.com/endpoint/extraction_of_registry_hives/)
  - [Attempted Credential Dump From Registry via Reg exe](https://research.splunk.com/endpoint/attempted_credential_dump_from_registry_via_reg_exe/)
  - [Extraction of Registry Hives](https://research.splunk.com/endpoint/extraction_of_registry_hives/)
  - [Suspicious Reg exe Process](https://research.splunk.com/endpoint/suspicious_reg_exe_process/)
  - [Suspicious Windows Registry Activities](https://research.splunk.com/stories/suspicious_windows_registry_activities/)

- **Elastic**
  - [Query Registry via reg.exe (Deprecated)](https://github.com/elastic/detection-rules/blob/main/rules/_deprecated/discovery_query_registry_via_reg.toml)
  - [Credential Acquisition via Registry Hive Dumping](https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_dump_registry_hives.toml)

- **Sigma**
  - [Suspicious ScreenSave Change by Reg.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_screensaver_reg.yml)
  - [Reg Disable Security Service](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_reg_disable_sec_services.yml)
  - [Non-privileged Usage of Reg or Powershell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_non_priv_reg_or_ps.yml)
  - [Reg Add RUN Key](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_reg_add_run_key.yml)
  - [Suspicious Desktopimgdownldr Command](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_desktopimgdownldr.yml)
  - [Direct Autorun Keys Modification](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_direct_asep_reg_keys_modification.yml)
  - [Detected Windows Software Discovery](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_software_discovery.yml)
  - [Modification Of Existing Services For Persistence](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_modif_of_services_for_via_commandline.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)
  - [Disabled Volume Snapshots](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_volsnap_disable.yml)
  - [Write Protect For Storage Disabled](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_write_protect_for_storage_disabled.yml)
  - [Imports Registry Key From an ADS](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_regedit_import_keys_ads.yml)

## LOLBAS / GTFOBins References

- [LOLBAS - Reg.exe](https://lolbas-project.github.io/lolbas/Binaries/Reg/)
