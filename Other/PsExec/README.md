# PsExec

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software** - [MSDN](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

## Common CommandLine

```batch
psexec.exe -i -s [Executable]

psexec.exe @[ListOfIPsFile] -d cmd /c [StringOfCommands]

psexec.exe -accepteula @[ListOfIPsFile] -u [User] -p [Password] cmd /c [StringOfCommands]

psexec.exe -accepteula -d -s \\@IP [Executable] [Arguments] 

psexec.exe [Executable] /accepteula -s -high

psexec.exe \\@IP -r [ServiceName] -s -d [Executable]
```

## Default Install Location

- PsExec is a downloadable portable utility so no installation is required to execute it.

- The Sysinternals suite is available in the Microsoft Store. If downloaded from there then the `psexec` utility will be installed in the following location:

```batch
C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_[Version]\Tools\psexec.exe
```

## DFIR Artifacts

- RegistryKey created

```batch
HKEY_CURRENT_USER\Software\Sysinternals\PsExec\EulaAccepted
```

- Service Creation

```batch
C:\Windows\PSEXESVC.exe
```

## Examples In The Wild

- [Hatching Triage (tria.ge) - ky.exe](https://tria.ge/201002-avbjhbd3we/behavioral2#report)

## Documentation

- [Microsoft Docs - PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

## Blogs / Reports References

- [The DFIR Report - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)
- [The DFIR Report - PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [The DFIR Report - NetWalker Ransomware in 1 Hour](https://thedfirreport.com/2020/08/31/netwalker-ransomware-in-1-hour/)
- [The DFIR Report - Dridex – From Word to Domain Dominance](https://thedfirreport.com/2020/08/03/dridex-from-word-to-domain-dominance/)
- [Red Canary - Threat Hunting for PsExec, Open-Source Clones, and Other Lateral Movement Tools](https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/)
- [Securelist By Kaspersky - GhostEmperor: From ProxyLogon to kernel mode](https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/)
- [Securelist By Kaspersky - IAmTheKing and the SlothfulMedia malware family](https://securelist.com/iamtheking-and-the-slothfulmedia-malware-family/99000/)
- [Securelist By Kaspersky - Cycldek: Bridging the (air) gap](https://securelist.com/cycldek-bridging-the-air-gap/97157/)
- [Mandiant - Unhappy Hour Special: KEGTAP and SINGLEMALT With a Ransomware Chaser](https://www.mandiant.com/resources/kegtap-and-singlemalt-with-a-ransomware-chaser)
- [Volexity - Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
- [[Palo Alto Networks - Unite 42 - Mespinoza Ransomware Gang Calls Victims “Partners,” Attacks with Gasket, "MagicSocks" Tools](https://unit42.paloaltonetworks.com/gasket-and-magicsocks-tools-install-mespinoza-ransomware/)

## ATT&CK Techniques

- [T1021.002 - Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1136.002 - Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002)
- [T1543.003 - Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003)
- [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1021/002)
- [T1570 - Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- **Splunk**
  - [Detect Renamed PSExec](https://research.splunk.com/endpoint/detect_renamed_psexec/)
  - [Detect PsExec With accepteula Flag](https://research.splunk.com/endpoint/detect_psexec_with_accepteula_flag/)
  - [PowerShell 4104 Hunting](https://research.splunk.com/endpoint/powershell_4104_hunting/)

- **Elastic**
  - [PsExec Network Connection](https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_psexec_lateral_movement_command.toml)
  - [Suspicious Process Execution via Renamed PsExec Executable](https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_suspicious_psexesvc.toml)
  - [Remotely Started Services via RPC](https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_remote_services.toml)

- **Sigma**
  - [Renamed PsExec](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_psexec.yml)
  - [Suspicious PsExec Execution - Zeek](https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml)
  - [Suspicious PsExec Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_susp_psexec.yml)
  - [PsExec/PAExec Flags](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_psexex_paexec_flags.yml)
  - [PSExec and WMI Process Creations Block](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/other/win_defender_psexec_wmi_asr.yml)
  - [Highly Relevant Renamed Binary](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_binary_highly_relevant.yml)
  - [Renamed Binary](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_binary.yml)
  - [Psexec Accepteula Condition](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_psexec_eula.yml)
  - [PsExec Pipes Artifacts](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_psexec_pipes_artifacts.yml)
  - [PsExec Service Start](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_psexesvc_start.yml)
  - [PsExec Tool Execution (File)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/file_event_tool_psexec.yml)
  - [PsExec Tool Execution (Other)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_tool_psexec.yml)
  - [PsExec Tool Execution (Pipe)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_tool_psexec.yml)
  - [Quick Execution of a Series of Suspicious Commands](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_multiple_suspicious_cli.yml)

## LOLBAS / GTFOBins References

- None
