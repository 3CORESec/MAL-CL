# Certutil

## Table of Contents

- [Certutil](#certutil)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement(s)](#acknowledgements)
  - [Description](#description)
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

> **Certutil.exe is a command-line program that is used to dump and display certification authority (CA) configuration information, configure Certificate Services, backup and restore CA components, and verify certificates, key pairs, and certificate chains.** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

## Common CommandLine

```batch
rem Download Files
certutil -urlcache -f [URL] [DestinationPath]
certutil -urlcache -split -f [URL] [DestinationPath]
certutil -verifyctl -f -split [URL]

rem Decode Base64 Files
certutil -decode [EncodedFile] [DestinationPath]
certutil -decode -f [EncodedFile] [DestinationPath]

rem Obfuscated certutil
c^e^r^tutil -urlca^che -spl^it -f [URL]

rem Encode Data
certutil -f -encode [Input] [Output]

rem Adds a certificate to the store
certutil -addstore -f -user [certificatestorename] [infile]
```

## Default Install Location

```batch
C:\Windows\System32\certutil.exe

C:\Windows\SysWOW64\certutil.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - setup_x86_x64_install.exe](https://app.any.run/tasks/12bf82ab-5e67-41a7-8f8b-a592affa6c85/)
- [ANY.RUN - gg.lnk](https://app.any.run/tasks/03bb1566-7d3c-487f-974f-caa964c8931a/)
- [ANY.RUN - 1.js](https://app.any.run/tasks/e6312f6e-8f0c-4944-95c0-288bde8c9e97/)
- [ANY.RUN - 828392.bat](https://app.any.run/tasks/c1d20d66-f3e7-4a14-96a8-780381cda407/)
- [ANY.RUN - run.bat](https://app.any.run/tasks/424c10f5-4643-403b-8290-482c173d1af0/)
- [ANY.RUN - 16e273bc26da46697a9d3d0e3a2073b8](https://app.any.run/tasks/ec91a642-233c-4bd4-89da-cf131ff7131f/)
- [ANY.RUN - 1634069448.6985812.dll](https://app.any.run/tasks/8affbb93-f428-4160-bce1-e295e444ce3f/)
- [ANY.RUN - covid21 online installer.bat](https://app.any.run/tasks/e4af10ef-b856-4227-8b48-06a03950287d/)
- [ANY.RUN - Fattura.xlsb](https://app.any.run/tasks/7f76aae7-8e7a-4a6b-9852-96ee28d95cd9/)

## Documentation

- [Microsoft Docs - Certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [SS64.com - Windows CMD - Certutil](https://ss64.com/nt/certutil.html)

## Blogs / Reports References

- [Cybereason - THREAT ALERT: Malicious Code Implant in the UAParser.js Library](https://www.cybereason.com/blog/threat-alert-malicious-code-implant-in-the-uaparser.js-library)
- [Cybereason - Cybereason vs. DarkSide Ransomware](https://www.cybereason.com/blog/cybereason-vs-darkside-ransomware)
- [Cybereason - LOLbins and trojans: How the Ramnit Trojan spreads via sLoad in a cyberattack](https://www.cybereason.com/blog/banking-trojan-delivered-by-lolbins-ramnit-trojan)
- [Cybereason - Cybereason vs. REvil Ransomware: The Kaseya Chronicles](https://www.cybereason.com/blog/cybereason-vs-revil-ransomware-the-kaseya-chronicles)
- [Cybereason - Glupteba Expands Operation and Toolkit with LOLBins And Cryptominer](https://www.cybereason.com/blog/glupteba-expands-operation-and-toolkit-with-lolbins-cryptominer-and-router-exploit)
- [Cybereason - Pervasive Brazilian Financial Malware Targets Bank Customers in Latin America and Europe](https://www.cybereason.com/blog/brazilian-financial-malware-banking-europe-south-america)
- [Cybereason - The Hole in the Bucket: Attackers Abuse Bitbucket to Deliver an Arsenal of Malware](https://www.cybereason.com/blog/the-hole-in-the-bucket-attackers-abuse-bitbucket-to-deliver-an-arsenal-of-malware)
- [The DFIR Report - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [WeLiveSecurity - Operation In(ter)ception: Aerospace and military companies in the crosshairs of cyberspies](https://www.welivesecurity.com/2020/06/17/operation-interception-aerospace-military-companies-cyberspies/)
- [WeLiveSecurity - Guildma: The Devil drives electric](https://www.welivesecurity.com/2020/03/05/guildma-devil-drives-electric/)
- [Volexity - Microsoft Exchange Control Panel (ECP) Vulnerability CVE-2020-0688 Exploited](https://www.volexity.com/blog/2020/03/06/microsoft-exchange-control-panel-ecp-vulnerability-cve-2020-0688-exploited/)
- [Securelist By Kaspersky - GhostEmperor: From ProxyLogon to kernel mode](https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/)
- [Securelist By Kaspersky - Managed Detection and Response analytics report, H1 2019](https://securelist.com/managed-detection-and-response-analytics-report/94076/)
- [Palo Alto Networks - Unite 42 - BazarCall Method: Call Centers Help Spread BazarLoader Malware](https://unit42.paloaltonetworks.com/bazarloader-malware/)
- [Palo Alto Networks - Unite 42 - Actors Still Exploiting SharePoint Vulnerability to Attack Middle East Government Organizations](https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/)
- [Palo Alto Networks - Unite 42 - New BabyShark Malware Targets U.S. National Security Think Tanks](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: Attacks on Kuwait Shipping and Transportation Organizations](https://unit42.paloaltonetworks.com/xhunt-campaign-attacks-on-kuwait-shipping-and-transportation-organizations/)
- [Palo Alto Networks - Unite 42 - The Fractured Block Campaign: CARROTBAT Used to Deliver Malware Targeting Southeast Asia](https://unit42.paloaltonetworks.com/unit42-the-fractured-block-campaign-carrotbat-malware-used-to-deliver-malware-targeting-southeast-asia/)
- [Palo Alto Networks - Unite 42 - RANCOR: Targeted Attacks in South East Asia Using PLAINTEE and DDKONG Malware Families](https://unit42.paloaltonetworks.com/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/)
- [Palo Alto Networks - Unite 42 - OopsIE! OilRig Uses ThreeDollars to Deliver New Trojan](https://unit42.paloaltonetworks.com/unit42-oopsie-oilrig-uses-threedollars-deliver-new-trojan/)
- [Palo Alto Networks - Unite 42 - Sofacy Group’s Parallel Attacks](https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/)
- [Palo Alto Networks - Unite 42 - Pulling Back the Curtains on EncodedCommand PowerShell Attacks](https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/)
- [Palo Alto Networks - Unite 42 - Retefe Banking Trojan Targets Sweden, Switzerland and Japan](https://unit42.paloaltonetworks.com/retefe-banking-trojan-targets-sweden-switzerland-and-japan/)
- [Palo Alto Networks - Unite 42 - OilRig Group Steps Up Attacks with New Delivery Documents and New Injector Trojan](https://unit42.paloaltonetworks.com/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/)
- [Crowdstrike Blog - Falcon OverWatch Hunts Down Adversaries Where They Hide](https://www.crowdstrike.com/blog/four-popular-defensive-evasion-techniques-in-2021/)
- [Microsoft Blog - Dismantling a fileless campaign: Microsoft Defender ATP’s Antivirus exposes Astaroth attack](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/)
- [Microsoft Blog - Multi-stage downloader Trojan sLoad abuses BITS almost exclusively for malicious activities](https://www.microsoft.com/security/blog/2019/12/12/multi-stage-downloader-trojan-sload-abuses-bits-almost-exclusively-for-malicious-activities/)

## ATT&CK Techniques

- [T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1553.004 - Subvert Trust Controls: Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Certutil exe certificate extraction](https://research.splunk.com/endpoint/certutil_exe_certificate_extraction/)
  - [Office Product Spawning CertUtil](https://research.splunk.com/endpoint/office_product_spawning_certutil/)
  - [CertUtil With Decode Argument](https://research.splunk.com/endpoint/certutil_with_decode_argument/)
  - [CertUtil Download With URLCache and Split Arguments](https://research.splunk.com/endpoint/certutil_download_with_urlcache_and_split_arguments/)
  - [CertUtil Download With VerifyCtl and Split Arguments](https://research.splunk.com/endpoint/certutil_download_with_verifyctl_and_split_arguments/)

- **Elastic**
  - [Suspicious CertUtil Commands](https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_suspicious_certutil_commands.toml)
  - [Network Connection via Certutil](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_certutil_network_connection.toml)
  - [Remote File Download via Desktopimgdownldr Utility](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_remote_file_copy_desktopimgdownldr.toml)

- **Azure-Sentinel**
  - [Ingress Tool Transfer - Certutil](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/FalconFriday/Analytic%20Rules/CertutilIngressToolTransfer.yaml)
  - [Certutil (LOLBins and LOLScripts, Normalized Process Events)](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/ASimProcess/imProcess_Certutil-LOLBins.yaml)
  - [Certutil (LOLBins and LOLScripts)](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/SecurityEvent/Certutil-LOLBins.yaml)

- **Microsoft 365 Defender**
  - [BazaCall dropping payload via certutil.exe](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Campaigns/Bazacall/Dropping%20payload%20via%20certutil.md)
  - [Bazacall Excel Macro Execution](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Campaigns/Bazacall/Excel%20Macro%20Execution.md)
  - [Detect suspicious commands initiated by web server processes](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Discovery/detect-suspicious-commands-initiated-by-web-server-processes.md)

- **Sigma**
  - [Suspicious Certutil Command](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_certutil_command.yml)
  - [Certutil Encode](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_certutil_encode.yml)
  - [Root Certificate Installed](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_root_certificate_installed.yml)
  - [Highly Relevant Renamed Binary](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_binary_highly_relevant.yml)
  - [Renamed Binary](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_renamed_binary.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)
  - [Suspicious Shells Spawn by WinRM](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/win_susp_shell_spawn_from_winrm.yml)
  - [Suspicious Copy From or To System32](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_copy_system32.yml)
  - [Windows Shell Spawning Suspicious Program](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml)
  - [Suspicious User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/proxy/proxy_ua_suspicious.yml)

## LOLBAS / GTFOBins References

- [LOLBAS - Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
