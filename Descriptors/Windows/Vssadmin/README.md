# Vssadmin

## Table of Contents

- [Vssadmin](#vssadmin)
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

> **Vssadmin is a command-line utility that displays current volume shadow copy backups and all installed shadow copy writers and providers, deletes a specified volume's shadow copies and lists all existing shadow copies of a specified volume** — [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin)

## Versions History

- TBD

## Common CommandLine

```batch
vssadmin list shadows

vssadmin delete shadows /all

vssadmin delete shadows /all /quiet

vssadmin resize shadowstorage /for=[Partition] /on=[Partition] /maxsize=[Size]
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

```batch
C:\Windows\System32\vssadmin.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - QkpxnTb.exe](https://app.any.run/tasks/472b5424-60e6-4553-bf69-c0a441dcc3d7/)
- [ANY.RUN - Ryuk9.Bat.bat](https://app.any.run/tasks/9fa2e70c-0164-4993-8338-1e5b4b48c8c4/)
- [ANY.RUN - shadow.bat](https://app.any.run/tasks/fb2efbdc-e839-470e-bdcd-6fd8c52f74b0/)
- [ANY.RUN - LegionLocker2.1.exe](https://app.any.run/tasks/e1cca6ed-85d6-4b6d-b663-1b73f9fcab74/)
- [ANY.RUN - 9784148014987a39d87265c015962e9535ed86e861093a6c59691095a19be7c2.exe](https://app.any.run/tasks/8d8b2079-291d-448a-9821-78ad73dd386f/)
- [ANY.RUN - BlackMamba2.0.exe](https://app.any.run/tasks/98aa9615-de19-4ec2-a86c-e6599e5c1793/)
- [ANY.RUN - or4qtckT.exe](https://app.any.run/tasks/30a48f99-5aef-4214-b6ed-5863a92825f8/)

## Documentation

- [Microsoft Docs - Vssadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin)
- [SS64.com - Windows CMD - Vssadmin](https://ss64.com/nt/vssadmin.html)

## Blogs / Reports References

- [BlackBerry Security Blog- Threat Spotlight: Sodinokibi Ransomware](https://blogs.blackberry.com/en/2019/07/threat-spotlight-sodinokibi-ransomware)
- [Cybereason - REvil/Sodinokibi: The Crown Prince of Ransomware](https://www.cybereason.com/blog/the-sodinokibi-ransomware-attack)
- [Cybereason - Triple Threat: Emotet Deploys TrickBot to Steal Data & Spread Ryuk](https://www.cybereason.com/blog/triple-threat-emotet-deploys-trickbot-to-steal-data-spread-ryuk-ransomware)
- [Cybereason - Cybereason vs. MedusaLocker Ransomware](https://www.cybereason.com/blog/medusalocker-ransomware)
- [WeLiveSecurity - Ransomware vs. printing press? US newspapers face “foreign cyberattack](https://www.welivesecurity.com/2018/12/31/ransomware-printing-press-newspapers/)
- [WeLiveSecurity - Buhtrap backdoor and Buran ransomware distributed via major advertising platform](https://www.welivesecurity.com/2019/04/30/buhtrap-backdoor-ransomware-advertising-platform/)
- [The DFIR Report - The Little Ransomware That Couldn’t (Dharma)](https://thedfirreport.com/2020/06/16/the-little-ransomware-that-couldnt-dharma/)
- [The DFIR Report - Lockbit Ransomware, Why You No Spread?](https://thedfirreport.com/2020/06/10/lockbit-ransomware-why-you-no-spread/)
- [Palo Alto Networks - Unite 42 - Mespinoza Ransomware Gang Calls Victims “Partners,” Attacks with Gasket, "MagicSocks" Tools](https://unit42.paloaltonetworks.com/gasket-and-magicsocks-tools-install-mespinoza-ransomware/)
- [Palo Alto Networks - Unite 42 - Updated PClock Ransomware Still Comes Up Short](https://unit42.paloaltonetworks.com/updated-pclock-ransomware-still-comes-up-short/)
- [CISA - Alert (AA20-302A) - Ransomware Activity Targeting the Healthcare and Public Health Sector](https://us-cert.cisa.gov/ncas/alerts/aa20-302a)
- [CISA - Alert (AA21-265A) - Conti Ransomware](https://us-cert.cisa.gov/ncas/alerts/aa21-265a)
- [Red Canary Blog - Detecting Ransomware: Behind the Scenes of an Attack](https://redcanary.com/blog/detecting-ransomware/)
- [Red Canary Blog - It’s all fun and games until ransomware deletes the shadow copies](https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/)

## ATT&CK Techniques

- [T1003.003 - OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)
- [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- **Elastic - Red Team Automation**
  - [Volume Shadow Copy Deletion with vssadmin and wmic](https://github.com/elastic/detection-rules/blob/main/rta/delete_volume_shadows.py)

- **Uber - Metta**
  - [On-target Recon For Password With Builtin Windows Tools](https://github.com/uber-common/metta/blob/master/MITRE/Credential_Access/credaccess_win_creddump.yml)

- **Red Canary - Atomic Red Team**
  - [Create Volume Shadow Copy with vssadmin](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md#atomic-test-1---create-volume-shadow-copy-with-vssadmin)
  - [Windows - Delete Volume Shadow Copies](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-1---windows---delete-volume-shadow-copies)

## Detection Rules

- **Splunk**
  - [Creation of Shadow Copy](https://research.splunk.com/endpoint/creation_of_shadow_copy/)
  - [Deleting Shadow Copies](https://research.splunk.com/endpoint/deleting_shadow_copies/)

- **Elastic**
  - [Volume Shadow Copy Deleted or Resized via VssAdmin](https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_volume_shadow_copy_deletion_or_resized_via_vssadmin.toml)

- **Microsoft 365 Defender**
  - [Check for multiple signs of ransomware activity](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Ransomware/Check%20for%20multiple%20signs%20of%20ransomware%20activity.md)
  - [Possible Ransomware Related Destruction Activity](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/Possible%20Ransomware%20Related%20Destruction%20Activity.md)

- **Sigma**
  - [Activity Related to NTDS.dit Domain Hash Retrieval](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/deprecated/win_susp_vssadmin_ntds_activity.yml)
  - [Shadow Copies Deletion Using Operating Systems Utilities](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shadow_copies_deletion.yml)
  - [Shadow Copies Creation Using Operating Systems Utilities](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_shadow_copies_creation.yml)
  - [Godmode Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml)

## LOLBAS / GTFOBins References

- None
