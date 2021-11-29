# LaZagne

## Table of Contents

- [LaZagne](#lazagne)
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

<p align="center"><img src="/Images/Screenshots/LaZagne.png"></p>

> **The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.** — [LaZagne Github](https://github.com/AlessandroZ/LaZagne/)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 2.4.3    | fa2f281fd4009100b2293e120997bfd7feb10c16 | [LINK](https://www.virustotal.com/gui/file/ed2f501408a7a6e1a854c29c4b0bc5648a6aa8612432df829008931b3e34bf56)                                                                                                             |
| 2.4.2    | 66e4c9becbc96c57232d38bfec01fb2b352181b2 | [LINK](https://www.virustotal.com/gui/file/5a2e947aace9e081ecd2cfa7bc2e485528238555c7eeb6bcca560576d4750a50)                                                                                                             |
| 2.4.0    | e5c2cf6a7239e895cf2b01f8a382b4463a613859 | [LINK](https://www.virustotal.com/gui/file/c03ef8106c58c8980b7859e0a8ee2363d70e2b7f1346356127c826faf2c0caa3)                                                                                                             |
| 2.3.2 x86    | e94ab2b39f152bcae8261613796f98355e258262 | [LINK](https://www.virustotal.com/gui/file/709df1bbd0a5b15e8f205b2854204e8caf63f78203e3b595e0e66c918ec23951)                                                                                                             |
| 2.3.2 x64    | 81451f6884a616e96cb0bf57d7052a890092ba0c | [LINK](https://www.virustotal.com/gui/file/d5fa28cbf3a73ac20d908acedfce3849477648e37391e8e926ec2e7933f175a0)                                                                                                             |
| 2.3.1    | b4ffdf4a67c3b5343e07e581ec7aa1d6a3514569 | [LINK](https://www.virustotal.com/gui/file/6095c89d2fc86b215a1fe2d1848862d03736c9e91d4f3aa7009fb0837c1263b5)                                                                                                             |
| 2.3.0    | d6d07c511598a6a9e3b08002afbcb7373caae406 | [LINK](https://www.virustotal.com/gui/file/058d4efce1007e6cfb7a4e0ff9fee7e0b5172a2e0059d21d876d40e4ec2d90ae)                                                                                                             |
| 2.2    | 8900ff0ee8d70485f31dfa7d572e969dea06346a | [LINK](https://www.virustotal.com/gui/file/9485a1630d9283d7efee3828fca32d72cfcb3fb1e91015a9753df09a21f14da2)                                                                                                             |
| 2.1    | 498ab7d75b858addb1a3952cf1541a28093916e0 | [LINK](https://www.virustotal.com/gui/file/6b6bd8516840b60faac26c3f40e50ab616e7428e763fd61f6299da2843743422)                                                                                                             |
| 2.0    | 6571ad4133ca7425d2cfb4d36c65f7aebe13ed94 | [LINK](https://www.virustotal.com/gui/file/5d953d887abf65fa7c8d3a2336b6ec8e510b1019819e93a6cfc0d767b0c89a4c)                                                                                                             |
| 1.8    | b59cd9c67162f4a3604353b783829fc8ef629863 | [LINK](https://www.virustotal.com/gui/file/87e2cf4aa266212aa8cf1b1c98ae905c7bac40a6fc21b8e821ffe88cf9234586)                                                                                                             |
| 1.7    | e91593a1695f3d3c051ba52d5aba30d9031d3ce0 | [LINK](https://www.virustotal.com/gui/file/3f6e8dea07b6e87182b3068868746e5054123a7c86e04d775292af7ffd1ce9b4)                                                                                                             |
| 1.6    | 1c95b8e5d987f2a0a642a8c1f9ee99bc78131e00 | [LINK](https://www.virustotal.com/gui/file/a64f99909adf9f29e74524eb592a1efd7f70e1fb11abc305799e9dcbc8c43f84)                                                                                                             |
| 1.5    | 2f5a3b13439537668ddbd79d9b19309e6f30cd82 | [LINK](https://www.virustotal.com/gui/file/f3c7fd842f9391f64bb739d56558c54d5e239211069ed6592ece5c281129a273)                                                                                                             |
| 1.4    | 34cb2a2a57e06bdc5a278c6620b5d312bb4cccb3 | [LINK](https://www.virustotal.com/gui/file/5b0a0f4e24637b56bc6734cc8be8417ddbd8964511429888df331d00bd834155)                                                                                                             |
| 1.3    | 33b4b599cd2af718c36cee05a8bec84b2b4688cc | [LINK](https://www.virustotal.com/gui/file/b6b1115f75a124e4cf9dd776f13ed5883e1a3de96610c97645bed6770a541aec)                                                                                                             |
| 1.1    | df4e7f468a28bca313f185eda9ea20b7c4de49eb | [LINK](https://www.virustotal.com/gui/file/82fdbbb6897d76ed4ac8e0d6341f31d2cedbcce43c219d27940f0092befeb56e)                                                                                                             |
| 1.0    | f0893825176784827e8216b3ce9224c70c4db522 | [LINK](https://www.virustotal.com/gui/file/e3a61e9cf23cd2dcb54056aa1daa5381bd9b8d3a7e5d38c8bbd14a9e2c368a2d)                                                                                                             |
| 0.9.1    | fd3b89c2f8bc74f199b60f7b52c83bb67eec780a | [LINK](https://www.virustotal.com/gui/file/398ca467689d459a370ea4c1d454638feda4f75433b54a81de8f3c69719d9380)                                                                                                             |
| 0.9    | b2a013ce5e0fa720c41744e75cefe77e7a09ad13 | [LINK](https://www.virustotal.com/gui/file/9c89a4750109bbf1362afe937daacbb55ef4aa9440f934c3175f0b07ce7845a0)                                                                                                             |

## Common CommandLine

```batch
laZagne.exe all

laZagne.exe all -oA -output [Path]

laZagne.exe browsers

laZagne.exe Sysadmin
```

- See [docs](#documentation) below for a complete list of arguments

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- TBD

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - usb Rubber Ducky.7z](https://app.any.run/tasks/d1186820-0a66-425a-a064-9fd69ac269f9/)
- [ANY.RUN - USBStealer-3.zip](https://app.any.run/tasks/62056621-8b6a-4351-887f-fa3ce2bdb7d0/)
- [ANY.RUN - zugu.exe](https://app.any.run/tasks/417c7dee-3da6-4e1b-a9d5-2dafc953eb1d/)
- [ANY.RUN - 6a85c564-2dd3-11e8-8ca9-c8b003f8d9f9](https://app.any.run/tasks/c7fdc9bd-93bf-46cc-9413-3dc38cc2bdfb/)
- [ANY.RUN - cd.exe](https://app.any.run/tasks/3db0de8e-b9a9-4443-93fe-bc0c9e4299a2/)

## Documentation

- [AlessandroZ/LaZagne: Credentials recovery project](https://github.com/AlessandroZ/LaZagne/)

## Blogs / Reports References

- [The DFIR Report  - Cobalt Strike, a Defender’s Guide](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
- [The DFIR Report  - Trickbot Brief: Creds and Beacons](https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/)
- [The DFIR Report  - GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)
- [Trend Micro - Weaponizing Open Source Software for Targeted Attacks](https://www.trendmicro.com/en_us/research/20/k/weaponizing-open-source-software-for-targeted-attacks.html)
- [Yoroi - Shadows From the Past Threaten Italian Enterprises](https://yoroi.company/research/shadows-from-the-past-threaten-italian-enterprises/)

## ATT&CK Techniques

- [T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [T1555.003 — Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [T1555.004 — Credentials from Password Stores: Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004/)
- [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [T1003.004 — OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004/)
- [T1003.005 — OS Credential Dumping: Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)
- [T1003.007 — OS Credential Dumping: Proc Filesystem](https://attack.mitre.org/techniques/T1003/007/)
- [T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)
- [T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- **Red Canary - Atomic Red Team**
  - [LaZagne - Credentials from Browser](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md#atomic-test-3---lazagne---credentials-from-browser)
  - [Extract Browser and System credentials with LaZagne](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md#atomic-test-1---extract-browser-and-system-credentials-with-lazagne)

## Detection Rules

- **Splunk**
  - [Credential Extraction indicative of Lazagne command line options](https://research.splunk.com/endpoint/credential_extraction_indicative_of_lazagne_command_line_options/)

- **Sigma**
  - [Credential Dumping by LaZagne](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/sysmon_lazagne_cred_dump_lsass_access.yml)

## LOLBAS / GTFOBins References

- None
