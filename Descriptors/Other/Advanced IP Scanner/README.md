# Advanced IP Scanner

## Table of Contents

- [Advanced IP Scanner](#advanced-ip-scanner)
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

<p align="center"><img src="/Images/Screenshots/Advanced-IP-Scanner.png"></p>

> **Advanced IP Scanner is fast and free software for network scanning. It will allow you to quickly detect all network computers and obtain access to them.** — [Advanced IP Scanner](https://www.advanced-ip-scanner.com/help/)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 2.5.3850    | 1556232c5b6a998a4765a8f53d48a059cd617c59 | [LINK](https://www.virustotal.com/gui/file/87bfb05057f215659cc801750118900145f8a22fa93ac4c6e1bfd81aa98b0a55)                                                                                                             |
| 2.5.3748    | d4793c97b4a1d36cbb39b3e76a60dde182a9d7ad | [LINK](https://www.virustotal.com/gui/file/1976e556909dd8d8c3b901965333b171ad5986593c83ff4b061814126de49a82)                                                                                                             |
| 2.4    | a01b7f55c5edc6576d1349a0a23b781552c74244 | [LINK](https://www.virustotal.com/gui/file/4179e299c24a130f3c567ddbbfe1835064a3497e8c2a1971aaba597794e8c14d)                                                                                                             |
| 2.3    | 0e840ae8efa952429c15c00776d63539c44fcef2 | [LINK](https://www.virustotal.com/gui/file/9ff3191ef41253460a8161c520948bf1eb332a239b30f8330a2b4d7023ad9384)                                                                                                             |

## Common CommandLine

```batch
advanced_ip_scanner.exe /portable [PATH] /lng [Language]

advanced_ip_scanner_console.exe /r:[IP RANGE]

advanced_ip_scanner_console.exe /r:[IP RANGE] /v

advanced_ip_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

````batch
C:\Program Files (x86)\Advanced IP Scanner\

C:\Users\[user]\AppData\Local\Temp\Advanced IP Scanner 2\

C:\Users\[user]\AppData\Local\Programs\Advanced IP Scanner Portable\
````

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN — ipscan25.exe](https://app.any.run/tasks/c73630e0-a3ca-40fe-9301-392e8f61f170/)

## Documentation

- [Advanced IP Scanner (GUI) — Help](https://www.advanced-ip-scanner.com/help/)

- Advanced IP Scanner Console Help:

```yaml
Usage:
</r:<IP range> OR /s:<source_file>> [/f:<output_file>] [/v]

Description:
/r - address or range of IP addresses to scan, ex 192.168.0.1-192.168.0.255
or
/s - path to the file with IP ranges with 1 IP/IP range per line format, ex
     192.168.0.1-192.168.0.128
     192.168.0.155
     192.168.1.10

/f - path to the file where scan results will be written

/v - show results of service scan (/v2 to show grouped)
Example:
advanced_ip_scanner_console.exe /r:192.168.0.1-192.168.0.255
advanced_ip_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

## Blogs / Reports References

- [The DFIR Report — All That for a Coinminer?](https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/)
- [The DFIR Report — BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report — GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)

## ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1135 — Network Share Discovery](https://attack.mitre.org/versions/v9/techniques/T1135/)

## Telemetry

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)

## Detection Validation

- TBD

## Detection Rules

- **Sigma**
  - [Advanced IP Scanner - Process Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_advanced_ip_scanner.yml)
  - [Advanced IP Scanner - File Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/file_event_advanced_ip_scanner.yml)

## LOLBAS / GTFOBins References

- None
