# Advanced IP Scanner

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Advanced IP Scanner is fast and free software for network scanning. It will allow you to quickly detect all network computers and obtain access to them.** — [Advanced IP Scanner](https://www.advanced-ip-scanner.com/help/)

## Common CommandLine

```batch
\Advanced IP Scanner 2\advanced_ip_scanner.exe /portable [PATH] /lng en_us
advanced_ip_scanner_console.exe /r:[IP RANGE]
advanced_ip_scanner_console.exe /r:[IP RANGE] /v
advanced_ip_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

## Default Install Location

````batch
C:\Program Files (x86)\Advanced IP Scanner\

C:\Users\[user]\AppData\Local\Temp\Advanced IP Scanner 2

C:\Users\[user]\AppData\Local\Programs\Advanced IP Scanner Portable\
````

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN — ipscan25.exe](https://app.any.run/tasks/c73630e0-a3ca-40fe-9301-392e8f61f170/)

## Documentation

- [Advanced IP Scanner — Help](https://www.advanced-ip-scanner.com/help/)

## Blogs / Reports References

- [The DFIR Report — All That for a Coinminer?](https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/)
- [The DFIR Report — BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report — GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)

## ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1135 — Network Share Discovery](https://attack.mitre.org/versions/v9/techniques/T1135/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- **Sigma**
  - [Advanced IP Scanner - Process Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_advanced_ip_scanner.yml)
  - [Advanced IP Scanner - File Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/file_event_advanced_ip_scanner.yml)

## LOLBAS / GTFOBins References

- None
