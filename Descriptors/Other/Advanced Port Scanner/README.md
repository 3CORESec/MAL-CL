# Advanced Port Scanner

## Table of Contents

- [Advanced Port Scanner](#advanced-port-scanner)
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

<p align="center"><img src="/Images/Screenshots/Advanced-Port-Scanner.png"></p>

> **Advanced Port Scanner is a free network scanner allowing you to quickly find open ports on network computers and retrieve versions of programs running on the detected ports** — [Advanced Port Scanner](https://www.advanced-port-scanner.com/)

## Versions History

- TBD

## Common CommandLine

```batch
advanced_port_scanner.exe /portable [PATH] /lng [Language]

advanced_port_scanner_console.exe /r:[IP RANGE]

advanced_port_scanner_console.exe /r:[IP RANGE] /p:[PORT RANGE]

advanced_port_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

````batch
C:\Program Files (x86)\Advanced Port Scanner\

C:\Users\Administrator\AppData\Local\Temp\2\Advanced Port Scanner 2\

C:\Users\[user]\AppData\Local\Programs\Advanced Port Scanner Portable\
````

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN — pscan24.exe](https://app.any.run/tasks/ec44d645-7d35-43c1-bae5-03e641cce91d/)

## Documentation

- [Advanced Port Scanner (GUI) — Help](https://www.advanced-port-scanner.com/help/)

- Advanced Port Scanner Help:

```yaml
Usage:
</r:<IP range> OR /s:<source_file>> [/p:<ports list>] [/f:<output_file>]

Description:
/r - address or range of IP addresses to scan, ex 192.168.0.1-192.168.0.255
or
/s - path to the file with IP ranges with 1 IP/IP range per line format, ex
     192.168.0.1-192.168.0.128
     192.168.0.155
     192.168.1.10

/p - list of ports to scan, ex
     1-20
     1,2,UDP:1-10

/f - path to the file where scan results will be written

Example:
advanced_port_scanner_console.exe /r:192.168.0.1-192.168.0.255
advanced_port_scanner_console.exe /r:192.168.0.1-192.168.0.255 /p:1-10
advanced_port_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1135 — Network Share Discovery](https://attack.mitre.org/versions/v9/techniques/T1135/)

## Telemetry

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
