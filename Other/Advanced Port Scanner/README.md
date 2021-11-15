# Advanced Port Scanner

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **Advanced Port Scanner is a free network scanner allowing you to quickly find open ports on network computers and retrieve versions of programs running on the detected ports** — [Advanced Port Scanner](https://www.advanced-port-scanner.com/)

## Common CommandLine

```batch
advanced_port_scanner.exe /portable [PATH] /lng [Language]

advanced_port_scanner_console.exe /r:[IP RANGE]

advanced_port_scanner_console.exe /r:[IP RANGE] /p:[PORT RANGE]

advanced_port_scanner_console.exe /s:ip_ranges.txt /f:scan_results.txt
```

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

- [Advanced Port Scanner — Help](https://www.advanced-port-scanner.com/help/)

## Blogs / Reports References

- TBD

## ATT&CK Techniques

- [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [T1135 — Network Share Discovery](https://attack.mitre.org/versions/v9/techniques/T1135/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 — A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 — Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Rules

- TBD

## LOLBAS / GTFOBins References

- None
