# Taskkill

## Acknowledgement(s)

- 3CORESec - [@3CORESec](https://twitter.com/3CORESec)
- Nasreddine Bencherchali - [@nas_bench](https://twitter.com/nas_bench)

## Description

> **The Taskkill utility ends one or more tasks or processes. Processes can be ended by process ID or image name.** - [MSDN](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill)

## Common CommandLine

```batch
taskkill /IM [ImageName] /F

taskkill /S system /F /IM

taskkill /F /PID [PID]
```

## Default Install Location

```batch
C:\Windows\System32\taskkill.exe

C:\Windows\SysWOW64\taskkill.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [Hatching Triage (tria.ge) - b01054d750aaa982359bee75707847f30df668135ca139e25b142e18f8cf2f51.exe](https://tria.ge/200423-ncymqv6pca/behavioral2#report)
- [Hatching Triage (tria.ge) - STATEMENT.jar](https://tria.ge/200806-k3ev8mxahj/behavioral1#report)
- [Hatching Triage (tria.ge) - c50bf8069221d689963c17b931f835ad47ed62cfc0a0674df52b123818d942bd.exe](https://tria.ge/200629-ehf8vdq75x/behavioral1#report)
- [Hatching Triage (tria.ge) - ee0400adcec67d05e4b6825df53ff7e5fb5d86680a65264976940239c322d9fb.exe](https://tria.ge/201101-qd45fdzfz2/behavioral1#report)
- [Hatching Triage (tria.ge) - e98fcce723a2bd5e65ea25f993ec1f7148f73ce2.input.exe](https://tria.ge/201103-vajz4wl3ee/behavioral2#report)
- [Hatching Triage (tria.ge) - wnsrf_sp10.0.3.10214-1.exe](https://tria.ge/200401-zdnred9dgj/behavioral1#report)
- [Hatching Triage (tria.ge) - SyncApteka.bin.exe](https://tria.ge/210419-9crd845edj/behavioral1#report)

## Documentation

- [Microsoft Docs - Taskkill](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill)
- [SS64.com - Windows CMD - Taskkill](https://ss64.com/nt/taskkill.html)

## Blogs / Reports References

- [The DFIR Report - Ryuk Speed Run, 2 Hours to Ransom](https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/)
- [The DFIR Report - Ryuk’s Return](https://thedfirreport.com/2020/10/08/ryuks-return/)
- [The DFIR Report - The Little Ransomware That Couldn’t (Dharma)](https://thedfirreport.com/2020/06/16/the-little-ransomware-that-couldnt-dharma/)
- [Palo Alto Networks - Unite 42 - xHunt Campaign: New BumbleBee Webshell and SSH Tunnels Used for Lateral Movement](https://unit42.paloaltonetworks.com/bumblebee-webshell-xhunt-campaign/)
- [Palo Alto Networks - Unite 42 - OilRig Targets Middle Eastern Telecommunications Organization and Adds Novel C2 Channel with Steganography to Its Inventory](https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/)
- [Palo Alto Networks - Unite 42 - Studying How Cybercriminals Prey on the COVID-19 Pandemic](https://unit42.paloaltonetworks.com/how-cybercriminals-prey-on-the-covid-19-pandemic/)
- [Securelist By Kaspersky - To crypt, or to mine – that is the question](https://securelist.com/to-crypt-or-to-mine-that-is-the-question/86307/)
- [Securelist By Kaspersky - Zero-day vulnerability in Telegram](https://securelist.com/zero-day-vulnerability-in-telegram/83800/)
- [Securelist By Kaspersky - TeamXRat: Brazilian cybercrime meets ransomware](https://securelist.com/teamxrat-brazilian-cybercrime-meets-ransomware/76153/)

## ATT&CK Techniques

- [T1489 - Service Stop](https://attack.mitre.org/techniques/T1489/)
- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Excessive Usage Of Taskkill](https://research.splunk.com/endpoint/excessive_usage_of_taskkill/)

- **Elastic**
  - [High Number of Process and/or Service Terminations](https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_stop_process_service_threshold.toml)

- **Sigma**
  - [Quick Execution of a Series of Suspicious Commands](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_multiple_suspicious_cli.yml)
  - [Kill multiple process](https://github.com/joesecurity/sigma-rules/blob/master/rules/killmultipleprocess.yml)

## LOLBAS / GTFOBins References

- None
