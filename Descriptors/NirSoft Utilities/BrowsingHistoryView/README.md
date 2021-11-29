# BrowsingHistoryView

## Table of Contents

- [BrowsingHistoryView](#browsinghistoryview)
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

> **BrowsingHistoryView is a utility that reads the history data of different Web browsers (Mozilla Firefox, Google Chrome, Internet Explorer, Microsoft Edge, Opera) and displays the browsing history of all these Web browsers in one table.** — [NirSoft](https://www.nirsoft.net/utils/browsing_history_view.html)

## Versions History

| Version | SHA1                                     | VT                                                                                                                   |
|---------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 2.50 (x86)   | 441e7d140a4d831c8ac550c1ea8db4db214516dc | [LINK](https://www.virustotal.com/gui/file/61ccbeee05269bba4b2e121e48f153b59abef08e718d3f049090afb95f1853b5)                                                                                                             |
| 2.50 (x64)    | 30e4ed8f24ca68d3776372cef8484a54db4af3cb | [LINK](https://www.virustotal.com/gui/file/e8666204dcda71dfef778f40beebc76b4266443a925fcf88a9b3c6001b2a0030)                                                                                                             |
| 2.46 (x86)    | 0b03b34cfb2985a840db279778ca828e69813116 | [LINK](https://www.virustotal.com/gui/file/deb1246347ce88e8cdd63a233a64bc2090b839f2d933a3097a2fd8fd913c4112)                                                                                                             |
| 2.46 (x64)    | 6626524933ec7a54713e615cc4565b3293c1f570 | [LINK](https://www.virustotal.com/gui/file/0e56e1d0e1ff6659de6c9521c01688360477b94fafc203bcba2cdce60b32c97b)                                                                                                             |
| 2.45 (x86)    | 79bd39f7ca8649907782a5efe3c2c0c3f0084258 | [LINK](https://www.virustotal.com/gui/file/c3b1694aa27e1c861ddb21b84955b646f0e371130accbbc9689ce7973ec4e0cf)                                                                                                             |
| 2.45 (x64)    | 6626524933ec7a54713e615cc4565b3293c1f570 | [LINK](https://www.virustotal.com/gui/file/10ccf0ce2bd63d35ab92a2af8d81d2dd04fa014a855bb3e32ee0bb7f121ec979)                                                                                                             |

## Common CommandLine

```batch
rem Dump chrome history of all users into an HTML file 
BrowsingHistoryView.exe /HistorySource 1 /LoadChrome 1 /shtml [ResultsPath]

rem Dump all history of all users into a CSV file
BrowsingHistoryView.exe  /HistorySource 1 /SaveDirect /scomma [ResultsPath]

rem Dump all history into a TXT file
BrowsingHistoryView  /stext [ResultsPath]
```

Here is a list of some of the available export flags (See [docs](#documentation) below for a complete list)

```batch
/stext <Filename> - Save the list of passwords into a regular text file.

/stab <Filename> - Save the list of passwords into a tab-delimited text file.

/scomma <Filename> - Save the list of passwords into a comma-delimited text file.

/stabular <Filename> - Save the list of passwords into a tabular text file.

/shtml <Filename> - Save the list of passwords into HTML file (Horizontal).

/sverhtml <Filename> - Save the list of passwords into HTML file (Vertical).

/sxml <Filename> - Save the list of passwords to XML file.
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- BrowsingHistoryView is a downloadable portable package so no installation is required to execute it.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - ttp100.zip](https://app.any.run/tasks/b73154d4-3535-41a7-b607-f9c115f24623/)
- [ANY.RUN - hexe.docx](https://app.any.run/tasks/663cc334-e294-411f-9313-7cc357cc2efd/)
- [ANY.RUN - gtavicecity.exe](https://app.any.run/tasks/0d7f39dc-b74d-446d-a4b0-d8b7c8a85ebd/)
- [ANY.RUN - reap_full.exe](https://app.any.run/tasks/0fe5c8d8-ef61-402c-8535-11dcb26bdec8/)

## Documentation

- [NirSoft - BrowsingHistoryView - View browsing history of your Web browsers](https://www.nirsoft.net/utils/browsing_history_view.html)

## Blogs / Reports References

- [Trend Micro  - New RETADUP Variants Hit South America, Turn To Cryptocurrency Mining](https://blog.trendmicro.com/trendlabs-security-intelligence/new-retadup-variants-hit-south-america-turn-cryptocurrency-mining/)

## ATT&CK Techniques

- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [T1533 - Data from Local System](https://attack.mitre.org/techniques/T1533/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Detection of tools built by NirSoft](https://research.splunk.com/endpoint/detection_of_tools_built_by_nirsoft/)

## LOLBAS / GTFOBins References

- None
