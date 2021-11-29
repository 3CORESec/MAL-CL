# NirSoft Password Recovery Tools

## Table of Contents

- [NirSoft Password Recovery Tools](#nirsoft-password-recovery-tools)
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

> **NirSoft Web site provides free password recovery tools for variety of Windows programs, including Chrome Web browser, Firefox Web browser, Microsoft Edge, Internet Explorer, Microsoft Outlook, Network passwords of Windows, Wireless network keys, Dialup entries of Windows, and more.** — [NirSoft](https://www.nirsoft.net/password_recovery_tools.html)

## Versions History

- TBD

## Common CommandLine

- Executables Included

```yaml
- ChromePass.exe
- Dialupass.exe
- iepv.exe (IE PassView)
- mailpv.exe (Mail PassView)
- mspass.exe (MessenPass)
- netpass.exe (Network Password Recovery)
- PasswordFox.exe
- PstPassword.exe
- WebBrowserPassView.exe
```

All the tools have the same commandline arguments to export passwords

```batch
rem Exporting passwords using PasswordFox
PasswordFox.exe /stext C:\Users\admin\AppData\Local\Temp\firefox.txt

rem Exporting passwords using IE PassView
iepv.exe /stext C:\Users\admin\AppData\Local\Temp\ie.txt

rem Exporting passwords using any of the tools above
[ToolName].exe /stext [PathToSaveOnDisk]
```

Here is a list of some of the available export flags (See [docs](#documentation) below for a complete list for every tool)

```batch
/stext <Filename> - Save the list of passwords into a regular text file.

/stab <Filename> - Save the list of passwords into a tab-delimited text file.

/scomma <Filename> - Save the list of passwords into a comma-delimited text file.

/stabular <Filename> - Save the list of passwords into a tabular text file.

/shtml <Filename> - Save the list of passwords into HTML file (Horizontal).

/sverhtml <Filename> - Save the list of passwords into HTML file (Vertical).

/sxml <Filename> - Save the list of passwords to XML file.

/skeepass <Filename> - Save the list of passwords to KeePass csv file.
```

## Threat Actor Ops (TAOps)

- TBD

## Common Process Trees

- TBD

## Default Install Location

- The ``NirSoft Password Recovery Tools`` are a set of downloadable portable packages, so no installation is required to execute them.

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - usdtransfswift.zip](https://app.any.run/tasks/6b0da712-6337-4784-a950-a6ccd0fb17d2/)
- [ANY.RUN - nirsoft_package_enc_1.20.74.zip](https://app.any.run/tasks/e515adc5-c1f6-462e-a9d3-d673972d4d03/)
- [ANY.RUN - 2af0af11b70df15865dcec9c36bef39edfc00737fe419dc88936d0ae849cb64c_4.exe](https://app.any.run/tasks/9cd632a0-c7d1-405d-84b9-a25b89f37ac6/)

## Documentation

- [NirSoft - Windows Password Recovery Tools](https://www.nirsoft.net/password_recovery_tools.html)
- [NirSoft  - ChromePass](https://www.nirsoft.net/utils/chromepass.html)
- [NirSoft  - Dialupass - Extract dialup / RAS / VPN passwords stored by Windows](https://www.nirsoft.net/utils/dialupass.html)
- [NirSoft  - IE PassView - Recover lost passwords stored by Internet Explorer](https://www.nirsoft.net/utils/internet_explorer_password.html)
- [NirSoft  - Mail PassView - Extract lost email passwords](https://www.nirsoft.net/utils/mailpv.html)
- [NirSoft  - MessenPass - Recover Lost Instant Messenger Passwords](https://www.nirsoft.net/utils/mspass.html)
- [NirSoft  - Network Password Recovery - Recover Windows 10/7/8/Vista/XP network passwords (Credentials file)](https://www.nirsoft.net/utils/network_password_recovery.html)
- [NirSoft  - PasswordFox - Extract the user names / passwords stored in Firefox](https://www.nirsoft.net/utils/passwordfox.html)
- [NirSoft  - PstPassword - Recover lost password of Outlook PST file.](https://www.nirsoft.net/utils/pst_password.html)
- [NirSoft  - WebBrowserPassView](https://www.nirsoft.net/utils/web_browser_password.html)

## Blogs / Reports References

- [The DFIR Report  - GoGoogle Ransomware](https://thedfirreport.com/2020/04/04/gogoogle-ransomware/)

## ATT&CK Techniques

- [T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [T1555.003 — Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)

## Telemetry

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
- [PsSetCreateProcessNotifyRoutine/Ex](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [ETW - Microsoft-Windows-Kernel-Process - Event ID 1 - ProcessStart](https://github.com/nasbench/EVTX-ETW-Resources)
- [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Detection of tools built by NirSoft](https://research.splunk.com/endpoint/detection_of_tools_built_by_nirsoft/)

## LOLBAS / GTFOBins References

- None
