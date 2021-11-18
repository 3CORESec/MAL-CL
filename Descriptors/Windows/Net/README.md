# Net

## Table of Contents

- [Net](#net)
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

> **The Net.exe Utility component is a command-line tool that controls users, groups, services, and network connections.** — [MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/aa939914(v=winembedded.5)?redirectedfrom=MSDN)

## Common CommandLine

- Note that the ``net1`` command achieves the same results.

```batch
rem View user account details
net user

rem Add/Delete User
net user [username] [password] /add
net user [username] /delete

net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Users" /domain
net group "Domain Computers" /DOMAIN

rem List/Start/Stop Services
net start
net stop [Service] /y
net start [Service]

rem Display the details of all local shares, including the folder/pathname that is being shared
net share

net use [DeviceName]: \\[IP\DomainName] /user:[DomainName\Username] [Password]

net config workstation

net accounts

net time /domain

net localgroup [groupname]
net localgroup [groupname] /domain
net localgroup administrators localadmin /add 
net localgroup Administrators

net view
net view [Domain Controller Name]  
net view /all  
net view /all /domain  
```

## Default Install Location

```batch
C:\Windows\System32\net.exe

C:\Windows\System32\net1.exe

C:\Windows\SysWOW64\net.exe

C:\Windows\SysWOW64\net1.exe
```

## DFIR Artifacts

- TBD

## Examples In The Wild

- [ANY.RUN - ebb528207b2fc06a6bc89e9d430bcdfe254f0838b0f4660f67cc6bd1ebc193be](https://app.any.run/tasks/58efdddc-48e4-4d89-a90e-3f72d9c6ee5e/)
- [ANY.RUN - Adobe.CC2018.Anticloud.r3.exe](https://app.any.run/tasks/e9651056-1116-4264-b41d-f840e4491b8a/)
- [ANY.RUN - OpenVPN-2.5.1-I601-amd64.exe](https://app.any.run/tasks/c7952b1b-1793-4fe9-9f1a-98c301bdeff1/)
- [ANY.RUN - ConsoleApplication1.exe](https://app.any.run/tasks/a2ddc7e1-deae-47c5-8ebe-84487d5013b9/)
- [ANY.RUN - 3676f59fcb1934a4c79dcbba725006f36cbd2a1cb6c9061da24d0cb93fc6edd9.xls](https://app.any.run/tasks/29943e7b-aa5f-44bb-be53-dde7c12052df/)
- [ANY.RUN - 44108FAC.vsc](https://app.any.run/tasks/506eb1b9-db0d-4979-b507-a11d69928a89/)
- [ANY.RUN - EMVInstalador_3.3_standalone.exe](https://app.any.run/tasks/e517fc91-379d-4166-a4f1-6f9b1502877f/)

## Documentation

- [Microsoft Docs - Net](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/aa939914(v=winembedded.5)?redirectedfrom=MSDN)
- [SS64.com - Windows CMD - Net](https://ss64.com/nt/net.html)

## Blogs / Reports References

- [The DFIR Report  - From Zero to Domain Admin](https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/)
- [The DFIR Report  - IcedID to XingLocker Ransomware in 24 hours](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
- [The DFIR Report  - BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/)
- [The DFIR Report  - BazarLoader to Conti Ransomware in 32 Hours](https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/)
- [The DFIR Report  - Trickbot Leads Up to Fake 1Password Installation](https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/)
- [The DFIR Report  - BazarCall to Conti Ransomware via Trickbot and Cobalt Strike](https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/)
- [The DFIR Report  - IcedID and Cobalt Strike vs Antivirus](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/)
- [The DFIR Report  - Hancitor Continues to Push Cobalt Strike](https://thedfirreport.com/2021/06/28/hancitor-continues-to-push-cobalt-strike/)

## ATT&CK Techniques

- [T1087.001 Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)
- [T1087.002 Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
- [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [T1136.002 Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/)
- [T1070.005 Indicator Removal on Host: Network Share Connection Removal](https://attack.mitre.org/techniques/T1070/005/)
- [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [T1201 Password Policy Discovery](https://attack.mitre.org/techniques/T1201/)
- [T1069.001 Permission Groups Discovery: Local Groups](https://attack.mitre.org/techniques/T1069/001/)
- [T1069.002 Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/)
- [T1021.002 Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
- [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007/)
- [T1569.002 System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [T1124 System Time Discovery](https://attack.mitre.org/techniques/T1124/)

## Eventlog / Sysmon Events to Monitor

- [Security Event ID 4688 - A new process has been created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [Security Event ID 4720 - A user account was created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4720)
- [Security Event ID 4722 - A user account was enabled](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4722)
- [Security Event ID 4725 - A user account was disabled](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4725)
- [Security Event ID 4726 - A user account was deleted](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4726)
- [Service Control Manager Event ID 7036](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc756308(v=ws.10)?redirectedfrom=MSDN)
- [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

## Detection Validation

- TBD

## Detection Rules

- **Splunk**
  - [Account Discovery With Net App](https://research.splunk.com/endpoint/account_discovery_with_net_app/)
  - [Create local admin accounts using net exe](https://research.splunk.com/endpoint/create_local_admin_accounts_using_net_exe/)
  - [Create or delete windows shares using net exe](https://research.splunk.com/endpoint/create_or_delete_windows_shares_using_net_exe/)
  - [Delete A Net User](https://research.splunk.com/endpoint/delete_a_net_user/)
  - [Deleting Of Net Users](https://research.splunk.com/endpoint/deleting_of_net_users/)
  - [Disable Net User Account](https://research.splunk.com/endpoint/disable_net_user_account/)
  - [Disabling Net User Account](https://research.splunk.com/endpoint/disabling_net_user_account/)
  - [Domain Account Discovery With Net App](https://research.splunk.com/endpoint/domain_account_discovery_with_net_app/)
  - [Domain Group Discovery With Net](https://research.splunk.com/endpoint/domain_group_discovery_with_net/)
  - [Elevated Group Discovery With Net](https://research.splunk.com/endpoint/elevated_group_discovery_with_net/)
  - [Excessive Usage Of Net App](https://research.splunk.com/endpoint/excessive_usage_of_net_app/)
  - [Local Account Discovery with Net](https://research.splunk.com/endpoint/local_account_discovery_with_net/)
  - [Net Localgroup Discovery](https://research.splunk.com/endpoint/net_localgroup_discovery/)
  - [Password Policy Discovery with Net](https://research.splunk.com/endpoint/password_policy_discovery_with_net/)
  - [Remote System Discovery with Net](https://research.splunk.com/endpoint/remote_system_discovery_with_net/)

- **Sigma**
  - [Windows Network Enumeration](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_net_enum.yml)
  - [Net.exe User Account Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_net_user_add.yml)
  - [Net.exe Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_net_execution.yml)
  - [Stop Windows Service](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_service_stop.yml)
  - [Mounted Windows Admin Shares with net.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_net_use_admin_share.yml)

## LOLBAS / GTFOBins References

- None
