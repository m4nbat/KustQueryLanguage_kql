# Title: BumbleBee Analytics 2022
# Source: https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/

```
//Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
SecurityEvent 
|  where EventID == 4688 | where ((CommandLine contains @' -ma ' and CommandLine contains @' lsass') or (CommandLine contains @' -ma ' and CommandLine contains @' ls'))
```

```
//Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
DeviceProcessEvents | where ((ProcessCommandLine contains @' -ma ' and ProcessCommandLine contains @' lsass') or (ProcessCommandLine contains @' -ma ' and ProcessCommandLine contains @' ls'))
```

```
//Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
//https://www.cobaltstrike.com/help-opsec
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
DeviceProcessEvents | where ((ProcessCommandLine endswith @'\rundll32.exe' and (InitiatingProcessFolderPath !endswith @'\svchost.exe')) and not ((InitiatingProcessFolderPath contains @'\AppData\Local\' or 
InitiatingProcessFolderPath contains @'\Microsoft\Edge\')))
```

```
//Detects keywords that could indicate the use of some PowerShell exploitation framework
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
//https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
//https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1
//https://gist.github.com/MHaggis/0dbe00ad401daa7137c81c99c268cfb7
DeviceProcessEvents 
| where FileName endswith "powershell.exe" or FileName endswith "powershell_ise.exe"
| where (ProcessCommandLine contains @'System.Reflection.Assembly.Load($' or ProcessCommandLine contains @'[System.Reflection.Assembly]::Load($' or ProcessCommandLine contains @'[Reflection.Assembly]::Load($' or ProcessCommandLine contains @'System.Reflection.AssemblyName' or ProcessCommandLine contains @'Reflection.Emit.AssemblyBuilderAccess' or ProcessCommandLine contains @'Runtime.InteropServices.DllImportAttribute' or ProcessCommandLine contains @'SuspendThread' or ProcessCommandLine contains @'rundll32' or ProcessCommandLine contains @'Invoke-WMIMethod' or ProcessCommandLine contains @'http://127.0.0.1')
```

```
//Detects keywords that could indicate the use of some PowerShell exploitation framework
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
//https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
//https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1
//https://gist.github.com/MHaggis/0dbe00ad401daa7137c81c99c268cfb7
SecurityEvent 
| where EventData contains "powershell.exe" or EventData contains "powershell_ise.exe"
| where (EventData contains @'System.Reflection.Assembly.Load($' or EventData contains @'[System.Reflection.Assembly]::Load($' or EventData contains @'[Reflection.Assembly]::Load($' or EventData contains @'System.Reflection.AssemblyName' or EventData contains @'Reflection.Emit.AssemblyBuilderAccess' or EventData contains @'Runtime.InteropServices.DllImportAttribute' or EventData contains @'SuspendThread' or EventData contains @'rundll32' or EventData contains @'Invoke-WMIMethod' or EventData contains @'http://127.0.0.1')
```

```
//Detects suspicious PowerShell invocation command parameters
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
DeviceProcessEvents
| where FileName endswith "powershell.exe" or FileName endswith "powershell_ise.exe"
| where (((ProcessCommandLine contains @'-nop' and ProcessCommandLine contains @' -w ' and ProcessCommandLine contains @'hidden' and ProcessCommandLine contains @' -c ' and ProcessCommandLine contains @'[Convert]::FromBase64String') or (ProcessCommandLine contains @' -w ' and ProcessCommandLine contains @'hidden' and ProcessCommandLine contains @'-noni' and ProcessCommandLine contains @'-nop' and ProcessCommandLine contains @' -c ' and ProcessCommandLine contains @'iex' and ProcessCommandLine contains @'New-Object') or (ProcessCommandLine contains @' -w ' and ProcessCommandLine contains @'hidden' and ProcessCommandLine contains @'-ep' and ProcessCommandLine contains @'bypass' and ProcessCommandLine contains @'-Enc') or (ProcessCommandLine contains @'powershell' and ProcessCommandLine contains @'reg' and ProcessCommandLine contains @'add' and ProcessCommandLine contains @'HKCU\software\microsoft\windows\currentversion\run') or (ProcessCommandLine contains @'bypass' and ProcessCommandLine contains @'-noprofile' and ProcessCommandLine contains @'-windowstyle' and ProcessCommandLine contains @'hidden' and ProcessCommandLine contains @'new-object' and ProcessCommandLine contains @'system.net.webclient' and ProcessCommandLine contains @'.download') or (ProcessCommandLine contains @'iex' and ProcessCommandLine contains @'New-Object' and ProcessCommandLine contains @'Net.WebClient' and ProcessCommandLine contains @'.Download')) and not (((ProcessCommandLine contains @"(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')" or ProcessCommandLine contains @"(New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')" or ProcessCommandLine contains @'Write-ChocolateyWarning'))))
```

```
//Successful Overpass the Hash Attempt.Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
// False Positives: Runas command-line tool using /netonly parameter
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
// https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html
SecurityEvent | where (EventID == 4624 and LogonType == 9 and LogonProcessName =~ @'seclogo' and AuthenticationPackageName =~ @'Negotiate')
```

```
//Detects the shell open key manipulation (exefile and ms-settings) used for persistence and the pattern of UAC Bypass using fodhelper.exe, computerdefaults.exe, slui.exe via registry keys (e.g. UACMe 33 or 62)
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//not overly confident of the SIGMA conversion on this one.
DeviceRegistryEvents 
| where (ActionType =~ @'SetValue' and RegistryKey endswith @'Classes\ms-settings\shell\open\command\SymbolicLinkValue' and (RegistryValueData contains @'\Software\Classes\{' or RegistryValueType contains @'\Software\Classes\{')) or (RegistryKey endswith @'Classes\ms-settings\shell\open\command\DelegateExecute') or (ActionType =~ @'SetValue' and (RegistryKey endswith @'Classes\ms-settings\shell\open\command\(Default)' or RegistryKey endswith @'Classes\exefile\shell\open\command\(Default)')) and (isnotempty(RegistryValueData) or isnotempty(RegistryValueType))
```

```
//Registry Dump of SAM Creds and Secrets. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through Windows Registry where the SAM database is stored
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets
SecurityEvent |  where EventID == 4688 | where (CommandLine contains @' save ' and (CommandLine contains @'HKLM\sam' or CommandLine contains @'HKLM\system' or CommandLine contains @'HKLM\security'))
```

```
//Registry Dump of SAM Creds and Secrets. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through Windows Registry where the SAM database is stored
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets
DeviceProcessEvents | where (ProcessCommandLine contains @' save ' and (ProcessCommandLine contains @'HKLM\sam' or ProcessCommandLine contains @'HKLM\system' or ProcessCommandLine contains @'HKLM\security'))
```

```
//Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
//https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
SecurityEvent |  where EventID == 4688 | where ((ParentProcessName endswith @'\services.exe' and ((CommandLine contains @'cmd' and CommandLine contains @'/c' and CommandLine contains @'echo' and CommandLine contains @'\pipe\') or (CommandLine contains @'%COMSPEC%' and CommandLine contains @'/c' and CommandLine contains @'echo' and CommandLine contains @'\pipe\') or (CommandLine contains @'cmd.exe' and CommandLine contains @'/c' and CommandLine contains @'echo' and CommandLine contains @'\pipe\') or (CommandLine contains @'rundll32' and CommandLine contains @'.dll,a' and CommandLine contains @'/p:'))) and (CommandLine !contains @'MpCmdRun'))
```

```
//Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
//https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
DeviceProcessEvents | where ((InitiatingProcessFolderPath endswith @'\services.exe' and ((ProcessCommandLine contains @'cmd' and ProcessCommandLine contains @'/c' and ProcessCommandLine contains @'echo' and ProcessCommandLine contains @'\pipe\') or (ProcessCommandLine contains @'%COMSPEC%' and ProcessCommandLine contains @'/c' and ProcessCommandLine contains @'echo' and ProcessCommandLine contains @'\pipe\') or (ProcessCommandLine contains @'cmd.exe' and ProcessCommandLine contains @'/c' and ProcessCommandLine contains @'echo' and ProcessCommandLine contains @'\pipe\') or (ProcessCommandLine contains @'rundll32' and ProcessCommandLine contains @'.dll,a' and ProcessCommandLine contains @'/p:'))) and (ProcessCommandLine !contains @'MpCmdRun'))
```

```
//LSASS memory dumping. Detect creation of dump files containing the memory space of lsass.exe, which contains sensitive credentials. Identifies usage of Sysinternals procdump.exe to export the memory space of lsass.exe which contains sensitive credentials.
//https://eqllib.readthedocs.io/en/latest/analytics/1e1ef6be-12fc-11e9-8d76-4d6bb837cda4.html
//https://eqllib.readthedocs.io/en/latest/analytics/210b4ea4-12fc-11e9-8d76-4d6bb837cda4.html
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
SecurityEvent
| where (CommandLine contains 'lsass' and CommandLine contains '.dmp' and ProcessName !endswith '\\werfault.exe') or (ProcessName contains '\\procdump' and ProcessName endswith '.exe' and CommandLine contains 'lsass')
```

```
//LSASS memory dumping. Detect creation of dump files containing the memory space of lsass.exe, which contains sensitive credentials. Identifies usage of Sysinternals procdump.exe to export the memory space of lsass.exe which contains sensitive credentials.
//https://eqllib.readthedocs.io/en/latest/analytics/1e1ef6be-12fc-11e9-8d76-4d6bb837cda4.html
//https://eqllib.readthedocs.io/en/latest/analytics/210b4ea4-12fc-11e9-8d76-4d6bb837cda4.html
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
DeviceProcessEvents 
| where (ProcessCommandLine contains 'lsass' and ProcessCommandLine contains '.dmp' and FolderPath !endswith '\\werfault.exe') or (FolderPath contains '\\procdump' and FolderPath endswith '.exe' and ProcessCommandLine contains 'lsass')
```

```
// Detects a possible process memory dump based on a keyword in the file name of the accessing process
//https://twitter.com/_xpn_/status/1491557187168178176
//https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
DeviceFileEvents 
| where ((FolderPath contains @'\pwdump' or FolderPath contains @'\kirbi' or FolderPath contains @'\pwhashes' or FolderPath contains @'\wce_ccache' or FolderPath contains @'\wce_krbtkts' or FolderPath contains @'\fgdump-log') or (FolderPath endswith @'\test.pwd' or FolderPath endswith @'\lsremora64.dll' or FolderPath endswith @'\lsremora.dll' or FolderPath endswith @'\fgexec.exe' or FolderPath endswith @'\wceaux.dll' or FolderPath endswith @'\SAM.out' or FolderPath endswith @'\SECURITY.out' or FolderPath endswith @'\SYSTEM.out' or FolderPath endswith @'\NTDS.out' or FolderPath endswith @'\DumpExt.dll' or FolderPath endswith @'\DumpSvc.exe' or FolderPath endswith @'\cachedump64.exe' or FolderPath endswith @'\cachedump.exe' or FolderPath endswith @'\pstgdump.exe' or FolderPath endswith @'\servpw.exe' or FolderPath endswith @'\servpw64.exe' or FolderPath endswith @'\pwdump.exe' or FolderPath endswith @'\procdump64.exe'))
```

```
// Detects a possible process memory dump based on a keyword in the file name of the accessing process
//https://twitter.com/_xpn_/status/1491557187168178176
//https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
SecurityEvent
| where EventID == 4688 or EventID == 4663
| where (NewProcessName contains @'\pwdump' or NewProcessName contains @'\kirbi' or NewProcessName contains @'\pwhashes' or NewProcessName contains @'\wce_ccache' or NewProcessName contains @'\wce_krbtkts' or NewProcessName contains @'\fgdump-log') 
or 
(NewProcessName endswith @'\test.pwd' or NewProcessName endswith @'\lsremora64.dll' or NewProcessName endswith @'\lsremora.dll' or NewProcessName endswith @'\fgexec.exe' or NewProcessName endswith @'\wceaux.dll' or NewProcessName endswith @'\SAM.out' or NewProcessName endswith @'\SECURITY.out' or NewProcessName endswith @'\SYSTEM.out' or NewProcessName endswith @'\NTDS.out' or NewProcessName endswith @'\DumpExt.dll' or NewProcessName endswith @'\DumpSvc.exe' or NewProcessName endswith @'\cachedump64.exe' or NewProcessName endswith @'\cachedump.exe' or NewProcessName endswith @'\pstgdump.exe' or NewProcessName endswith @'\servpw.exe' or NewProcessName endswith @'\servpw64.exe' or NewProcessName endswith @'\pwdump.exe' or NewProcessName endswith @'\procdump64.exe'or NewProcessName endswith @'\procdump.exe')
or 
(ObjectName endswith @'\test.pwd' or ObjectName endswith @'\lsremora64.dll' or ObjectName endswith @'\lsremora.dll' or ObjectName endswith @'\fgexec.exe' or ObjectName endswith @'\wceaux.dll' or ObjectName endswith @'\SAM.out' or ObjectName endswith @'\SECURITY.out' or ObjectName endswith @'\SYSTEM.out' or ObjectName endswith @'\NTDS.out' or ObjectName endswith @'\DumpExt.dll' or ObjectName endswith @'\DumpSvc.exe' or ObjectName endswith @'\cachedump64.exe' or ObjectName endswith @'\cachedump.exe' or ObjectName endswith @'\pstgdump.exe' or ObjectName endswith @'\servpw.exe' or ObjectName endswith @'\servpw64.exe' or ObjectName endswith @'\pwdump.exe' or ObjectName endswith @'\procdump64.exe'or NewProcessName endswith @'\procdump.exe')
```

```
//The attacker might use LOLBAS nltest.exe for discovery of domain controllers, domain trusts, parent domain and the current user permissions.
//it is unlikely they would run this from the DC itself. 
//https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
//https://attack.mitre.org/software/S0359/
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
SecurityEvent 
| where TimeGenerated > ago(60d)
| where (EventID == 4689 and ProcessName endswith @'nltest.exe' and Status =~ @'0x0')
//| summarize count() by bin(TimeGenerated,1d) // use to visualise the results over time
//| render timechart 
```

```
// CobaltStrike Named Pipe. Detects the creation of a named pipe as used by CobaltStrike
// Untested analytic. FPs may inlcude legitimate strings matched in RelativeTargetName
SecurityEvent
| where EventID == '5145'
// %%4418 looks for presence of CreatePipeInstance value 
| where AccessList has '%%4418'     
| where RelativeTargetName has_any ('\\postex_','\\postex_ssh_','\\status_','\\msagent_') and not(RelativeTargetName matches regex "status_codes.(py|cpy)")
```

```
//title: Bypass UAC via WSReset.exe
//description: Identifies use of WSReset.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.
////https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\wsreset.exe" and not (FolderPath endswith "\\conhost.exe" or PreviousFileName =~ "CONHOST.EXE")
```

```
//Bypass UAC Using DelegateExecute. Bypasses User Account Control using a fileless method
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
//https://devblogs.microsoft.com/oldnewthing/20100312-01/?p=14623
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-7---bypass-uac-using-sdclt-delegateexecute
SecurityEvent
| where TimeGenerated < ago(30d)
| where EventID == 4657 and ObjectName endswith @'\open\command\DelegateExecute'
```

```
//Bypass UAC Using DelegateExecute. Bypasses User Account Control using a fileless method
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
//https://devblogs.microsoft.com/oldnewthing/20100312-01/?p=14623
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-7---bypass-uac-using-sdclt-delegateexecute
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet"  and RegistryKey endswith @'\open\command\DelegateExecute'
```

```
//AD Find usage detection. ADFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
//https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
//https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
//https://thedfirreport.com/2020/05/08/adfind-recon/
let commands = datatable (command:string)['domainlist','trustdmp','dcmodes','adinfo',' dclist ','computer_pwdnotreqd','objectcategory=','-subnets -f','name=\"Domain Admins\"','-sc u:','domainncs','dompol',' oudmp ','subnetdmp','gpodmp','fspdmp','users_noexpire','computers_active'];
SecurityEvent 
| where EventID == 4688 
| where CommandLine has_any (commands)
```

```
//AD Find usage detection. ADFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
//https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
//https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
//https://thedfirreport.com/2020/05/08/adfind-recon/
let commands = datatable (command:string)['domainlist','trustdmp','dcmodes','adinfo',' dclist ','computer_pwdnotreqd','objectcategory=','-subnets -f','name=\"Domain Admins\"','-sc u:','domainncs','dompol',' oudmp ','subnetdmp','gpodmp','fspdmp','users_noexpire','computers_active'];
DeviceProcessEvents
| where ProcessCommandLine has_any (commands) or InitiatingProcessCommandLine has_any (commands)
```

```
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//Abused Debug Privilege by Arbitrary Parent Processes - Detection of unusual child processes by different system processes
//Windows Defender for Endpoint
DeviceProcessEvents 
| where (((InitiatingProcessFolderPath endswith @"\winlogon.exe" or InitiatingProcessFolderPath endswith @"\services.exe" or InitiatingProcessFolderPath endswith @"\lsass.exe" or InitiatingProcessFolderPath endswith @"\csrss.exe" or InitiatingProcessFolderPath endswith @"\smss.exe" or InitiatingProcessFolderPath endswith @"\wininit.exe" or InitiatingProcessFolderPath endswith @"\spoolsv.exe" or InitiatingProcessFolderPath endswith @"\searchindexer.exe") and (FolderPath endswith @"\powershell.exe" or FolderPath endswith @"\cmd.exe") and ((AccountUpn contains "AUTHORI" or AccountUpn contains "AUTORI") or (AccountName contains "AUTHORI" or AccountName contains "AUTORI"))) and not (ProcessCommandLine contains " route " and ProcessCommandLine contains " ADD "))
```

```
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//Abused Debug Privilege by Arbitrary Parent Processes - Detection of unusual child processes by different system processes
//SIGMA  
SecurityEvent 
|  where EventID == 1 
| where (((ParentProcessName endswith @'\winlogon.exe' or ParentProcessName endswith @'\services.exe' or ParentProcessName endswith @'\lsass.exe' or ParentProcessName endswith @'\csrss.exe' or ParentProcessName endswith @'\smss.exe' or ParentProcessName endswith @'\wininit.exe' or ParentProcessName endswith @'\spoolsv.exe' or ParentProcessName endswith @'\searchindexer.exe') and (NewProcessName endswith @'\powershell.exe' or NewProcessName endswith @'\cmd.exe') and (TargetUserName contains 'AUTHORI' or TargetUserName contains 'AUTORI')) and (CommandLine !contains ' route ' and CommandLine !contains ' ADD '))
```

```
//https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/
//Abused Debug Privilege by Arbitrary Parent Processes - Detection of unusual child processes by different system processes
//Windows Events
SecurityEvent
| where EventID == 4688
| where (((ParentProcessName endswith @'\winlogon.exe' or ParentProcessName endswith @'\services.exe' or ParentProcessName endswith @'\lsass.exe' or ParentProcessName endswith @'\csrss.exe' or ParentProcessName endswith @'\smss.exe' or ParentProcessName endswith @'\wininit.exe' or ParentProcessName endswith @'\spoolsv.exe' or ParentProcessName endswith @'\searchindexer.exe') and (NewProcessName endswith @'\powershell.exe' or NewProcessName endswith @'\cmd.exe') and (TargetUserName contains 'AUTHORI' or TargetUserName contains 'AUTORI')) and (CommandLine !contains ' route ' and CommandLine !contains ' ADD '))
```

```
//Detects Commandlet names from PowerView of PowerSploit exploitation framework.
//https://github.com/SigmaHQ/sigma/blob/e10fa684bdd0254b5ba5102feae293b8564f4628/rules/windows/powershell/powershell_script/posh_ps_powerview_malicious_commandlets.yml
let commandlines = datatable (comamnd:string)["Export-PowerViewCSV",'ConvertFrom-UACValue','Export-PowerViewCSV','Get-IPAddress','Resolve-IPAddress','Convert-NameToSid','ConvertTo-SID','Convert-ADName','ConvertFrom-UACValue','Add-RemoteConnection','Remove-RemoteConnection','Invoke-UserImpersonation','Invoke-RevertToSelf','Request-SPNTicket','Get-DomainSPNTicket','Invoke-Kerberoast','Get-PathAcl','Get-DNSZone','Get-DomainDNSZone','Get-DNSRecord','Get-DomainDNSRecord','Get-NetDomain','Get-Domain','Get-NetDomainController','Get-DomainController','Get-NetForest','Get-Forest','Get-NetForestDomain','Get-ForestDomain','Get-NetForestCatalog','Get-ForestGlobalCatalog','Find-DomainObjectPropertyOutlier','Get-NetUser','Get-DomainUser','New-DomainUser','Set-DomainUserPassword','Get-UserEvent','Get-DomainUserEvent','Get-NetComputer','Get-DomainComputer','Get-ADObject','Get-DomainObject','Set-ADObject','Set-DomainObject','Get-ObjectAcl','Get-DomainObjectAcl','Add-ObjectAcl','Add-DomainObjectAcl','Invoke-ACLScanner','Find-InterestingDomainAcl','Get-NetOU','Get-DomainOU','Get-NetSite','Get-DomainSite','Get-NetSubnet','Get-DomainSubnet','Get-DomainSID','Get-NetGroup','Get-DomainGroup','New-DomainGroup','Find-ManagedSecurityGroups','Get-DomainManagedSecurityGroup','Get-NetGroupMember','Get-DomainGroupMember','Add-DomainGroupMember','Get-NetFileServer','Get-DomainFileServer','Get-DFSshare','Get-DomainDFSShare','Get-NetGPO','Get-DomainGPO','Get-NetGPOGroup','Get-DomainGPOLocalGroup','Find-GPOLocation','Get-DomainGPOUserLocalGroupMapping','Find-GPOComputerAdmin','Get-DomainGPOComputerLocalGroupMapping','Get-DomainPolicy','Get-NetLocalGroup','Get-NetLocalGroupMember','Get-NetShare','Get-NetLoggedon','Get-NetSession','Get-LoggedOnLocal','Get-RegLoggedOn','Get-NetRDPSession','Invoke-CheckLocalAdminAccess','Test-AdminAccess','Get-SiteName','Get-NetComputerSiteName','Get-Proxy','Get-WMIRegProxy','Get-LastLoggedOn','Get-WMIRegLastLoggedOn','Get-CachedRDPConnection','Get-WMIRegCachedRDPConnection','Get-RegistryMountedDrive','Get-WMIRegMountedDrive','Get-NetProcess','Get-WMIProcess','Find-InterestingFile','Invoke-UserHunter','Find-DomainUserLocation','Invoke-ProcessHunter','Find-DomainProcess','Invoke-EventHunter','Find-DomainUserEvent','Invoke-ShareFinder','Find-DomainShare','Invoke-FileFinder','Find-InterestingDomainShareFile','Find-LocalAdminAccess','Invoke-EnumerateLocalAdmin','Find-DomainLocalGroupMember','Get-NetDomainTrust','Get-DomainTrust','Get-NetForestTrust','Get-ForestTrust','Find-ForeignUser','Get-DomainForeignUser','Find-ForeignGroup','Get-DomainForeignGroupMember','Invoke-MapDomainTrust','Get-DomainTrustMapping'];
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (commandlines)
let commandlines = datatable (comamnd:string)["Export-PowerViewCSV",'ConvertFrom-UACValue','Export-PowerViewCSV','Get-IPAddress','Resolve-IPAddress','Convert-NameToSid','ConvertTo-SID','Convert-ADName','ConvertFrom-UACValue','Add-RemoteConnection','Remove-RemoteConnection','Invoke-UserImpersonation','Invoke-RevertToSelf','Request-SPNTicket','Get-DomainSPNTicket','Invoke-Kerberoast','Get-PathAcl','Get-DNSZone','Get-DomainDNSZone','Get-DNSRecord','Get-DomainDNSRecord','Get-NetDomain','Get-Domain','Get-NetDomainController','Get-DomainController','Get-NetForest','Get-Forest','Get-NetForestDomain','Get-ForestDomain','Get-NetForestCatalog','Get-ForestGlobalCatalog','Find-DomainObjectPropertyOutlier','Get-NetUser','Get-DomainUser','New-DomainUser','Set-DomainUserPassword','Get-UserEvent','Get-DomainUserEvent','Get-NetComputer','Get-DomainComputer','Get-ADObject','Get-DomainObject','Set-ADObject','Set-DomainObject','Get-ObjectAcl','Get-DomainObjectAcl','Add-ObjectAcl','Add-DomainObjectAcl','Invoke-ACLScanner','Find-InterestingDomainAcl','Get-NetOU','Get-DomainOU','Get-NetSite','Get-DomainSite','Get-NetSubnet','Get-DomainSubnet','Get-DomainSID','Get-NetGroup','Get-DomainGroup','New-DomainGroup','Find-ManagedSecurityGroups','Get-DomainManagedSecurityGroup','Get-NetGroupMember','Get-DomainGroupMember','Add-DomainGroupMember','Get-NetFileServer','Get-DomainFileServer','Get-DFSshare','Get-DomainDFSShare','Get-NetGPO','Get-DomainGPO','Get-NetGPOGroup','Get-DomainGPOLocalGroup','Find-GPOLocation','Get-DomainGPOUserLocalGroupMapping','Find-GPOComputerAdmin','Get-DomainGPOComputerLocalGroupMapping','Get-DomainPolicy','Get-NetLocalGroup','Get-NetLocalGroupMember','Get-NetShare','Get-NetLoggedon','Get-NetSession','Get-LoggedOnLocal','Get-RegLoggedOn','Get-NetRDPSession','Invoke-CheckLocalAdminAccess','Test-AdminAccess','Get-SiteName','Get-NetComputerSiteName','Get-Proxy','Get-WMIRegProxy','Get-LastLoggedOn','Get-WMIRegLastLoggedOn','Get-CachedRDPConnection','Get-WMIRegCachedRDPConnection','Get-RegistryMountedDrive','Get-WMIRegMountedDrive','Get-NetProcess','Get-WMIProcess','Find-InterestingFile','Invoke-UserHunter','Find-DomainUserLocation','Invoke-ProcessHunter','Find-DomainProcess','Invoke-EventHunter','Find-DomainUserEvent','Invoke-ShareFinder','Find-DomainShare','Invoke-FileFinder','Find-InterestingDomainShareFile','Find-LocalAdminAccess','Invoke-EnumerateLocalAdmin','Find-DomainLocalGroupMember','Get-NetDomainTrust','Get-DomainTrust','Get-NetForestTrust','Get-ForestTrust','Find-ForeignUser','Get-DomainForeignUser','Find-ForeignGroup','Get-DomainForeignGroupMember','Invoke-MapDomainTrust','Get-DomainTrustMapping'];
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any (commandlines) or ProcessCommandLine has_any (commandlines)
```
