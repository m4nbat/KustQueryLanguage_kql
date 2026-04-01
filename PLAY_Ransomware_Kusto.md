# PLAY Ransomware (DEV-0882) Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087 | Account Discovery | [Account Discovery](https://attack.mitre.org/techniques/T1087/) |
| T1082 | System Information Discovery | [System Information Discovery](https://attack.mitre.org/techniques/T1082/) |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

#### Description
Detection queries for PLAY ransomware (DEV-0882) tradecraft including pushd persistence, PsExec execution, account/system discovery, rclone data exfiltration, encoded PowerShell, and LSASS dumping.

#### Risk
PLAY ransomware group (DEV-0882) targets corporate networks for double-extortion ransomware attacks. They use legitimate tools like PsExec, rclone, and nltest for lateral movement and data exfiltration before deploying ransomware.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/
- https://attack.mitre.org/groups/G1040/

## Defender For Endpoint
```KQL
// DEV-0882 pushd let start = now(-30d); let end = now(); DeviceProcessEvents | where Timestamp between (start..end) | where InitiatingProcessFileName =~ "cmd.exe" | where InitiatingProcessCommandLine has_cs @'"cmd.exe" /s /k pushd "C:\' | where InitiatingProcessCommandLine matches regex @'"C:\\Users\\([\w]+)\\Music\"'     or InitiatingProcessCommandLine endswith 'ProgramData"' | where ProcessCommandLine =~ "PsExec.exe -s -i cmd.exe"     or (         ProcessCommandLine startswith "runas /netonly /user:"         and ProcessCommandLine endswith "cmd"     )     or ProcessCommandLine matches regex @'rundll32([\s]+)([a-z0-9]{1,9})\.dll, rundll'     or ProcessCommandLine startswith 'Wevtutil.exe'
```

```KQL
DeviceProcessEvents | where (ProcessCommandLine in~ (@'net group "domain admins" /domain', @'net localgroup administrators'))
```

```KQL
DeviceProcessEvents | where ((ProcessCommandLine in~ (@'ipconfig /all', @'systeminfo')) and InitiatingProcessFolderPath endswith @'regsvr32.exe' and InitiatingProcessCommandLine contains @'.dll')
```

```KQL
DeviceProcessEvents | where (((FolderPath endswith @'\nltest.exe') or (ProcessVersionInfoOriginalFileName =~ @'nltestrk.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'nltestrk.exe')) and (((ProcessCommandLine contains @'/server' and ProcessCommandLine contains @'/query')) or ((ProcessCommandLine contains @'/dclist:' or ProcessCommandLine contains @'/parentdomain' or ProcessCommandLine contains @'/domain_trusts' or ProcessCommandLine contains @'/trusted_domains' or ProcessCommandLine contains @'/user'))))
```

```KQL
DeviceProcessEvents | where (((ProcessCommandLine contains @'--config ' and ProcessCommandLine contains @'--no-check-certificate ' and ProcessCommandLine contains @' copy ')) or (((ProcessCommandLine contains @'pass' or ProcessCommandLine contains @'user' or ProcessCommandLine contains @'copy' or ProcessCommandLine contains @'sync' or ProcessCommandLine contains @'config' or ProcessCommandLine contains @'lsd' or ProcessCommandLine contains @'remote' or ProcessCommandLine contains @'ls' or ProcessCommandLine contains @'mega' or ProcessCommandLine contains @'pcloud' or ProcessCommandLine contains @'ftp' or ProcessCommandLine contains @'ignore-existing' or ProcessCommandLine contains @'auto-confirm' or ProcessCommandLine contains @'transfers' or ProcessCommandLine contains @'multi-thread-streams' or ProcessCommandLine contains @'no-check-certificate ') and ((((ProcessVersionInfoFileDescription =~ @'Rsync for cloud storage') or (InitiatingProcessVersionInfoFileDescription =~ @'Rsync for cloud storage'))) or ((FolderPath endswith @'\rclone.exe' and (InitiatingProcessFolderPath endswith @'\PowerShell.exe' or InitiatingProcessFolderPath endswith @'\pwsh.exe' or InitiatingProcessFolderPath endswith @'\cmd.exe')))))))
```

```KQL
DeviceProcessEvents | where (((FolderPath endswith @'\powershell.exe' or FolderPath endswith @'\pwsh.exe') and (ProcessCommandLine contains @' -e ' or ProcessCommandLine contains @' -en ' or ProcessCommandLine contains @' -enc ' or ProcessCommandLine contains @' -enco') and (ProcessCommandLine contains @' JAB' or ProcessCommandLine contains @' SUVYI' or ProcessCommandLine contains @' SQBFAFgA' or ProcessCommandLine contains @' aWV4I' or ProcessCommandLine contains @' IAB' or ProcessCommandLine contains @' PAA' or ProcessCommandLine contains @' aQBlAHgA')) and not((InitiatingProcessFolderPath contains @'C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\' or InitiatingProcessFolderPath contains @'\gc_worker.exe')))
```

```KQL
Windows | where ((((FileName endswith @'\lsass.exe') or (FolderPath endswith @'\lsass.exe')) and (GrantedAccess contains @'0x1038' or GrantedAccess contains @'0x1438' or GrantedAccess contains @'0x143a') and (CallTrace contains @'dbghelp.dll' or CallTrace contains @'dbgcore.dll' or CallTrace contains @'ntdll.dll')) and not(((CallTrace contains @'|C:\Windows\Temp\asgard2-agent\' and CallTrace contains @'\thor\thor64.exe+' and CallTrace contains @'|UNKNOWN(' and GrantedAccess =~ @'0x103800')) or ((((InitiatingProcessFolderPath =~ @'C:\Windows\Sysmon64.exe') or (InitiatingProcessFileName =~ @'C:\Windows\Sysmon64.exe'))))))
```

```KQL
DeviceProcessEvents | where (((((FolderPath endswith @'\wmic.exe') or (ProcessVersionInfoOriginalFileName =~ @'wmic.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'wmic.exe')) and (ProcessCommandLine contains @'process' and ProcessCommandLine contains @'call' and ProcessCommandLine contains @'create '))) or ((((FolderPath endswith @'\wmic.exe') or (ProcessVersionInfoOriginalFileName =~ @'wmic.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'wmic.exe')) and (ProcessCommandLine contains @' path ' and (ProcessCommandLine contains @'AntiVirus' or ProcessCommandLine contains @'Firewall') and ProcessCommandLine contains @'Product' and ProcessCommandLine contains @' get ' and ProcessCommandLine contains @'wmic csproduct get name'))))
```

## Sentinel
```KQL
// DEV-0882 pushd let start = now(-30d); let end = now(); DeviceProcessEvents | where Timestamp between (start..end) | where InitiatingProcessFileName =~ "cmd.exe" | where InitiatingProcessCommandLine has_cs @'"cmd.exe" /s /k pushd "C:\' | where InitiatingProcessCommandLine matches regex @'"C:\\Users\\([\w]+)\\Music\"'     or InitiatingProcessCommandLine endswith 'ProgramData"' | where ProcessCommandLine =~ "PsExec.exe -s -i cmd.exe"     or (         ProcessCommandLine startswith "runas /netonly /user:"         and ProcessCommandLine endswith "cmd"     )     or ProcessCommandLine matches regex @'rundll32([\s]+)([a-z0-9]{1,9})\.dll, rundll'     or ProcessCommandLine startswith 'Wevtutil.exe'
```

```KQL
DeviceProcessEvents | where (ProcessCommandLine in~ (@'net group "domain admins" /domain', @'net localgroup administrators'))
```

```KQL
DeviceProcessEvents | where ((ProcessCommandLine in~ (@'ipconfig /all', @'systeminfo')) and InitiatingProcessFolderPath endswith @'regsvr32.exe' and InitiatingProcessCommandLine contains @'.dll')
```

```KQL
DeviceProcessEvents | where (((FolderPath endswith @'\nltest.exe') or (ProcessVersionInfoOriginalFileName =~ @'nltestrk.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'nltestrk.exe')) and (((ProcessCommandLine contains @'/server' and ProcessCommandLine contains @'/query')) or ((ProcessCommandLine contains @'/dclist:' or ProcessCommandLine contains @'/parentdomain' or ProcessCommandLine contains @'/domain_trusts' or ProcessCommandLine contains @'/trusted_domains' or ProcessCommandLine contains @'/user'))))
```

```KQL
DeviceProcessEvents | where (((ProcessCommandLine contains @'--config ' and ProcessCommandLine contains @'--no-check-certificate ' and ProcessCommandLine contains @' copy ')) or (((ProcessCommandLine contains @'pass' or ProcessCommandLine contains @'user' or ProcessCommandLine contains @'copy' or ProcessCommandLine contains @'sync' or ProcessCommandLine contains @'config' or ProcessCommandLine contains @'lsd' or ProcessCommandLine contains @'remote' or ProcessCommandLine contains @'ls' or ProcessCommandLine contains @'mega' or ProcessCommandLine contains @'pcloud' or ProcessCommandLine contains @'ftp' or ProcessCommandLine contains @'ignore-existing' or ProcessCommandLine contains @'auto-confirm' or ProcessCommandLine contains @'transfers' or ProcessCommandLine contains @'multi-thread-streams' or ProcessCommandLine contains @'no-check-certificate ') and ((((ProcessVersionInfoFileDescription =~ @'Rsync for cloud storage') or (InitiatingProcessVersionInfoFileDescription =~ @'Rsync for cloud storage'))) or ((FolderPath endswith @'\rclone.exe' and (InitiatingProcessFolderPath endswith @'\PowerShell.exe' or InitiatingProcessFolderPath endswith @'\pwsh.exe' or InitiatingProcessFolderPath endswith @'\cmd.exe')))))))
```

```KQL
DeviceProcessEvents | where (((FolderPath endswith @'\powershell.exe' or FolderPath endswith @'\pwsh.exe') and (ProcessCommandLine contains @' -e ' or ProcessCommandLine contains @' -en ' or ProcessCommandLine contains @' -enc ' or ProcessCommandLine contains @' -enco') and (ProcessCommandLine contains @' JAB' or ProcessCommandLine contains @' SUVYI' or ProcessCommandLine contains @' SQBFAFgA' or ProcessCommandLine contains @' aWV4I' or ProcessCommandLine contains @' IAB' or ProcessCommandLine contains @' PAA' or ProcessCommandLine contains @' aQBlAHgA')) and not((InitiatingProcessFolderPath contains @'C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\' or InitiatingProcessFolderPath contains @'\gc_worker.exe')))
```

```KQL
Windows | where ((((FileName endswith @'\lsass.exe') or (FolderPath endswith @'\lsass.exe')) and (GrantedAccess contains @'0x1038' or GrantedAccess contains @'0x1438' or GrantedAccess contains @'0x143a') and (CallTrace contains @'dbghelp.dll' or CallTrace contains @'dbgcore.dll' or CallTrace contains @'ntdll.dll')) and not(((CallTrace contains @'|C:\Windows\Temp\asgard2-agent\' and CallTrace contains @'\thor\thor64.exe+' and CallTrace contains @'|UNKNOWN(' and GrantedAccess =~ @'0x103800')) or ((((InitiatingProcessFolderPath =~ @'C:\Windows\Sysmon64.exe') or (InitiatingProcessFileName =~ @'C:\Windows\Sysmon64.exe'))))))
```

```KQL
DeviceProcessEvents | where (((((FolderPath endswith @'\wmic.exe') or (ProcessVersionInfoOriginalFileName =~ @'wmic.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'wmic.exe')) and (ProcessCommandLine contains @'process' and ProcessCommandLine contains @'call' and ProcessCommandLine contains @'create '))) or ((((FolderPath endswith @'\wmic.exe') or (ProcessVersionInfoOriginalFileName =~ @'wmic.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'wmic.exe')) and (ProcessCommandLine contains @' path ' and (ProcessCommandLine contains @'AntiVirus' or ProcessCommandLine contains @'Firewall') and ProcessCommandLine contains @'Product' and ProcessCommandLine contains @' get ' and ProcessCommandLine contains @'wmic csproduct get name'))))
```
