# ProxyNotShell Exploitation of Exchange Servers

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190 | Exploit Public-Facing Application | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| T1505.003 | Server Software Component: Web Shell | [Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | [Visual Basic](https://attack.mitre.org/techniques/T1059/005/) |

#### Description
Detection queries for ProxyNotShell (CVE-2022-41040 / CVE-2022-41082) exploitation of Microsoft Exchange servers. Covers rundll32 loading DLLs from Windows Temp, web shell file creation in Exchange paths, activity spawned from w3wp.exe with MSExchangePowerShellAppPool, and VBScript dropping and executing Meterpreter payloads from Temp directories.

#### Risk
ProxyNotShell exploitation allows unauthenticated remote code execution on on-premises Exchange servers, enabling attackers to deploy web shells, execute arbitrary commands, and establish persistent access to corporate email infrastructure.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-january-2023/

## Defender For Endpoint

### Rundll32 executing DLL files located in the Windows Temp directory
```KQL
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where ((InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") or (InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine contains @"windows\temp")) and not(InitiatingProcessCommandLine has_any (trustedDlls) or ProcessCommandLine has_any (trustedDlls))
```

### Web shell files named iisstart.aspx and logout.aspx written to Exchange paths
```KQL
DeviceFileEvents
| where ActionType =~ "FileCreated" and FileName has_any ("iisstart.exe","logout.aspx") and FolderPath has_any (@"inetpub\wwwroot\aspnet_client",@"server\v15\frontend\httpproxy\ecp\auth")
```

### Activity initiated from w3wp.exe with MSExchangePowerShellAppPool command line
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe" and InitiatingProcessCommandLine contains "MSExchangePowerShellAppPool"
```

### VBScript from Windows Temp folder writing and executing Meterpreter payload
```KQL
DeviceFileEvents
| where InitiatingProcessFileName endswith ".vbs" and InitiatingProcessFolderPath contains @"windows\temp" and FileName matches regex "[a-zA-Z]{2}\\.exe"
```
