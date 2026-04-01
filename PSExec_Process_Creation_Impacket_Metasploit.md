# PsExec Process Creation via Metasploit/Impacket Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1569.002 | System Services: Service Execution | [Service Execution](https://attack.mitre.org/techniques/T1569/002/) |

#### Description
Detects the creation of random 8-character executable files in the Windows directory by services.exe, which is a common pattern used by Impacket and Metasploit PsExec-style lateral movement.

#### Risk
Impacket and Metasploit's PsExec implementation creates services that launch executables with random 8-character filenames in C:\Windows\. This pattern is used for lateral movement and is a strong indicator of malicious activity.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/SecureAuthCorp/impacket
- https://github.com/SigmaHQ/sigma

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName has "services.exe"
| where FolderPath matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| project Timestamp, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by Timestamp
```

## Sentinel
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName has "services.exe"
| where FolderPath matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| project TimeGenerated, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by TimeGenerated
```

```KQL
SecurityEvent
| where ParentProcessName has "services.exe"
| where NewProcessName matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| where EventID == "4688"
| project EventID, NewProcessName, CommandLine, Computer, ParentProcessName
```
