# Paste Site Activity Detection via PowerShell and Network Connections

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| T1567 | Exfiltration Over Web Service | [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) |

#### Description
Detects network connections and PowerShell download activity targeting paste sites (e.g., pastebin.com). Uses an external list of known paste sites to identify potential malware downloading or data exfiltration.

#### Risk
Adversaries commonly use paste sites to host malicious payloads or commands that are downloaded and executed via PowerShell. This technique is used by many malware families for second-stage payload delivery.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://gist.github.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1

## Defender For Endpoint
```KQL
// Detect network connections to paste sites
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceNetworkEvents
| where InitiatingProcessFileName endswith "powershell.exe" and RemoteUrl has_any (pasteSites) or (RemoteUrl endswith ".onion" or RemoteUrl contains "paste.")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileSize, InitiatingProcessSHA256
| order by Timestamp
```

```KQL
//Detect pastebin downloads via PowerShell
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceProcessEvents
| where FileName has "powershell.exe"
| where ProcessCommandLine contains "http" 
| where ProcessCommandLine has_any (pasteSites) or  ProcessCommandLine contains ".onion" or ProcessCommandLine contains "paste."
| project Timestamp, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by Timestamp
```

## Sentinel
```KQL
// Detect network connections to paste sites
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceNetworkEvents
| where InitiatingProcessFileName endswith "powershell.exe" and RemoteUrl has_any (pasteSites) or (RemoteUrl endswith ".onion" or RemoteUrl contains "paste.")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileSize, InitiatingProcessSHA256
| order by TimeGenerated
```

```KQL
//Detect pastebin downloads via PowerShell
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceProcessEvents
| where FileName has "powershell.exe"
| where ProcessCommandLine contains "http" 
| where ProcessCommandLine has_any (pasteSites) or  ProcessCommandLine contains ".onion" or ProcessCommandLine contains "paste."
| project TimeGenerated, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by TimeGenerated
```

```KQL
SecurityEvent
| where Process  has "powershell.exe"
| where CommandLine contains "http"
| where ProcessCommandLine has_any (pasteSites) or  ProcessCommandLine contains ".onion" or ProcessCommandLine contains "paste."
| project TimeGenerated, Computer, tostring(EventID), ParentProcessName, NewProcessName, CommandLine, SubjectUserName, SourceComputerId, processID=tolong(NewProcessId), parentProcessID=tolong(ProcessId), EventData| order by TimeGenerated
```
