# PsExec Process Creation (Metasploit / Impacket)

## Source: Cyborg / SIGMA

## 	T1569.002: System Services: Service Execution

## Sentinel

`DeviceProcessEvents
| where InitiatingProcessFileName has "services.exe"
| where FolderPath matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| project TimeGenerated, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by TimeGenerated`

`SecurityEvent
| where ParentProcessName has "services.exe"
| where NewProcessName matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| where EventID == "4688"
| project EventID, NewProcessName, CommandLine, Computer, ParentProcessName`

## MDE

`DeviceProcessEvents
| where InitiatingProcessFileName has "services.exe"
| where FolderPath matches regex "C:\\\\Windows\\\\[a-zA-Z]{8}.exe"
| project Timestamp, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by Timestamp`
