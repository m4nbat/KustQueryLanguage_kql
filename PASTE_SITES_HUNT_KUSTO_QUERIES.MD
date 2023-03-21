# Detect paste sites activity via powershell or network connections

### Sentinel

`// Detect network connections to paste sites
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceNetworkEvents
| where InitiatingProcessFileName endswith "powershell.exe" and RemoteUrl has_any (pasteSites) or (RemoteUrl endswith ".onion" or RemoteUrl contains "paste.")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileSize, InitiatingProcessSHA256
| order by TimeGenerated`

`//Detect pastebin downloads via PowerShell
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceProcessEvents
| where FileName has "powershell.exe"
| where ProcessCommandLine contains "http" 
| where ProcessCommandLine has_any (pasteSites) or  ProcessCommandLine contains ".onion" or ProcessCommandLine contains "paste."
| project TimeGenerated, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by TimeGenerated`


### MDE

`// Detect network connections to paste sites
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceNetworkEvents
| where InitiatingProcessFileName endswith "powershell.exe" and RemoteUrl has_any (pasteSites) or (RemoteUrl endswith ".onion" or RemoteUrl contains "paste.")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileSize, InitiatingProcessSHA256
| order by Timestamp`

`//Detect pastebin downloads via PowerShell
let pasteSites = externaldata(site:string)
[h@"https://gist.githubusercontent.com/m4nbat/519718259e6f3e0de80e393c02bf1aa1/raw/6cec351e8dcdf1982040f40f72080658a161a5b1/pastebin_sites.txt"]
with(format="txt",ignoreFirstRecord=false);
DeviceProcessEvents
| where FileName has "powershell.exe"
| where ProcessCommandLine contains "http" 
| where ProcessCommandLine has_any (pasteSites) or  ProcessCommandLine contains ".onion" or ProcessCommandLine contains "paste."
| project Timestamp, DeviceName, ActionType, AccountName, AccountDomain, FileName, FolderPath, ProcessId, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessAccountDomain, InitiatingProcessAccountName, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoProductVersion, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoFileDescription, FileSize, SHA256
| order by Timestamp`
