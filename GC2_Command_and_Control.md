
# GC2

# Tactic: Comand and Contol

```
//Processes interacting with Google Sheets (Has been known to be used for C2 communication) 
// https://github.com/looCiprian/GC2-sheet
//false positives - browsers going to the URL. Or a legitimate application that uses Google Sheets 
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let timeframe = 30d; //lookback period
DeviceNetworkEvents 
| where TimeGenerated > ago(timeframe)
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and RemoteUrl has_any ("docs.google.com","docs.google.com/spreadsheets/","drive.google.com") and isnotempty(InitiatingProcessFileName)
| summarize visitedURLs=make_set(RemoteUrl) by TenantId,
ActionType,
tostring(AdditionalFields),
AppGuardContainerId,
DeviceId,
DeviceName,
InitiatingProcessAccountDomain,
InitiatingProcessAccountName,
InitiatingProcessAccountObjectId,
InitiatingProcessAccountSid,
InitiatingProcessAccountUpn,
InitiatingProcessCommandLine,
InitiatingProcessFileName,
InitiatingProcessFolderPath,
InitiatingProcessId,
InitiatingProcessIntegrityLevel,
InitiatingProcessMD5,
InitiatingProcessParentFileName,
InitiatingProcessParentId,
InitiatingProcessSHA1,
InitiatingProcessSHA256,
InitiatingProcessTokenElevation,
InitiatingProcessFileSize,
InitiatingProcessVersionInfoCompanyName,
InitiatingProcessVersionInfoProductName,
InitiatingProcessVersionInfoProductVersion,
InitiatingProcessVersionInfoInternalFileName,
InitiatingProcessVersionInfoOriginalFileName,
InitiatingProcessVersionInfoFileDescription,
LocalIP,
LocalIPType,
LocalPort,
MachineGroup,
Protocol,
RemoteIP,
RemoteIPType,
RemotePort,
RemoteUrl,
ReportId,
InitiatingProcessParentCreationTime,
InitiatingProcessCreationTime,
SourceSystem,
Type
| where visitedURLs has_all ("docs.google.com","drive.google.com")
```
