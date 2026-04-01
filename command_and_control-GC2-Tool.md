# GC2 (Google Command and Control) C2 Tool Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.002 | Web Service: Bidirectional Communication | [Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) |

#### Description
Detects the use of the GC2 (Google Command and Control) red team tool that uses Google Sheets and Drive as C2 channels. Identifies non-browser processes communicating with Google APIs.

#### Risk
APT41 has been observed using GC2 to leverage Google infrastructure for C2, making detection difficult as traffic blends with legitimate Google usage.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/looCiprian/GC2-sheet/
- https://services.google.com/fh/files/blogs/gcat_threathorizons_full_apr2023.pdf

## Defender For Endpoint
```KQL
//Processes interacting with Google Sheets (Has been known to be used for C2 communication) 
// https://github.com/looCiprian/GC2-sheet
//false positives - browsers going to the URL. Or a legitimate application that uses Google Sheets 
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| summarize visitedURLs=make_list(RemoteUrl) by ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName
| project ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, visitedURLs, Connections=array_length(visitedURLs)
| where visitedURLs contains "oauth2.googleapis.com" and visitedURLs has_any ("sheets.googleapis.com","drive.googleapis.com") // may allow for higher fidelity as the GC2 go application communicates to both the google drive folder and sheets API.
```

```KQL
//Processes interacting with Google Sheets (Has been known to be used for C2 communication) 
// https://github.com/looCiprian/GC2-sheet
//false positives - browsers going to the URL. Or a legitimate application that uses Google Sheets 
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| summarize visitedURLs=make_list(RemoteUrl) by ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName
| project ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, visitedURLs, Connections=array_length(visitedURLs)
| where visitedURLs contains "oauth2.googleapis.com" and visitedURLs has_any ("sheets.googleapis.com","drive.googleapis.com") // may allow for higher fidelity as the GC2 go application communicates to both the google drive folder and sheets API.
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceFileEvents
| where ActionType == "FileCreated" and InitiatingProcessFileName in~ (processComWithGoogleAPI)
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceProcessEvents
| where FileName in~ (processComWithGoogleAPI) or InitiatingProcessFileName in~ (processComWithGoogleAPI) or InitiatingProcessParentFileName in~ (processComWithGoogleAPI)
```

## Sentinel
```KQL
//Processes interacting with Google Sheets (Has been known to be used for C2 communication) 
// https://github.com/looCiprian/GC2-sheet
//false positives - browsers going to the URL. Or a legitimate application that uses Google Sheets 
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| summarize visitedURLs=make_list(RemoteUrl) by ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName
| project ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, visitedURLs, Connections=array_length(visitedURLs)
| where visitedURLs contains "oauth2.googleapis.com" and visitedURLs has_any ("sheets.googleapis.com","drive.googleapis.com") // may allow for higher fidelity as the GC2 go application communicates to both the google drive folder and sheets API.
```

```KQL
//Processes interacting with Google Sheets (Has been known to be used for C2 communication) 
// https://github.com/looCiprian/GC2-sheet
//false positives - browsers going to the URL. Or a legitimate application that uses Google Sheets 
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| summarize visitedURLs=make_list(RemoteUrl) by ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName
| project ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, visitedURLs, Connections=array_length(visitedURLs)
| where visitedURLs contains "oauth2.googleapis.com" and visitedURLs has_any ("sheets.googleapis.com","drive.googleapis.com") // may allow for higher fidelity as the GC2 go application communicates to both the google drive folder and sheets API.
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceFileEvents
| where ActionType == "FileCreated" and InitiatingProcessFileName in~ (processComWithGoogleAPI)
```

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceProcessEvents
| where FileName in~ (processComWithGoogleAPI) or InitiatingProcessFileName in~ (processComWithGoogleAPI) or InitiatingProcessParentFileName in~ (processComWithGoogleAPI)
```
