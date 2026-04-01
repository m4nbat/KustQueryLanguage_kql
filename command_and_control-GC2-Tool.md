# GC2 Experimental Detection - Hosts Communicating With Possible C2 Server Using the GC2 Framework

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.002 | Web Service: Bidirectional Communication | [Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) |

#### Description
Detects non-browser processes communicating with Google APIs (OAuth2, Sheets, Drive) that may indicate use of the GC2 (Google Command & Control) framework. GC2 is an open-source red team tool that abuses Google Sheets for command retrieval and Google Drive for file exfiltration.

#### Risk
Attackers leveraging the GC2 framework establish covert C2 channels using Google Sheets and Drive APIs, bypassing network-level controls that trust Google infrastructure. This was observed being used by APT41. A process communicating with both oauth2.googleapis.com and sheets/drive APIs is a strong indicator of GC2 use.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://github.com/looCiprian/GC2-sheet
- https://www.youtube.com/watch?v=n2dFlSaBBKo
- https://services.google.com/fh/files/blogs/gcat_threathorizons_full_apr2023.pdf
- https://www.tanium.com/blog/apt41-deploys-google-gc2-for-attacks-cyber-threat-intelligence-roundup/
- https://www.bleepingcomputer.com/news/security/hackers-abuse-google-command-and-control-red-team-tool-in-attacks/

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

### Find files created by the process that created the suspicious connections

```KQL
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceFileEvents
| where ActionType == "FileCreated" and InitiatingProcessFileName in~ (processComWithGoogleAPI)
```

### Find Processes and commandlines launched by the suspicious process communicating with Google API's

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
