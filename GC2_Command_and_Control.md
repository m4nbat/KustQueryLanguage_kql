
# GC2

# Tactic: Comand and Contol

# Source: 

- https://github.com/looCiprian/GC2-sheet/
- https://www.youtube.com/watch?v=n2dFlSaBBKo

## MDE Kusto

```
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

## Sentinel Kusto

```
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


## Find files created by the process that created the suspicious connections

```
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceFileEvents
| where ActionType == "FileCreated" and InitiatingProcessFileName in~ (processComWithGoogleAPI)
```

## Find Processes and commandlines launched by the suspicious process communicating with Google API's

```
let excludedProcessFileNames = datatable (browser:string)["teams.exe","GoogleUpdate.exe","outlook.exe","msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more browsers or mail clients where needed for exclusion 
let processComWithGoogleAPI = DeviceNetworkEvents 
| where not(InitiatingProcessFileName has_any (excludedProcessFileNames))
| where RemoteUrl has_any ("oauth2.googleapis.com","sheets.googleapis.com","drive.googleapis.com","www.googleapis.com") and isnotempty(InitiatingProcessFileName)
| distinct InitiatingProcessFileName;
DeviceProcessEvents
| where FileName in~ (processComWithGoogleAPI) or InitiatingProcessFileName in~ (processComWithGoogleAPI) or InitiatingProcessParentFileName in~ (processComWithGoogleAPI)
```
