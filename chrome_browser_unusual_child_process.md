# Chrome Browser Unusual Child Process Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

#### Description
Detects unusual child processes spawned by the Chrome browser, such as cmd.exe or PowerShell, which may indicate browser exploitation or malicious extension activity.

#### Risk
Browser exploitation or malicious extensions can cause the browser to spawn unusual child processes. Chrome spawning cmd.exe outside of known extension paths is a strong indicator of compromise.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1185/

## Defender For Endpoint
```KQL
//Spawning CMD exclude extension related activity
let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where FileName =~ "cmd.exe" and not (ProcessCommandLine has_any ("Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe","chrome-extension://mjhbkkaddmmnkghdnnmkjcgpphnopnfk/","chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/","chrome-extension://akfldeakecjegioiiajhpjpekomdjnmh/"))
| summarize count() by ProcessCommandLine
```

```KQL
let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where not (ProcessCommandLine has_any ("chrome-extension://","Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe"))
| summarize count() by InitiatingProcessFileName, FileName, FolderPath
| sort by count_ asc
```

## Sentinel
```KQL
//Spawning CMD exclude extension related activity
let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where FileName =~ "cmd.exe" and not (ProcessCommandLine has_any ("Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe","chrome-extension://mjhbkkaddmmnkghdnnmkjcgpphnopnfk/","chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/","chrome-extension://akfldeakecjegioiiajhpjpekomdjnmh/"))
| summarize count() by ProcessCommandLine
```

```KQL
let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where not (ProcessCommandLine has_any ("chrome-extension://","Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe"))
| summarize count() by InitiatingProcessFileName, FileName, FolderPath
| sort by count_ asc
```
