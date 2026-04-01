# Chrome Browser Unusual Child Process

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | [Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) |
| T1203 | Exploitation for Client Execution | [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/) |

#### Description
Detects unusual child processes spawned by the Chrome browser, which may indicate malicious browser extensions, exploitation of the browser process, or abuse of Chrome's native messaging capabilities. These queries identify cmd.exe and other suspicious processes launched from chrome.exe while excluding known-legitimate patterns.

#### Risk
Unusual child processes spawned by Chrome can indicate browser exploitation, malicious extensions executing system commands, or an attacker leveraging the browser process to execute arbitrary code. This activity warrants investigation to rule out compromise.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1059/003/

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
