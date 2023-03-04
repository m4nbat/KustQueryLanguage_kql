Chrome Unusual Child Process

`//Spawning CMD exclude extension related activity
let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where FileName =~ "cmd.exe" and not (ProcessCommandLine has_any ("Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe","chrome-extension://mjhbkkaddmmnkghdnnmkjcgpphnopnfk/","chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/","chrome-extension://akfldeakecjegioiiajhpjpekomdjnmh/"))
| summarize count() by ProcessCommandLine`

`let exclusions = datatable (filename:string)["software_reporter_tool.exe"];
DeviceProcessEvents
| where InitiatingProcessFileName endswith "chrome.exe"
| where FileName !in~ (exclusions)
| where not (ProcessCommandLine has_any ("chrome-extension://","Microsoft.SharePoint.NativeMessagingClient.exe","C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe","C:\\Windows\\BrowserCore\\BrowserCore.exe"))
| summarize count() by InitiatingProcessFileName, FileName, FolderPath
| sort by count_ asc`
