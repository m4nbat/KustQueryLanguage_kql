# ProxyNotShell exploitation of Exchange servers
# Source: //https://redcanary.com/blog/intelligence-insights-january-2023/

//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
//https://redcanary.com/blog/intelligence-insights-january-2023/
DeviceProcessEvents
| where ((InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") or (InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine contains @"windows\temp")) and not(InitiatingProcessCommandLine has_any (trustedDlls) or ProcessCommandLine has_any (trustedDlls))

//Look for web shell files named iisstart.aspx and logout.aspx being written to inetpub\wwwroot\aspnet_client and exchange server\v15\frontend\httpproxy\ecp\auth
//https://redcanary.com/blog/intelligence-insights-january-2023/
DeviceFileEvents
| where ActionType =~ "FileCreated" and FileName has_any ("iisstart.exe","logout.aspx") and FolderPath has_any (@"inetpub\wwwroot\aspnet_client",@"server\v15\frontend\httpproxy\ecp\auth")

//Activity initiated from w3wp.exe with a command line containing MSExchangePowerShellAppPool. Based on Red Canary testing, the activity we saw, and other researchers’ observations, malicious activity spawning from a w3wp.exe process with this command line is an indicator of potential ProxyNotShell exploitation.
//https://redcanary.com/blog/intelligence-insights-january-2023/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe" and InitiatingProcessCommandLine contains "MSExchangePowerShellAppPool"

//We observed execution of Visual Basic Scripts (.vbs) from the windows\temp folder writing a malicious Meterpreter executable and subsequently making network connections. The executable’s internal file name, ab.exe, is the default metadata used by Meterpreter for its payloads.
//https://redcanary.com/blog/intelligence-insights-january-2023/
DeviceFileEvents
| where InitiatingProcessFileName endswith ".vbs" and InitiatingProcessFolderPath contains @"windows\temp" and FileName matches regex "[a-zA-Z]{2}\\.exe"
