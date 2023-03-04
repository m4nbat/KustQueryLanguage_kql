# PowerShell creating LNK files within a startup directory

# Source: https://redcanary.com/blog/intelligence-insights-december-2022/

`//PowerShell creating LNK files within a startup directory
//The following detection analytic identifies PowerShell creating LNK files in a startup directory. Malware like Yellow Cockatoo can be introduced as a fake installer binary, resulting in malicious PowerShell script execution. Some benign homegrown utilities or installers may create .lnk files in startup locations, so additional investigation of the activity may be necessary.
//https://redcanary.com/blog/intelligence-insights-december-2022/
let trusedUtilsInstallingLnkInStartup = datatable (util:string)["mytrustedutility.exe"];
DeviceFileEvents
| where ActionType =~ "FileCreated" and InitiatingProcessFileName =~ "powershell.exe" and FolderPath contains @"start menu\programs\startup" and not(InitiatingProcessCommandLine has_any (trusedUtilsInstallingLnkInStartup))`
