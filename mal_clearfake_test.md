
DeviceEvents
| where ActionType =~ "OtherAlertRelatedActivity"
| sort by TimeGenerated desc
 
DeviceEvents
| where ActionType =~ "ExploitGuardAcgEnforced"
| sort by TimeGenerated desc
 
DeviceFileEvents
| where FolderPath endswith @"\VFS\AppData\KSPSService.exe" and FileName =~ "KSPSService.exe"
 
DeviceFileEvents
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe" and FileName endswith "exe"

DeviceEvents
| where ActionType contains "ServiceInstalled"
| extend ServiceAccount_ = tostring(AdditionalFields.ServiceAccount)
| extend ServiceName_ = tostring(AdditionalFields.ServiceName)
| extend ServiceStartType_ = tostring(AdditionalFields.ServiceStartType)
| extend ServiceType_ = tostring(AdditionalFields.ServiceType)
| where FolderPath matches regex @"\\VFS\\AppData\\[a-zA-Z0-9]+.exe" //and ServiceName_ =~ "KSPSService.exe"
