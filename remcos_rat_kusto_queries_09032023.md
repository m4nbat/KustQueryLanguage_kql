# Remcos RAT Hunt Queries

**Source:** https://www.sentinelone.com/blog/dbatloader-and-remcos-rat-sweep-eastern-europe/

`//Addition of mock trusted directories to attempt to bypass user account control
//https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/
DeviceProcessEvents
| where ProcessCommandLine endswith @"mkdir \\?\C:\Windows " or ProcessCommandLine endswith @"mkdir \\?\C:\Windows \System32"`

`//Deletion of mock trusted directories as part of cleanup
DeviceProcessEvents
| where ProcessCommandLine has_all ("del","/q",@"C:\Windows \System32") or ProcessCommandLine has_all ('rmdir',@"C:\Windows \System32") or ProcessCommandLine has_all ('rmdir',@"C:\Windows \")` 

`//Detection of files created in the above folder possibly dropped by the DBATLoader
DeviceFileEvents
| where ActionType =~ "FileCreated" and FileName has_any (".bat",".exe",".dll") and (FolderPath startswith @"C:\Windows \System32" or FolderPath startswith @"C:\Windows \")`

`//Detection of PowerShell defese evasion via Micrososft Defender exclusions
DeviceProcessEvents
| where ProcessCommandLine has_all ("-WindowStyle","Hidden","-Command","Add-MpPreference","-ExclusionPath",@"C:\Users")` 

`// Hunt for registry run key being created for persistence when hunting for DBatLoader as part of Remcos RAT campaign
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey =~ @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"`
