//Loading Latrodectus DLLs
The following query looks for evidence of rundll32 loading the Latrodectus DLL. Run query

//DeviceProcessEvents
| where InitiatingProcessCommandLine has_any("capisp.dll", "aclui.dll") and InitiatingProcessFileName in ("rundll32.exe", "msiexec.exe")
Latrodectus MSI and DLL files

//This query identifies newly created (dropped) Latrodectus MSI and DLL files. Run query
DeviceFileEvents
| where FolderPath has_any ("Roaming\\aclui", "Roaming\\capisp", "temp\vpn.msi", "neuro.msi", "bst.msi") and InitiatingProcessCommandLine has_any("msiexec", "rundll32")
Latrodectus DLL persistence

//The following query looks for evidence of Latrodectus DLL persistence using the startup registry key. Run query 
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"CurrentVersion\Run"
| where RegistryValueData has_any(@"AppData\Roaming\capisp.dll", @"AppData\Roaming\aclui.dll")
| where InitiatingProcessFileName == "rundll32.exe"
