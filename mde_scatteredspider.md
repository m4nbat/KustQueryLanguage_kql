# Title
Scattered Spider Hunt Queries

# Description


# Source


# MITRE ATT&CK


## RM Tool Presence

```
let RMMToolPaths = datatable(toolPath:string)[ "\\NinjaRMMAgentPatcher.exe", "\\NinjaRMMAgent\\NinjaRMMAgentPatcher.exe", "C:\\ProgramData\\NinjaRMMAgent\\ninjarmm-cli.exe", "\\NinjaRMMAgent.exe", "\\NinjaRMMAgent\\NinjaRMMAgent.exe", "\\ATERA Networks\\AteraAgent\\AteraAgent.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageNetworkDiscoveryWG\\AgentPackageNetworkDiscoveryWG.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageAgentInformation\\AgentPackageAgentInformation.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageSTRemote\\AgentPackageSTRemote.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageFileExplorer\\AgentPackageFileExplorer.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageMonitoring\\AgentPackageMonitoring.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageRuntimeInstaller\\AgentPackageRuntimeInstaller.exe", "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\LogMeIn\\GoToAssist Corporate\\", "\\GoToMeeting\\", "\\AppData\\Local\\GoToMeeting\\", "\\AppData\\Local\\GoToMeeting\\", "\\GoToAssist Remote Support Customer\\", "\\GoToAssist Remote Support Customer\\", "\\AppData\\Local\\GoTo Resolve Applet\\", "\\GoToAssist Remote Support Unattended\\", "\\GoToAssist Remote Support Unattended\\", "\\AppData\\Local\\goto-updater\\pending\\GoToSetup-", "\\GoToMeeting\\", "\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\AppData\\Local\\GoToMeeting\\", "C:\\ManageEngine\\DesktopCentralMSP_Server\\jre\\bin\\java.exe", "C:\\ManageEngine\\ADManager Plus\\jre\\bin\\java.exe", "\\ManageEngine\\PMP\\tools\\archiver\\windows\\x86-64\\7za.exe", "C:\\ManageEngine\\elasticsearch\\jre\\bin\\java.exe", "\\ManageEngine\\PMP\\jre\\bin\\java.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\bin\\7za.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\bin\\wrapper.exe", "C:\\ManageEngine\\OpManager\\jre\\bin\\java.exe", "C:\\ManageEngine\\EventLog Analyzer\\jre\\bin\\java.exe", "C:\\ManageEngine\\ADAudit Plus\\pgsql\\bin\\postgres.exe", "C:\\ManageEngine\\OpManager\\Probe\\OpManagerProbe\\pgsql\\bin\\postgres.exe", "\\Microsoft Intune Management Extension\\ClientHealthEval.exe", "\\IntuneManagementExtensionBridge\\IntuneManagementExtensionBridge.exe", "\\BridgeLauncher\\BridgeLauncher.exe", "\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe", "\\Microsoft Intune Management Extension\\Microsoft.Management.Clients.CopyAgentCatalog.exe", "\\Microsoft Intune Management Extension\\SensorLogonTask.exe", "\\Microsoft Intune Management Extension\\AgentExecutor.exe", "\\AppData\\Local\\MSP Anywhere for N-central\\Viewer\\Tmp\\SWI_MSP_RC_ViewerUpdate-", "\\DesktopCentral_Agent\\bin\\dcagentservice.exe", "\\DesktopCentral_Agent\\bin\\DCFAService64.exe", "\\DesktopCentral_Agent\\bin\\dcagentregister.exe", "\\DesktopCentral_Server\\pgsql\\bin\\postgres.exe", "\\DesktopCentral_Server\\bin\\wrapper.exe", "C:\\ManageEngine\\DesktopCentral_Server\\bin\\wrapper.exe", "\\DesktopCentral_Server\\bin\\UEMS.exe", "\\DesktopCentral_Server\\nginx\\dcnginx.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Agent\\bin\\EMSAddonInstaller.exe", "C:\\ManageEngine\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Server\\apache\\bin\\dcserverhttpd.exe", "\\DesktopCentral_Server\\bin\\7za.exe", "\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Server\\bin\\dcnotificationserver.exe", "\\DesktopCentral_Agent\\dcconfig.exe", "\\DesktopCentral_Agent\\patches\\", "C:\\ManageEngine\\AssetExplorer\\DesktopCentral_Server\\bin\\wrapper.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\wrapper.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\awt.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\sunec.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\freetype.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\fontmanager.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\SyMNative.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\OSDSyMNative.dll", "C:\\Windows\\Action1\\action1_remote.exe", "C:\\Windows\\Action1\\action1_agent.exe"]; DeviceFileEvents | where FolderPath has_any (RMMToolPaths)
```

## Exfiltration to known Scattered Spider Domains  

```
//Exfiltration to known Scattered Spider Domains  
let exfilDomains = dynamic(["transfer.sh", "Mega.nz", "riseup.net"]);  
DeviceNetworkEvents 
| where RemoteUrl in exfilDomains 
| summarize count() by DeviceName, Timestamp   
```

```
## RMM File Certificate Hunt Query  
let RMMCertInfo = datatable(signer:string)['NinjaRMM, LLC',"Atera Networks Ltd","LogMeIn, Inc.","Action1 Corporation","add_more_in"]; 
DeviceFileCertificateInfo
| where Signer has_any (RMMCertInfo)   
```


## Azure ARC Related Persistence  

```
//unexpected installation of azure arc agent - service installation
//https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview
//scattered spider have been known to register their own azure tenant and install azure arc agents on devices to maintain persistence
let ServiceNames = datatable(name:string)["himds.exe","gc_arc_service.exe","gc_extension_service.exe"];
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServiceAccount = tostring(parse_json(AdditionalFields).ServiceAccount)
| extend ServiceStartType = tostring(parse_json(AdditionalFields).ServiceStartType)
| extend ServiceType = tostring(parse_json(AdditionalFields).ServiceType)
| where ServiceName has_any (ServiceNames)
```


```
//unexpected installation of azure arc agent - filepaths
//https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview
//scattered spider have been known to register their own azure tenant and install azure arc agents on devices to maintain persistence
//if using azure arc then exclude hosts that should be managed by it
let AzureArcServicePaths = datatable(name:string)[@"\AzureConnectedMachineAgent\GCArcService\GC"];
DeviceFileEvents
| where ActionType =~ "FileCreated"
| where FolderPath  has_any (AzureArcServicePaths)
```

## Scattered Spider Defense Evasion via Conditional Access Policies

```
AuditLogs
| where OperationName =~ "Update conditional access policy" and TargetResources has_all ('locations','excludeLocations')
```

```
AuditLogs
| where OperationName =~ "Add named location" and TargetResources contains '"isTrusted":true' and AADOperationType == "Add" 
```
