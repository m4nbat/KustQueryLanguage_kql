# Scattered Spider RMM Tool Presence Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                                 | Link                                                         |
|--------------|---------------------------------------|--------------------------------------------------------------|
| T1219        | Remote Monitoring and Management Tools| [Remote Monitoring and Management Tools](https://attack.mitre.org/techniques/T1219/)|

#### Description
This detection rule is designed to identify the unauthorized presence of Remote Monitoring and Management (RMM) tools, which are often exploited by threat groups like Scattered Spider. The query searches for file paths and executables commonly associated with RMM tools, indicating potential misuse within the network.

#### Risk
The main risk addressed by this rule is the illicit use of RMM tools for unauthorized access, lateral movement, and persistence. These tools, while legitimate, can be weaponized by attackers to maintain control over compromised systems.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [CISA Advisory on Scattered Spider](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Microsoft Security Blog on Scattered Spider](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)

## Defender For Endpoint
```KQL
let RMMToolPaths = datatable(toolPath:string)[ "\\NinjaRMMAgentPatcher.exe", "\\NinjaRMMAgent\\NinjaRMMAgentPatcher.exe", "C:\\ProgramData\\NinjaRMMAgent\\ninjarmm-cli.exe", "\\NinjaRMMAgent.exe", "\\NinjaRMMAgent\\NinjaRMMAgent.exe", "\\ATERA Networks\\AteraAgent\\AteraAgent.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageNetworkDiscoveryWG\\AgentPackageNetworkDiscoveryWG.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageAgentInformation\\AgentPackageAgentInformation.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageSTRemote\\AgentPackageSTRemote.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageFileExplorer\\AgentPackageFileExplorer.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageMonitoring\\AgentPackageMonitoring.exe", "\\ATERA Networks\\AteraAgent\\Packages\\AgentPackageRuntimeInstaller\\AgentPackageRuntimeInstaller.exe", "C:\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\LogMeIn\\GoToAssist Corporate\\", "\\GoToMeeting\\", "\\AppData\\Local\\GoToMeeting\\", "\\AppData\\Local\\GoToMeeting\\", "\\GoToAssist Remote Support Customer\\", "\\GoToAssist Remote Support Customer\\", "\\AppData\\Local\\GoTo Resolve Applet\\", "\\GoToAssist Remote Support Unattended\\", "\\GoToAssist Remote Support Unattended\\", "\\AppData\\Local\\goto-updater\\pending\\GoToSetup-", "\\GoToMeeting\\", "\\AppData\\Local\\GoToAssist Remote Support Applet\\", "\\AppData\\Local\\GoToMeeting\\", "C:\\ManageEngine\\DesktopCentralMSP_Server\\jre\\bin\\java.exe", "C:\\ManageEngine\\ADManager Plus\\jre\\bin\\java.exe", "\\ManageEngine\\PMP\\tools\\archiver\\windows\\x86-64\\7za.exe", "C:\\ManageEngine\\elasticsearch\\jre\\bin\\java.exe", "\\ManageEngine\\PMP\\jre\\bin\\java.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\bin\\7za.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\bin\\wrapper.exe", "C:\\ManageEngine\\OpManager\\jre\\bin\\java.exe", "C:\\ManageEngine\\EventLog Analyzer\\jre\\bin\\java.exe", "C:\\ManageEngine\\ADAudit Plus\\pgsql\\bin\\postgres.exe", "C:\\ManageEngine\\OpManager\\Probe\\OpManagerProbe\\pgsql\\bin\\postgres.exe", "\\Microsoft Intune Management Extension\\ClientHealthEval.exe", "\\IntuneManagementExtensionBridge\\IntuneManagementExtensionBridge.exe", "\\BridgeLauncher\\BridgeLauncher.exe", "\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe", "\\Microsoft Intune Management Extension\\Microsoft.Management.Clients.CopyAgentCatalog.exe", "\\Microsoft Intune Management Extension\\SensorLogonTask.exe", "\\Microsoft Intune Management Extension\\AgentExecutor.exe", "\\AppData\\Local\\MSP Anywhere for N-central\\Viewer\\Tmp\\SWI_MSP_RC_ViewerUpdate-", "\\DesktopCentral_Agent\\bin\\dcagentservice.exe", "\\DesktopCentral_Agent\\bin\\DCFAService64.exe", "\\DesktopCentral_Agent\\bin\\dcagentregister.exe", "\\DesktopCentral_Server\\pgsql\\bin\\postgres.exe", "\\DesktopCentral_Server\\bin\\wrapper.exe", "C:\\ManageEngine\\DesktopCentral_Server\\bin\\wrapper.exe", "\\DesktopCentral_Server\\bin\\UEMS.exe", "\\DesktopCentral_Server\\nginx\\dcnginx.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Agent\\bin\\EMSAddonInstaller.exe", "C:\\ManageEngine\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Server\\apache\\bin\\dcserverhttpd.exe", "\\DesktopCentral_Server\\bin\\7za.exe", "\\DesktopCentral_Server\\jre\\bin\\java.exe", "\\DesktopCentral_Server\\bin\\dcnotificationserver.exe", "\\DesktopCentral_Agent\\dcconfig.exe", "\\DesktopCentral_Agent\\patches\\", "C:\\ManageEngine\\AssetExplorer\\DesktopCentral_Server\\bin\\wrapper.exe", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\wrapper.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\awt.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\sunec.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\freetype.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\jre\\bin\\fontmanager.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\SyMNative.dll", "\\ManageEngine\\ServiceDesk\\DesktopCentral_Server\\lib\\native\\64bit\\OSDSyMNative.dll", "C:\\Windows\\Action1\\action1_remote.exe", "C:\\Windows\\Action1\\action1_agent.exe"]; 
DeviceFileEvents 
| where FolderPath has_any (RMMToolPaths)
```

```KQL
## RMM File Certificate Hunt Query  
let RMMCertInfo = datatable(signer:string)['NinjaRMM, LLC',"Atera Networks Ltd","LogMeIn, Inc.","Action1 Corporation","add_more_in"]; 
DeviceFileCertificateInfo
| where Signer has_any (RMMCertInfo)   
```
