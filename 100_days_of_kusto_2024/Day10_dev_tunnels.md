UPDATE: Looks like MS released GPO controls finally: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/policies
This query is designed to detect suspicious network communications involving Visual Studio's DevTunnels feature, which is used for secure remote connections and debugging. The query specifically looks for network events where the destination URL ends with tunnels.api.visualstudio.com or devtunnels.ms. It excludes legitimate Visual Studio processes (ServiceHub.Host.dotnet.x64.dll or ServiceHub.Host.dotnet.arm64) to focus on potentially unauthorized or malicious activity. By monitoring these criteria, the query aims to identify unusual or suspicious use of DevTunnels that could indicate unauthorized remote access or data exfiltration.

DeviceNetworkEvents
| where RemoteUrl endswith "tunnels.api.visualstudio.com" or RemoteUrl endswith "devtunnels.ms" 
| where InitiatingProcessVersionInfoOriginalFileName != @"ServiceHub.Host.dotnet.x64.dll" 
| where InitiatingProcessVersionInfoFileDescription != @"ServiceHub.Host.dotnet.arm64"

This query is designed to detect suspicious file activities in folders named "DevTunnels," which are used in Visual Studio for secure remote connections. The goal is to identify potential unauthorized or malicious operations within these folders, which could indicate an attempt to establish or maintain unauthorized access to the system.

The query works by:

Monitoring file events (DeviceFileEvents) where the folder path includes "DevTunnels."
Excluding known legitimate software, specifically Dell Display Manager 2, to avoid false positives.
In simple terms, this query helps in identifying unusual file activities in "DevTunnels" folders, which might be used by attackers for malicious purposes, while ignoring activities from trusted software.

DeviceFileEvents
| where FolderPath has "DevTunnels" 
 //exclude Dell Display Manager  | where InitiatingProcessFileName != "DellDisplayManager.exe"

Device process events hunt query for VSCode DevTunells where the executable has been renamed.

DeviceProcessEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "electron.exe" and ProcessCommandLine has_all ("tunnel",".exe")
