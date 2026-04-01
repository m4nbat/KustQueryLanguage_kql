# PowerShell Hunting Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

#### Description
A collection of hunting queries for suspicious PowerShell activity. These queries cover PowerShell processes creating external network connections followed by commands, PowerShell creating executable files, and PowerShell DLLs being loaded by non-PowerShell processes.

#### Risk
Adversaries frequently abuse PowerShell for execution, lateral movement, and C2 communication. These queries help detect anomalous PowerShell network activity, executable creation, and reflective/in-memory loading of PowerShell capabilities in non-standard processes.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- N/A

## Defender For Endpoint

### PowerShell creating external network connections followed by commands (may be noisy)
```KQL
DeviceNetworkEvents 
| where InitiatingProcessParentFileName != @"SenseIR.exe"
| where ActionType == 'ConnectionSuccess' 
| where InitiatingProcessFileName has_any ("pwsh.exe","powershell.exe")
| where RemoteUrl !contains "winatp-gw"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName,NetConTimestamp = Timestamp, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessId, InitiatingProcessParentFileName
| join kind= leftouter(
DeviceEvents
| where ActionType == 'PowerShellCommand' 
| project PsCommandTimestamp = Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessId, AdditionalFields, PSCommand=extractjson("$.Command", AdditionalFields, typeof(string))
) on InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessId, DeviceName
| join kind=leftouter(
DeviceProcessEvents
| project ChildProcessStartTime = Timestamp, ChildProcessName = FileName, ChildProcessSHA1 = SHA1, ChildProcessCommandline = ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessId, DeviceName
) on InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessId, DeviceName
| project DeviceName, NetConTimestamp, RemoteIP, RemoteUrl,InitiatingProcessParentFileName,InitiatingProcessFileName, InitiatingProcessCommandLine, PsCommandTimestamp, PSCommand, ChildProcessStartTime, ChildProcessName, ChildProcessSHA1, ChildProcessCommandline
```

### PowerShell creating .exe
```KQL
DeviceFileEvents 
| where InitiatingProcessParentFileName != @"SenseIR.exe"
| where InitiatingProcessFileName has_any ("pwsh.exe","powershell.exe")
| where ActionType == 'FileCreated' 
| where FileName endswith ".exe"
| project Timestamp, FileCreationTimestamp = Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA1, FileName, DeviceName
| join (
DeviceProcessEvents
| project DeviceName, SHA1, FileName, ProcessCreationTimestamp = Timestamp, ProcessCommandLine, FolderPath, ProcessCreationParentName = InitiatingProcessFileName, ProcessCreationParentCmdline = InitiatingProcessCommandLine, ProcessCreationParentFolderPath = InitiatingProcessFolderPath, ProcessCreationGrandParentName = InitiatingProcessParentFileName
) on FileName, SHA1, DeviceName
| project DeviceName, FileCreationTimestamp, FileName, SHA1, ProcessCreationTimestamp, FolderPath, ProcessCommandLine, ProcessCreationParentName, ProcessCreationParentCmdline, ProcessCreationParentFolderPath, ProcessCreationGrandParentName
```

### PowerShell DLLs being called by non-PowerShell processes
```KQL
DeviceImageLoadEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ("System.Management.Automation.Dll","System.Management.Automation.ni.Dll","System.Reflection.Dl") and ActionType =~ "ImageLoaded"
| where InitiatingProcessFolderPath !in~ (@"c:\windows\system32\windowspowershell\v1.0\powershell.exe",@"c:\windows\syswow64\windowspowershell\v1.0\powershell.exe",@"c:\program files\microsoft visual studio\2022\community\common7\ide\devenv.exe") and not (InitiatingProcessFileName =~ "mscorsvw.exe" and InitiatingProcessCommandLine has_all (@"mscorsvw.exe","-StartupEvent","-InterruptEvent","-NGENProcess","-Pipe","-Comment","NGen Worker Process")) and not (InitiatingProcessFolderPath startswith @"c:\program files\microsoft visual studio\" and InitiatingProcessFileName startswith "ServiceHub")
```
