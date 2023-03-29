
## PowerShell creating external network connections followed by commands (may be noisy)

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

## Powershell creating .exe

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
