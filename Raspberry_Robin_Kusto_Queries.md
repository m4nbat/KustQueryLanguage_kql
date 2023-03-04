# Raspberry Robin Hunts

# RaspeberryRobin detect msiexec.exe downloading and executing packages
`//RaspeberryRobin detect msiexec.exe downloading and executing packages
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (InitiatingProcessFileName  =~ "msiexec.exe" or FileName =~ "msiexec.exe")
| where ProcessCommandLine  has_any ("http:","https:") and (ProcessCommandLine contains '/q' or ProcessCommandLine contains '-q')`

# RaspeberryRobin detect a legitimate Windows utility, fodhelper.exe, which in turn spawns rundll32.exe to execute a malicious command.
`//RaspeberryRobin detect a legitimate Windows utility, fodhelper.exe, which in turn spawns rundll32.exe to execute a malicious command. Processes launched by fodhelper.exe run with elevated administrative privileges without requiring a User Account Control prompt. It is unusual for fodhelper.exe to spawn any processes as the parent, making this another useful detection opportunity.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where InitiatingProcessParentFileName  =~ "fodhelper.exe"
| project DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine`

# RaspeberryRobin Detect the Windows Open Database Connectivity utility loading a configuration file or DLL.
`//RaspeberryRobin Detect the Windows Open Database Connectivity utility loading a configuration file or DLL. The /A flag specifies an action, /F uses a response file, and /S runs in silent mode. Odbcconf.exe running rgsvr actions in silent mode could indicate misuse.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (FileName  =~ "odbcconf.exe" or InitiatingProcessFileName  =~ "odbcconf.exe") and (ProcessCommandLine contains "regsvr")
| where (ProcessCommandLine contains '/f' or ProcessCommandLine contains '-f' or ProcessCommandLine contains '/a' or ProcessCommandLine contains '-a' or ProcessCommandLine contains '/s' or ProcessCommandLine contains '-s')`

# RaspberryRobin detect network connections from the command line with no parameters
`//RaspberryRobin detect network connections from the command line with no parameters
// https://redcanary.com/blog/raspberry-robin/
DeviceNetworkEvents
| where RemoteIPType =~ "Public" and InitiatingProcessFileName in~ ("regsvr32.exe","rundll32","dllhost") and InitiatingProcessCommandLine =~ ""`
