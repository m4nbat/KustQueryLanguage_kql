# Raspberry Robin Worm Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.007 | Signed Binary Proxy Execution: Msiexec | [Msiexec](https://attack.mitre.org/techniques/T1218/007/) |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | [Bypass UAC](https://attack.mitre.org/techniques/T1548/002/) |
| T1218 | Signed Binary Proxy Execution | [Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |

#### Description
Detects Raspberry Robin worm activity including msiexec downloading and executing MSI packages, fodhelper.exe spawning rundll32.exe for UAC bypass, odbcconf.exe loading DLLs/configs, and network connections from signed binaries without command-line arguments.

#### Risk
Raspberry Robin is a sophisticated worm that spreads via USB drives and uses legitimate Windows utilities for execution. It has been observed dropping various malware families including FakeUpdates, IcedID, and Bumblebee.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/raspberry-robin/

## Defender For Endpoint
```KQL
//RaspeberryRobin detect msiexec.exe downloading and executing packages
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (InitiatingProcessFileName  =~ "msiexec.exe" or FileName =~ "msiexec.exe")
| where ProcessCommandLine  has_any ("http:","https:") and (ProcessCommandLine contains '/q' or ProcessCommandLine contains '-q')
```

```KQL
//RaspeberryRobin detect a legitimate Windows utility, fodhelper.exe, which in turn spawns rundll32.exe to execute a malicious command. Processes launched by fodhelper.exe run with elevated administrative privileges without requiring a User Account Control prompt. It is unusual for fodhelper.exe to spawn any processes as the parent, making this another useful detection opportunity.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where InitiatingProcessParentFileName  =~ "fodhelper.exe"
| project DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

```KQL
//RaspeberryRobin Detect the Windows Open Database Connectivity utility loading a configuration file or DLL. The /A flag specifies an action, /F uses a response file, and /S runs in silent mode. Odbcconf.exe running rgsvr actions in silent mode could indicate misuse.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (FileName  =~ "odbcconf.exe" or InitiatingProcessFileName  =~ "odbcconf.exe") and (ProcessCommandLine contains "regsvr")
| where (ProcessCommandLine contains '/f' or ProcessCommandLine contains '-f' or ProcessCommandLine contains '/a' or ProcessCommandLine contains '-a' or ProcessCommandLine contains '/s' or ProcessCommandLine contains '-s')
```

```KQL
//RaspberryRobin detect network connections from the command line with no parameters
// https://redcanary.com/blog/raspberry-robin/
DeviceNetworkEvents
| where RemoteIPType =~ "Public" and InitiatingProcessFileName in~ ("regsvr32.exe","rundll32","dllhost") and InitiatingProcessCommandLine =~ ""
```

## Sentinel
```KQL
//RaspeberryRobin detect msiexec.exe downloading and executing packages
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (InitiatingProcessFileName  =~ "msiexec.exe" or FileName =~ "msiexec.exe")
| where ProcessCommandLine  has_any ("http:","https:") and (ProcessCommandLine contains '/q' or ProcessCommandLine contains '-q')
```

```KQL
//RaspeberryRobin detect a legitimate Windows utility, fodhelper.exe, which in turn spawns rundll32.exe to execute a malicious command. Processes launched by fodhelper.exe run with elevated administrative privileges without requiring a User Account Control prompt. It is unusual for fodhelper.exe to spawn any processes as the parent, making this another useful detection opportunity.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where InitiatingProcessParentFileName  =~ "fodhelper.exe"
| project DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

```KQL
//RaspeberryRobin Detect the Windows Open Database Connectivity utility loading a configuration file or DLL. The /A flag specifies an action, /F uses a response file, and /S runs in silent mode. Odbcconf.exe running rgsvr actions in silent mode could indicate misuse.
// https://redcanary.com/blog/raspberry-robin/
DeviceProcessEvents
| where (FileName  =~ "odbcconf.exe" or InitiatingProcessFileName  =~ "odbcconf.exe") and (ProcessCommandLine contains "regsvr")
| where (ProcessCommandLine contains '/f' or ProcessCommandLine contains '-f' or ProcessCommandLine contains '/a' or ProcessCommandLine contains '-a' or ProcessCommandLine contains '/s' or ProcessCommandLine contains '-s')
```

```KQL
//RaspberryRobin detect network connections from the command line with no parameters
// https://redcanary.com/blog/raspberry-robin/
DeviceNetworkEvents
| where RemoteIPType =~ "Public" and InitiatingProcessFileName in~ ("regsvr32.exe","rundll32","dllhost") and InitiatingProcessCommandLine =~ ""
```
