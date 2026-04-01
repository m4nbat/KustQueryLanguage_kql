# Red Canary 2023: Windows Command Shell Detection (T1059.003)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) |

#### Description
Detection queries for malicious Windows Command Shell (cmd.exe) usage based on Red Canary 2023 threat report. Covers cmd.exe spawned from mshta.exe/w3wp.exe, obfuscated command lines, scheduled task abuse, and Service Control Manager spawning cmd.exe.

#### Risk
Windows Command Shell is one of the most commonly abused techniques. Adversaries use cmd.exe for execution, persistence via scheduled tasks, and post-exploitation activity including web shell commands.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/windows-command-shell/

## Defender For Endpoint
```KQL
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "mshta.exe" or InitiatingProcessFileName endswith "mshta.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ActionType in~ ("FileCreated","FileModified")
```

```KQL
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe" or InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe"
| extend a = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','^')
| extend b = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','=')
| extend c = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','%')
| extend d = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','!')
| extend e = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','[')
| extend f = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','(')
| extend g = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt',';')
| extend suspiciousChars = a + b + c + d + e + f + g
| where suspiciousChars > 4
```

```KQL
let badCommands = datatable (command:string)[@"http://",@"https://","echo"];
DeviceProcessEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ((InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe") or (InitiatingProcessCommandLine has_any (badCommands) or ProcessCommandLine has_any (badCommands)))
```

```KQL
let exampleCommand = datatable(ProcessCommandLine:string,FileName:string)['schtasks /Create /SC DAILY /TN spawncmd /TR "cmd.exe /c echo tweet, tweet" /RU SYSTEM','schtasks.exe'];
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "create" and (ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "cmd /c")
```

```KQL
//Service Control Manager spawning Command Shell with suspect strings
//The following pseudo detector should generate an alert when services.exe spawns cmd.exe along with a corresponding echo or /c command, which are common attributes of post exploitation that we’ve seen in association with this technique.
//pseudocode: parent_process == 'services.exe' && process == 'cmd.exe'  && command_includes ('echo' || '/c') 
DeviceProcessEvents
| where InitiatingProcessFileName == "services.exe"
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "echo" or ProcessCommandLine contains "/c"
```

```KQL
//Windows Explorer spawning Command Shell with start and exit commands
//This detection analytic looks for instances of explorer.exe spawning cmd.exe along with corresponding start and exit commands that we commonly observe in conjunction with a wide variety of malicious activity.
// pseudocode: parent_process == 'explorer.exe' && process == 'cmd.exe' && command_includes ('start' && 'exit')
DeviceProcessEvents
| where InitiatingProcessFileName == "explorer.exe"
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "start" and ProcessCommandLine contains "exit"
```

## Sentinel
```KQL
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "mshta.exe" or InitiatingProcessFileName endswith "mshta.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ActionType in~ ("FileCreated","FileModified")
```

```KQL
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe" or InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe"
| extend a = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','^')
| extend b = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','=')
| extend c = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','%')
| extend d = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','!')
| extend e = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','[')
| extend f = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','(')
| extend g = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt',';')
| extend suspiciousChars = a + b + c + d + e + f + g
| where suspiciousChars > 4
```

```KQL
let badCommands = datatable (command:string)[@"http://",@"https://","echo"];
DeviceProcessEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ((InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe") or (InitiatingProcessCommandLine has_any (badCommands) or ProcessCommandLine has_any (badCommands)))
```

```KQL
let exampleCommand = datatable(ProcessCommandLine:string,FileName:string)['schtasks /Create /SC DAILY /TN spawncmd /TR "cmd.exe /c echo tweet, tweet" /RU SYSTEM','schtasks.exe'];
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "create" and (ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "cmd /c")
```

```KQL
//Service Control Manager spawning Command Shell with suspect strings
//The following pseudo detector should generate an alert when services.exe spawns cmd.exe along with a corresponding echo or /c command, which are common attributes of post exploitation that we’ve seen in association with this technique.
//pseudocode: parent_process == 'services.exe' && process == 'cmd.exe'  && command_includes ('echo' || '/c') 
DeviceProcessEvents
| where InitiatingProcessFileName == "services.exe"
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "echo" or ProcessCommandLine contains "/c"
```

```KQL
//Windows Explorer spawning Command Shell with start and exit commands
//This detection analytic looks for instances of explorer.exe spawning cmd.exe along with corresponding start and exit commands that we commonly observe in conjunction with a wide variety of malicious activity.
// pseudocode: parent_process == 'explorer.exe' && process == 'cmd.exe' && command_includes ('start' && 'exit')
DeviceProcessEvents
| where InitiatingProcessFileName == "explorer.exe"
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "start" and ProcessCommandLine contains "exit"
```
