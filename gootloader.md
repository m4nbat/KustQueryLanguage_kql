# Gootloader Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

#### Description
Hunt queries to detect Gootloader activity. Gootloader is a JScript-based malware loader that uses Windows Script Host (wscript.exe) to execute JScript from user AppData directories. It spawns cscript.exe and PowerShell for follow-on activity, including reflective .NET assembly loading and Cobalt Strike beacon injection via rundll32.exe.

#### Risk
Gootloader infections lead to deployment of secondary payloads like Cobalt Strike, enabling attackers to establish persistence, move laterally, and deploy ransomware. Detecting the process execution chain (wscript → cscript → PowerShell) and reflective assembly loading provides early warning of compromise.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://redcanary.com/blog/gootloader/

## Defender For Endpoint

**New detection opportunity: wscript.exe spawning cscript.exe and PowerShell**
This detection opportunity identifies the chain of process executions—whereby wscript.exe spawns cscript.exe and cscript.exe spawns powershell.exe—described in the Execution section that we updated on November 18, 2022.

```KQL
// looking for gootloader process execution pattern
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") and FileName in~ ("cscript.exe","powershell.exe","cmd.exe")
```

```KQL
//looking for the typical gootloader process execution pattern
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wscript.exe" and InitiatingProcessFileName =~ "cscript.exe" and FileName in~ ("powershell.exe")
```

```KQL
//can be used to look at process ancestry in defender
DeviceProcessEvents
| project InitiatingProcessParentFileName, InitiatingProcessFileName, FileName
| summarize count() by InitiatingProcessParentFileName, InitiatingProcessFileName, FileName
```

**Detection opportunity: Windows Script Host (wscript.exe) executing content from a user's AppData folder**
This detection opportunity identifies the Windows Script Host, wscript.exe, executing a JScript file from the user's AppData folder. This works well to detect instances where a user has double-clicked into a Gootloader ZIP file and then double-clicked on the JScript script to execute it.

```KQL
DeviceProcessEvents
| where FileName =~ "wscript.exe" and ProcessCommandLine has_all ("appdata\\",".js")
```

**Detection opportunity: PowerShell (powershell.exe) performing a reflective load of a .NET assembly**
This detection opportunity identifies PowerShell loading a .NET assembly into memory for execution using the System.Reflection capabilities of the .NET Framework. This detects PowerShell loading the .NET component of Gootloader and multiple additional threats in the wild.

```KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_all ("Reflection.Assembly","Load","byte[]")
```

**Detection opportunity: Rundll32 (rundll32.exe) with no command-line arguments**
This detection opportunity identifies rundll32.exe executing with no command-line arguments as an injection target like we usually see for Cobalt Strike beacon injection. The beacon distributed by Gootloader in this instance used rundll32.exe, as do many other beacons found in the wild.

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe" and isempty(InitiatingProcessCommandLine)
| join DeviceNetworkEvents on InitiatingProcessFileName
| where isnotempty(RemoteUrl)
```
