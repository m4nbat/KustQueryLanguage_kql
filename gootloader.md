# Gootloader Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) |

#### Description
Detection queries for Gootloader malware execution. Covers wscript.exe spawning cscript.exe and PowerShell, Windows Script Host executing JScript from AppData, PowerShell .NET assembly reflective load, and rundll32 with no command-line arguments.

#### Risk
Gootloader is a sophisticated malware loader that spreads through SEO poisoning of legitimate websites. It delivers secondary payloads including Cobalt Strike and ransomware.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/gootloader/

## Defender For Endpoint
```KQL
**Detection opportunity: Windows Script Host (wscript.exe) executing content from a user’s AppData folder**
This detection opportunity identifies the Windows Script Host, wscript.exe, executing a JScript file from the user’s AppData folder. This works well to detect instances where a user has double-clicked into a Gootloader ZIP file and then double-clicked on the JScript script to execute it.

`DeviceProcessEvents
| where FileName =~ "wscript.exe" and ProcessCommandLine has_all ("appdata\\",".js")`

**Detection opportunity: PowerShell (powershell.exe) performing a reflective load of a .NET assembly**
This detection opportunity identifies PowerShell loading a .NET assembly into memory for execution using the System.Reflection capabilities of the .NET Framework. This detects PowerShell loading the .NET component of Gootloader and multiple additional threats in the wild.

`DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_all ("Reflection.Assembly","Load","byte[]")`

**Detection opportunity: Rundll32 (rundll32.exe) with no command-line arguments**
This detection opportunity identifies rundll32.exe executing with no command-line arguments as an injection target like we usually see for Cobalt Strike beacon injection. The beacon distributed by Gootloader in this instance used rundll32.exe, as do many other beacons found in the wild.
```

## Sentinel
```KQL
**Detection opportunity: Windows Script Host (wscript.exe) executing content from a user’s AppData folder**
This detection opportunity identifies the Windows Script Host, wscript.exe, executing a JScript file from the user’s AppData folder. This works well to detect instances where a user has double-clicked into a Gootloader ZIP file and then double-clicked on the JScript script to execute it.

`DeviceProcessEvents
| where FileName =~ "wscript.exe" and ProcessCommandLine has_all ("appdata\\",".js")`

**Detection opportunity: PowerShell (powershell.exe) performing a reflective load of a .NET assembly**
This detection opportunity identifies PowerShell loading a .NET assembly into memory for execution using the System.Reflection capabilities of the .NET Framework. This detects PowerShell loading the .NET component of Gootloader and multiple additional threats in the wild.

`DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_all ("Reflection.Assembly","Load","byte[]")`

**Detection opportunity: Rundll32 (rundll32.exe) with no command-line arguments**
This detection opportunity identifies rundll32.exe executing with no command-line arguments as an injection target like we usually see for Cobalt Strike beacon injection. The beacon distributed by Gootloader in this instance used rundll32.exe, as do many other beacons found in the wild.
```
