# Red Canary 2023: Process Injection Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1055 | Process Injection | [Process Injection](https://attack.mitre.org/techniques/T1055/) |

#### Description
Detection queries based on the Red Canary 2023 threat report for process injection. Covers PowerShell injecting into processes, processes executing without command lines, unusual network connections from trusted processes, and LSASS injection.

#### Risk
Process injection is one of the most versatile adversary techniques, enabling code execution in trusted processes, privilege escalation, and defense evasion. It is heavily used by post-exploitation frameworks like Cobalt Strike.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/process-injection/

## Defender For Endpoint
```KQL
let exclusions = datatable (processFileName:string,processFolderPath:string)["MsMpEng.exe",@"C:\ProgramData\Microsoft\Windows Defender\Platform\","MsSense.exe",@"C:\Program Files\Windows Defender Advanced Threat Protection"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and FileName =~ "powershell.exe"
| where InitiatingProcessFileName !in~ (exclusions) and InitiatingProcessFolderPath !in~ (exclusions)
```

```KQL
DeviceProcessEvents
| where FileName in ('backgroundtaskhost.exe', 'svchost.exe', 'dllhost.exe', 'werfault.exe', 'searchprotocolhost.exe', 'wuauclt.exe', 'spoolsv.exe', 'rundll32.exe', 'regasm.exe', 'regsvr32.exe', 'regsvcs.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)
```

```KQL
let FileNames = datatable(name:string)["notepad.exe","calc.exe"];
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (FileNames)
```

```KQL
let exclusions = datatable (processFileName:string,processFolderPath:string)["healthservice.exe",@"C:\Program Files\Microsoft Monitoring Agent\Agent",
"MsMpEng.exe",@"C:\ProgramData\Microsoft\Windows Defender\Platform\","MsSense.exe",@"C:\Program Files\Windows Defender Advanced Threat Protection"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and FileName =~ "lsass.exe" and (InitiatingProcessFileName !in~ (exclusions) and InitiatingProcessFolderPath !in~ (exclusions))
```

```KQL
DeviceProcessEvents
| where InitiatingProcessCommandLine has_all ("procdump", "lsass") or InitiatingProcessCommandLine has_all ("rundll32", "comsvcs", "MiniDump")
```

```KQL
let lolbins = datatable (file:string)["rundll32.exe","MSbuild.exe","PowerShell.exe","Wscript.exe","Cscript.exe","Msiexec.exe","Rundll32"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and InitiatingProcessFileName in~ (lolbins)
```

## Sentinel
```KQL
let exclusions = datatable (processFileName:string,processFolderPath:string)["MsMpEng.exe",@"C:\ProgramData\Microsoft\Windows Defender\Platform\","MsSense.exe",@"C:\Program Files\Windows Defender Advanced Threat Protection"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and FileName =~ "powershell.exe"
| where InitiatingProcessFileName !in~ (exclusions) and InitiatingProcessFolderPath !in~ (exclusions)
```

```KQL
DeviceProcessEvents
| where FileName in ('backgroundtaskhost.exe', 'svchost.exe', 'dllhost.exe', 'werfault.exe', 'searchprotocolhost.exe', 'wuauclt.exe', 'spoolsv.exe', 'rundll32.exe', 'regasm.exe', 'regsvr32.exe', 'regsvcs.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)
```

```KQL
let FileNames = datatable(name:string)["notepad.exe","calc.exe"];
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (FileNames)
```

```KQL
let exclusions = datatable (processFileName:string,processFolderPath:string)["healthservice.exe",@"C:\Program Files\Microsoft Monitoring Agent\Agent",
"MsMpEng.exe",@"C:\ProgramData\Microsoft\Windows Defender\Platform\","MsSense.exe",@"C:\Program Files\Windows Defender Advanced Threat Protection"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and FileName =~ "lsass.exe" and (InitiatingProcessFileName !in~ (exclusions) and InitiatingProcessFolderPath !in~ (exclusions))
```

```KQL
DeviceProcessEvents
| where InitiatingProcessCommandLine has_all ("procdump", "lsass") or InitiatingProcessCommandLine has_all ("rundll32", "comsvcs", "MiniDump")
```

```KQL
let lolbins = datatable (file:string)["rundll32.exe","MSbuild.exe","PowerShell.exe","Wscript.exe","Cscript.exe","Msiexec.exe","Rundll32"];
DeviceEvents
| where ActionType =~ "ReadProcessMemoryApiCall" and InitiatingProcessFileName in~ (lolbins)
```
