# Red Canary 2023: Rundll32 Abuse Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | [Rundll32](https://attack.mitre.org/techniques/T1218/011/) |

#### Description
Detection queries for malicious rundll32.exe usage based on Red Canary 2023 threat report. Covers DllRegisterServer function execution, suspicious process lineage, and suspicious export function calls.

#### Risk
Rundll32 is heavily abused by threat actors including Qakbot, Ursnif, and Zloader for code execution and defense evasion. It allows execution of malicious DLLs through a signed Windows binary.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/rundll32/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where FileName =~ "rundll32.exe" and ProcessCommandLine contains "DllRegisterServer"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','msaccess.exe','lsass.exe','taskeng.exe','winlogon.exe','schtask.exe','regsvr32.exe','wmiprvse.exe','wsmprovhost.exe') and FileName =~ "rundll32.exe"
```

```KQL
let processEvents = DeviceProcessEvents
| where FileName == "rundll32.exe" and ProcessCommandLine has_any ("MiniDump","#24");
let moduleEvents = DeviceImageLoadEvents
| where FileName =~ "comsvcs.dll" and InitiatingProcessCommandLine has_any ("MiniDump","#24");
union isfuzzy=true processEvents,moduleEvents
```

```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" //and InitiatingProcessFileName =~ "lsass.exe"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe" and isempty(InitiatingProcessCommandLine)
```

```KQL
DeviceProcessEvents
| where FileName in ('rundll32.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)
```

```KQL
DeviceNetworkEvents 
| where InitiatingProcessFileName =~ "rundll32.exe" //regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command. 
| where InitiatingProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$" //regex to extract the commandline after the .exe 
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, InitiatingProcessCommandLine) 
| where isempty(CommandLineArgs)
```

## Sentinel
```KQL
DeviceProcessEvents
| where FileName =~ "rundll32.exe" and ProcessCommandLine contains "DllRegisterServer"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','msaccess.exe','lsass.exe','taskeng.exe','winlogon.exe','schtask.exe','regsvr32.exe','wmiprvse.exe','wsmprovhost.exe') and FileName =~ "rundll32.exe"
```

```KQL
let processEvents = DeviceProcessEvents
| where FileName == "rundll32.exe" and ProcessCommandLine has_any ("MiniDump","#24");
let moduleEvents = DeviceImageLoadEvents
| where FileName =~ "comsvcs.dll" and InitiatingProcessCommandLine has_any ("MiniDump","#24");
union isfuzzy=true processEvents,moduleEvents
```

```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" //and InitiatingProcessFileName =~ "lsass.exe"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe" and isempty(InitiatingProcessCommandLine)
```

```KQL
DeviceProcessEvents
| where FileName in ('rundll32.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)
```

```KQL
DeviceNetworkEvents 
| where InitiatingProcessFileName =~ "rundll32.exe" //regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command. 
| where InitiatingProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$" //regex to extract the commandline after the .exe 
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, InitiatingProcessCommandLine) 
| where isempty(CommandLineArgs)
```
