# Red Canary 2023: Windows Management Instrumentation (WMI) Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1047 | Windows Management Instrumentation | [WMI](https://attack.mitre.org/techniques/T1047/) |

#### Description
Detection queries for malicious WMI usage based on Red Canary 2023 threat report. Covers suspicious process lineage, wmic.exe with suspicious commands, office products spawning WMI, WMI reconnaissance, shadow copy deletion, and PowerShell WMI cmdlets.

#### Risk
WMI is heavily abused by adversaries for execution, persistence, lateral movement, and reconnaissance. Detecting anomalous WMI activity is critical as it is used by many threat groups including ransomware operators.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/wmi/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse.exe" or InitiatingProcessFileName =~ "wmiprvse.exe"
| where InitiatingProcessFileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe") or FileName in~ FileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe")
```

```KQL
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe") and (ProcessCommandLine  has_any ("create", "node:", "process", "call") or  InitiatingProcessCommandLine has_any ("create", "node:", "process", "call"))
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe" or InitiatingProcessParentFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandline contains "format:" or ProcessCommandline contains "format:"
// work to be done to identify how to link module loads | where InitiatingProcessFileName in~ ("jscript.dll", "vbscript.dll") "wmic.exe" or FileName in~ ("jscript.dll", "vbscript.dll")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("winword.exe", "excel.exe") or InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandLine has_any ("\\ldap", "ntdomain") or ProcessCommandLine has_any ("\\ldap", "ntdomain")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandLine has_all ("shadowcopy", "delete") or ProcessCommandLine has_all ("shadowcopy", "delete")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_any ("invoke-wmimethod", "invoke-cimmethod", "get-wmiobject", "get-ciminstance", "wmiclass") or ProcessCommandLine has_any ("invoke-wmimethod", "invoke-cimmethod", "get-wmiobject", "get-ciminstance", "wmiclass")
```

## Sentinel
```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse.exe" or InitiatingProcessFileName =~ "wmiprvse.exe"
| where InitiatingProcessFileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe") or FileName in~ FileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe")
```

```KQL
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe") and (ProcessCommandLine  has_any ("create", "node:", "process", "call") or  InitiatingProcessCommandLine has_any ("create", "node:", "process", "call"))
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe" or InitiatingProcessParentFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandline contains "format:" or ProcessCommandline contains "format:"
// work to be done to identify how to link module loads | where InitiatingProcessFileName in~ ("jscript.dll", "vbscript.dll") "wmic.exe" or FileName in~ ("jscript.dll", "vbscript.dll")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("winword.exe", "excel.exe") or InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandLine has_any ("\\ldap", "ntdomain") or ProcessCommandLine has_any ("\\ldap", "ntdomain")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandLine has_all ("shadowcopy", "delete") or ProcessCommandLine has_all ("shadowcopy", "delete")
```

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_any ("invoke-wmimethod", "invoke-cimmethod", "get-wmiobject", "get-ciminstance", "wmiclass") or ProcessCommandLine has_any ("invoke-wmimethod", "invoke-cimmethod", "get-wmiobject", "get-ciminstance", "wmiclass")
```
