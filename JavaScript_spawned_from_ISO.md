# JavaScript Files Executing from Optical Disc Image (ISO)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | [MOTW Bypass](https://attack.mitre.org/techniques/T1553/005/) |

#### Description
Detects JavaScript (.js) files executing from drives other than the default C:\ drive, which is a common indicator of malware delivered via ISO files (such as Qakbot). It is rare for .js files to execute from non-default drives.

#### Risk
Malware such as Qakbot can be introduced through ISO files containing malicious .js scripts. This method bypasses MOTW protections and is a common initial access technique.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-november-2022/

## Defender For Endpoint
```KQL
//Detection opportunity: JavaScript .js files executing from optical disc image ISOs
//The following detection analytic identifies .js files executing from drives other than the default C:\ drive. Malware such as Qbot can be introduced through ISOs that contain malicious .js files. It is rare for .js files to execute from a drive other than the default drive. Since this may occur legitimately if the endpoint’s main partition is not on C:\: additional review may be needed to determine if this is malicious behavior.
// https://redcanary.com/blog/intelligence-insights-november-2022/
DeviceProcessEvents
| where FolderPath !startswith "c:" and FolderPath !startswith "/" and InitiatingProcessFolderPath !startswith "c:" and InitiatingProcessFolderPath !startswith "/" and FolderPath !startswith "\\\\" and InitiatingProcessFolderPath !startswith "\\\\" and isnotempty(InitiatingProcessFolderPath) and isnotempty(FolderPath) and FileName endswith ".js"
```

## Sentinel
```KQL
//Detection opportunity: JavaScript .js files executing from optical disc image ISOs
//The following detection analytic identifies .js files executing from drives other than the default C:\ drive. Malware such as Qbot can be introduced through ISOs that contain malicious .js files. It is rare for .js files to execute from a drive other than the default drive. Since this may occur legitimately if the endpoint’s main partition is not on C:\: additional review may be needed to determine if this is malicious behavior.
// https://redcanary.com/blog/intelligence-insights-november-2022/
DeviceProcessEvents
| where FolderPath !startswith "c:" and FolderPath !startswith "/" and InitiatingProcessFolderPath !startswith "c:" and InitiatingProcessFolderPath !startswith "/" and FolderPath !startswith "\\\\" and InitiatingProcessFolderPath !startswith "\\\\" and isnotempty(InitiatingProcessFolderPath) and isnotempty(FolderPath) and FileName endswith ".js"
```
