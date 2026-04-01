# Scheduled Task Persistence from the Roaming Folder

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |

#### Description
Detects scheduled tasks executing from the Users AppData Roaming folder with no command-line arguments. Tasks executing from user-writable directories with no arguments are a common indicator of malicious persistence, as legitimate software rarely uses this pattern.

#### Risk
Malware frequently establishes persistence by registering scheduled tasks that execute payloads from writable user directories such as AppData\Roaming. This detection helps identify such tasks early in an investigation.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-february-2023/

## Defender For Endpoint
```KQL
//Scheduled task persistence from the roaming folder with no command-line arguments
//The following detection analytic looks for scheduled tasks executing from the Users folder. Tasks executing with no command-line arguments are more likely to be malicious. To reduce noise, you will likely need to create exceptions for any approved applications in your environment that have this behavior.
DeviceProcessEvents
| where FileName has_any ("taskeng.exe","svchost.exe") and FolderPath has_all ("users","appdata\\roaming") and isempty(ProcessCommandLine)
```
