# SNAKE Malware Service Persistence

## Query Information

#### MITRE ATT&CK Tactic(s)

| Tactic ID | Title    | Link    |
| ---  | --- | --- |
| TA0003 | Persistence | [Persistence](https://attack.mitre.org/tactics/TA0003/) |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service | [Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

#### Description
Detects the creation of a service named `WerFaultSvc` which seems to be used by the SNAKE malware as a persistence mechanism, as described by CISA in their report.

#### Risk
The detection covers persistence mechanisms that involve creating malicious Windows services, allowing attackers to maintain access on compromised systems.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [CISA Report on Snake Malware](https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF)
- [LinkedIn - Snake Malware Hunting Queries](https://www.linkedin.com/pulse/snake-malware-hunting-queries-kql-jani-vleurinck/)
- [GitHub SigmaHQ Pull Request on Snake Malware](https://github.com/SigmaHQ/sigma/pull/4231/files)
- [CISA Cybersecurity Advisory - AA23-129A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)

---

## Queries

### Query 1 - Detect SNAKE Malware Service Persistence via Security Events

#### Query Information
This query detects the creation of a service named `WerFaultSvc` by monitoring security event logs, particularly focusing on service creation under `Service Control Manager`.
```KQL
SecurityEvent 
| where (Provider_Name =~ 'Service Control Manager' and EventID == 7045) 
| where ServiceName contains 'WerFaultSvc' 
| where ImagePath startswith 'C:\Windows\WinSxS\' and ImagePath endswith '\WerFault.exe'
```
#### Query 2 - Detect SNAKE Malware Service Persistence via Device Events
This query monitors DeviceEvents to detect service installations involving WerFaultSvc using Snake malware by inspecting the installed service metadata.

```KQL
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend AdditionalData = parse_json(AdditionalFields)
| extend ServiceName = (AdditionalData).ServiceName
| extend ServiceType = (AdditionalData).ServiceType
| extend ServiceStartType = (AdditionalData).ServiceStartType
| extend ServiceAccount = (AdditionalData).ServiceAccount
| where ServiceName contains 'WerFaultSvc' 
| where FolderPath startswith 'C:\Windows\WinSxS\' and FileName =~ '\WerFault.exe'
```


Here’s a full markdown template for the provided queries under the Persistence tactic and related techniques, using the format you have provided earlier. All the queries are listed under one markdown page, and the details have been structured accordingly:

markdown
Copy code
# SNAKE Malware Service Persistence

## Query Information

#### MITRE ATT&CK Tactic(s)

| Tactic ID | Title    | Link    |
| ---  | --- | --- |
| TA0003 | Persistence | [Persistence](https://attack.mitre.org/tactics/TA0003/) |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service | [Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

#### Description
Detects the creation of a service named `WerFaultSvc` which seems to be used by the SNAKE malware as a persistence mechanism, as described by CISA in their report.

#### Risk
The detection covers persistence mechanisms that involve creating malicious Windows services, allowing attackers to maintain access on compromised systems.

#### Author <Optional>
- **Name:** N/A
- **Github:** N/A
- **Twitter:** N/A
- **LinkedIn:** N/A
- **Website:** N/A

#### References
- [CISA Report on Snake Malware](https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF)
- [LinkedIn - Snake Malware Hunting Queries](https://www.linkedin.com/pulse/snake-malware-hunting-queries-kql-jani-vleurinck/)
- [GitHub SigmaHQ Pull Request on Snake Malware](https://github.com/SigmaHQ/sigma/pull/4231/files)
- [CISA Cybersecurity Advisory - AA23-129A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)

---

## Queries

### Query 1 - Detect SNAKE Malware Service Persistence via Security Events

#### Query Information
This query detects the creation of a service named `WerFaultSvc` by monitoring security event logs, particularly focusing on service creation under `Service Control Manager`.

```KQL
SecurityEvent 
| where (Provider_Name =~ 'Service Control Manager' and EventID == 7045) 
| where ServiceName contains 'WerFaultSvc' 
| where ImagePath startswith 'C:\Windows\WinSxS\' and ImagePath endswith '\WerFault.exe'
Query 2 - Detect SNAKE Malware Service Persistence via Device Events
Query Information
This query monitors DeviceEvents to detect service installations involving WerFaultSvc using Snake malware by inspecting the installed service metadata.



### Query 2 - Detect SNAKE Malware Persistence via Registry Events
#### Description
This query detects modifications in the Windows registry related to the service WerFaultSvc used by Snake malware.

```KQL
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend AdditionalData = parse_json(AdditionalFields)
| extend ServiceName = (AdditionalData).ServiceName
| extend ServiceType = (AdditionalData).ServiceType
| extend ServiceStartType = (AdditionalData).ServiceStartType
| extend ServiceAccount = (AdditionalData).ServiceAccount
| where ServiceName contains 'WerFaultSvc' 
| where FolderPath startswith 'C:\Windows\WinSxS\' and FileName =~ '\WerFault.exe'
```
### Query 3 - Alternative Detection via Registry Events
#### Query Information
Another query for detecting registry changes related to the WerFaultSvc service, monitoring registry paths used by the Snake malware for persistence.

```KQL
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```

### Query 4: SNAKE Malware Covert Store Registry Key
### Description: 
Detects any registry event that targets the key 'SECURITY\Policy\Secrets\n' which is a key related to SNAKE malware as described by CISA

```KQL
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents 
| where RegistryKey endswith @'SECURITY\Policy\Secrets\n'
```






