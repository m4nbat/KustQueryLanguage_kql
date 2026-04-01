# Turla SNAKE Malware Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service | [Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| T1564 | Hide Artifacts | [Hide Artifacts](https://attack.mitre.org/techniques/T1564/) |
| T1027 | Obfuscated Files or Information | [Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |

#### Description
This set of queries hunts for indicators of Turla's SNAKE malware, an advanced rootkit used by the Russian FSB. The queries detect service persistence, file indicators, registry modifications, and CLI argument patterns associated with SNAKE.

#### Risk
SNAKE is an advanced cyberespionage tool used by Russia's FSB (Turla threat group). It provides long-term access to compromised systems and has been observed targeting NATO member governments and other high-value targets.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a
- https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
- https://www.linkedin.com/pulse/snake-malware-hunting-queries-kql-jani-vleurinck/
- https://github.com/SigmaHQ/sigma/pull/4231/files

## Defender For Endpoint
```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```

```KQL
// Title: SNAKE Malware Kernel Driver File Indicator
// Description: Detects SNAKE malware kernel driver file indicator
// Tactic: Execution// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
DeviceFileEvents 
| where FolderPath =~ @'C:\Windows\System32\Com\Comadmin.dat'
```

```KQL
// Title: SNAKE Malware Installer Name Indicators
// Description: Detects filename indicators associated with the SNAKE malware as reported by CISA in their report
// Tactic: Execution
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
DeviceFileEvents 
| where (FolderPath endswith @'\jpsetup.exe' or FolderPath endswith @'\jpinst.exe')
```

```KQL
// title: SNAKE Malware WerFault Persistence File Creation
// description: Detects the creation of a filename named "WerFault.exe" in the WinSxS directory by a non system process. Which can be indicative of potential SNAKE malware activity
// references:https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
//Tactic: ADFSSISPackageExecutionComponentPhases
DeviceFileEvents 
| where ((FolderPath startswith @'C:\Windows\WinSxS\' and FolderPath endswith @'\WerFault.exe') and not (InitiatingProcessFolderPath startswith @'C:\Windows\Systems32\' or InitiatingProcessFolderPath startswith @'C:\Windows\SysWOW64\' or InitiatingProcessFolderPath startswith @'C:\Windows\WinSxS\'))
```

```KQL
// Title: Potential SNAKE Malware Installation CLI Arguments Indicator
// Description: Detects specific command line arguments sequence seen used by SNAKE malware during its installation as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Execution
DeviceProcessEvents | where ProcessCommandLine matches regex @'(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}' or InitiatingProcessCommandLine matches regex @'(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}'
```

```KQL
// Title: Potential SNAKE Malware Installation Binary Indicator
// Description: Detects specific image binary name seen used by SNAKE malware during its installation as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Execution
DeviceProcessEvents 
| where ((FolderPath endswith @'\jpsetup.exe' or FolderPath endswith @'\jpinst.exe') and not ((ProcessCommandLine in~ (@'jpinst.exe', @'jpinst', @'jpsetup.exe', @'jpsetup')) or ProcessCommandLine =~ @'' or isempty(ProcessCommandLine))) or ((InitiatingProcessFolderPath endswith @'\jpsetup.exe' or InitiatingProcessFolderPath endswith @'\jpinst.exe') and not ((InitiatingProcessCommandLine in~ (@'jpinst.exe', @'jpinst', @'jpsetup.exe', @'jpsetup')) or InitiatingProcessCommandLine =~ @'' or isempty(InitiatingProcessCommandLine)))
```

```KQL
// Title: SNAKE Malware Covert Store Registry Key
// Description: Detects any registry event that targets the key 'SECURITY\Policy\Secrets\n' which is a key related to SNAKE malware as described by CISA
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents 
| where RegistryKey endswith @'SECURITY\Policy\Secrets\n'
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
SecurityEvent | where (Provider_Name =~ @'Service Control Manager' and EventID == 7045 and ServiceName contains @'WerFaultSvc' and ImagePath startswith @'C:\Windows\WinSxS\' and ImagePath endswith @'\WerFault.exe')
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend AdditionalData = parse_json(AdditionalFields)
| extend ServiceName = (AdditionalData).ServiceName
| extend ServiceType = (AdditionalData).ServiceType
| extend ServiceStartType = (AdditionalData).ServiceStartType
| extend ServiceAccount = (AdditionalData).ServiceAccount
| where ServiceName contains @'WerFaultSvc' and FolderPath startswith @'C:\Windows\WinSxS\' and FileName =~ @'\WerFault.exe'
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/OINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```

## Sentinel
```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```

```KQL
// Title: SNAKE Malware Kernel Driver File Indicator
// Description: Detects SNAKE malware kernel driver file indicator
// Tactic: Execution// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
DeviceFileEvents 
| where FolderPath =~ @'C:\Windows\System32\Com\Comadmin.dat'
```

```KQL
// Title: SNAKE Malware Installer Name Indicators
// Description: Detects filename indicators associated with the SNAKE malware as reported by CISA in their report
// Tactic: Execution
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
DeviceFileEvents 
| where (FolderPath endswith @'\jpsetup.exe' or FolderPath endswith @'\jpinst.exe')
```

```KQL
// title: SNAKE Malware WerFault Persistence File Creation
// description: Detects the creation of a filename named "WerFault.exe" in the WinSxS directory by a non system process. Which can be indicative of potential SNAKE malware activity
// references:https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
//Tactic: ADFSSISPackageExecutionComponentPhases
DeviceFileEvents 
| where ((FolderPath startswith @'C:\Windows\WinSxS\' and FolderPath endswith @'\WerFault.exe') and not (InitiatingProcessFolderPath startswith @'C:\Windows\Systems32\' or InitiatingProcessFolderPath startswith @'C:\Windows\SysWOW64\' or InitiatingProcessFolderPath startswith @'C:\Windows\WinSxS\'))
```

```KQL
// Title: Potential SNAKE Malware Installation CLI Arguments Indicator
// Description: Detects specific command line arguments sequence seen used by SNAKE malware during its installation as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Execution
DeviceProcessEvents | where ProcessCommandLine matches regex @'(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}' or InitiatingProcessCommandLine matches regex @'(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}'
```

```KQL
// Title: Potential SNAKE Malware Installation Binary Indicator
// Description: Detects specific image binary name seen used by SNAKE malware during its installation as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Execution
DeviceProcessEvents 
| where ((FolderPath endswith @'\jpsetup.exe' or FolderPath endswith @'\jpinst.exe') and not ((ProcessCommandLine in~ (@'jpinst.exe', @'jpinst', @'jpsetup.exe', @'jpsetup')) or ProcessCommandLine =~ @'' or isempty(ProcessCommandLine))) or ((InitiatingProcessFolderPath endswith @'\jpsetup.exe' or InitiatingProcessFolderPath endswith @'\jpinst.exe') and not ((InitiatingProcessCommandLine in~ (@'jpinst.exe', @'jpinst', @'jpsetup.exe', @'jpsetup')) or InitiatingProcessCommandLine =~ @'' or isempty(InitiatingProcessCommandLine)))
```

```KQL
// Title: SNAKE Malware Covert Store Registry Key
// Description: Detects any registry event that targets the key 'SECURITY\Policy\Secrets\n' which is a key related to SNAKE malware as described by CISA
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents 
| where RegistryKey endswith @'SECURITY\Policy\Secrets\n'
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
SecurityEvent | where (Provider_Name =~ @'Service Control Manager' and EventID == 7045 and ServiceName contains @'WerFaultSvc' and ImagePath startswith @'C:\Windows\WinSxS\' and ImagePath endswith @'\WerFault.exe')
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend AdditionalData = parse_json(AdditionalFields)
| extend ServiceName = (AdditionalData).ServiceName
| extend ServiceType = (AdditionalData).ServiceType
| extend ServiceStartType = (AdditionalData).ServiceStartType
| extend ServiceAccount = (AdditionalData).ServiceAccount
| where ServiceName contains @'WerFaultSvc' and FolderPath startswith @'C:\Windows\WinSxS\' and FileName =~ @'\WerFault.exe'
```

```KQL
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/OINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```
