# Title: Turla Snake malware hunt queries

# Sources:
-
-
- Me

```
//Title: SNAKE Malware Service Persistence
// Description: Detects the creation of a service named "WerFaultSvc" which seems to be used by the SNAKE malware as a persistence mechanism as described by CISA in their report
// References: https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF
// Tactic: Persistence
DeviceRegistryEvents
| where RegistryKey endswith @"SYSTEM\ControlSet001\Services\WerFaultSvc"
```
