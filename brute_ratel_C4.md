# Brute Ratel C4

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| T1543 | Create or Modify System Process | [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/) |

#### Description
Detection queries for Brute Ratel C4 (BRC4), a commercial adversary simulation and red team tool. These queries detect the presence of known BRC4 file artifacts (ISO files, DLL agents) and named pipe patterns associated with BRC4 activity.

#### Risk
Brute Ratel C4 is a sophisticated C2 framework used by threat actors for post-exploitation. Detection of its unique file artifacts and named pipe patterns can indicate an active compromise or red team engagement using this tooling.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://bruteratel.com/
- https://attack.mitre.org/techniques/T1105/

## Defender For Endpoint
```KQL
// Possible Brute Ratel C4 Red Team Tool Detect (via DeviceFileEvents)
DeviceFileEvents 
| where ActionType =~ "FileCreated" 
| where FileName has_any ('fotos.iso','version.dll','brute-dll-agent.bin','versions.dll') or PreviousFileName has_any ('fotos.iso','version.dll','brute-dll-agent.bin','versions.dll')
```

## Sentinel
```KQL
// Possible Brute Ratel C4 Red Team Tool Detect (via file_event)
SecurityEvent |  where EventID == 11 | where (TargetFileName contains 'fotos.iso' or TargetFileName contains 'version.dll' or TargetFileName contains 'brute-dll-agent.bin' or TargetFileName contains 'versions.dll')
```

```KQL
// Sentinel query for pipe BRC4
SecurityEvent | where (PipeName endswith @'\wewe')
```

## Grep (Non-KQL Reference)

```
grep -P '^(?:.*.*fotos\.iso.*|.*.*version\.dll.*|.*.*brute-dll-agent\.bin.*|.*.*versions\.dll.*)'
```

```
grep -P '^(?:.*.*\wewe)'
```
