# Brute Ratel C4 Red Team Tool Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| T1587.001 | Develop Capabilities: Malware | [Malware](https://attack.mitre.org/techniques/T1587/001/) |

#### Description
Detects potential Brute Ratel C4 red team tool activity via file indicators (fotos.iso, version.dll, brute-dll-agent.bin) and named pipe indicators used by the tool.

#### Risk
Brute Ratel C4 is an adversary simulation framework sold to nation-state threat actors. It was observed used by COZY BEAR (APT29) and other threat groups for C2 and lateral movement.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://bruteratel.com/
- https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/

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
SecurityEvent | where (PipeName endswith @'\wewe')
```
