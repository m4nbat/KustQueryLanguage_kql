# RMM Tool Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | [Remote Access Software](https://attack.mitre.org/techniques/T1219/) |
| T1133 | External Remote Services | [External Remote Services](https://attack.mitre.org/techniques/T1133/) |

#### Description
Analytics to hunt for Remote Monitoring and Management (RMM) tool usage in the environment. Threat actors increasingly abuse legitimate RMM tools to maintain persistent access and blend in with normal IT activity.

#### Risk
RMM tools provide attackers with a stealthy, legitimate-looking remote access channel that bypasses many security controls. They are commonly used by ransomware groups and APT actors to maintain persistence, execute commands, and exfiltrate data while evading detection.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References

## Defender For Endpoint

### Splashtop
```KQL
DeviceProcessEvents
| where (ProcessVersionInfoProductName contains "SplashTop" and ProcessVersionInfoFileDescription contains "SplashTop") or (ProcessVersionInfoOriginalFileName contains "SplashTop")

```
