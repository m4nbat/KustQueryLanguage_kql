# Admin Share Access via WMI (Lateral Movement Detection)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB/Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |

#### Description
Detects processes spawned by wmiprvse.exe using cmd.exe with admin share paths, a pattern used by Impacket and similar tools for lateral movement via WMI.

#### Risk
Attackers use admin shares in combination with WMI for lateral movement. This is a strong indicator of Impacket or similar attack frameworks being used.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/SecureAuthCorp/impacket
- https://attack.mitre.org/techniques/T1021/002/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where (InitiatingProcessParentFileName =~ "wmiprvse.exe" or InitiatingProcessFileName =~ "wmiprvse.exe") and (InitiatingProcessFileName =~ "cmd.exe" or FileName =~ "cmd.exe") and (InitiatingProcessCommandLine contains @"\\\\127.0.0.1\\ADMIN" or ProcessCommandLine contains @"\\\\127.0.0.1\\ADMIN")
```

## Sentinel
```KQL
DeviceProcessEvents
| where (InitiatingProcessParentFileName =~ "wmiprvse.exe" or InitiatingProcessFileName =~ "wmiprvse.exe") and (InitiatingProcessFileName =~ "cmd.exe" or FileName =~ "cmd.exe") and (InitiatingProcessCommandLine contains @"\\\\127.0.0.1\\ADMIN" or ProcessCommandLine contains @"\\\\127.0.0.1\\ADMIN")
```
