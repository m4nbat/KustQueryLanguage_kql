# Regsvr32.exe Loading Scripts from External Sources (Squiblydoo)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.010 | Signed Binary Proxy Execution: Regsvr32 | [Regsvr32](https://attack.mitre.org/techniques/T1218/010/) |

#### Description
Detects regsvr32.exe executing scriptlet files loaded from external URLs (the 'Squiblydoo' technique). This allows application whitelisting bypass by loading remote COM scriptlets.

#### Risk
Regsvr32 can be abused to execute remote COM scriptlets, bypassing application whitelisting. This technique (Squiblydoo) is used by multiple threat actors to execute malicious code via a trusted signed Windows binary.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1218/010/
- https://docs.microsoft.com/en-us/security/

## Defender For Endpoint
```KQL
// Finds regsvr32.exe command line executions that loads scriptlet files from remote sites.
// This technique could be used to avoid application whitelisting and antimalware protection.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "regsvr32.exe" and InitiatingProcessCommandLine contains "/i:http" 
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
| top 100 by Timestamp
```

## Sentinel
```KQL
// Finds regsvr32.exe command line executions that loads scriptlet files from remote sites.
// This technique could be used to avoid application whitelisting and antimalware protection.
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName =~ "regsvr32.exe" and InitiatingProcessCommandLine contains "/i:http" 
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
| top 100 by TimeGenerated
```
