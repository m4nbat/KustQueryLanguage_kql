# Munchkin Tool

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1564.006 | Hide Artifacts: Run Virtual Instance | [Hide Artifacts: Run Virtual Instance](https://attack.mitre.org/techniques/T1564/006/) |
| T1486 | Data Encrypted for Impact | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |

#### Description
The Munchkin utility is delivered as an ISO file, which is loaded in a newly installed instance of the VirtualBox virtualization product. This ISO file represents a customized implementation of the Alpine OS, which threat operators likely chose due to its small footprint. Upon running the operating system, the following commands are executed at boot. Munchkin is associated with the BlackCat (ALPHV) ransomware group.

#### Risk
Munchkin enables BlackCat ransomware operators to execute malicious payloads inside a virtual machine, bypassing host-based security controls. This technique allows lateral movement and encryption operations to run in an environment that is isolated from endpoint detection tools running on the host OS.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [BlackCat Ransomware Releases New Utility Munchkin](https://unit42.paloaltonetworks.com/blackcat-ransomware-releases-new-utility-munchkin/)

## Defender For Endpoint
```KQL
let commands = datatable(command:string)["new-session","-A","-s","controller","send","-t","controller","/app/controller","&&","poweroff","ENTER","detach","-s","controller"];
DeviceProcessEvents
| where ProcessCommandLine has_all (commands) or InitiatingProcessCommandLine has_all (commands)
```

```KQL
let c1 = datatable(a:string)["new-session","-A","-s","controller","send","-t","controller","/app/controller","&&","poweroff","ENTER","detach","-s","controller"];
let c2 = datatable(b:string)["echo","-n","password","|","chpasswd"];
let c3 = datatable(c:string)["eject"];
let command1 = DeviceProcessEvents | where ProcessCommandLine has_all (c1) | distinct DeviceId, ProcessCommandLine;
let command2 = DeviceProcessEvents | where ProcessCommandLine has_all (c2) | distinct DeviceId, ProcessCommandLine;
let command3 = DeviceProcessEvents | where ProcessCommandLine has_all (c3) | distinct DeviceId, ProcessCommandLine;
command1 | join command2 on DeviceId | join command3 on DeviceId
| where isnotempty(DeviceId) and  isnotempty(DeviceId1) and  isnotempty(DeviceId2)
```
