# Cloudflared AKIRA Ransomware Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1572 | Protocol Tunneling | [Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) |
| T1486 | Data Encrypted for Impact | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |

#### Description
Interesting use of the cloudflared agent by the AKIRA ransomware group. A few analytics that can be tested for hunting cloudflared usage based on the Recon InfoSec report.

#### Risk
The AKIRA ransomware group has been observed using Cloudflare's cloudflared tunnelling agent to establish covert command-and-control channels and exfiltrate data before encrypting files. Detecting cloudflared usage in unexpected contexts can help identify early-stage ransomware intrusions.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://blog.reconinfosec.com/emergence-of-akira-ransomware-group

## Defender For Endpoint
```KQL
//use of cloudflared in intrusions by ransomware actor AKIRA
// https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
let possibleVictims = 
DeviceFileEvents
| where PreviousFileName contains "cloudflared" and PreviousFileName endswith ".exe"
| distinct DeviceId;
let args = datatable(arg:string)[".exe","tunnel","run","--token"];
DeviceProcessEvents
| where DeviceId in (possibleVictims) and InitiatingProcessCommandLine has_all (args) or ProcessCommandLine has_all (args)
```

```KQL
//use of cloudflared in intrusions by ransomware actor AKIRA
// https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
let args = datatable(arg:string)[".exe","tunnel","run","--token"];
DeviceProcessEvents
| where InitiatingProcessCommandLine has_all (args) or ProcessCommandLine has_all (args)
```

```KQL
//use of cloudflared in intrusions by ransomware actor AKIRA
// https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
DeviceFileEvents
| where PreviousFileName contains "cloudflared" and PreviousFileName endswith ".exe"
```
