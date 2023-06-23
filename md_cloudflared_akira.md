# Description

Interesting use of the cloudflared agent by the AKIRA ransomware Group and a quality writeup by Recon InfoSec team. A treasure trove of threat intelligence that can be used for informing defence.

# Source: https://blog.reconinfosec.com/emergence-of-akira-ransomware-group

A few analytics that can be tested for hunting cloudflared usage based on the report.

```
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

```
//use of cloudflared in intrusions by ransomware actor AKIRA
// https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
let args = datatable(arg:string)[".exe","tunnel","run","--token"];
DeviceProcessEvents
| where InitiatingProcessCommandLine has_all (args) or ProcessCommandLine has_all (args)
```

```
//use of cloudflared in intrusions by ransomware actor AKIRA
// https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
DeviceFileEvents
| where PreviousFileName contains "cloudflared" and PreviousFileName endswith ".exe"
```
