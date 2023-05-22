# LOLDRIVERS Threat Hunting

# Source:

- WWW.LOLDRIVERS.IO

# KQL Hunt Query

```
let loldrivers = externaldata(Id:string, Author:string, Created:datetime, MitreID:string, Category:string, Verified:bool, Commands:dynamic, Resources:dynamic, Acknowledgement:dynamic, Detection:dynamic, KnownVulnerableSamples:dynamic, Tags:dynamic)
[h@'https://www.loldrivers.io/api/drivers.json']
with(format='multijson')
| mv-expand KnownVulnerableSamples
| extend SHA256_ = tostring(KnownVulnerableSamples.SHA256)
| extend SHA1_ = tostring(KnownVulnerableSamples.SHA1)
| extend MD5_ = tostring(KnownVulnerableSamples.MD5)
;
DeviceFileEvents
| where SHA1 in~ (loldrivers) or MD5 in~ (loldrivers) or SHA256 in~ (loldrivers)
```
