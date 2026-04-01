# Redline Stealer C2 via Pastebin Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
Detects Redline Stealer malware using Pastebin to retrieve its C2 configuration. Identifies non-browser processes making connections to pastebin.com.

#### Risk
Redline Stealer uses Pastebin to host its C2 server configuration, a technique that evades network detection by using a trusted hosting service. Redline harvests credentials, credit card data, and cryptocurrency wallets.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://twitter.com/NexusFuzzy/status/1654056343127425026

## Defender For Endpoint
```KQL
let excludedPaths = datatable(path:string)["browserpath1","browserpath2","etc..."];
DeviceNetworkEvents 
| where RemoteUrl contains "pastebin.com" and InitiatingProcessFolderPath !has_any (excludedPaths)
```

## Sentinel
```KQL
let excludedPaths = datatable(path:string)["browserpath1","browserpath2","etc..."];
DeviceNetworkEvents 
| where RemoteUrl contains "pastebin.com" and InitiatingProcessFolderPath !has_any (excludedPaths)
```
