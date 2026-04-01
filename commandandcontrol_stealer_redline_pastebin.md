# Redline Stealer Using Pastebin

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102 | Web Service | [Web Service](https://attack.mitre.org/techniques/T1102/) |

#### Description
Detects Redline Stealer using pastebin.com to retrieve its C2 configuration. Redline Stealer has been reported to reach out to pastebin.com to pull down configuration data, making non-browser processes connecting to pastebin an indicator of potential infection.

#### Risk
Processes (excluding known browsers and applications) connecting to pastebin.com may indicate Redline Stealer or other malware using pastebin for C2 configuration retrieval. This can lead to credential theft, browser data exfiltration, and further host compromise.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://twitter.com/NexusFuzzy/status/1654056343127425026?s=19

## Defender For Endpoint
```KQL
let excludedPaths = datatable(path:string)["browserpath1","browserpath2","etc..."];
DeviceNetworkEvents 
| where RemoteUrl contains "pastebin.com" and InitiatingProcessFolderPath !has_any (excludedPaths)
```
