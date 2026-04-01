# Reddit Used for C2

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102 | Web Service | [Web Service](https://attack.mitre.org/techniques/T1102/) |
| T1102.002 | Web Service: Bidirectional Communication | [Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) |

#### Description
Detects non-browser processes interacting with the Reddit API, which has been abused as a command and control (C2) channel. Browsers are excluded from this detection to reduce false positives from legitimate Reddit browsing activity.

#### Risk
Threat actors can use the Reddit API as a covert C2 channel to blend malicious traffic with legitimate web activity, making it harder to detect using traditional network-based controls.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://github.com/m4nbat/sigma/blob/master/rules/windows/network_connection/net_connection_win_reddit_api_non_browser_access.yml
- https://github.com/kleiton0x00/RedditC2

## Defender For Endpoint
```KQL
//Processes interacting with Reddit API (Has been known to be used for C2 communication)
// https://github.com/kleiton0x00/RedditC2
//false positives - browsers going to the URL. Or a legitimate application that uses Reddit API
let browserNames = datatable (browser:string)["msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more broswers where needed for exclusion
DeviceNetworkEvents
| where not(InitiatingProcessFileName has_any (browserNames)) and RemoteUrl contains "reddit.com/api/"
```
