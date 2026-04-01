# SOCGholish Malware - Suspicious WScript Network Connection Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [JavaScript](https://attack.mitre.org/techniques/T1059/007/) |

#### Description
Detects SOCGholish (FakeUpdates) malware activity where wscript.exe or cscript.exe makes external network connections after being spawned by a browser process. This is a key indicator of the SOCGholish infection chain.

#### Risk
SOCGholish (FakeUpdates) is a drive-by download campaign that compromises legitimate websites with malicious JavaScript. Victims are prompted to download a fake browser update that executes via wscript.exe.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/threats/socgholish/

## Defender For Endpoint
```KQL
//TTP: SOCGhoulish variants network connection from wscript.exe with a parent process that is a browser.
let browsers = datatable(name:string)["chrome","edge","firefox"]; //add more
DeviceNetworkEvents
| where InitiatingProcessParentFileName has_any (browsers) and InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") and RemoteIPType =~ "Public"
```

## Sentinel
```KQL
//TTP: SOCGhoulish variants network connection from wscript.exe with a parent process that is a browser.
let browsers = datatable(name:string)["chrome","edge","firefox"]; //add more
DeviceNetworkEvents
| where InitiatingProcessParentFileName has_any (browsers) and InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") and RemoteIPType =~ "Public"
```
