# SOCGholish Detection Analytics

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| T1071.001 | Application Layer Protocol: Web Protocols | [Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
While JavaScript is everywhere on the web, it is rather unusual for the browser to download a JavaScript file and execute it via the Windows Script Host (wscript.exe). When this downloaded script starts communicating with devices outside of your network, things get even more suspicious. That said, this detection analytic may be noisy in some environments, so be prepared to identify what scripts are normally run in this way to tune out the noise.

#### Risk
SOCGholish is a JavaScript-based malware framework delivered via fake browser updates on compromised websites. It can lead to data theft, ransomware deployment, and further compromise of the environment.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
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
