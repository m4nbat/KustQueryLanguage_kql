# Title
SOCGholish Detection Analytics

# Description
While JavaScript is everywhere on the web, it is rather unusual for the browser to download a JavaScript file and execute it via the Windows Script Host (wscript.exe). When this downloaded script starts communicating with devices outside of your network, things get even more suspicious. That said, this detection analytic may be noisy in some environments, so be prepared to identify what scripts are normally run in this way to tune out the noise.

# Source
- https://redcanary.com/threat-detection-report/threats/socgholish/

# MITRE ATT&CK
-

# Queries for sentinel and MDE

```
//TTP: SOCGhoulish variants network connection from wscript.exe with a parent process that is a browser.
let browsers = datatable(name:string)["chrome","edge","firefox"]; //add more
DeviceNetworkEvents
| where InitiatingProcessParentFileName has_any (browsers) and InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") and RemoteIPType =~ "Public"
```
