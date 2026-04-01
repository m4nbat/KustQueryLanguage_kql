# LOLBIN Detection: MSHTA Suspicious Usage

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.005 | Signed Binary Proxy Execution: Mshta | [Mshta](https://attack.mitre.org/techniques/T1218/005/) |

#### Description
Detection queries for suspicious mshta.exe (Microsoft HTML Application Host) activity. Detects network connections, renamed instances, protocol handler abuse (javascript/vbscript/about), and unusual process ancestry involving mshta.

#### Risk
Mshta is a signed Windows binary frequently abused by threat actors to execute malicious HTA files, bypassing application controls. It can execute JavaScript or VBScript code via protocol handlers.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1218/005/

## Defender For Endpoint
```KQL
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

```KQL
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

```KQL
//find mshta executing code via protocol handlers
let protocolHandlers = dynamic(["javascript","vbscript","about"]);
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
| where ( InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles) ) and ProcessCommandLine has_any (protocolHandlers)
```

```KQL
// mshta process execution with unusual process parent ancestry
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
//look for suspicious process parent ancestry
| where (InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles)) and (InitiatingProcessParentFileName in~ ("PowerShell.exe","cmd.exe") or InitiatingProcessFileName in~ ("PowerShell.exe","cmd.exe"))
```

## Sentinel
```KQL
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

```KQL
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

```KQL
//find mshta executing code via protocol handlers
let protocolHandlers = dynamic(["javascript","vbscript","about"]);
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
| where ( InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles) ) and ProcessCommandLine has_any (protocolHandlers)
```

```KQL
// mshta process execution with unusual process parent ancestry
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
//look for suspicious process parent ancestry
| where (InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles)) and (InitiatingProcessParentFileName in~ ("PowerShell.exe","cmd.exe") or InitiatingProcessFileName in~ ("PowerShell.exe","cmd.exe"))
```
