# LOLBIN - MSHTA

## MDE / Sentinel - network connections by MSHTA
```
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

## MDE / Sentinel - MSHTA renamed

```
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
//mshta.exe creating a network connection
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (mshtaFiles) and RemoteIPType =~ "Public"
```

## MDE / Sentinel - MSHTA leveraging protocol handlers to execute code

```
//find mshta executing code via protocol handlers
let protocolHandlers = dynamic(["javascript","vbscript","about"]);
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
| where ( InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles) ) and ProcessCommandLine has_any (protocolHandlers)
```

## MDE / Sentinel - MSHTA process execution with unusual process parent ancestry

```
// mshta process execution with unusual process parent ancestry
//get renamed mshta.exe filenames and renamed mshta.exe filenames
let mshtaFiles = DeviceImageLoadEvents
| where InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" | distinct InitiatingProcessFileName;
DeviceProcessEvents
//look for suspicious process parent ancestry
| where (InitiatingProcessFileName in~ (mshtaFiles) or FileName in~ (mshtaFiles)) and (InitiatingProcessParentFileName in~ ("PowerShell.exe","cmd.exe") or InitiatingProcessFileName in~ ("PowerShell.exe","cmd.exe"))
```









