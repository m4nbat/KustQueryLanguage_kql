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
//renamed version of mshta.exe
DeviceImageLoadEvents
| where (InitiatingProcessVersionInfoOriginalFileName =~ "mshta.exe" and tolower(InitiatingProcessFileName) != tolower(InitiatingProcessVersionInfoOriginalFileName))
```
