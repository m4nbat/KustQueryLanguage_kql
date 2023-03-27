# Emotet TTPs Q1 2023
## Source: Microsoft Threat Analytics

![image](https://user-images.githubusercontent.com/16122365/227981654-827905ae-9088-42bf-925a-990c6b163a5b.png)


**NOTE:** The following sample queries let you search for a week's worth of events. To explore up to 30 days’ worth of raw data to inspect events in your network and locate potential Emotet zip bomb-related indicators for more than a week, go to the Advanced Hunting page > Query tab, select the calendar dropdown menu to update your query to hunt for the Last 30 days.

To locate possible exploitation activity, run the following queries in Microsoft 365 security center.

Large file delivered from small archive file. Look for the delivery of a large (> 256MB) executable by an archive file. This is often used as a security detection evasion.

`let largeFileMin = 268435456; // 256mb
let smallFileMin = 102400; // 100kb
let smallFileMax = 67108864; // 64mb
let ratioMin = 75; // compression ratio, larger number indicates padding/ empty values more likely
//
let start = now(-10d);
let end = now();
//
let largeFileCreate=
DeviceFileEvents
| where Timestamp between (start..end)
| where FileSize > largeFileMin
| where InitiatingProcessCommandLine has_any ('.rar', '.zip')
| where FolderPath has @'\Users\'  //'
    and FolderPath has_any (@'\Downloads\', @'\AppData\') //'
    and not (FolderPath has @'\chocolatey\') //'
| extend fileExt = tolower(tostring(split(FileName,'.')[-1]))
| where fileExt in~ ('exe', 'scr', 'com')
    // fileExt needs to be monitored on continuous basis for emerging threats
| summarize FileUnpackTime=min(Timestamp) by DeviceId, UnpackSize=FileSize, 
    FolderPath, FileName, fileExt, InitiatingProcessCommandLine,
    InitiatingProcessAccountUpn, InitiatingProcessAccountSid
;
let device_FileName_set =
largeFileCreate
| distinct DeviceId, FileName
;
let device_set = 
largeFileCreate
| distinct DeviceId
| where isnotempty(DeviceId)
;
let pullFromCmd = 
largeFileCreate
| distinct InitiatingProcessCommandLine
| extend InitiatingProcessCommandLine = tolower(InitiatingProcessCommandLine)
| extend targetFile = extract(@'([\\]?).*(rar|zip)',0,InitiatingProcessCommandLine)
| extend targetFile = trim_start(@'.*\\',targetFile) //'
| where isnotempty(targetFile)
| distinct targetFile
;
let largeFileParent = 
DeviceFileEvents
| where Timestamp between (start..end)
| where DeviceId in (device_set)
| where FileName in~ (pullFromCmd)
| join kind=inner device_FileName_set on $left.DeviceId==$right.DeviceId, $left.InitiatingProcessFileName==$right.FileName
| project-away DeviceId1, FileName1
| where FileSize between (smallFileMin..smallFileMax)
| summarize DownloadTime=min(Timestamp), FileOriginUrl=max(FileOriginUrl), 
    FileOriginReferrerUrl=max(FileOriginReferrerUrl) by DeviceId, 
    DownloadFileSize=FileSize, InitiatingProcessAccountUpn, InitiatingProcessAccountSid
;
let screenShotTaken = 
DeviceEvents
| where Timestamp between (start..end)
| where DeviceId in (device_set)
| where ActionType =~ "ScreenshotTaken"
| join kind=inner device_FileName_set on $left.DeviceId==$right.DeviceId, $left.InitiatingProcessFileName==$right.FileName
| project-away DeviceId1, FileName1
| summarize ScreenShotTime=min(Timestamp) by DeviceId, 
    InitiatingProcessAccountUpn, InitiatingProcessAccountSid
;
let unprotectDPAPI = 
DeviceEvents
| where Timestamp between (start..end)
| where DeviceId in (device_set)
| where ActionType =~ "DpapiAccessed"
| join kind=inner device_FileName_set on $left.DeviceId==$right.DeviceId, $left.InitiatingProcessFileName==$right.FileName
| project-away DeviceId1, FileName1
| summarize UnprotectTime=min(Timestamp) by DeviceId, 
    InitiatingProcessAccountUpn, InitiatingProcessAccountSid
;
let fileOpen = 
DeviceEvents
| where Timestamp between (start..end)
| where DeviceId in (device_set)
| where ActionType =~ "SensitiveFileRead"
| join kind=inner device_FileName_set on $left.DeviceId==$right.DeviceId, $left.InitiatingProcessFileName==$right.FileName
| project-away DeviceId1, FileName1
| summarize FileOpenTime=min(Timestamp), FileTargetSet=array_sort_asc(make_set(FileName))
    by DeviceId, InitiatingProcessAccountUpn, InitiatingProcessAccountSid
;
let smallParentFull = 
largeFileParent
| join kind=inner largeFileCreate on DeviceId
| project-away DeviceId1, InitiatingProcessAccountSid1, InitiatingProcessAccountUpn1
| extend ratioPacked = UnpackSize/DownloadFileSize
| where ratioPacked >= ratioMin
| extend DownloadFileSize=format_bytes(DownloadFileSize,1),
    UnpackSize=format_bytes(UnpackSize,1)
;
smallParentFull
| join kind=leftouter screenShotTaken on DeviceId
| project-away DeviceId1, InitiatingProcessAccountSid1, InitiatingProcessAccountUpn1
| join kind=leftouter unprotectDPAPI on DeviceId
| project-away DeviceId1, InitiatingProcessAccountSid1, InitiatingProcessAccountUpn1
| join kind=leftouter fileOpen on DeviceId
| project-away DeviceId1, InitiatingProcessAccountSid1, InitiatingProcessAccountUpn1
| extend has_ScreenShot=iff(isnotnull(ScreenShotTime),true,bool(null)),
    has_UnprotectDPAPI=iff(isnotnull(UnprotectTime),true,bool(null)),
    has_FileOpen=iff(isnotnull(FileOpenTime),true,bool(null))
| project-reorder DownloadTime, FileUnpackTime, ScreenShotTime, FileOpenTime, 
    UnprotectTime, has_*, DeviceId, ratioPacked, DownloadFileSize, UnpackSize`
