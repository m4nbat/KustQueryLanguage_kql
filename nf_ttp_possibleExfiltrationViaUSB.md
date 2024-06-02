# * Possible Exfiltration via USB Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                             | Link                                                  |
|--------------|-----------------------------------|-------------------------------------------------------|
| T1052.001   | Exfiltration Over Physical Medium: Exfiltration over USB| [Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001) |

#### Description
Adversaries such as insiders have been known to exfilrate data via removable media such as USB devices. 

#### Risk
Removable media including USB can present a data loss risk to organisations.

#### Author 
- **Name:** Nathan Webb
- **Github:**
- **Twitter:**
- **LinkedIn:** [https://www.linkedin.com/in/nathanjohnwebb](htps://www.linkedin.com/in/nathanjohnwebb) 
- **Website:**

#### References
- [Threat hunt] Detecting Possible USB Data Exfiltration
https://www.linkedin.com/pulse/threat-hunt-detecting-possible-usb-data-exfiltration-nathan-webb-t3ode?utm_source=share&utm_medium=member_android&utm_campaign=share_via

## Defender For Endpoint

```KQL
let LookBackPeriod=14d; // How long to look back for USB activity
let DetectionPeriod=1d;
let DeviceConnectedCopiedWindow=1h; // adjust to have a longer time range between device connected and files copied
let SystemDrive=dynamic(['C:', 'D:']); // add known system drive paths in here
DeviceEvents
| where Timestamp > ago(LookBackPeriod)
| where ActionType contains "PnpDeviceConnected"
| extend DeviceType = tostring(todynamic(AdditionalFields).ClassName)
| extend UsbId = tostring(todynamic(AdditionalFields).DeviceId)
| where DeviceType contains "drive" or DeviceType contains "disk"
// get a count of how many times that USB vendor and id has been inserted (this just identifies the type of device and is not a unique ID per USB device)
// bin our timestamp so we can join on this time window when searching for USB events
| summarize FirstSeen=min(Timestamp), TimesDriveConnected=count() by UsbId, bin(Timestamp, DeviceConnectedCopiedWindow), DeviceId, DeviceName
| where FirstSeen > ago(DetectionPeriod)
// do a join to get copied files from the host that occur within the same timeeframe
| join (DeviceFileEvents
    | where Timestamp > ago(DetectionPeriod)
    | where ActionType == "FileCreated"
    | where FileOriginReferrerUrl contains @"\" // file has come from a windows path
    | extend SourceDrive=tostring(split(FileOriginReferrerUrl, @"\")[0]) // get the drive letter of the system path
    | extend DestDrive=tostring(split(FolderPath, @"\")[0]) // get the drive letter of where the file was written to
    | where SourceDrive has_any (SystemDrive) and not(DestDrive has_any (SystemDrive)) // a copy off the system drive
    | summarize FilesPathsCopied=make_set(FolderPath, 1000), FileCopiesCount=count() by SourceDrive, DestDrive, DeviceId, DeviceName, bin(Timestamp, DeviceConnectedCopiedWindow))
    on DeviceId, Timestamp
```