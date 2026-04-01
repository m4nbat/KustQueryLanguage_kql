# USB Device Hunting and Malicious HID Device Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1200 | Hardware Additions | [Hardware Additions](https://attack.mitre.org/techniques/T1200/) |

#### Description
Detection queries for suspicious USB device activity including known malicious HID device vendors like Rubber Ducky, Digispark, and Arduino. Identifies keystroke injection devices.

#### Risk
Malicious USB devices (HID attacks) can execute keystrokes and inject commands. Physical security tools like Rubber Ducky are used by attackers with physical access.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.amestofortytwo.com/hunting-malicious-usb/

## Defender For Endpoint
```KQL
//source: https://blog.amestofortytwo.com/hunting-malicious-usb/
// A great tool to add to this query: https://devicehunt.com/view/type/usb/
let known_suspicious = dynamic(["VID_03eb", "PID_2401"  // Atmel
                            , "VID_16D0", "PID_0753"    // Digispark
                            , "VID_16C0", "PID_0483"    // Teensyduino
                            , "VID_2341"                // Arduino https://devicehunt.com/view/type/usb/vendor/2341
                            ]); 
DeviceEvents
| mv-expand AdditionalFields
| where AdditionalFields["VendorIds"] has_any (known_suspicious)
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine != ""
    | extend CommandRun = TimeGenerated
    ) on DeviceId, DeviceName
| where CommandRun between (TimeGenerated .. 10s) // Time from plugin to action
| where InitiatingProcessParentFileName1  has_any ("userinit.exe", "explorer.exe") // User initiated - non system actions
| project Plugin=TimeGenerated, CommandRun, AdditionalFields, DeviceName, PossibleFileExec=FileName1, InitPCMD = InitiatingProcessCommandLine1, InitPPFN = InitiatingProcessParentFileName1, InitPPID=InitiatingProcessParentId1, PID=ProcessId1
```

## Sentinel
```KQL
//source: https://blog.amestofortytwo.com/hunting-malicious-usb/
// A great tool to add to this query: https://devicehunt.com/view/type/usb/
let known_suspicious = dynamic(["VID_03eb", "PID_2401"  // Atmel
                            , "VID_16D0", "PID_0753"    // Digispark
                            , "VID_16C0", "PID_0483"    // Teensyduino
                            , "VID_2341"                // Arduino https://devicehunt.com/view/type/usb/vendor/2341
                            ]); 
DeviceEvents
| mv-expand AdditionalFields
| where AdditionalFields["VendorIds"] has_any (known_suspicious)
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine != ""
    | extend CommandRun = TimeGenerated
    ) on DeviceId, DeviceName
| where CommandRun between (TimeGenerated .. 10s) // Time from plugin to action
| where InitiatingProcessParentFileName1  has_any ("userinit.exe", "explorer.exe") // User initiated - non system actions
| project Plugin=TimeGenerated, CommandRun, AdditionalFields, DeviceName, PossibleFileExec=FileName1, InitPCMD = InitiatingProcessCommandLine1, InitPPFN = InitiatingProcessParentFileName1, InitPPID=InitiatingProcessParentId1, PID=ProcessId1
```
