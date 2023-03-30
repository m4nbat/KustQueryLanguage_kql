# USB Related Hunting Queries

# Sources:
- https://blog.amestofortytwo.com/hunting-malicious-usb/
- 
- 

Kusto Queries (KQL):

`//source: https://blog.amestofortytwo.com/hunting-malicious-usb/
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
| project Plugin=TimeGenerated, CommandRun, AdditionalFields, DeviceName, PossibleFileExec=FileName1, InitPCMD = InitiatingProcessCommandLine1, InitPPFN = InitiatingProcessParentFileName1, InitPPID=InitiatingProcessParentId1, PID=ProcessId1`
