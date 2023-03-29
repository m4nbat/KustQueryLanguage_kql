Source:



## Child process or rundll32 with a webrequest in the commandline

`DeviceImageLoadEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine has_any ("iwr","Invoke-webrequest")`

## Weeding out partial matches of iex or iwr using regex

`DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iex[^\w]|invoke-expression"`

`DeviceProcessEvents
| where ProcessCommandLine matches regex @"[^\w]iwr[^\w]|invoke-webrequest"`

## system.management.automation.dll

let excludedParentProcesses = datatable (process:string)["SenseIR.exe","SenseCM.exe"];
DeviceImageLoadEvents
| where FileName contains "system.management.automation.dll" and InitiatingProcessParentFileName !in~ (excludedParentProcesses)
| project InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine

