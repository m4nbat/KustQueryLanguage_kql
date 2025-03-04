# Day 9 - Detection opportunity: Renamed instances of AutoIT

## Description

This pseudo detection analytic identifies renamed instances of AutoIT. Adversaries—like those behind HijackLoader—use this tool to execute scripts with goals including C2 communication and additional payload delivery. The renamed binary may be located in a suspicious location like TEMP, APPDATA, or with a path that includes seemingly randomly generated names. 

### Example Script / Pseudo Code

```

process_is_renamed == (autoit)*

```

## References

https://redcanary.com/blog/threat-intelligence/intelligence-insights-december-2024/

## Query MDE

### Renamed autoit files from certain locations

``` KQL

let SuspiciousLocations = dynamic(["C:\\Users\\*", "C:\\ProgramData\\*", "C:\\Windows\\Temp\\*", "C:\\Users\\*\\AppData\\Local\\*", "C:\\Users\\*\\AppData\\Roaming\\*"]);
let KnownAutoITNames = dynamic(["autoit.exe", "autoit3.exe"]);
DeviceProcessEvents
| where ProcessCommandLine has_any ("autoit", "autoit3") // Catch common AutoIT executions
| where not(InitiatingProcessFileName in (KnownAutoITNames)) // Exclude expected process names
| where FolderPath has_any (SuspiciousLocations) // Check for execution from suspicious locations
| where InitiatingProcessFileName !contains "Updater" // Exclude legitimate software updaters
| extend RenamedAutoIT = iff(InitiatingProcessFileName !in (KnownAutoITNames), "Renamed AutoIT Instance", "Legit AutoIT")
| project Timestamp, DeviceName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessFileName, FolderPath, RenamedAutoIT

```

### Renamed autoit files

``` KQL

DeviceProcessEvents
| where ( FileName !has "autoit" and ProcessVersionInfoOriginalFileName has_any ("autoit", "autoit3") ) or ( InitiatingProcessFileName !has "autoit" and InitiatingProcessVersionInfoOriginalFileName has_any ("autoit", "autoit3") )

```
