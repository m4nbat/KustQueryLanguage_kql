# Day 8 - 

## Description

**Detection opportunity:** printui.exe relocated to a suspicious location
This pseudo detection analytic identifies instances of printui.exe relocated outside of Windows\System32. Relocation of this binary outside of System32 will be highly unusual, although third-party system administrative binaries may occasionally utilize a relocated and/or renamed version of the binary. Vulnerable DLLs like printui.dll can be abused by threats like Tangerine Turkey for **DLL search order hijacking** and side-loading. Here at Red Canary we have profiled System32 binaries, collected and stored their expected metadata, and used the information to build detection analytics. 

### Example Script / Pseudo Code

```

Pseudo query - process_path_is_unexpected == (printui)

```

## References

https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2025/

## Query MDE

### Device Process Events

``` KQL

DeviceProcessEvents
| where ( InitiatingProcessFileName =~ "printui.exe" and not ( InitiatingProcessFolderPath has_any ( @"Windows\System32", @"Windows\\System32", @"Windows\SysWOW64" ) ) ) or ( FileName =~ "printui.exe" and not (FolderPath has_any ( @"Windows\System32", @"Windows\\System32", @"Windows\SysWOW64" ) ) )

```

### Device File Events

``` KQL
//Lower Fidelity
DeviceFileEvents
| where ( ActionType in~ ("FileCreated","FileModified") and FileName =~ "printui.exe" and not ( FolderPath has_any ( @"Windows\System32", @"Windows\\System32", @"Windows\SysWOW64" ) ) )

```
