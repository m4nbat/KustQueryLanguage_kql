

DeviceProcessEvents
| where (IniatingProcessParentFileName =~ "wmiprvse.exe" or IniatingProcessFileName =~ "wmiprvse.exe") and (IniatingProcessFileName =~ "cmd.exe" or FileName =~ "cmd.exe") and (InitiatingProcessCommandLine contains @"\\127.0.0.1\ADMIN" or ProcessCommandLine contains @"\\127.0.0.1\ADMIN")
