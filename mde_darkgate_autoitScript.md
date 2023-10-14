# Title
DarkGate autoIT script commandline detection

# Source
Intrusion analysis

# Description

```
DeviceProcessEvents    | where FileName =~ "cmd.exe"   | where ProcessCommandLine has_all ("curl","http",".au3")

```
