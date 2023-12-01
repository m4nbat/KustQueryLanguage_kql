# Name
Munchkin Tool

# Description
The Munchkin utility is delivered as an ISO file, which is loaded in a newly installed instance of the VirtualBox virtualization product. This ISO file represents a customized implementation of the Alpine OS, which threat operators likely chose due to its small footprint. Upon running the operating system, the following commands are executed at boot:

# Source:
https://unit42.paloaltonetworks.com/blackcat-ransomware-releases-new-utility-munchkin/


# Detection

```
let commands = datatable(command:string)["new-session","-A","-s","controller","send","-t","controller","/app/controller","&&","poweroff","ENTER","detach","-s","controller"];
DeviceProcessEvents
| where ProcessCommandLine has_all (commands) or InitiatingProcessCommandLine has_all (commands)
```

```
let c1 = datatable(a:string)["new-session","-A","-s","controller","send","-t","controller","/app/controller","&&","poweroff","ENTER","detach","-s","controller"];
let c2 = datatable(b:string)["echo","-n","password","|","chpasswd"];
let c3 = datatable(c:string)["eject"];
let command1 = DeviceProcessEvents | where ProcessCommandLine has_all (c1) | distinct DeviceId, ProcessCommandLine;
let command2 = DeviceProcessEvents | where ProcessCommandLine has_all (c2) | distinct DeviceId, ProcessCommandLine;
let command3 = DeviceProcessEvents | where ProcessCommandLine has_all (c3) | distinct DeviceId, ProcessCommandLine;
command1 | join command2 on DeviceId | join command3 on DeviceId
| where isnotempty(DeviceId) and  isnotempty(DeviceId1) and  isnotempty(DeviceId2)
```
