# DarkGate VBS File Downlod

# Source
Intrusion Analysis

# MDE
```
DeviceNetworkEvents
| where InitiatingProcessCommandLine has_all (".vbs") and RemotePort == 2351
```
