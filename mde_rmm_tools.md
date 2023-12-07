# Title
RMM Tool Hunt Queries

# Description
Analytics to hunt for RMM tool usage in the environment

# MITRE ATT&CK
TA0011: Command and Control
T1219: Remote Access Software
T1133: External Remote Services

# MDE Queries

## Splashtop
```
DeviceProcessEvents
| where (ProcessVersionInfoProductName contains "SplashTop" and ProcessVersionInfoFileDescription contains "SplashTop") or (ProcessVersionInfoOriginalFileName contains "SplashTop")

```
