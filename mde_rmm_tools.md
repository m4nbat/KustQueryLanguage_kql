# Title
RMM Tool Hunt Queries

# Description
Analytics to hunt for RMM tool usage in the environment

# MITRE ATT&CK
T1219 - Remote Access Software

# MDE Queries

## Splashtop
```
DeviceProcessEvents
| where (ProcessVersionInfoProductName contains "SplashTop" and ProcessVersionInfoFileDescription contains "SplashTop") or (ProcessVersionInfoOriginalFileName contains "SplashTop")

```
