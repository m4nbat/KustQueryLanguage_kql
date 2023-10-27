# Name:
Execution of python scripts via python installer binary

# Description:


# Source:
@kostatsale

# MITRE ATT&CK
-  Defense Evasion
- T1202

# Query for MDE or Sentinel

```
DeviceProcessEvents
| where InitiatingProcessParentFileName has_any "setup.exe" and InitiatingProcessFileName =~ "pythonw.exe" and InitiatingProcessCommandLine has_all (@"\AppData\",".py")
```
