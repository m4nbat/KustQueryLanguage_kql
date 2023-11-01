# Title
ClearFake Detection Analytics

# Description
Queries to detect initial download of .appx file

# Source
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

# MITRE ATT&CK
-

# Queries for sentinel and MDE

```
//TTP: ClearFake - Possible creation of malicious .appx file
DeviceFileEvents
| where InitiatingProcessFileName =~ "Explorer.exe" and FileName in~ ("AppxProvider.dll","AppxManifest.xml")
```
