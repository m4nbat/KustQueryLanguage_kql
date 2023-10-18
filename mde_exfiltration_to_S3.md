# Title
Data exfiltration to AWS S3 via commandline

# Source
DFIR Report - 

# Description

```
DeviceProcessEvents
| where InitiatingProcessFileName endswith "WaAppAgent.exe" and InitiatingProcessCommandLine has_all (" s3 "," cp ","--exclude",".dll",".exe")

```
