# Regsvr32.exe loading scripts or files from external sources

## Source: Microsoft

// Finds regsvr32.exe command line executions that loads scriptlet files from remote sites.
// This technique could be used to avoid application whitelisting and antimalware protection.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "regsvr32.exe" and InitiatingProcessCommandLine contains "/i:http" 
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
| top 100 by Timestamp
