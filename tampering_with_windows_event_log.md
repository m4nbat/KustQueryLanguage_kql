# Tampering with the Windows event log

source: https://www.linkedin.com/feed/update/urn:li:activity:7038997228815867904/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_recent_activity_details_all%3B6gVrKrP2R1exxyyHSPCOjg%3D%3D

## MDE DeviceRegistryEvents Table Detection
`//Detect possible tampering with the Windows event log registry keys
DeviceRegistryEvents
| where InitiatingProcessCommandLine has @"powershell.exe"
| where ActionType == @"RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\" and RegistryValueData endswith ".dll"`

## Windows Event IDs
`//Detect possible tampering with the Windows event log registry keys
SecurityEvent
| where EventID in (1108,1107)`
