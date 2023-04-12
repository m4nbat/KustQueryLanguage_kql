# Autostart Persistence

## HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension\PeerdistDllName=peerdist.dll
The wininet.dll library is using this location internally in its P2P_PEER_DIST_API::LoadPeerDist function.

## source:
https://www.hexacorn.com/blog/2022/01/23/beyond-good-ol-run-key-part-138/
<br> 
Kusto inspiration from [@Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/edit/main/DFIR/DFE%20-%20Registry-Run-Keys-Forensics.md)

### Defender For Endpoint

```
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where PreviousRegistryKey startswith "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension\PeerdistDllName=peerdist.dll"
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```
### Sentinel

```
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where PreviousRegistryKey startswith "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PeerDist\Extension\PeerdistDllName=peerdist.dll"
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```
