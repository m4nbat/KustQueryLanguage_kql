# File Downloads

## mde kql query
// Detect file downloads
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction= tostring(json.direction), user_agent=tostring(json.user_agent), uri=tostring(json.uri)
| where uri matches regex @"\.(?:dll|exe|zip|7z|ps1|ps|bat|sh)$"
