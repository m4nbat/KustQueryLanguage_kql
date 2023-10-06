# Bunny Loader MDE Detections

# Source
https://www.zscaler.com/blogs/security-research/bunnyloader-newest-malware-service

# Command and Control - Useragent and URI related IoCs
```
let UserAgents = datatable(useragent:string)["BunnyLoader","BunnyTasks"];
DeviceNetworkEvents
| extend user_agent = tostring(AdditionalFields.user_agent)
| extend HTTPMethod = tostring(AdditionalFields.method)
| extend uri = tostring(AdditionalFields.uri)
| where ActionType has_any ("HttpConnectionInspected","SslConnectionInspected") and user_agent has_any (UserAgents) and uri has_all ("Bunny") and HTTPMethod =~ "GET"
| extend direction = tostring(AdditionalFields.direction)
| extend host = tostring(AdditionalFields.host)
| extend request_body_len = tostring(AdditionalFields.request_body_len)
| extend response_body_len = tostring(AdditionalFields.response_body_len)
| extend status_code = tostring(AdditionalFields.status_code)
| extend status_msg = tostring(AdditionalFields.status_msg)
| extend tags = tostring(parse_json(tostring(AdditionalFields.tags)))
| extend trans_depth = tostring(AdditionalFields.trans_depth)
| extend version_ = tostring(AdditionalFields.version)
```
# Persistence - Registry key creation
```
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey =~ @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" and RegistryValueName =~ "Spyware_Blocker"
```
