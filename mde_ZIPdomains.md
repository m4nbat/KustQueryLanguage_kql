# Zip Domain Hunt Query
# Source: 
# Description
Kusto queries to detect Zip domains

```
DeviceNetworksEvents
| where RemoteUrl matches regex @"(?i)^(?:https?://)?[^/]+\.zip$"
```

