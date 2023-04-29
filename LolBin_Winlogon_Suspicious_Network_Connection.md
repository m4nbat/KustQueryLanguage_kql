# LolBin Winlogon Suspicious Network Connection

# Tactics: Execution

# Source

- https://twitter.com/ellishlomo/status/1652312221156794369?t=sx5lxEpNYrwjRUNWgytRdQ&s=19


# Description

Find Winlogon with outbound connections #MDE

Kusto:


```
DeviceProcessEvents
| where FileName == "winlogon.exe"
| where ActionType == "CreateRemoteThread"
| join (
DeviceNetworkEvents
| where RemoteIPType == "Public"
) on DeviceId
```
