# Title
Darkgate

# Source
Intrusion Anlysis

# Description


```
UrlClickEvents
| where Workload =~ "Teams"
| where Url matches regex @"https:\/\/[a-zA-Z0-9-_]+\.sharepoint\.com\/:[a-zA-Z]:\/g\/personal\/[a-zA-Z0-9_]+_onmicrosoft_com"

```

```
DeviceNetworkEvents
| where RemoteUrl has_all ("ceo",".sharepoint.com","_onmicrosoft_com")

```

```
UrlClickEvents
| where Url has_all ("ceo",".sharepoint.com","_onmicrosoft_com")
```

```
DeviceNetworkEvents
| where RemoteUrl matches regex @"https:\/\/[a-zA-Z0-9-_]+\.sharepoint\.com\/:[a-zA-Z]:\/g\/personal\/[a-zA-Z0-9_]+_onmicrosoft_com"

```
