# Title
ClearFake Detection Analytics

# Description
Queries to detect initial download of .appx file and subsequent C2 communications.

# Source
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

# MITRE ATT&CK
-

# Queries for sentinel and MDE

```
//TTP: ClearFake - Possible download of malicious .appx file
let browsers = datatable(name:string)["edge.exe","chrome.exe","firefox.exe"];
DeviceFileEvents
| where ActionType in~ ("FileCreated","FileRenamed") and InitiatingProcessFileName has_any (browsers) and FileName endswith ".appx"
```

```
//IOC: ClearFake - Possible connection to ClearFake C2 infrastructure certificate subject CN
let clearFakeDomains = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where ActionType =~ "SslConnectionInspected"
| extend issuer = tostring(AdditionalFields.issuer)
| extend server_name = tostring(AdditionalFields.server_name)
| extend subject = tostring(AdditionalFields.subject)
| extend established = tostring(parse_json(tostring(AdditionalFields.established)))
| extend direction = tostring(AdditionalFields.direction)
| where subject has_any (clearFakeDomains)
```

```
//IOC: ClearFake - Possible connection to ClearFake C2 Infrastructure network connetcion to domain
let clearFakeDomains = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where RemoteUrl has_any (clearFakeDomains)
```
