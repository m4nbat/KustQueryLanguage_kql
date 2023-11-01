# Title
ClearFake Detection Analytics

# Description
Queries to detect  C2 communications.

# Source
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

# MITRE ATT&CK
-

# Queries for sentinel and MDE

```
//IOC: ClearFake - Possible connection to ClearFake C2 infrastructure certificate subject CN
let clearFakeDomains = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt") | distinct domain;
DeviceNetworkEvents
| where ActionType =~ "SslConnectionInspected"
| extend issuer = tostring(parse_json(AdditionalFields.issuer))
| extend server_name = tostring(parse_json(AdditionalFields.server_name))
| extend subject = tostring(parse_json(AdditionalFields.subject))
| extend established = tostring(parse_json(AdditionalFields.established))
| extend direction = tostring(parse_json(AdditionalFields.direction))
| where server_name has_any (clearFakeDomains)
```

```
//IOC: ClearFake - Possible connection to ClearFake C2 Infrastructure network connection to domain
let clearFakeDomains = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where RemoteUrl has_any (clearFakeDomains)
```

```
//IOC: ClearFake - Possible connection to ClearFake C2 Infrastructure network connetcion to IPs
let clearFakeIps = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where RemoteIP has_any (clearFakeIps)
```
