# ClearFake Detection Analytics - C2 Communications

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071 | Application Layer Protocol | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) |
| T1102 | Web Service | [Web Service](https://attack.mitre.org/techniques/T1102/) |

#### Description
Queries to detect C2 communications associated with ClearFake infrastructure, including SSL certificate subject inspection, domain connections, and IP connections using an external IOC list.

#### Risk
Connections to ClearFake C2 infrastructure indicate an active infection. ClearFake uses compromised websites to deliver fake browser updates and subsequently establish C2 communications with infected hosts.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Sekoia - ClearFake: a newcomer to the fake updates threats landscape](https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/)

## Defender For Endpoint

```KQL
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

```KQL
//IOC: ClearFake - Possible connection to ClearFake C2 Infrastructure network connection to domain
let clearFakeDomains = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where RemoteUrl has_any (clearFakeDomains)
```

```KQL
//IOC: ClearFake - Possible connection to ClearFake C2 Infrastructure network connetcion to IPs
let clearFakeIps = externaldata(domain:string)[h@"https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt"]
with(format="txt");
DeviceNetworkEvents
| where RemoteIP has_any (clearFakeIps)
```
