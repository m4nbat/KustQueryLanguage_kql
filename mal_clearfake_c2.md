# ClearFake C2 Infrastructure Communication Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
Detects connections to ClearFake C2 infrastructure using an external IOC list. Covers SSL certificate server names, URL matches, and direct IP connections to known ClearFake infrastructure.

#### Risk
ClearFake is a fake browser update campaign that uses compromised websites to distribute malware. C2 communication uses SSL to blend with legitimate traffic.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/
- https://raw.githubusercontent.com/m4nbat/ioc_lists/main/clearFakeIocs.txt

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

## Sentinel
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
