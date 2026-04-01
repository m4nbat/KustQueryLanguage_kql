# Mastodon Social Network Used for C2 Communication Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.001 | Web Service: Dead Drop Resolver | [Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/) |
| T1071.001 | Application Layer Protocol: Web Protocols | [Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
Detects non-whitelisted processes making network connections to Mastodon social media instances, which can indicate use of Mastodon as a C2 channel. Uses an external list of Mastodon server domains for detection.

#### Risk
Threat actors have been observed using Mastodon and other social media platforms for command and control to blend into legitimate network traffic and evade detection.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://instances.social/api/token#
- https://github.com/m4nbat/mastodon_servers

## Defender For Endpoint
```KQL
curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json
```

```KQL
let exclusions = datatable (filepattern:string)["mastodon.exe","Discord.exe","firefox.exe","msedge.exe","chrome.exe","telegram.exe","brave.exe","ExpressConnectNetworkService.exe","sidekick.exe"];
let mastodonServers1 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_1-9999.txt'];
let mastodonServers2 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_10000-17175.txt'];
// e.g. let iocs = externaldata (ip:string, hash:string, domain:string)[@'https://my-external-lookup.com/ioc.csv'];
//to generate mastodon bearer token go here: https://instances.social/api/token#
// to grab all mastodon servers use: curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where RemoteUrl has_any (iocs) or RemoteUrl has_any (mastodonServers2)
| where InitiatingProcessFileName !in~ (exclusions)
```

## Sentinel
```KQL
curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json
```

```KQL
let exclusions = datatable (filepattern:string)["mastodon.exe","Discord.exe","firefox.exe","msedge.exe","chrome.exe","telegram.exe","brave.exe","ExpressConnectNetworkService.exe","sidekick.exe"];
let mastodonServers1 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_1-9999.txt'];
let mastodonServers2 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_10000-17175.txt'];
// e.g. let iocs = externaldata (ip:string, hash:string, domain:string)[@'https://my-external-lookup.com/ioc.csv'];
//to generate mastodon bearer token go here: https://instances.social/api/token#
// to grab all mastodon servers use: curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where RemoteUrl has_any (iocs) or RemoteUrl has_any (mastodonServers2)
| where InitiatingProcessFileName !in~ (exclusions)
```
